use async_trait::async_trait;
use c2pa::http::http::{HeaderName, HeaderValue, Method, Request, Response};
use c2pa::http::{AsyncHttpResolver, HttpResolverError};
use c2pa::{Context, Error as C2paError, Reader};
use std::io::{Cursor, Read};
use std::sync::RwLock;
use wasm_bindgen::prelude::*;

static PROXY_ENDPOINT: RwLock<Option<String>> = RwLock::new(None);

#[wasm_bindgen]
pub fn init() {
    console_error_panic_hook::set_once();
}

/// Sets the OCSP/timestamp proxy endpoint used by [`ProxyHttpResolver`]. The browser
/// has no way to fetch most CA infrastructure (OCSP responders, some TSAs) directly —
/// they don't serve CORS headers — so every outbound HTTP request c2pa-rs makes is
/// relayed through our own SSRF-hardened server-side proxy instead.
#[wasm_bindgen]
pub fn set_ocsp_proxy_endpoint(url: String) {
    if let Ok(mut lock) = PROXY_ENDPOINT.write() {
        *lock = Some(url);
    }
}

fn get_proxy_endpoint() -> String {
    if let Ok(lock) = PROXY_ENDPOINT.read() {
        if let Some(ref ep) = *lock {
            if !ep.is_empty() {
                return ep.clone();
            }
        }
    }
    if let Some(win) = web_sys::window() {
        if let Ok(origin) = win.location().origin() {
            if !origin.is_empty() && origin != "null" {
                return format!("{}/api/ocsp-proxy", origin.trim_end_matches('/'));
            }
        }
    }
    "/api/ocsp-proxy".to_string()
}

/// Routes every outbound HTTP request c2pa-rs makes (OCSP, timestamp checks, AIA
/// cert-chasing) through our own proxy rather than fetching directly.
///
/// This resolver has no way to know in advance which target hosts serve CORS headers
/// and which don't — CA infrastructure is run by whoever issued the certificate being
/// checked, at whatever hostname and however they've configured it, so there's no
/// reliable signal (scheme, hostname substring, etc.) to decide "this one probably
/// doesn't need the proxy." Trying to guess is exactly what let some requests bypass
/// the proxy (and its SSRF hardening) entirely in an earlier version of this resolver.
/// Always proxying costs one extra hop; never proxying (or guessing wrong) fails silently
/// on CORS or reopens the SSRF surface, so unconditional proxying is the only case that's
/// always correct.
pub struct ProxyHttpResolver {
    client: reqwest::Client,
}

impl ProxyHttpResolver {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

// WASM is single-threaded, so `async_trait`'s default `Send`-bound futures don't apply
// there (reqwest's wasm32 client isn't `Send`) — mirrors c2pa-rs's own
// `maybe_send_sync` convention for the same reason (see that module's doc comment).
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl AsyncHttpResolver for ProxyHttpResolver {
    async fn http_resolve_async(
        &self,
        request: Request<Vec<u8>>,
    ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
        let (parts, body): (c2pa::http::http::request::Parts, Vec<u8>) = request.into_parts();
        let target_url = parts.uri.to_string();

        let proxy = get_proxy_endpoint();
        let encoded: String =
            url::form_urlencoded::byte_serialize(target_url.as_bytes()).collect();
        let fetch_url = format!("{}?url={}", proxy, encoded);

        let mut reqwest_builder = match parts.method {
            Method::GET => self.client.get(&fetch_url),
            Method::POST => self.client.post(&fetch_url),
            Method::PUT => self.client.put(&fetch_url),
            Method::HEAD => self.client.head(&fetch_url),
            _ => self.client.request(
                reqwest::Method::from_bytes(parts.method.as_str().as_bytes())
                    .unwrap_or(reqwest::Method::GET),
                &fetch_url,
            ),
        };

        for (name, value) in parts.headers.iter() {
            let name_str: &str = name.as_str();
            if name_str.eq_ignore_ascii_case("host")
                || name_str.eq_ignore_ascii_case("connection")
                || name_str.eq_ignore_ascii_case("content-length")
            {
                continue;
            }
            if let Ok(v) = reqwest::header::HeaderValue::from_bytes(value.as_bytes()) {
                reqwest_builder = reqwest_builder.header(name_str, v);
            }
        }

        if !body.is_empty() {
            reqwest_builder = reqwest_builder.body(body);
        }

        let resp = reqwest_builder
            .send()
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        let status = resp.status();
        let mut resp_builder = Response::builder().status(status.as_u16());

        for (name, value) in resp.headers().iter() {
            if let Ok(hn) = HeaderName::from_bytes(name.as_str().as_bytes()) {
                if let Ok(hv) = HeaderValue::from_bytes(value.as_bytes()) {
                    resp_builder = resp_builder.header(hn, hv);
                }
            }
        }

        let bytes = resp
            .bytes()
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        let body_box: Box<dyn Read> = Box::new(Cursor::new(bytes.to_vec()));
        Ok(resp_builder.body(body_box)?)
    }
}

fn build_context(settings_json: Option<String>) -> Result<Context, JsValue> {
    let context = match settings_json {
        Some(json) if !json.trim().is_empty() => Context::new()
            .with_settings(json)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse C2PA settings: {e}")))?,
        _ => Context::new(),
    };

    Ok(context.with_resolver_async(ProxyHttpResolver::new()))
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct ManifestCertificateData {
    pub label: String,
    pub is_active: bool,
    pub cert_chain_pem: Option<String>,
    pub issuer_org: Option<String>,
    pub common_name: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct ExtractedCertificatesResult {
    pub active_manifest: Option<String>,
    pub manifests: std::collections::HashMap<String, ManifestCertificateData>,
}

///
/// The caller is expected to always pass `verify.remote_manifest_fetch: false` in
/// `settings_json` — if the asset has no embedded manifest and only references one
/// hosted remotely, this returns `Err` with the message `"Remote manifest reference:
/// <url>"` instead of fetching it, so the caller can ask for consent first. Fetch the
/// URL yourself and validate the bytes via `read_sidecar_manifest_store`, which the
/// upstream SDK documents as usable for "a remote manifest or a sidecar manifest."
#[wasm_bindgen]
pub async fn read_manifest_store(
    file_bytes: Vec<u8>,
    format: String,
    settings_json: Option<String>,
) -> Result<String, JsValue> {
    let context = build_context(settings_json)?;

    match Reader::from_context(context)
        .with_stream_async(&format, Cursor::new(file_bytes))
        .await
    {
        Ok(reader) => Ok(reader.crjson()),
        Err(C2paError::RemoteManifestUrl(url)) => {
            Err(JsValue::from_str(&format!("Remote manifest reference: {url}")))
        }
        Err(e) => Err(JsValue::from_str(&format!("Failed to read C2PA data: {e}"))),
    }
}

#[wasm_bindgen]
pub async fn extract_manifest_certificates(
    file_bytes: Vec<u8>,
    format: String,
    settings_json: Option<String>,
) -> Result<String, JsValue> {
    let context = build_context(settings_json)?;

    let reader = Reader::from_context(context)
        .with_stream_async(&format, Cursor::new(file_bytes))
        .await
        .map_err(|e| JsValue::from_str(&format!("Failed to read C2PA data: {e}")))?;

    let active_label = reader.active_label().map(|s| s.to_string());
    let mut manifests_map = std::collections::HashMap::new();

    for (label, manifest) in reader.manifests() {
        let cert_chain_pem = manifest.signature_info().map(|s| s.cert_chain().to_string());
        let issuer_org = manifest.signature_info().and_then(|s| s.issuer.clone());
        let common_name = manifest.signature_info().and_then(|s| s.common_name.clone());
        let is_active = active_label.as_deref() == Some(label.as_str());

        manifests_map.insert(
            label.clone(),
            ManifestCertificateData {
                label: label.clone(),
                is_active,
                cert_chain_pem,
                issuer_org,
                common_name,
            },
        );
    }

    let result = ExtractedCertificatesResult {
        active_manifest: active_label,
        manifests: manifests_map,
    };

    serde_json::to_string(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize certificates result: {e}")))
}

/// Validate a detached (`.c2pa`) manifest store, a fetched remote manifest, or a
/// sidecar manifest against its referenced asset.
///
/// The C2PA manifest bytes live separately from the asset (`asset_bytes`) — either
/// because they came from a `.c2pa` sidecar file, or because the caller fetched them
/// from a remote manifest URL surfaced by `read_manifest_store`. We feed both into
/// c2pa-rs's `with_manifest_data_and_stream_async`, which evaluates the asset-hash
/// assertions *against the actual asset bytes* — something we cannot do with
/// the single-blob `read_manifest_store` path.
///
/// * `manifest_bytes` - raw bytes of the manifest store (JUMBF), from a `.c2pa`
///   sidecar or a fetched remote manifest.
/// * `asset_bytes` - raw bytes of the referenced asset.
/// * `asset_format` - MIME type of the asset (e.g. "image/jpeg"). The
///   sidecar's own format is always `application/c2pa` and the SDK infers that.
/// * `settings_json` - trust settings (same shape as `read_manifest_store`).
#[wasm_bindgen]
pub async fn read_sidecar_manifest_store(
    manifest_bytes: Vec<u8>,
    asset_bytes: Vec<u8>,
    asset_format: String,
    settings_json: Option<String>,
) -> Result<String, JsValue> {
    let context = build_context(settings_json)?;

    let reader = Reader::from_context(context)
        .with_manifest_data_and_stream_async(
            &manifest_bytes,
            &asset_format,
            Cursor::new(asset_bytes),
        )
        .await
        .map_err(|e| {
            JsValue::from_str(&format!("Failed to validate sidecar against asset: {e}"))
        })?;

    Ok(reader.crjson())
}

#[wasm_bindgen]
pub async fn extract_sidecar_manifest_certificates(
    manifest_bytes: Vec<u8>,
    asset_bytes: Vec<u8>,
    asset_format: String,
    settings_json: Option<String>,
) -> Result<String, JsValue> {
    let context = build_context(settings_json)?;

    let reader = Reader::from_context(context)
        .with_manifest_data_and_stream_async(
            &manifest_bytes,
            &asset_format,
            Cursor::new(asset_bytes),
        )
        .await
        .map_err(|e| {
            JsValue::from_str(&format!("Failed to read sidecar C2PA data: {e}"))
        })?;

    let active_label = reader.active_label().map(|s| s.to_string());
    let mut manifests_map = std::collections::HashMap::new();

    for (label, manifest) in reader.manifests() {
        let cert_chain_pem = manifest.signature_info().map(|s| s.cert_chain().to_string());
        let issuer_org = manifest.signature_info().and_then(|s| s.issuer.clone());
        let common_name = manifest.signature_info().and_then(|s| s.common_name.clone());
        let is_active = active_label.as_deref() == Some(label.as_str());

        manifests_map.insert(
            label.clone(),
            ManifestCertificateData {
                label: label.clone(),
                is_active,
                cert_chain_pem,
                issuer_org,
                common_name,
            },
        );
    }

    let result = ExtractedCertificatesResult {
        active_manifest: active_label,
        manifests: manifests_map,
    };

    serde_json::to_string(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize certificates result: {e}")))
}

/// Resolve a JUMBF resource URI (e.g. a thumbnail identifier) to its raw bytes.
///
/// Re-reads the manifest store from the provided file bytes so no persistent
/// state is required between calls. Non-fatal: callers should treat errors as
/// "resource unavailable" rather than a hard failure.
///
/// * `file_bytes`   - Raw bytes of the original asset file.
/// * `format`       - MIME type of the asset (e.g. "image/jpeg").
/// * `uri`          - JUMBF resource URI from a crJSON `identifier` field.
/// * `settings_json`- Optional trust/verify settings (same shape as `read_manifest_store`).
#[wasm_bindgen]
pub async fn get_resource_bytes(
    file_bytes: Vec<u8>,
    format: String,
    uri: String,
    settings_json: Option<String>,
) -> Result<Vec<u8>, JsValue> {
    let context = build_context(settings_json)?;

    let reader = Reader::from_context(context)
        .with_stream_async(&format, Cursor::new(file_bytes))
        .await
        .map_err(|e| JsValue::from_str(&format!("Failed to read C2PA data: {e}")))?;

    let mut out = Cursor::new(Vec::new());
    reader
        .resource_to_stream(&uri, &mut out)
        .map_err(|e| JsValue::from_str(&format!("Resource not found: {e}")))?;

    Ok(out.into_inner())
}

/// Get version information
#[wasm_bindgen]
pub fn get_version() -> String {
    format!("c2pa-local-wasm v{} using c2pa-rs {}",
            env!("CARGO_PKG_VERSION"),
            c2pa::VERSION)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        let version = get_version();
        assert!(version.contains("c2pa-local-wasm"));
    }
}

/// Regression coverage for the trust_config/EKU behavior fixed alongside #59: c2pa-rs
/// (as of the "unified trust lists" redesign in upstream commit be7f5ea2) does not seed
/// any default EKU allow-list when custom trust anchors are supplied — the caller must
/// pass `trust.trust_config` explicitly, or certificates whose only relevant EKU is the
/// C2PA claim-signing OID (not one of the always-accepted email/timestamping/OCSP EKUs)
/// are rejected as `signingCredential.invalid`, even when their issuer is fully trusted.
///
/// This exercises the real `read_manifest_store` entry point end-to-end (not mocked),
/// against a real signed asset, with a settings JSON matching exactly what
/// `src/lib/c2pa.ts`'s `toLocalSettingsJson` sends — so a future c2pa-rs upgrade that
/// changes this contract (renames the field, changes its format, stops honoring it)
/// will fail this test rather than silently reintroducing the bug.
#[cfg(test)]
mod eku_trust_config_tests {
    use super::*;
    use c2pa::{create_signer, Builder, BuilderIntent, ClaimGeneratorInfo, DigitalSourceType, SigningAlg};

    const ROOT_CERT_PEM: &str = include_str!("../tests/fixtures/eku/root_cert.pem");
    const LEAF_CERT_PEM: &str = include_str!("../tests/fixtures/eku/leaf_cert.pem");
    const LEAF_KEY_PEM: &str = include_str!("../tests/fixtures/eku/leaf_key.pem");
    const BASE_JPEG: &[u8] = include_bytes!("../tests/fixtures/eku/base.jpg");

    // Must match DEFAULT_TRUST_CONFIG in src/lib/c2pa.ts.
    const DEFAULT_TRUST_CONFIG: &str = "1.3.6.1.5.5.7.3.4\n1.3.6.1.5.5.7.3.36\n1.3.6.1.5.5.7.3.8\n1.3.6.1.5.5.7.3.9\n1.3.6.1.4.1.311.76.59.1.9\n1.3.6.1.4.1.62558.2.1";

    /// Signs `BASE_JPEG` with a leaf certificate (chained to `ROOT_CERT_PEM`) whose
    /// *only* Extended Key Usage is the C2PA claim-signing OID (1.3.6.1.4.1.62558.2.1) —
    /// deliberately not id-kp-emailProtection, which c2pa-rs accepts unconditionally
    /// regardless of trust_config and so would not exercise this regression at all
    /// (even c2pa-rs's own generic test-signing certs use emailProtection).
    fn sign_test_asset() -> Vec<u8> {
        let signer = create_signer::from_keys(
            LEAF_CERT_PEM.as_bytes(),
            LEAF_KEY_PEM.as_bytes(),
            SigningAlg::Es256,
            None,
        )
        .expect("failed to build test signer from fixture cert/key");

        // verify_after_sign is disabled here because the signing certificate isn't in
        // any trust list yet at sign time (that's exactly what read_manifest_store,
        // called afterwards with real trust settings, is meant to test).
        let signing_context = Context::new()
            .with_settings(r#"{"verify":{"verify_after_sign":false}}"#)
            .expect("failed to build signing context");
        let mut builder = Builder::from_context(signing_context);
        builder.set_intent(BuilderIntent::Create(DigitalSourceType::Empty));
        builder.set_claim_generator_info(ClaimGeneratorInfo::new("conformulator-eku-test"));

        let mut source = Cursor::new(BASE_JPEG.to_vec());
        let mut dest = Cursor::new(Vec::new());
        builder
            .sign(signer.as_ref(), "image/jpeg", &mut source, &mut dest)
            .expect("failed to sign test asset");
        dest.into_inner()
    }

    /// Same shape `toLocalSettingsJson` (c2pa.ts) builds: `verify` plus a `trust` block
    /// whose `anchors` array holds our root as a manifest-kind `TrustAnchor`, and,
    /// optionally, `trust_config` both at the top level and on that anchor.
    fn settings_json(trust_config: Option<&str>) -> String {
        let mut anchor = serde_json::json!({
            "trust_anchors": ROOT_CERT_PEM,
            "trust_uri": "test-root",
            "trust_kind": "manifest",
        });
        let mut trust = serde_json::json!({});
        if let Some(tc) = trust_config {
            anchor["trust_config"] = serde_json::json!(tc);
            trust["trust_config"] = serde_json::json!(tc);
        }
        trust["anchors"] = serde_json::json!([anchor]);
        serde_json::json!({
            "verify": { "verify_after_reading": true, "verify_trust": true },
            "trust": trust,
        })
        .to_string()
    }

    #[test]
    fn trust_config_makes_a_c2pa_only_eku_cert_trusted() {
        let signed_bytes = sign_test_asset();

        let crjson = pollster::block_on(read_manifest_store(
            signed_bytes,
            "image/jpeg".to_string(),
            Some(settings_json(Some(DEFAULT_TRUST_CONFIG))),
        ))
        .unwrap_or_else(|e| panic!("read_manifest_store failed: {e:?}"));

        assert!(
            crjson.contains("signingCredential.trusted"),
            "expected signingCredential.trusted in crJSON: {crjson}"
        );
        assert!(
            !crjson.contains("signingCredential.invalid"),
            "did not expect signingCredential.invalid in crJSON: {crjson}"
        );
        assert!(
            !crjson.contains("signingCredential.untrusted"),
            "did not expect signingCredential.untrusted in crJSON: {crjson}"
        );
    }

    /// The per-anchor `trust_config` alone is not enough: c2pa-rs's signer trust check
    /// reads only the top-level `trust.trust_config` for EKUs, so toLocalSettingsJson
    /// must keep sending both.
    #[test]
    fn per_anchor_trust_config_alone_does_not_accept_a_c2pa_only_eku_cert() {
        let signed_bytes = sign_test_asset();
        let mut settings: serde_json::Value =
            serde_json::from_str(&settings_json(Some(DEFAULT_TRUST_CONFIG))).unwrap();
        settings["trust"].as_object_mut().unwrap().remove("trust_config");

        let crjson = pollster::block_on(read_manifest_store(
            signed_bytes,
            "image/jpeg".to_string(),
            Some(settings.to_string()),
        ))
        .unwrap_or_else(|e| panic!("read_manifest_store failed: {e:?}"));

        assert!(
            !crjson.contains("signingCredential.trusted"),
            "expected per-anchor trust_config alone to be insufficient, but got: {crjson}"
        );
    }

    /// Proves the test above is meaningful: without trust_config, the identical
    /// cert/asset — whose issuing root IS in trust.anchors — is still rejected purely
    /// on EKU grounds. This is the exact bug #59 reported and PR #60 fixed.
    #[test]
    fn without_trust_config_the_same_cert_is_rejected_on_eku_grounds() {
        let signed_bytes = sign_test_asset();

        let crjson = pollster::block_on(read_manifest_store(
            signed_bytes,
            "image/jpeg".to_string(),
            Some(settings_json(None)),
        ))
        .unwrap_or_else(|e| panic!("read_manifest_store failed: {e:?}"));

        assert!(
            !crjson.contains("signingCredential.trusted"),
            "expected the cert to be rejected without trust_config, but got: {crjson}"
        );
        // Matches issue #59's exact reported failure signature: both codes together,
        // even though the issuing root is in trust_anchors — the cert is rejected
        // purely because its EKU isn't on any (now-empty) accepted list.
        assert!(
            crjson.contains("signingCredential.invalid") && crjson.contains("certificate missing required EKU"),
            "expected 'certificate missing required EKU' without trust_config, but got: {crjson}"
        );
        assert!(
            crjson.contains("signingCredential.untrusted"),
            "expected signingCredential.untrusted without trust_config, but got: {crjson}"
        );
    }
}

/// CAWG identity trust as configured by `toLocalSettingsJson` (c2pa.ts): a
/// `trust_kind: "cawg"` `TrustAnchor` carrying session-supplied X.509 roots and/or
/// trusted ICA issuer DIDs. Uses c2pa-rs's own signed CAWG fixtures, read through the
/// real `read_manifest_store` entry point, and checks the statuses scoped to the
/// `cawg.identity` assertion — which is what src/lib/cawg.ts derives its state from.
#[cfg(test)]
mod cawg_trust_tests {
    use super::*;

    // Manifest signed with c2pa-rs's test certs, carrying an X.509 `cawg.identity`
    // assertion whose certificate chains to the same test root bundle.
    const CAWG_X509_JPEG: &[u8] = include_bytes!("../../c2pa-rs/sdk/tests/fixtures/C_with_CAWG_data.jpg");
    const TEST_ROOT_BUNDLE_PEM: &str =
        include_str!("../../c2pa-rs/sdk/tests/fixtures/certs/trust/test_cert_root_bundle.pem");

    // Manifest carrying an identity-claims-aggregation `cawg.identity` assertion.
    const CAWG_ICA_JPEG: &[u8] = include_bytes!(
        "../../c2pa-rs/sdk/src/identity/tests/fixtures/claim_aggregation/ica_validation/success.jpg"
    );
    const ICA_ISSUER_DID: &str = "did:jwk:eyJhbGciOiJFZERTQSIsImt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiTXA1LTBlODNuTmdRaGRoQlc4UnNoa2p5OTBzYTFBOUpJemtJdGNEcUN1SSJ9";

    /// Settings with no C2PA anchors of interest and, optionally, a CAWG anchor.
    fn settings_json(cawg_anchor: Option<serde_json::Value>) -> String {
        let mut anchors = vec![];
        if let Some(a) = cawg_anchor {
            anchors.push(a);
        }
        serde_json::json!({
            "verify": { "verify_after_reading": true, "verify_trust": true, "remote_manifest_fetch": false },
            "trust": { "anchors": anchors },
        })
        .to_string()
    }

    fn cawg_anchor(trust_anchors: &str, trusted_ica_issuers: &[&str]) -> serde_json::Value {
        serde_json::json!({
            "trust_anchors": trust_anchors,
            "trust_uri": "session:cawg-identity-trust",
            "trust_kind": "cawg",
            "trusted_ica_issuers": trusted_ica_issuers,
        })
    }

    /// Codes in crJSON whose `url` points at a `cawg.identity` assertion.
    fn identity_codes(crjson: &str) -> Vec<String> {
        let v: serde_json::Value = serde_json::from_str(crjson).expect("crJSON should parse");
        let mut codes = vec![];
        let mut visit = |list: &serde_json::Value| {
            for s in list.as_array().into_iter().flatten() {
                let url = s["url"].as_str().unwrap_or("");
                if url.ends_with("/cawg.identity") {
                    codes.push(s["code"].as_str().unwrap_or("").to_string());
                }
            }
        };
        for m in v["manifests"].as_array().into_iter().flatten() {
            for bucket in ["success", "informational", "failure"] {
                visit(&m["validationResults"][bucket]);
            }
        }
        for bucket in ["success", "informational", "failure"] {
            visit(&v["validationResults"]["activeManifest"][bucket]);
        }
        codes
    }

    fn read(bytes: &[u8], settings: String) -> String {
        pollster::block_on(read_manifest_store(bytes.to_vec(), "image/jpeg".to_string(), Some(settings)))
            .unwrap_or_else(|e| panic!("read_manifest_store failed: {e:?}"))
    }

    #[test]
    fn x509_identity_is_untrusted_without_a_cawg_anchor() {
        let codes = identity_codes(&read(CAWG_X509_JPEG, settings_json(None)));
        assert!(
            !codes.iter().any(|c| c == "cawg.x509.credential.trusted"),
            "did not expect a trusted CAWG identity without a CAWG anchor: {codes:?}"
        );
        assert!(
            codes.iter().any(|c| c == "cawg.x509.credential.untrusted" || c == "signingCredential.untrusted"),
            "expected an untrusted CAWG identity without a CAWG anchor: {codes:?}"
        );
    }

    #[test]
    fn x509_identity_is_trusted_once_its_cawg_anchor_is_configured() {
        let settings = settings_json(Some(cawg_anchor(TEST_ROOT_BUNDLE_PEM, &[])));
        let codes = identity_codes(&read(CAWG_X509_JPEG, settings));
        assert!(
            codes.iter().any(|c| c == "cawg.x509.credential.trusted"),
            "expected cawg.x509.credential.trusted with the CAWG anchor configured: {codes:?}"
        );
        assert!(
            !codes.iter().any(|c| c == "cawg.x509.credential.untrusted" || c == "signingCredential.untrusted"),
            "did not expect an untrusted CAWG identity with the anchor configured: {codes:?}"
        );
    }

    /// Documents why c2pa.ts only keeps `cawg.identity`-scoped statuses from its CAWG
    /// read: c2pa-rs adds every anchor to the C2PA signer trust policy regardless of
    /// `trust_kind`, so a CAWG-only anchor also makes the claim signer "trusted".
    /// If this starts failing, c2pa-rs scoped CAWG anchors to identities and the
    /// separate CAWG read in runTrustValidationFlow could be folded into step 1.
    #[test]
    fn cawg_anchor_also_trusts_the_c2pa_claim_signer() {
        let settings = settings_json(Some(cawg_anchor(TEST_ROOT_BUNDLE_PEM, &[])));
        let crjson = read(CAWG_X509_JPEG, settings);
        let v: serde_json::Value = serde_json::from_str(&crjson).unwrap();
        let signer_trusted_via_cawg = v["manifests"].as_array().into_iter().flatten().any(|m| {
            m["validationResults"]["success"].as_array().into_iter().flatten().any(|s| {
                s["code"] == "signingCredential.trusted"
                    && s["url"].as_str().unwrap_or("").ends_with("/c2pa.signature")
                    && s["explanation"].as_str().unwrap_or("").contains("session:cawg-identity-trust")
            })
        });
        assert!(signer_trusted_via_cawg, "expected the CAWG anchor to leak into C2PA signer trust: {crjson}");
    }

    // The Mozilla S/MIME snapshot the app bundles, and a copy of the IPTC end-entity
    // list (trust.iptc.org/end-entity-list.pem, fetched 2026-10-19).
    const MOZILLA_SMIME_ROOTS_PEM: &str =
        include_str!("../../public/trust/cawg/mozilla-smime-roots.pem");
    const IPTC_END_ENTITY_PEM: &str = include_str!("../tests/fixtures/cawg/iptc-end-entity-list.pem");

    /// The opt-in CAWG interim trust lists, shaped as toLocalSettingsJson sends them:
    /// Mozilla roots as one CAWG anchor, and the IPTC lists as another whose anchor
    /// list is empty (as trust.iptc.org serves it today) but whose end-entity list
    /// rides on `allowed_list`.
    #[test]
    fn cawg_interim_trust_lists_are_accepted_by_c2pa_rs() {
        let mozilla = serde_json::json!({
            "trust_anchors": MOZILLA_SMIME_ROOTS_PEM,
            "trust_uri": "https://ccadb.my.salesforce-sites.com/mozilla/IncludedRootsPEMTxt?TrustBitsInclude=Email",
            "trust_kind": "cawg",
        });
        let iptc = serde_json::json!({
            "trust_anchors": "",
            "trust_uri": "https://trust.iptc.org/anchor-list.pem",
            "trust_kind": "cawg",
            "allowed_list": IPTC_END_ENTITY_PEM,
        });
        let settings = serde_json::json!({
            "verify": { "verify_after_reading": true, "verify_trust": true, "remote_manifest_fetch": false },
            "trust": { "anchors": [mozilla, iptc] },
        })
        .to_string();

        // read() panics if c2pa-rs rejects the settings.
        let codes = identity_codes(&read(CAWG_X509_JPEG, settings));
        // c2pa-rs's test identity cert chains to neither list.
        assert!(
            !codes.iter().any(|c| c == "cawg.x509.credential.trusted"),
            "did not expect the test identity to be trusted by the public lists: {codes:?}"
        );
    }

    #[test]
    fn ica_identity_is_untrusted_without_a_trusted_issuer() {
        let codes = identity_codes(&read(CAWG_ICA_JPEG, settings_json(None)));
        assert!(
            codes.iter().any(|c| c == "cawg.ica.untrusted_issuer"),
            "expected cawg.ica.untrusted_issuer with no ICA issuers configured: {codes:?}"
        );
        assert!(!codes.iter().any(|c| c == "cawg.ica.credential_valid"), "{codes:?}");
    }

    #[test]
    fn ica_identity_is_trusted_once_its_issuer_did_is_configured() {
        let settings = settings_json(Some(cawg_anchor("", &[ICA_ISSUER_DID])));
        let codes = identity_codes(&read(CAWG_ICA_JPEG, settings));
        assert!(
            codes.iter().any(|c| c == "cawg.ica.credential_valid"),
            "expected cawg.ica.credential_valid with the issuer DID configured: {codes:?}"
        );
        assert!(!codes.iter().any(|c| c == "cawg.ica.untrusted_issuer"), "{codes:?}");
    }
}
