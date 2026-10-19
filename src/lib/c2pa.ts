import { VERSION_INFO } from './version'
import type { ConformanceReport, IcaOcspInfo } from './types'
import { VALIDATION_STATUS } from './constants'
import {
  isCrJson, legacyToCrJson, getActiveManifestValidationStatus, withCawgIdentityStatusesFrom, type CrJson,
} from './crjson'
import { getCawgIdentities } from './cawg'

// One named trust list, mapped to a c2pa-rs `TrustAnchor` entry in `trust.anchors`.
type TrustListSettings = {
  /** PEM bundle of root certificates */
  pem: string
  /** Reported by c2pa-rs as the trust list a signer was found in */
  uri: string
  kind?: 'manifest' | 'tsa' | 'cawg'
  /** PEM bundle of explicitly allowed end-entity certificates */
  allowedList?: string
  /** CAWG lists only: exact-match DIDs of trusted ICA credential issuers */
  trustedIcaIssuers?: string[]
}

/**
 * Session-only CAWG identity trust, configured in CertificateManager and kept in
 * memory only. Used to evaluate `cawg.identity` credentials: X.509 identity
 * certificates against `anchors`, identity claims aggregation (ICA) credentials
 * against `trustedIcaIssuers` (exact-match DIDs).
 */
export type CawgTrustConfig = {
  /** PEM root certificates trusted for CAWG X.509 identity credentials */
  anchors?: string[]
  /** DIDs of trusted ICA credential issuers */
  trustedIcaIssuers?: string[]
  /**
   * Opt in to the CAWG interim trust lists: the bundled Mozilla S/MIME root
   * snapshot, plus the IPTC lists fetched live from trust.iptc.org.
   */
  publicLists?: boolean
}

/** CAWG interim trust lists (CAWG identity assertion spec §8.2.4.1), as loaded. */
export type CawgPublicLists = {
  mozillaSmimeRoots: string
  /** When the bundled Mozilla snapshot was taken, if recorded */
  mozillaSnapshotDate?: string
  iptcAnchors: string
  iptcEndEntities: string
}

// Trust/verify settings passed to the local WASM read functions.
type Settings = {
  verify?: { verifyAfterReading?: boolean; verifyTrust?: boolean }
  trust?: { lists?: TrustListSettings[] }
  softBindingAlgorithms?: string[]
}

type LocalC2paModule = {
  default: () => Promise<unknown>
  get_version: () => string
  read_manifest_store: (fileBytes: Uint8Array, format: string, settingsJson?: string) => Promise<string>
  read_sidecar_manifest_store?: (
    manifestBytes: Uint8Array,
    assetBytes: Uint8Array,
    assetFormat: string,
    settingsJson?: string,
  ) => Promise<string>
  get_resource_bytes?: (
    fileBytes: Uint8Array,
    format: string,
    uri: string,
    settingsJson?: string,
  ) => Promise<Uint8Array>
  set_ocsp_proxy_endpoint?: (url: string) => void
  extract_manifest_certificates?: (
    fileBytes: Uint8Array,
    format: string,
    settingsJson?: string,
  ) => Promise<string>
  extract_sidecar_manifest_certificates?: (
    manifestBytes: Uint8Array,
    assetBytes: Uint8Array,
    assetFormat: string,
    settingsJson?: string,
  ) => Promise<string>
}

type ExtractedCrJsonResult = {
  crJson: CrJson
  usedITL: boolean
  usedTestCerts: boolean
  usedCawgTrust: boolean
  usedCawgPublicLists: boolean
  icaOcsp?: Record<string, IcaOcspInfo>
}

const importModule = new Function('modulePath', 'return import(modulePath)') as (modulePath: string) => Promise<LocalC2paModule>

type ITL = { allowed: string; anchors: string }

type MainTrustLists = { c2pa: string; tsa: string }

let c2paInstance: C2paInstance | null = null
let mainTrustLists: MainTrustLists | null = null
let cawgTrust: CawgTrustConfig = {}
let cawgPublicLists: CawgPublicLists | null = null
let itl: ITL | null = null
let softBindingAlgorithms: string[] | null = null

// Official C2PA trust list URLs
const TRUST_LIST_URL = 'https://raw.githubusercontent.com/c2pa-org/conformance-public/main/trust-list/C2PA-TRUST-LIST.pem'
const TSA_TRUST_LIST_URL = 'https://raw.githubusercontent.com/c2pa-org/conformance-public/main/trust-list/C2PA-TSA-TRUST-LIST.pem'
// C2PA soft binding algorithm registry (canonical URL, redirects to latest JSON).
// Its 301 response doesn't send Access-Control-Allow-Origin, so browsers block the
// redirect before it ever reaches GitHub (see #48) — the correct fix is for the
// sbal.c2pa.org hosting platform to add CORS headers to that redirect response.
// Until that's fixed upstream, fall back to fetching the redirect target directly.
const SOFT_BINDING_REGISTRY_URL = 'https://sbal.c2pa.org/'
const SOFT_BINDING_REGISTRY_FALLBACK_URL =
  'https://raw.githubusercontent.com/c2pa-org/specifications/main/supplemental-ui/softbinding-alg-list/softbinding-algorithm-list.json'
// ITL (Interim Trust List) - stored locally; use base URL for deployed (e.g. GitHub Pages)
const base = typeof import.meta.env?.BASE_URL === 'string' ? import.meta.env.BASE_URL : '/'
const ITL_ALLOWED_URL = `${base}trust/allowed.pem`   // leaf certificates
const ITL_ANCHORS_URL = `${base}trust/anchors.pem`   // root certificates

// CAWG interim trust lists, used only when the user opts in. CCADB serves the
// Mozilla list without CORS headers, so a same-origin snapshot is bundled (see
// scripts/update-cawg-trust.mjs); the IPTC lists allow cross-origin fetches and
// are fetched live, which reveals the user's IP address to trust.iptc.org.
const MOZILLA_SMIME_SOURCE_URL = 'https://ccadb.my.salesforce-sites.com/mozilla/IncludedRootsPEMTxt?TrustBitsInclude=Email'
const MOZILLA_SMIME_SNAPSHOT_URL = `${base}trust/cawg/mozilla-smime-roots.pem`
const MOZILLA_SMIME_SNAPSHOT_META_URL = `${base}trust/cawg/mozilla-smime-roots.json`
const IPTC_ANCHOR_LIST_URL = 'https://trust.iptc.org/anchor-list.pem'
const IPTC_END_ENTITY_LIST_URL = 'https://trust.iptc.org/end-entity-list.pem'

// Trust list URIs for lists that aren't fetched from a URL of their own. c2pa-rs
// reports the URI in `signingCredential.trusted` explanations.
const TEST_CERTS_TRUST_URI = 'session:test-certificates'
const CAWG_SESSION_TRUST_URI = 'session:cawg-identity-trust'

// c2pa-rs clears its built-in EKU allow-list when constructing a Store from
// custom context settings. Restore the SDK's standard C2PA EKUs whenever this
// app supplies custom trust anchors.
const DEFAULT_TRUST_CONFIG = [
  '1.3.6.1.5.5.7.3.4',         // id-kp-emailProtection
  '1.3.6.1.5.5.7.3.36',        // id-kp-documentSigning
  '1.3.6.1.5.5.7.3.8',         // id-kp-timeStamping
  '1.3.6.1.5.5.7.3.9',         // id-kp-OCSPSigning
  '1.3.6.1.4.1.311.76.59.1.9', // Microsoft C2PA signing
  '1.3.6.1.4.1.62558.2.1',     // C2PA claim signing
].join('\n')

function hasSessionCawgTrust(cawg?: CawgTrustConfig): boolean {
  return !!(cawg?.anchors?.length || cawg?.trustedIcaIssuers?.length)
}

/**
 * Builds c2pa-rs `trust` settings as a `trust.anchors: TrustAnchor[]` array (the
 * deprecated `trust.trust_anchors` / `user_anchors` strings are removed in c2pa-rs
 * 0.92). Each trust list becomes its own anchor so its URI is reported back.
 *
 * c2pa-rs adds every anchor to the C2PA signer trust policy regardless of
 * `trust_kind`, so a CAWG anchor here can also make a C2PA claim signer chaining
 * to it look trusted. Only pass `cawg` for reads whose `cawg.identity`-scoped
 * statuses are the only ones kept (see runTrustValidationFlow).
 */
function toLocalTrustSettings(trust?: Settings['trust']) {
  const anchors: Record<string, unknown>[] = (trust?.lists ?? []).map((list) => {
    const kind = list.kind ?? 'manifest'
    return {
      trust_anchors: list.pem,
      trust_uri: list.uri,
      trust_kind: kind,
      // A CAWG anchor's trust_config replaces c2pa-rs's CAWG EKU policy, so leave it unset.
      ...(kind !== 'cawg' ? { trust_config: DEFAULT_TRUST_CONFIG } : {}),
      // Skip an allowed_list with nothing in it (the IPTC lists can be served empty).
      ...(list.allowedList?.includes('BEGIN CERTIFICATE') ? { allowed_list: list.allowedList } : {}),
      ...(list.trustedIcaIssuers ? { trusted_ica_issuers: list.trustedIcaIssuers } : {}),
    }
  })

  if (anchors.length === 0) return undefined

  // The top-level trust_config is what the signer trust check itself consults for
  // EKUs; the per-anchor copy only overrides the certificate profile check.
  return { trust_config: DEFAULT_TRUST_CONFIG, anchors }
}

function toLocalSettingsJson(settings?: Settings): string {
  const localSettings = {
    verify: {
      verify_after_reading: settings?.verify?.verifyAfterReading ?? true,
      verify_trust: settings?.verify?.verifyTrust ?? true,
      // Never let c2pa-rs auto-fetch remote manifests: doing so would silently reveal
      // the validating user's IP address and the fact they're inspecting this file to
      // a third-party host, with no consent. We surface remote references instead and
      // fetch them ourselves only after the user explicitly opts in (see
      // processRemoteManifest).
      remote_manifest_fetch: false,
      // Live-fetch OCSP status for the signing certificate when the manifest doesn't
      // already staple an OCSP response. Routed through our own SSRF-hardened proxy
      // (see set_ocsp_proxy_endpoint / ProxyHttpResolver in the wasm crate) since OCSP
      // responders don't serve CORS headers and can't be fetched from the browser directly.
      ocsp_fetch: true,
    },
    trust: toLocalTrustSettings(settings?.trust),
    ...(settings?.softBindingAlgorithms?.length
      ? { soft_binding: { soft_binding_algorithms: settings.softBindingAlgorithms } }
      : {}),
  }

  return JSON.stringify(localSettings)
}

// ── Local WASM instance ───────────────────────────────────────────────────────

type C2paInstance = {
  module: LocalC2paModule
  reader: {
    fromBlob: (format: string, file: Blob, settings?: Settings) => Promise<ReaderHandle | null>
    fromSidecarAndBlob?: (
      sidecarBytes: Uint8Array,
      assetFormat: string,
      assetFile: Blob,
      settings?: Settings,
    ) => Promise<ReaderHandle | null>
  }
  getVersion: () => string
  extractCertificates?: (format: string, file: Blob, settings?: Settings) => Promise<any>
  extractSidecarCertificates?: (
    sidecarBytes: Uint8Array,
    assetFormat: string,
    assetFile: Blob,
    settings?: Settings,
  ) => Promise<any>
}

type ReaderHandle = {
  manifestStore: () => Promise<CrJson>
  free: () => Promise<void>
}

// Test-only escape hatch: set to bypass the probe+import path.
let _overrideLocalModule: LocalC2paModule | null = null

export function _setLocalModuleForTesting(mod: LocalC2paModule | null): void {
  _overrideLocalModule = mod
  c2paInstance = null
}

function buildC2paFromModule(localModule: LocalC2paModule): C2paInstance {
  const parseCrJson = (raw: string): CrJson => {
    const parsed = JSON.parse(raw) as CrJson
    if (!isCrJson(parsed)) {
      throw new Error('Local WASM returned non-crJSON format')
    }
    return parsed
  }

  return {
    module: localModule,
    reader: {
      fromBlob: async (format: string, file: Blob, settings?: Settings) => ({
        manifestStore: async () => {
          const fileBytes = new Uint8Array(await file.arrayBuffer())
          const json = await localModule.read_manifest_store(
            fileBytes,
            format,
            toLocalSettingsJson(settings),
          )
          return parseCrJson(json)
        },
        free: async () => {},
      }),
      ...(typeof localModule.read_sidecar_manifest_store === 'function'
        ? {
            fromSidecarAndBlob: async (
              sidecarBytes: Uint8Array,
              assetFormat: string,
              assetFile: Blob,
              settings?: Settings,
            ) => ({
              manifestStore: async () => {
                const assetBytes = new Uint8Array(await assetFile.arrayBuffer())
                const json = await localModule.read_sidecar_manifest_store!(
                  sidecarBytes,
                  assetBytes,
                  assetFormat,
                  toLocalSettingsJson(settings),
                )
                return parseCrJson(json)
              },
              free: async () => {},
            }),
          }
        : {}),
    },
    getVersion: () => localModule.get_version(),
    ...(typeof localModule.extract_manifest_certificates === 'function'
      ? {
          extractCertificates: async (format: string, file: Blob, settings?: Settings) => {
            const fileBytes = new Uint8Array(await file.arrayBuffer())
            const json = await localModule.extract_manifest_certificates!(
              fileBytes,
              format,
              toLocalSettingsJson(settings),
            )
            return JSON.parse(json)
          },
        }
      : {}),
    ...(typeof localModule.extract_sidecar_manifest_certificates === 'function'
      ? {
          extractSidecarCertificates: async (
            sidecarBytes: Uint8Array,
            assetFormat: string,
            assetFile: Blob,
            settings?: Settings,
          ) => {
            const assetBytes = new Uint8Array(await assetFile.arrayBuffer())
            const json = await localModule.extract_sidecar_manifest_certificates!(
              sidecarBytes,
              assetBytes,
              assetFormat,
              toLocalSettingsJson(settings),
            )
            return JSON.parse(json)
          },
        }
      : {}),
  }
}

async function createLocalC2pa(): Promise<C2paInstance | null> {
  if (_overrideLocalModule) {
    return buildC2paFromModule(_overrideLocalModule)
  }

  try {
    const moduleUrl = `${base}local-c2pa/c2pa_local.js`
    const probe = await fetch(moduleUrl, { method: 'HEAD' })
    const contentType = probe.headers.get('content-type') ?? ''
    if (!probe.ok || (!contentType.includes('javascript') && !contentType.includes('ecmascript'))) {
      return null
    }

    const localModule = await importModule(moduleUrl)
    await localModule.default()

    if (typeof localModule.set_ocsp_proxy_endpoint === 'function') {
      const origin = typeof window !== 'undefined' && window.location?.origin ? window.location.origin : ''
      if (origin) {
        localModule.set_ocsp_proxy_endpoint(`${origin}/api/ocsp-proxy`)
      }
    }

    return buildC2paFromModule(localModule)
  } catch (error) {
    console.info('Local c2pa-rs WASM not available:', error)
    return null
  }
}

async function initC2pa(): Promise<C2paInstance> {
  if (c2paInstance) {
    return c2paInstance
  }

  const instance = await createLocalC2pa()
  if (!instance) {
    throw new Error('Local c2pa-rs WASM not available. Run `npm run build:local-wasm` to build it.')
  }

  c2paInstance = instance
  return c2paInstance
}

/**
 * Set the session-only CAWG identity trust used by later validations. Kept in
 * memory only; reports flag `usedCawgTrust` when it changed an identity's verdict.
 */
export function setCawgTrust(config: CawgTrustConfig): void {
  cawgTrust = {
    anchors: [...(config.anchors ?? [])],
    trustedIcaIssuers: [...(config.trustedIcaIssuers ?? [])],
    publicLists: config.publicLists === true,
  }
}

/**
 * Load the CAWG interim trust lists (cached once loaded). Fetches the IPTC lists
 * from trust.iptc.org, so only call this after the user has opted in.
 */
export async function loadCawgPublicLists(): Promise<CawgPublicLists> {
  if (cawgPublicLists) return cawgPublicLists

  const fetchText = async (url: string, name: string) => {
    const response = await fetch(url)
    if (!response.ok) {
      throw new Error(`Failed to fetch ${name}: ${response.status} ${response.statusText}`)
    }
    return response.text()
  }

  const [mozillaSmimeRoots, mozillaMeta, iptcAnchors, iptcEndEntities] = await Promise.all([
    fetchText(MOZILLA_SMIME_SNAPSHOT_URL, 'bundled Mozilla S/MIME roots'),
    fetch(MOZILLA_SMIME_SNAPSHOT_META_URL)
      .then((r): Promise<{ fetchedAt?: string }> => (r.ok ? r.json() : Promise.resolve({})))
      .catch((): { fetchedAt?: string } => ({})),
    fetchText(IPTC_ANCHOR_LIST_URL, 'IPTC anchor list'),
    fetchText(IPTC_END_ENTITY_LIST_URL, 'IPTC end-entity list'),
  ])

  cawgPublicLists = {
    mozillaSmimeRoots,
    mozillaSnapshotDate: mozillaMeta.fetchedAt,
    iptcAnchors,
    iptcEndEntities,
  }
  console.log('✅ Loaded CAWG interim trust lists (Mozilla S/MIME snapshot + IPTC)')
  return cawgPublicLists
}

export function _resetCawgPublicListsCacheForTesting(): void {
  cawgPublicLists = null
}

/** CAWG trust lists for the configured CAWG trust; public lists are skipped if they fail to load. */
async function cawgTrustLists(): Promise<{ publicLists: TrustListSettings[]; sessionLists: TrustListSettings[] }> {
  const publicLists: TrustListSettings[] = []
  if (cawgTrust.publicLists) {
    try {
      const lists = await loadCawgPublicLists()
      publicLists.push({ pem: lists.mozillaSmimeRoots, uri: MOZILLA_SMIME_SOURCE_URL, kind: 'cawg' })
      if (lists.iptcAnchors.includes('BEGIN CERTIFICATE') || lists.iptcEndEntities.includes('BEGIN CERTIFICATE')) {
        publicLists.push({
          pem: lists.iptcAnchors,
          uri: IPTC_ANCHOR_LIST_URL,
          kind: 'cawg',
          allowedList: lists.iptcEndEntities,
        })
      }
    } catch (error) {
      console.warn('CAWG interim trust lists unavailable; skipping them:', error)
    }
  }

  const sessionLists: TrustListSettings[] = hasSessionCawgTrust(cawgTrust)
    ? [{
        pem: (cawgTrust.anchors ?? []).join('\n'),
        uri: CAWG_SESSION_TRUST_URI,
        kind: 'cawg',
        trustedIcaIssuers: cawgTrust.trustedIcaIssuers ?? [],
      }]
    : []

  return { publicLists, sessionLists }
}

function countTrustedCawgIdentities(crJson: CrJson): number {
  return (crJson.manifests ?? []).reduce(
    (n, manifest) => n + getCawgIdentities(crJson, manifest).filter((id) => id.state === 'trusted').length,
    0,
  )
}

// ── Trust list fetching ───────────────────────────────────────────────────────

async function fetchMainTrustLists(): Promise<MainTrustLists> {
  if (mainTrustLists) {
    return mainTrustLists
  }

  try {
    const [trustListResponse, tsaTrustListResponse] = await Promise.all([
      fetch(TRUST_LIST_URL),
      fetch(TSA_TRUST_LIST_URL)
    ])

    if (!trustListResponse.ok) {
      throw new Error(`Failed to fetch C2PA trust list: ${trustListResponse.status} ${trustListResponse.statusText}`)
    }
    if (!tsaTrustListResponse.ok) {
      throw new Error(`Failed to fetch TSA trust list: ${tsaTrustListResponse.status} ${tsaTrustListResponse.statusText}`)
    }

    const [trustList, tsaTrustList] = await Promise.all([
      trustListResponse.text(),
      tsaTrustListResponse.text()
    ])

    mainTrustLists = { c2pa: trustList, tsa: tsaTrustList }
    console.log('✅ Loaded main trust lists')
    return mainTrustLists
  } catch (error) {
    console.error('Failed to fetch main trust lists:', error)
    throw new Error('Failed to fetch C2PA trust lists')
  }
}

/**
 * Fetch the ITL (Interim Trust List)
 * The ITL consists of two files with distinct roles:
 * - allowed.pem: end-entity (leaf) certificates → TrustAnchor allowed_list
 * - anchors.pem: root CA certificates → TrustAnchor trust_anchors
 */
async function fetchITL(): Promise<ITL> {
  if (itl) {
    return itl
  }

  try {
    const [allowedResponse, anchorsResponse] = await Promise.all([
      fetch(ITL_ALLOWED_URL),
      fetch(ITL_ANCHORS_URL)
    ])

    if (!allowedResponse.ok) {
      throw new Error(`Failed to fetch ITL allowed.pem: ${allowedResponse.status} ${allowedResponse.statusText}`)
    }
    if (!anchorsResponse.ok) {
      throw new Error(`Failed to fetch ITL anchors.pem: ${anchorsResponse.status} ${anchorsResponse.statusText}`)
    }

    const [allowed, anchors] = await Promise.all([
      allowedResponse.text(),
      anchorsResponse.text()
    ])

    itl = { allowed, anchors }
    console.log('✅ Loaded ITL (Interim Trust List) - allowed.pem (leaf certs) + anchors.pem (root CAs)')
    return itl
  } catch (error) {
    console.error('Failed to fetch ITL:', error)
    throw new Error('Failed to fetch ITL')
  }
}

async function fetchSoftBindingAlgorithms(): Promise<string[]> {
  if (softBindingAlgorithms) {
    return softBindingAlgorithms
  }

  for (const url of [SOFT_BINDING_REGISTRY_URL, SOFT_BINDING_REGISTRY_FALLBACK_URL]) {
    try {
      const response = await fetch(url)
      if (!response.ok) {
        throw new Error(`Failed to fetch soft binding registry: ${response.status} ${response.statusText}`)
      }
      const entries = await response.json() as Array<{ alg?: string }>
      softBindingAlgorithms = entries.flatMap((e) => (e.alg ? [e.alg] : []))
      console.log(`✅ Loaded soft binding registry from ${url} (${softBindingAlgorithms.length} algorithms)`)
      return softBindingAlgorithms
    } catch (error) {
      console.warn(`Failed to fetch soft binding registry from ${url}:`, error)
    }
  }

  console.warn('Failed to fetch soft binding registry from all sources; soft binding validation may report unsupported algorithms')
  return []
}

export const _fetchSoftBindingAlgorithmsForTesting = fetchSoftBindingAlgorithms

export function _resetSoftBindingCacheForTesting(): void {
  softBindingAlgorithms = null
}

// ── MIME / file type helpers ──────────────────────────────────────────────────

const MIME_TYPE_MAP: Record<string, string> = {
  'audio/x-m4a': 'audio/mp4',
  'audio/m4a': 'audio/mp4',
  'video/x-m4v': 'video/mp4',
  'video/quicktime': 'video/mp4',
  'image/dng': 'image/x-adobe-dng',
}

const EXTENSION_MIME_MAP: Record<string, string> = {
  'heic': 'image/heic',
  'heif': 'image/heif',
  'avci': 'image/avci',
  'avcs': 'image/avcs',
  'dng': 'image/x-adobe-dng',
  'arw': 'image/x-sony-arw',
  'cr2': 'image/x-canon-cr2',
  'cr3': 'image/x-canon-cr3',
  'nef': 'image/x-nikon-nef',
  'orf': 'image/x-olympus-orf',
  'rw2': 'image/x-panasonic-rw2',
  'c2pa': 'application/c2pa',
}

export const SIDECAR_MIME = 'application/c2pa'

export function isSidecarFile(file: File): boolean {
  if (file.type === SIDECAR_MIME) return true
  const ext = file.name.split('.').pop()?.toLowerCase() ?? ''
  return ext === 'c2pa'
}

export function resolveMimeType(file: File): string {
  const mapped = MIME_TYPE_MAP[file.type]
  if (mapped) return mapped
  if (file.type && file.type !== 'application/octet-stream') return file.type
  const ext = file.name.split('.').pop()?.toLowerCase() ?? ''
  return EXTENSION_MIME_MAP[ext] ?? file.type
}

// ── Thumbnail enrichment ──────────────────────────────────────────────────────

/**
 * Resolve unresolved JUMBF `identifier` URIs in thumbnail assertions to inline
 * base64 `data` fields. Uses the local WASM's `get_resource_bytes` when
 * available; silently skips when not.
 */
async function enrichThumbnailsViaWasm(
  crJson: CrJson,
  fileBytes: Uint8Array,
  format: string,
  localModule: LocalC2paModule,
): Promise<void> {
  if (typeof localModule.get_resource_bytes !== 'function') return

  // Pass explicit settings (not undefined) so the wasm side doesn't fall back to
  // c2pa-rs's own defaults, which have remote_manifest_fetch: true — resolving a
  // thumbnail must never silently fetch a remote manifest.
  const resourceToBytes = async (uri: string): Promise<Uint8Array> => {
    return localModule.get_resource_bytes!(fileBytes, format, uri, toLocalSettingsJson({}))
  }

  await enrichThumbnails(crJson, resourceToBytes)
}

async function enrichThumbnails(
  crJson: CrJson,
  resourceToBytes: (uri: string) => Promise<Uint8Array>,
): Promise<void> {
  for (const manifest of (crJson.manifests ?? [])) {
    const assertions = (manifest.assertions ?? {}) as Record<string, Record<string, unknown>>
    for (const [key, assertion] of Object.entries(assertions)) {
      if (!assertion || typeof assertion !== 'object') continue

      const targets: Array<Record<string, unknown>> = []
      if (key.startsWith('c2pa.thumbnail')) {
        targets.push(assertion)
      } else if (key.startsWith('c2pa.ingredient')) {
        const thumb = assertion.thumbnail as Record<string, unknown> | undefined
        if (thumb && typeof thumb === 'object') targets.push(thumb)
      }

      for (const target of targets) {
        if (target.data) continue
        const identifier = target.identifier
        if (typeof identifier !== 'string') continue
        try {
          const bytes = await resourceToBytes(identifier)
          const chunkSize = 8192
          let binary = ''
          for (let i = 0; i < bytes.length; i += chunkSize) {
            binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize))
          }
          target.data = `b64'${btoa(binary)}'`
        } catch {
          // Non-fatal: skip thumbnails we can't resolve
        }
      }
    }
  }
}

// ── Trust validation flow ─────────────────────────────────────────────────────

type ReadManifestStore = (settings: Settings) => Promise<CrJson | null>

/**
 * Three-step trust validation flow, independent of how bytes are sourced:
 *
 *   1. Official C2PA trust list.
 *   2. + Session-only test certificates, if they change the outcome.
 *   3. + ITL (Interim Trust List), as a last-resort fallback.
 *
 * Then CAWG identities, with the chosen step's settings plus CAWG anchors:
 *
 *   4. + CAWG interim trust lists (Mozilla S/MIME, IPTC), if the user opted in.
 *   5. + Session-only CAWG anchors / ICA issuers, flagged if they change a verdict.
 *
 * Only `cawg.identity`-scoped statuses are kept from steps 4 and 5, because c2pa-rs
 * would also accept a CAWG anchor for the C2PA claim signer.
 */
async function runTrustValidationFlow(
  readManifestStore: ReadManifestStore,
  testCertificates: string[],
  noManifestErrorMessage: string,
): Promise<ExtractedCrJsonResult> {
  console.log('Fetching official C2PA trust lists and soft binding registry...')
  const [mainLists, itlData, softBindingAlgs] = await Promise.all([
    fetchMainTrustLists(),
    fetchITL(),
    fetchSoftBindingAlgorithms(),
  ])

  const officialLists: TrustListSettings[] = [
    { pem: mainLists.c2pa, uri: TRUST_LIST_URL },
    { pem: mainLists.tsa, uri: TSA_TRUST_LIST_URL, kind: 'tsa' },
  ]

  console.log('Step 1: Validating with official trust list only...')
  const officialSettings: Settings = {
    verify: { verifyTrust: true, verifyAfterReading: true },
    trust: { lists: officialLists },
    softBindingAlgorithms: softBindingAlgs,
  }

  const officialCrJson = await readManifestStore(officialSettings)
  if (!officialCrJson) {
    throw new Error(noManifestErrorMessage)
  }

  console.log('📋 Raw crJSON keys:', Object.keys(officialCrJson))
  console.log('📋 validationResults:', JSON.stringify(officialCrJson.validationResults ?? null))
  console.log('📋 manifests[0] vr:', JSON.stringify((officialCrJson.manifests?.[0] as Record<string, unknown>)?.validationResults ?? null))

  const officialVr = getActiveManifestValidationStatus(officialCrJson)
  const officialUntrusted = officialVr?.failure?.some(
    (status) => status.code === VALIDATION_STATUS.SIGNING_CREDENTIAL_UNTRUSTED
  )

  console.log('Official TL validation results:', {
    isUntrusted: officialUntrusted,
    success: officialVr?.success?.map((s) => s.code),
    failure: officialVr?.failure?.map((f) => f.code)
  })

  let crJson = officialCrJson
  let crJsonSettings = officialSettings
  let usedTestCerts = false

  if (testCertificates.length > 0) {
    console.log('Step 2: Validating with test certificates added...')
    const testSettings: Settings = {
      verify: { verifyTrust: true, verifyAfterReading: true },
      trust: {
        lists: [...officialLists, { pem: testCertificates.join('\n'), uri: TEST_CERTS_TRUST_URI }],
      },
      softBindingAlgorithms: softBindingAlgs,
    }

    const testCrJson = await readManifestStore(testSettings)
    if (testCrJson) {
      const testVr = getActiveManifestValidationStatus(testCrJson)
      const testUntrusted = testVr?.failure?.some(
        (status) => status.code === VALIDATION_STATUS.SIGNING_CREDENTIAL_UNTRUSTED
      )

      console.log('Test cert validation results:', {
        isUntrusted: testUntrusted,
        success: testVr?.success?.map((s) => s.code),
        failure: testVr?.failure?.map((f) => f.code)
      })

      if (officialUntrusted && !testUntrusted) {
        console.log('✅ Test certificates made the difference - signature now trusted')
        usedTestCerts = true
        crJson = testCrJson
        crJsonSettings = testSettings
      } else {
        console.log('ℹ️  Test certificates loaded but not needed for validation')
      }
    }
  }

  const mainVr = getActiveManifestValidationStatus(crJson)
  const isUntrusted = mainVr?.failure?.some(
    (status) => status.code === VALIDATION_STATUS.SIGNING_CREDENTIAL_UNTRUSTED
  )

  console.log('Main validation results:', {
    isUntrusted,
    success: mainVr?.success?.map((s) => s.code),
    failure: mainVr?.failure?.map((f) => f.code)
  })

  let usedITL = false
  let finalCrJson = crJson
  let finalSettings = crJsonSettings

  if (isUntrusted) {
    console.log('⚠️  Signature untrusted on main list, checking ITL...')

    const itlSettings: Settings = {
      verify: { verifyTrust: true, verifyAfterReading: true },
      trust: {
        lists: [
          ...officialLists,
          { pem: itlData.anchors, uri: ITL_ANCHORS_URL, allowedList: itlData.allowed },
        ],
      },
      softBindingAlgorithms: softBindingAlgs,
    }

    const itlCrJson = await readManifestStore(itlSettings)
    if (itlCrJson) {
      const itlVr = getActiveManifestValidationStatus(itlCrJson)
      console.log('ITL validation results:', {
        success: itlVr?.success?.map((s) => s.code),
        failure: itlVr?.failure?.map((f) => ({ code: f.code, explanation: f.explanation }))
      })

      const itlTrusted = itlVr?.success?.some(
        (status) => status.code === VALIDATION_STATUS.SIGNING_CREDENTIAL_TRUSTED
      )
      const itlStillUntrusted = itlVr?.failure?.some(
        (status) => status.code === VALIDATION_STATUS.SIGNING_CREDENTIAL_UNTRUSTED
      )

      console.log('ITL validation check:', { itlTrusted, itlStillUntrusted })
      if (itlStillUntrusted) {
        const untrustedFailure = itlVr?.failure?.find(
          (status) => status.code === VALIDATION_STATUS.SIGNING_CREDENTIAL_UNTRUSTED
        )
        console.log('ITL still untrusted, reason:', untrustedFailure?.explanation)
      }

      if (itlTrusted && !itlStillUntrusted) {
        console.log('✅ Signature validated by ITL')
        usedITL = true
        finalCrJson = itlCrJson
        finalSettings = itlSettings
      } else {
        console.log('❌ Signature still not trusted even with ITL')
      }
    }
  }

  let usedCawgTrust = false
  let usedCawgPublicLists = false
  const { publicLists, sessionLists } = await cawgTrustLists()

  const withCawgLists = (lists: TrustListSettings[]): Settings => ({
    ...finalSettings,
    trust: { lists: [...(finalSettings.trust?.lists ?? []), ...lists] },
  })

  if (publicLists.length > 0) {
    console.log('Step 4: Evaluating CAWG identities against the CAWG interim trust lists...')
    const publicCrJson = await readManifestStore(withCawgLists(publicLists))
    if (publicCrJson) {
      finalCrJson = withCawgIdentityStatusesFrom(finalCrJson, publicCrJson)
      usedCawgPublicLists = true
    }
  }

  if (sessionLists.length > 0) {
    console.log('Step 5: Evaluating CAWG identities with session CAWG trust...')
    const cawgCrJson = await readManifestStore(withCawgLists([...publicLists, ...sessionLists]))
    if (cawgCrJson) {
      const merged = withCawgIdentityStatusesFrom(finalCrJson, cawgCrJson)
      usedCawgTrust = countTrustedCawgIdentities(merged) > countTrustedCawgIdentities(finalCrJson)
      console.log(usedCawgTrust
        ? '✅ Session CAWG trust made a CAWG identity trusted'
        : 'ℹ️  Session CAWG trust loaded but did not change any CAWG identity verdict')
      finalCrJson = merged
    }
  }

  console.log('✅ Manifest store retrieved with trust validation')

  return {
    crJson: finalCrJson,
    usedITL,
    usedTestCerts,
    usedCawgTrust,
    usedCawgPublicLists,
  }
}

// ── Public API ────────────────────────────────────────────────────────────────

async function extractCrJsonWithMetadata(file: File, testCertificates: string[] = []): Promise<ExtractedCrJsonResult> {
  const ext = file.name.split('.').pop()?.toLowerCase() ?? ''
  if (ext === 'json' || file.type === 'application/json') {
    throw new Error('JSON files are not supported. Uploading a raw crJSON report would let its contents (including trust/validation status) be displayed without any cryptographic verification.')
  }

  const mimeType = resolveMimeType(file)
  console.log('🔍 Starting file processing for:', file.name, 'Type:', file.type, mimeType !== file.type ? `(remapped to ${mimeType})` : '')

  console.log('Initializing C2PA SDK...')
  const c2pa = await initC2pa()
  console.log('✅ C2PA SDK initialized')

  const readManifestStore: ReadManifestStore = async (settings) => {
    const reader = await c2pa.reader.fromBlob(mimeType, file, settings)
    if (!reader) return null
    try {
      const crJson = await reader.manifestStore()
      const fileBytes = new Uint8Array(await file.arrayBuffer())
      await enrichThumbnailsViaWasm(crJson, fileBytes, mimeType, c2pa.module)
      return crJson
    } finally {
      await reader.free()
    }
  }

  try {
    const result = await runTrustValidationFlow(
      readManifestStore,
      testCertificates,
      mimeType === SIDECAR_MIME
        ? 'No C2PA manifest could be read from this sidecar. It may be corrupted or not a valid .c2pa file.'
        : 'No C2PA manifest found in this file',
    )

    return result
  } catch (error) {
    console.error('❌ Error in processFile:', error)
    const msg = error instanceof Error ? error.message : String(error)
    if (msg.startsWith('Remote manifest reference: ')) {
      // Not a failure — the asset only references a manifest hosted elsewhere.
      // Wrap in a real Error (the caught value may be a bare string from the wasm
      // boundary) so `instanceof Error` checks downstream see the message intact;
      // App.svelte matches this exact text to offer a consent prompt instead of
      // the generic error banner.
      throw new Error(msg)
    }
    if (msg.includes('UnsupportedFormatError') || msg.includes('Unsupported format')) {
      throw new Error(`Unsupported file format (${mimeType}). Supported formats include JPEG, PNG, WebP, AVIF, MP4, MOV, MP3, WAV, and PDF.`)
    }
    if (msg.includes('InvalidAsset') || msg.includes('Box size extends beyond') || msg.includes('box size')) {
      throw new Error(`Could not parse this file. It may be corrupted, use an unsupported codec, or the C2PA manifest may be malformed.`)
    }
    if (msg.includes('NoManifest') || msg.includes('no manifest') || msg.includes('No C2PA manifest') || msg.includes('no JUMBF data')) {
      throw new Error(`No C2PA manifest found in this file.`)
    }
    throw new Error(`Failed to process file: ${msg}`)
  }
}

export async function extractCrJson(file: File, testCertificates: string[] = []): Promise<CrJson> {
  const { crJson } = await extractCrJsonWithMetadata(file, testCertificates)
  return crJson
}

function buildConformanceReport(extracted: ExtractedCrJsonResult): ConformanceReport {
  return {
    ...extracted.crJson,
    usedITL: extracted.usedITL,
    usedTestCerts: extracted.usedTestCerts,
    usedCawgTrust: extracted.usedCawgTrust,
    usedCawgPublicLists: extracted.usedCawgPublicLists,
    _icaOcsp: extracted.icaOcsp,
    _conformanceToolVersion: {
      commit: VERSION_INFO.sha,
      shortCommit: VERSION_INFO.shortSha,
      date: VERSION_INFO.date,
      branch: VERSION_INFO.branch,
      generatedAt: VERSION_INFO.timestamp
    }
  }
}

export async function processFile(file: File, testCertificates: string[] = []): Promise<ConformanceReport> {
  return buildConformanceReport(await extractCrJsonWithMetadata(file, testCertificates))
}

async function extractSidecarWithAssetCrJsonWithMetadata(
  sidecar: File,
  asset: File,
  testCertificates: string[] = [],
): Promise<ExtractedCrJsonResult> {
  const c2pa = await initC2pa()
  const fromSidecarAndBlob = c2pa.reader.fromSidecarAndBlob
  if (!fromSidecarAndBlob) {
    throw new Error('read_sidecar_manifest_store is not available in the local WASM build.')
  }

  const assetMimeType = resolveMimeType(asset)
  const sidecarBytes = new Uint8Array(await sidecar.arrayBuffer())

  const readManifestStore: ReadManifestStore = async (settings) => {
    const reader = await fromSidecarAndBlob(sidecarBytes, assetMimeType, asset, settings)
    if (!reader) return null
    try {
      const crJson = await reader.manifestStore()
      const assetBytes = new Uint8Array(await asset.arrayBuffer())
      await enrichThumbnailsViaWasm(crJson, assetBytes, assetMimeType, c2pa.module)
      return crJson
    } finally {
      await reader.free()
    }
  }

  try {
    const result = await runTrustValidationFlow(
      readManifestStore,
      testCertificates,
      `No C2PA manifest could be read from sidecar "${sidecar.name}" paired with "${asset.name}".`,
    )

    return result
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error)
    if (msg.includes('HashMismatch') || msg.includes('dataHash') || msg.includes('bmffHash')) {
      throw new Error(
        `Asset hash mismatch: the sidecar's hash bindings don't match "${asset.name}". ` +
        `The sidecar and asset are probably not a matched pair.`,
      )
    }
    throw error
  }
}

export async function processSidecarWithAsset(
  sidecar: File,
  asset: File,
  testCertificates: string[] = [],
): Promise<ConformanceReport> {
  return buildConformanceReport(
    await extractSidecarWithAssetCrJsonWithMetadata(sidecar, asset, testCertificates),
  )
}

async function extractRemoteManifestCrJsonWithMetadata(
  file: File,
  manifestBytes: Uint8Array,
  remoteManifestUrl: string,
  testCertificates: string[] = [],
): Promise<ExtractedCrJsonResult> {
  const c2pa = await initC2pa()
  const fromSidecarAndBlob = c2pa.reader.fromSidecarAndBlob
  if (!fromSidecarAndBlob) {
    throw new Error('read_sidecar_manifest_store is not available in the local WASM build.')
  }

  const assetMimeType = resolveMimeType(file)

  const readManifestStore: ReadManifestStore = async (settings) => {
    const reader = await fromSidecarAndBlob(manifestBytes, assetMimeType, file, settings)
    if (!reader) return null
    try {
      const crJson = await reader.manifestStore()
      const assetBytes = new Uint8Array(await file.arrayBuffer())
      await enrichThumbnailsViaWasm(crJson, assetBytes, assetMimeType, c2pa.module)
      return crJson
    } finally {
      await reader.free()
    }
  }

  return runTrustValidationFlow(
    readManifestStore,
    testCertificates,
    `No C2PA manifest could be read from the remote manifest at ${remoteManifestUrl}.`,
  )
}

/**
 * Validate a manifest already fetched from a remote manifest URL — no network call.
 * Used to re-run validation (e.g. when test certificates or trust settings change)
 * without re-fetching or re-prompting for consent for the same URL.
 */
export async function revalidateRemoteManifest(
  file: File,
  manifestBytes: Uint8Array,
  remoteManifestUrl: string,
  testCertificates: string[] = [],
): Promise<ConformanceReport> {
  const extracted = await extractRemoteManifestCrJsonWithMetadata(
    file, manifestBytes, remoteManifestUrl, testCertificates,
  )
  return {
    ...buildConformanceReport(extracted),
    fetchedRemoteManifest: true,
    remoteManifestUrl,
  }
}

/**
 * Fetch a remote manifest the user has explicitly consented to retrieve, and
 * validate it against `file`. Returns the manifest bytes alongside the report so the
 * caller can cache them and re-validate later via revalidateRemoteManifest without a
 * second fetch or consent prompt.
 */
export async function processRemoteManifest(
  file: File,
  remoteManifestUrl: string,
  testCertificates: string[] = [],
): Promise<{ report: ConformanceReport; manifestBytes: Uint8Array }> {
  const response = await fetch(remoteManifestUrl)
  if (!response.ok) {
    throw new Error(`Failed to fetch remote manifest: ${response.status} ${response.statusText}`)
  }
  const manifestBytes = new Uint8Array(await response.arrayBuffer())
  const report = await revalidateRemoteManifest(file, manifestBytes, remoteManifestUrl, testCertificates)
  return { report, manifestBytes }
}

export async function getVersion(): Promise<string> {
  const c2pa = await initC2pa()
  return c2pa.getVersion()
}

export async function extractCertificatesForFile(file: File): Promise<any> {
  const c2pa = await initC2pa()
  const mime = resolveMimeType(file)
  if (isSidecarFile(file)) {
    return null
  }
  return c2pa.extractCertificates ? c2pa.extractCertificates(mime, file) : null
}

