import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import {
  processFile, getVersion, isSidecarFile, resolveMimeType, SIDECAR_MIME,
  processRemoteManifest, revalidateRemoteManifest, setCawgTrust, _resetCawgPublicListsCacheForTesting,
  _setLocalModuleForTesting, _fetchSoftBindingAlgorithmsForTesting, _resetSoftBindingCacheForTesting,
} from './c2pa'
import type { ConformanceReport } from './types'
import { getCawgIdentities } from './cawg'

// ── Shared crJSON factory ─────────────────────────────────────────────────────

function makeCrJson(opts: {
  trusted?: boolean
  untrusted?: boolean
  itlTrusted?: boolean
} = {}): string {
  const success = []
  const failure = []
  if (opts.trusted) success.push({ code: 'signingCredential.trusted' })
  if (opts.untrusted) failure.push({ code: 'signingCredential.untrusted', explanation: 'untrusted' })
  if (opts.itlTrusted) success.push({ code: 'signingCredential.trusted' })
  success.push({ code: 'timeStamp.validated' }, { code: 'claimSignature.validated' })

  return JSON.stringify({
    manifests: [{
      label: 'urn:c2pa:test',
      'claim.v2': { 'dc:format': 'image/jpeg' },
      validationResults: { success, failure, informational: [] }
    }],
    activeManifest: 'urn:c2pa:test',
    validationResults: {
      activeManifest: { success, failure, informational: [] }
    }
  })
}

// ── Mock local WASM module ────────────────────────────────────────────────────

let readCallCount = 0

type RecordedAnchor = {
  trust_anchors: string
  trust_uri?: string
  trust_kind: string
  trust_config?: string
  allowed_list?: string
  trusted_ica_issuers?: string[]
}

// Track trust settings per call so ITL tests can inspect them.
const recordedSettings: Array<{ trust?: Record<string, unknown> }> = []
const recordedTrustAnchors: RecordedAnchor[][] = []
const recordedTrustConfigs: string[] = []

function makeLocalModule(opts: {
  // Call index → overrides; unmatched calls use defaults.
  calls?: Array<{ trusted?: boolean; untrusted?: boolean } | string>
  // Override read_manifest_store entirely, e.g. to simulate a rejection.
  readManifestStore?: (fileBytes: Uint8Array, format: string, settingsJson?: string) => Promise<string>
  // Present only when the test needs sidecar/remote-manifest validation.
  readSidecarManifestStore?: (
    manifestBytes: Uint8Array, assetBytes: Uint8Array, assetFormat: string, settingsJson?: string,
  ) => Promise<string>
} = {}): Parameters<typeof _setLocalModuleForTesting>[0] {
  return {
    default: vi.fn(() => Promise.resolve()),
    get_version: vi.fn(() => 'c2pa-local-wasm v0.1.0 using c2pa-rs 0.99.0'),
    read_manifest_store: opts.readManifestStore ?? vi.fn((_bytes, _format, settingsJson) => {
      const idx = readCallCount++
      if (settingsJson) {
        try {
          const s = JSON.parse(settingsJson)
          recordedSettings.push(s)
          if (s?.trust?.anchors) recordedTrustAnchors.push(s.trust.anchors)
          if (s?.trust?.trust_config) recordedTrustConfigs.push(s.trust.trust_config)
        } catch { /* ignore */ }
      }
      const override = opts.calls?.[idx]
      return Promise.resolve(
        typeof override === 'string'
          ? override
          : override
            ? makeCrJson(override)
            : makeCrJson({ trusted: true })
      )
    }),
    ...(opts.readSidecarManifestStore ? { read_sidecar_manifest_store: opts.readSidecarManifestStore } : {}),
  }
}

// ── Test suite ────────────────────────────────────────────────────────────────

describe('c2pa utilities', () => {
  beforeEach(() => {
    readCallCount = 0
    recordedSettings.length = 0
    recordedTrustAnchors.length = 0
    recordedTrustConfigs.length = 0
    vi.clearAllMocks()

    // Default: inject a mock local module that always returns a trusted result.
    _setLocalModuleForTesting(makeLocalModule())

    // Mock trust list + ITL fetches.
    global.fetch = vi.fn((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString()
      let content = '-----BEGIN CERTIFICATE-----\nMockCertificate\n-----END CERTIFICATE-----'
      if (url.includes('allowed.pem')) {
        content = '-----BEGIN CERTIFICATE-----\nITLAllowedCert\n-----END CERTIFICATE-----'
      } else if (url.includes('anchors.pem')) {
        content = '-----BEGIN CERTIFICATE-----\nITLAnchorCert\n-----END CERTIFICATE-----'
      }
      return Promise.resolve({
        ok: true, status: 200, statusText: 'OK',
        text: () => Promise.resolve(content),
        headers: new Headers({ 'content-type': 'text/plain' }),
      } as Response)
    }) as ReturnType<typeof vi.fn>
  })

  afterEach(() => {
    setCawgTrust({})
    _resetCawgPublicListsCacheForTesting()
    _setLocalModuleForTesting(null)
    _resetSoftBindingCacheForTesting()
    vi.restoreAllMocks()
  })

  // ── getVersion ──────────────────────────────────────────────────────────────

  describe('getVersion', () => {
    it('returns the local WASM version string', async () => {
      const version = await getVersion()
      expect(version).toMatch(/c2pa-local-wasm/)
    })
  })

  // ── Sidecar detection ───────────────────────────────────────────────────────

  describe('sidecar detection', () => {
    it('detects a .c2pa file with no browser-reported MIME as a sidecar', () => {
      const f = new File([new Uint8Array([0])], 'my-manifest.c2pa', { type: '' })
      expect(isSidecarFile(f)).toBe(true)
      expect(resolveMimeType(f)).toBe(SIDECAR_MIME)
    })

    it('detects a .c2pa file served as application/octet-stream', () => {
      const f = new File([new Uint8Array([0])], 'my-manifest.c2pa', { type: 'application/octet-stream' })
      expect(isSidecarFile(f)).toBe(true)
      expect(resolveMimeType(f)).toBe(SIDECAR_MIME)
    })

    it('detects a file whose MIME is already application/c2pa', () => {
      const f = new File([new Uint8Array([0])], 'no-extension', { type: SIDECAR_MIME })
      expect(isSidecarFile(f)).toBe(true)
      expect(resolveMimeType(f)).toBe(SIDECAR_MIME)
    })

    it('does NOT mis-detect a .jpg as a sidecar', () => {
      const f = new File([new Uint8Array([0])], 'photo.jpg', { type: 'image/jpeg' })
      expect(isSidecarFile(f)).toBe(false)
      expect(resolveMimeType(f)).toBe('image/jpeg')
    })
  })

  // ── processFile — basic ─────────────────────────────────────────────────────

  describe('processFile', () => {
    it('returns a manifest store with a trusted signature', async () => {
      const result = await processFile(new File(['test'], 'test.jpg', { type: 'image/jpeg' }))
      expect(result.manifests?.length).toBeGreaterThan(0)
      expect(result.manifests?.[0]?.label).toBe('urn:c2pa:test')
      expect(result.usedITL).toBe(false)
    })

    it('attaches conformance tool version metadata', async () => {
      const result = await processFile(new File(['test'], 'test.jpg', { type: 'image/jpeg' }))
      expect(result._conformanceToolVersion).toBeDefined()
    })

    it('handles different image types', async () => {
      const result = await processFile(new File(['test'], 'test.png', { type: 'image/png' }))
      expect(result.manifests?.length).toBeGreaterThan(0)
    })

    it('accepts optional test certificates', async () => {
      const testCert = '-----BEGIN CERTIFICATE-----\nTestCert\n-----END CERTIFICATE-----'
      const result = await processFile(
        new File(['test'], 'test.jpg', { type: 'image/jpeg' }),
        [testCert],
      )
      expect(result.manifests?.length).toBeGreaterThan(0)
    })

    it('includes the standard C2PA EKUs in every trust validation pass', async () => {
      _setLocalModuleForTesting(makeLocalModule({
        calls: [
          { untrusted: true },  // main TL
          { untrusted: true },  // test certificates
          { trusted: true },    // ITL
        ],
      }))

      const testCert = '-----BEGIN CERTIFICATE-----\nTestCert\n-----END CERTIFICATE-----'
      await processFile(
        new File(['test'], 'test.jpg', { type: 'image/jpeg' }),
        [testCert],
      )

      expect(recordedTrustConfigs).toHaveLength(3)
      for (const trustConfig of recordedTrustConfigs) {
        expect(trustConfig).toContain('1.3.6.1.4.1.62558.2.1')
        expect(trustConfig).toContain('1.3.6.1.5.5.7.3.36')
      }
      // ...and on every manifest-kind anchor (DEFAULT_TRUST_CONFIG for the manifest kind).
      for (const anchors of recordedTrustAnchors) {
        for (const anchor of anchors.filter((a) => a.trust_kind === 'manifest')) {
          expect(anchor.trust_config).toContain('1.3.6.1.4.1.62558.2.1')
        }
      }
    })

    it('sends trust.anchors and none of the deprecated trust fields', async () => {
      await processFile(new File(['test'], 'test.jpg', { type: 'image/jpeg' }))

      const trust = recordedSettings[0].trust!
      expect(trust).not.toHaveProperty('trust_anchors')
      expect(trust).not.toHaveProperty('user_anchors')
      expect(trust).not.toHaveProperty('allowed_list')
      expect(recordedTrustAnchors[0].map((a) => a.trust_kind)).toEqual(['manifest', 'tsa'])
      expect(recordedTrustAnchors[0][0].trust_uri).toContain('C2PA-TRUST-LIST.pem')
      expect(recordedTrustAnchors[0][1].trust_uri).toContain('C2PA-TSA-TRUST-LIST.pem')
    })

    it('adds test certificates as their own manifest anchor in the test pass only', async () => {
      _setLocalModuleForTesting(makeLocalModule({
        calls: [{ untrusted: true }, { trusted: true }],
      }))

      const testCert = '-----BEGIN CERTIFICATE-----\nTestCert\n-----END CERTIFICATE-----'
      await processFile(new File(['test'], 'test.jpg', { type: 'image/jpeg' }), [testCert])

      expect(recordedTrustAnchors[0].some((a) => a.trust_anchors.includes('TestCert'))).toBe(false)
      const testAnchor = recordedTrustAnchors[1].find((a) => a.trust_anchors.includes('TestCert'))
      expect(testAnchor).toMatchObject({ trust_kind: 'manifest', trust_uri: 'session:test-certificates' })
    })
  })

  // ── ITL validation flow ─────────────────────────────────────────────────────

  describe('ITL validation fallback', () => {
    it('runs multiple passes when the main trust list reports untrusted', async () => {
      _setLocalModuleForTesting(makeLocalModule({
        calls: [
          { untrusted: true },  // call 0 — main TL: untrusted
          { trusted: true },    // call 1 — ITL: trusted
        ],
      }))

      await processFile(new File(['test'], 'test.jpg', { type: 'image/jpeg' }))
      expect(readCallCount).toBeGreaterThanOrEqual(2)
    })

    it('sets usedITL=true when the ITL makes the signature trusted', async () => {
      _setLocalModuleForTesting(makeLocalModule({
        calls: [
          { untrusted: true },  // main TL: untrusted
          { trusted: true },    // ITL: trusted
        ],
      }))

      const result = await processFile(new File(['test'], 'test.jpg', { type: 'image/jpeg' }))
      expect(result.usedITL).toBe(true)
    })

    it('leaves usedITL=false when the signature is trusted on the main list', async () => {
      // Default module always returns trusted — no ITL pass needed.
      const result = await processFile(new File(['test'], 'test.jpg', { type: 'image/jpeg' }))
      expect(result.usedITL).toBe(false)
      expect(readCallCount).toBe(1)
    })

    it('includes ITL anchors in the trust settings during the ITL pass', async () => {
      _setLocalModuleForTesting(makeLocalModule({
        calls: [
          { untrusted: true },
          { trusted: true },
        ],
      }))

      await processFile(new File(['test'], 'test.jpg', { type: 'image/jpeg' }))
      const itlAnchor = recordedTrustAnchors.flat().find((a) => a.trust_anchors.includes('ITLAnchorCert'))
      expect(itlAnchor).toBeDefined()
      // The ITL's leaf allow-list rides on its anchor (c2pa-rs has no top-level allowed_list).
      expect(itlAnchor!.allowed_list).toContain('ITLAllowedCert')
      expect(itlAnchor!.trust_kind).toBe('manifest')
    })
  })

  // ── Test certificate flow ───────────────────────────────────────────────────

  describe('test certificate flow', () => {
    it('sets usedTestCerts=true when test certs make the difference', async () => {
      _setLocalModuleForTesting(makeLocalModule({
        calls: [
          { untrusted: true },  // call 0 — main TL: untrusted
          { trusted: true },    // call 1 — with test certs: trusted
          { trusted: true },    // call 2 — ITL (won't be reached)
        ],
      }))

      const testCert = '-----BEGIN CERTIFICATE-----\nTestCert\n-----END CERTIFICATE-----'
      const result = await processFile(
        new File(['test'], 'test.jpg', { type: 'image/jpeg' }),
        [testCert],
      )
      expect(result.usedTestCerts).toBe(true)
    })
  })

  // ── CAWG identity trust ─────────────────────────────────────────────────────

  describe('CAWG identity trust', () => {
    const MANIFEST = 'urn:c2pa:test'
    const IDENTITY_URL = `self#jumbf=/c2pa/${MANIFEST}/c2pa.assertions/cawg.identity`

    // crJSON for a manifest carrying one X.509 cawg.identity assertion.
    function cawgCrJson(opts: { identityTrusted: boolean; signerTrusted: boolean }): string {
      const identity = opts.identityTrusted
        ? { success: [{ code: 'cawg.x509.credential.trusted', url: IDENTITY_URL }], failure: [] }
        : { success: [], failure: [{ code: 'cawg.x509.credential.untrusted', url: IDENTITY_URL }] }
      const signer = opts.signerTrusted
        ? { success: [{ code: 'signingCredential.trusted' }], failure: [] }
        : { success: [], failure: [{ code: 'signingCredential.untrusted' }] }
      const vr = {
        success: [...signer.success, { code: 'claimSignature.validated' }, ...identity.success],
        failure: [...signer.failure, ...identity.failure],
        informational: [],
      }
      return JSON.stringify({
        manifests: [{
          label: MANIFEST,
          'claim.v2': { 'dc:format': 'image/jpeg' },
          assertions: {
            'cawg.identity': {
              signer_payload: { sig_type: 'cawg.x509.cose', referenced_assertions: [] },
              signature: { certificateInfo: { subject: { CN: 'Jane Doe' } } },
            },
          },
          validationResults: vr,
        }],
        activeManifest: MANIFEST,
        validationResults: { activeManifest: vr },
      })
    }

    function identityState(report: ConformanceReport) {
      return getCawgIdentities(report, report.manifests[0])[0].state
    }

    it('makes no extra read and sends no CAWG anchor when no CAWG trust is configured', async () => {
      const report = await processFile(new File(['test'], 'test.jpg', { type: 'image/jpeg' }))
      expect(readCallCount).toBe(1)
      expect(recordedTrustAnchors.flat().some((a) => a.trust_kind === 'cawg')).toBe(false)
      expect(report.usedCawgTrust).toBe(false)
    })

    it('reaches trusted once its CAWG anchor is configured, and flags the report', async () => {
      _setLocalModuleForTesting(makeLocalModule({
        calls: [
          cawgCrJson({ identityTrusted: false, signerTrusted: true }), // official TL
          cawgCrJson({ identityTrusted: true, signerTrusted: true }),  // + CAWG anchor
        ],
      }))
      const cawgRoot = '-----BEGIN CERTIFICATE-----\nCawgRoot\n-----END CERTIFICATE-----'
      setCawgTrust({ anchors: [cawgRoot] })

      const report = await processFile(new File(['test'], 'test.jpg', { type: 'image/jpeg' }))

      expect(readCallCount).toBe(2)
      expect(recordedTrustAnchors[0].some((a) => a.trust_kind === 'cawg')).toBe(false)
      const cawgAnchor = recordedTrustAnchors[1].find((a) => a.trust_kind === 'cawg')
      expect(cawgAnchor).toMatchObject({ trust_anchors: cawgRoot, trust_uri: 'session:cawg-identity-trust' })
      // The CAWG read keeps the step's own C2PA anchors.
      expect(recordedTrustAnchors[1].filter((a) => a.trust_kind !== 'cawg')).toEqual(recordedTrustAnchors[0])

      expect(identityState(report)).toBe('trusted')
      expect(report.usedCawgTrust).toBe(true)
    })

    it('reaches trusted once its ICA issuer DID is configured', async () => {
      const did = 'did:web:issuer.example'
      _setLocalModuleForTesting(makeLocalModule({
        calls: [
          cawgCrJson({ identityTrusted: false, signerTrusted: true }),
          cawgCrJson({ identityTrusted: true, signerTrusted: true }),
        ],
      }))
      setCawgTrust({ trustedIcaIssuers: [did] })

      const report = await processFile(new File(['test'], 'test.jpg', { type: 'image/jpeg' }))

      const cawgAnchor = recordedTrustAnchors[1].find((a) => a.trust_kind === 'cawg')
      expect(cawgAnchor).toMatchObject({ trust_anchors: '', trusted_ica_issuers: [did] })
      expect(identityState(report)).toBe('trusted')
      expect(report.usedCawgTrust).toBe(true)
    })

    it('keeps only identity-scoped statuses from the CAWG read, never the C2PA signer verdict', async () => {
      // c2pa-rs also accepts CAWG anchors for the claim signer; that must not leak.
      _setLocalModuleForTesting(makeLocalModule({
        calls: [
          cawgCrJson({ identityTrusted: false, signerTrusted: false }), // official TL
          cawgCrJson({ identityTrusted: false, signerTrusted: false }), // ITL
          cawgCrJson({ identityTrusted: true, signerTrusted: true }),   // + CAWG anchor
        ],
      }))
      setCawgTrust({ anchors: ['-----BEGIN CERTIFICATE-----\nCawgRoot\n-----END CERTIFICATE-----'] })

      const report = await processFile(new File(['test'], 'test.jpg', { type: 'image/jpeg' }))

      expect(identityState(report)).toBe('trusted')
      const vr = report.validationResults!.activeManifest!
      expect(vr.failure!.map((s) => s.code)).toContain('signingCredential.untrusted')
      expect(vr.success!.map((s) => s.code)).not.toContain('signingCredential.trusted')
      expect(report.manifests[0].validationResults!.failure!.map((s) => s.code))
        .toContain('signingCredential.untrusted')
    })

    describe('CAWG interim trust lists (opt-in)', () => {
      const fetchedUrls: string[] = []

      function mockFetch(opts: { iptcAnchors?: string; iptcFails?: boolean } = {}) {
        fetchedUrls.length = 0
        global.fetch = vi.fn((input: RequestInfo | URL) => {
          const url = typeof input === 'string' ? input : input.toString()
          fetchedUrls.push(url)
          let content = '-----BEGIN CERTIFICATE-----\nMockCertificate\n-----END CERTIFICATE-----'
          if (url.includes('trust.iptc.org') && opts.iptcFails) {
            return Promise.reject(new TypeError('Failed to fetch'))
          }
          if (url.includes('mozilla-smime-roots.pem')) content = '-----BEGIN CERTIFICATE-----\nMozillaRoot\n-----END CERTIFICATE-----'
          else if (url.endsWith('anchor-list.pem')) content = opts.iptcAnchors ?? ''
          else if (url.endsWith('end-entity-list.pem')) content = '-----BEGIN CERTIFICATE-----\nIptcPublisher\n-----END CERTIFICATE-----'
          else if (url.includes('allowed.pem')) content = '-----BEGIN CERTIFICATE-----\nITLAllowedCert\n-----END CERTIFICATE-----'
          else if (url.includes('anchors.pem')) content = '-----BEGIN CERTIFICATE-----\nITLAnchorCert\n-----END CERTIFICATE-----'
          return Promise.resolve({
            ok: true, status: 200, statusText: 'OK',
            text: () => Promise.resolve(content),
            json: () => Promise.resolve(url.includes('mozilla-smime-roots.json') ? { fetchedAt: '2026-10-19T00:00:00Z' } : []),
            headers: new Headers({ 'content-type': 'text/plain' }),
          } as Response)
        }) as ReturnType<typeof vi.fn>
      }

      it('never contacts trust.iptc.org unless the user opts in', async () => {
        mockFetch()
        setCawgTrust({ trustedIcaIssuers: ['did:web:issuer.example'] })
        await processFile(new File(['test'], 'test.jpg', { type: 'image/jpeg' }))
        expect(fetchedUrls.some((u) => u.includes('trust.iptc.org'))).toBe(false)
        expect(fetchedUrls.some((u) => u.includes('mozilla-smime-roots'))).toBe(false)
      })

      it('adds the Mozilla and IPTC lists as CAWG anchors in an identity-only read', async () => {
        mockFetch()
        _setLocalModuleForTesting(makeLocalModule({
          calls: [
            cawgCrJson({ identityTrusted: false, signerTrusted: false }), // official TL
            cawgCrJson({ identityTrusted: false, signerTrusted: false }), // ITL
            cawgCrJson({ identityTrusted: true, signerTrusted: true }),   // + CAWG interim lists
          ],
        }))
        setCawgTrust({ publicLists: true })

        const report = await processFile(new File(['test'], 'test.jpg', { type: 'image/jpeg' }))

        expect(fetchedUrls).toContain('https://trust.iptc.org/anchor-list.pem')
        expect(fetchedUrls).toContain('https://trust.iptc.org/end-entity-list.pem')
        const cawgAnchors = recordedTrustAnchors[2].filter((a) => a.trust_kind === 'cawg')
        expect(cawgAnchors).toHaveLength(2)
        const [mozilla, iptc] = cawgAnchors
        expect(mozilla.trust_anchors).toContain('MozillaRoot')
        expect(mozilla.trust_uri).toContain('TrustBitsInclude=Email')
        // The IPTC anchor list is empty today; its end-entity list still applies.
        expect(iptc).toMatchObject({ trust_anchors: '', trust_uri: 'https://trust.iptc.org/anchor-list.pem' })
        expect(iptc.allowed_list).toContain('IptcPublisher')
        // CAWG anchors keep c2pa-rs's own CAWG EKU policy.
        for (const a of cawgAnchors) expect(a).not.toHaveProperty('trust_config')

        expect(identityState(report)).toBe('trusted')
        expect(report.usedCawgPublicLists).toBe(true)
        // Public lists aren't session test trust, and never touch the signer verdict.
        expect(report.usedCawgTrust).toBe(false)
        expect(report.validationResults!.activeManifest!.failure!.map((s) => s.code))
          .toContain('signingCredential.untrusted')
      })

      it('omits the IPTC anchor when both IPTC lists are empty', async () => {
        mockFetch()
        global.fetch = vi.fn((input: RequestInfo | URL) => {
          const url = typeof input === 'string' ? input : input.toString()
          const content = url.includes('trust.iptc.org')
            ? ''
            : '-----BEGIN CERTIFICATE-----\nMockCertificate\n-----END CERTIFICATE-----'
          return Promise.resolve({
            ok: true, status: 200, statusText: 'OK',
            text: () => Promise.resolve(content),
            json: () => Promise.resolve({}),
            headers: new Headers({ 'content-type': 'text/plain' }),
          } as Response)
        }) as ReturnType<typeof vi.fn>
        setCawgTrust({ publicLists: true })

        await processFile(new File(['test'], 'test.jpg', { type: 'image/jpeg' }))

        const cawgAnchors = recordedTrustAnchors.flat().filter((a) => a.trust_kind === 'cawg')
        expect(cawgAnchors.map((a) => a.trust_uri)).toEqual([expect.stringContaining('TrustBitsInclude=Email')])
      })

      it('still validates, without the lists, when the IPTC fetch fails', async () => {
        mockFetch({ iptcFails: true })
        setCawgTrust({ publicLists: true })

        const report = await processFile(new File(['test'], 'test.jpg', { type: 'image/jpeg' }))

        expect(report.manifests.length).toBeGreaterThan(0)
        expect(readCallCount).toBe(1)
        expect(report.usedCawgPublicLists).toBe(false)
      })

      it('flags session CAWG trust only when it changes a verdict beyond the public lists', async () => {
        mockFetch()
        _setLocalModuleForTesting(makeLocalModule({
          calls: [
            cawgCrJson({ identityTrusted: false, signerTrusted: true }), // official TL
            cawgCrJson({ identityTrusted: true, signerTrusted: true }),  // + interim lists
            cawgCrJson({ identityTrusted: true, signerTrusted: true }),  // + session trust
          ],
        }))
        setCawgTrust({ publicLists: true, trustedIcaIssuers: ['did:web:issuer.example'] })

        const report = await processFile(new File(['test'], 'test.jpg', { type: 'image/jpeg' }))

        expect(readCallCount).toBe(3)
        // The session read includes the public lists too.
        expect(recordedTrustAnchors[2].filter((a) => a.trust_kind === 'cawg')).toHaveLength(3)
        expect(identityState(report)).toBe('trusted')
        expect(report.usedCawgPublicLists).toBe(true)
        expect(report.usedCawgTrust).toBe(false)
      })
    })

    it('does not flag the report when CAWG trust leaves the verdict unchanged', async () => {
      _setLocalModuleForTesting(makeLocalModule({
        calls: [
          cawgCrJson({ identityTrusted: false, signerTrusted: true }),
          cawgCrJson({ identityTrusted: false, signerTrusted: true }),
        ],
      }))
      setCawgTrust({ trustedIcaIssuers: ['did:web:someone-else.example'] })

      const report = await processFile(new File(['test'], 'test.jpg', { type: 'image/jpeg' }))
      expect(identityState(report)).toBe('untrusted')
      expect(report.usedCawgTrust).toBe(false)
    })
  })

  // ── Soft binding registry fallback ──────────────────────────────────────────

  describe('soft binding registry fallback', () => {
    it('falls back to the raw.githubusercontent.com URL when sbal.c2pa.org is CORS-blocked', async () => {
      global.fetch = vi.fn((input: RequestInfo | URL) => {
        const url = typeof input === 'string' ? input : input.toString()
        if (url === 'https://sbal.c2pa.org/') {
          return Promise.reject(new TypeError('Failed to fetch'))
        }
        if (url.includes('raw.githubusercontent.com') && url.includes('softbinding-algorithm-list.json')) {
          return Promise.resolve({
            ok: true, status: 200, statusText: 'OK',
            json: () => Promise.resolve([{ alg: 'c2pa.hash.bmff.v3' }, { alg: 'c2pa.hash.data' }]),
          } as Response)
        }
        return Promise.reject(new Error(`unexpected fetch: ${url}`))
      }) as ReturnType<typeof vi.fn>

      const algs = await _fetchSoftBindingAlgorithmsForTesting()
      expect(algs).toEqual(['c2pa.hash.bmff.v3', 'c2pa.hash.data'])
    })

    it('returns an empty list without throwing when every source fails', async () => {
      global.fetch = vi.fn(() => Promise.reject(new TypeError('Failed to fetch'))) as ReturnType<typeof vi.fn>

      const algs = await _fetchSoftBindingAlgorithmsForTesting()
      expect(algs).toEqual([])
    })
  })

  // ── Remote manifest handling ────────────────────────────────────────────────

  function mockFetchWithRemoteManifest(remoteManifestUrl: string, manifestBytes: Uint8Array) {
    global.fetch = vi.fn((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString()
      if (url === remoteManifestUrl) {
        return Promise.resolve({
          ok: true, status: 200, statusText: 'OK',
          arrayBuffer: () => Promise.resolve(manifestBytes.buffer),
        } as Response)
      }
      let content = '-----BEGIN CERTIFICATE-----\nMockCertificate\n-----END CERTIFICATE-----'
      if (url.includes('allowed.pem')) content = '-----BEGIN CERTIFICATE-----\nITLAllowedCert\n-----END CERTIFICATE-----'
      else if (url.includes('anchors.pem')) content = '-----BEGIN CERTIFICATE-----\nITLAnchorCert\n-----END CERTIFICATE-----'
      return Promise.resolve({
        ok: true, status: 200, statusText: 'OK',
        text: () => Promise.resolve(content),
        json: () => Promise.reject(new Error('not json')),
        headers: new Headers({ 'content-type': 'text/plain' }),
      } as unknown as Response)
    }) as ReturnType<typeof vi.fn>
  }

  describe('remote manifest handling', () => {
    it('processFile surfaces the remote-manifest URL as a real Error, even though wasm rejects with a bare string', async () => {
      // wasm-bindgen turns Err(JsValue::from_str(...)) into a promise rejected with a
      // plain string, not an Error instance — reproduce that exactly here so this test
      // would have caught the bug where downstream `instanceof Error` checks silently
      // fell back to a generic message and dropped the URL.
      _setLocalModuleForTesting(makeLocalModule({
        readManifestStore: () =>
          Promise.reject('Remote manifest reference: https://example.com/manifest.c2pa'),
      }))

      const rejection = await processFile(new File(['test'], 'test.jpg', { type: 'image/jpeg' })).catch((e) => e)
      expect(rejection).toBeInstanceOf(Error)
      expect((rejection as Error).message).toBe('Remote manifest reference: https://example.com/manifest.c2pa')
    })

    it('processRemoteManifest fetches the manifest, validates it, and flags the report', async () => {
      const remoteManifestUrl = 'https://example.com/manifest.c2pa'
      const manifestBytes = new Uint8Array([1, 2, 3])
      mockFetchWithRemoteManifest(remoteManifestUrl, manifestBytes)

      _setLocalModuleForTesting(makeLocalModule({
        readSidecarManifestStore: () => Promise.resolve(makeCrJson({ trusted: true })),
      }))

      const { report, manifestBytes: returnedBytes } = await processRemoteManifest(
        new File(['test'], 'test.jpg', { type: 'image/jpeg' }),
        remoteManifestUrl,
      )

      expect(report.fetchedRemoteManifest).toBe(true)
      expect(report.remoteManifestUrl).toBe(remoteManifestUrl)
      expect(returnedBytes).toEqual(manifestBytes)
    })

    it('processRemoteManifest throws when the fetch itself fails', async () => {
      global.fetch = vi.fn(() =>
        Promise.resolve({ ok: false, status: 404, statusText: 'Not Found' } as Response)
      ) as ReturnType<typeof vi.fn>

      await expect(
        processRemoteManifest(new File(['test'], 'test.jpg', { type: 'image/jpeg' }), 'https://example.com/gone.c2pa')
      ).rejects.toThrow(/Failed to fetch remote manifest/)
    })

    it('revalidateRemoteManifest validates already-fetched bytes without a network call', async () => {
      const remoteManifestUrl = 'https://example.com/manifest.c2pa'
      const manifestBytes = new Uint8Array([1, 2, 3])

      const readSidecarSpy = vi.fn(() => Promise.resolve(makeCrJson({ trusted: true })))
      _setLocalModuleForTesting(makeLocalModule({ readSidecarManifestStore: readSidecarSpy }))

      const fetchedUrls: string[] = []
      global.fetch = vi.fn((input: RequestInfo | URL) => {
        const url = typeof input === 'string' ? input : input.toString()
        fetchedUrls.push(url)
        // Soft binding registry lookups are non-fatal if they fail; everything
        // else (trust list, ITL) should already be cached from earlier tests.
        return Promise.reject(new Error(`unexpected fetch: ${url}`))
      }) as ReturnType<typeof vi.fn>

      const report = await revalidateRemoteManifest(
        new File(['test'], 'test.jpg', { type: 'image/jpeg' }),
        manifestBytes,
        remoteManifestUrl,
      )

      expect(report.fetchedRemoteManifest).toBe(true)
      expect(report.remoteManifestUrl).toBe(remoteManifestUrl)
      expect(readSidecarSpy).toHaveBeenCalled()
      expect(fetchedUrls).not.toContain(remoteManifestUrl)
    })
  })
})
