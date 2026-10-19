#!/usr/bin/env node

/**
 * Refresh the bundled Mozilla S/MIME root snapshot used as a CAWG trust anchor list.
 *
 * The CAWG interim trust model (identity assertion spec §8.2.4.1) names the Mozilla
 * Root Store with the Email trust bit as a CAWG trust anchor list. CCADB serves it
 * without CORS headers, so browsers can't fetch it directly; the app loads this
 * same-origin snapshot instead. (The IPTC lists send CORS headers and are fetched
 * live by the browser when the user opts in.)
 */

import { mkdirSync, writeFileSync } from 'fs'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'

const SOURCE_URL = 'https://ccadb.my.salesforce-sites.com/mozilla/IncludedRootsPEMTxt?TrustBitsInclude=Email'

const __dirname = dirname(fileURLToPath(import.meta.url))
const outDir = join(__dirname, '..', 'public', 'trust', 'cawg')

const response = await fetch(SOURCE_URL)
if (!response.ok) {
  throw new Error(`Failed to fetch Mozilla S/MIME roots: ${response.status} ${response.statusText}`)
}

// Normalize line endings and keep only the PEM certificate blocks.
const text = (await response.text()).replace(/\r\n/g, '\n')
const blocks = text.match(/-----BEGIN CERTIFICATE-----\n[\s\S]*?\n-----END CERTIFICATE-----/g) ?? []
if (blocks.length === 0) {
  throw new Error('Mozilla S/MIME root list contained no certificates')
}

mkdirSync(outDir, { recursive: true })
writeFileSync(join(outDir, 'mozilla-smime-roots.pem'), blocks.join('\n') + '\n')
writeFileSync(
  join(outDir, 'mozilla-smime-roots.json'),
  JSON.stringify({ source: SOURCE_URL, fetchedAt: new Date().toISOString(), certificates: blocks.length }, null, 2) + '\n',
)

console.log(`✅ Wrote ${blocks.length} Mozilla S/MIME roots to public/trust/cawg/`)
