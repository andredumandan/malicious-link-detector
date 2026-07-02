export interface HeuristicResult {
  score: number
  reasons: string[]
  details: {
    ipDomain: boolean
    excessiveSubdomains: boolean
    shortener: boolean
    suspiciousKeywords: string[]
    lookalike: string | null
    excessiveLength: boolean
    excessiveEncoding: boolean
    noHttps: boolean
    highEntropy: boolean
    resolvedUrl?: string
  }
}

const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 'shorturl.at', 't.co', 'goo.gl', 'ow.ly',
  'is.gd', 'buff.ly', 'tiny.cc', 'tr.im', 'rb.gy', 'bl.ink',
  'shorte.st', 's.id', 'soo.gd', '2.gp', 'cutt.ly', 'rebrand.ly',
  'short.link', 'zzb.bz',
])

const SUSPICIOUS_KEYWORDS = [
  'login', 'verify', 'secure', 'update', 'account', 'confirm',
  'signin', 'sign-in', 'auth', 'authenticate', 'password',
  'credential', 'wallet', 'banking', 'payment', 'billing',
  'unlock', 'restore', 'recover', 'reset', '2fa',
]

const COMMON_BRANDS = [
  'google', 'facebook', 'youtube', 'twitter', 'x.com', 'instagram',
  'linkedin', 'whatsapp', 'tiktok', 'snapchat', 'reddit',
  'amazon', 'ebay', 'walmart', 'target', 'bestbuy',
  'microsoft', 'apple', 'netflix', 'spotify', 'paypal',
  'dropbox', 'github', 'stackoverflow', 'adobe', 'cloudflare',
  'godaddy', 'namecheap', 'shopify', 'wordpress', 'medium',
]

function parseUrl(url: string): URL | null {
  let normalized = url.trim()
  if (!/^https?:\/\//i.test(normalized)) {
    normalized = 'http://' + normalized
  }
  try {
    return new URL(normalized)
  } catch {
    return null
  }
}

function isIpDomain(hostname: string): boolean {
  return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)
}

function countSubdomains(hostname: string): number {
  return hostname.split('.').length - 1
}

function hasSuspiciousKeywords(url: string, hostname: string): string[] {
  const lower = url.toLowerCase()
  const hostParts = new Set(hostname.toLowerCase().split('.'))
  const mainDomain = hostname.replace(/^www\./, '').split('.')[0].toLowerCase()

  // Don't flag keywords on known-brand domains — they're legitimate pages
  if (COMMON_BRANDS.some(b => mainDomain === b)) return []

  const found: string[] = []
  for (const kw of SUSPICIOUS_KEYWORDS) {
    if (lower.includes(kw)) {
      const isInHostname = [...hostParts].some(part => part.includes(kw))
      if (!isInHostname) {
        found.push(kw)
      }
    }
  }
  return found
}

function levenshtein(a: string, b: string): number {
  const m = a.length, n = b.length
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0))
  for (let i = 0; i <= m; i++) dp[i][0] = i
  for (let j = 0; j <= n; j++) dp[0][j] = j
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1])
    }
  }
  return dp[m][n]
}

function checkLookalike(hostname: string): string | null {
  const mainDomain = hostname
    .replace(/^www\./, '')
    .split('.')[0]
    .toLowerCase()

  if (COMMON_BRANDS.some(b => mainDomain === b)) return null

  for (const brand of COMMON_BRANDS) {
    const domainPart = brand.split('.')[0]
    const dist = levenshtein(mainDomain, domainPart)
    if (dist > 0 && dist <= 2 && mainDomain.length >= 4) {
      return brand
    }
  }
  return null
}

function percentEncodingRatio(url: string): number {
  const encoded = (url.match(/%[0-9a-fA-F]{2}/g) || []).length
  return url.length > 0 ? encoded / url.length : 0
}

function calculateEntropy(text: string): number {
  const len = text.length
  if (len === 0) return 0
  const freq = new Map<string, number>()
  for (const ch of text) {
    freq.set(ch, (freq.get(ch) || 0) + 1)
  }
  let entropy = 0
  for (const count of freq.values()) {
    const p = count / len
    entropy -= p * Math.log2(p)
  }
  return entropy
}

function hasHighEntropy(hostname: string, pathname: string): boolean {
  const subdomain = hostname.replace(/^www\./, '').split('.')[0]
  const pathSegments = pathname.split('/').filter(Boolean)

  if (subdomain.length > 8 && calculateEntropy(subdomain) > 3.2) return true
  for (const seg of pathSegments) {
    if (seg.length > 6 && /[a-z]{2,}/i.test(seg) && calculateEntropy(seg) > 3.8) return true
  }
  return false
}

export function analyzeUrlHeuristics(url: string): HeuristicResult {
  const parsed = parseUrl(url)
  if (!parsed) {
    return {
      score: 0,
      reasons: ['Invalid URL'],
      details: {
        ipDomain: false, excessiveSubdomains: false, shortener: false,
        suspiciousKeywords: [], lookalike: null,
        excessiveLength: false, excessiveEncoding: false, noHttps: false,
        highEntropy: false,
      },
    }
  }

  const { hostname, pathname, protocol, href } = parsed
  const reasons: string[] = []
  let score = 0

  const ipDomain = isIpDomain(hostname)
  if (ipDomain) {
    score += 25
    reasons.push('Domain is an IP address')
  }

  const subdomainCount = countSubdomains(hostname)
  const excessiveSubdomains = subdomainCount > 3
  if (excessiveSubdomains) {
    score += 10
    reasons.push(`Excessive subdomains (${subdomainCount})`)
  }

  const hostnameLower = hostname.toLowerCase()
  const shortener = [...URL_SHORTENERS].some(s => hostnameLower === s || hostnameLower.endsWith('.' + s))
  if (shortener) {
    score += 15
    reasons.push('Known URL shortener — destination hidden')
  }

  const suspiciousKeywords = hasSuspiciousKeywords(href, hostname)
  if (suspiciousKeywords.length > 0) {
    const penalty = Math.min(suspiciousKeywords.length * 8, 24)
    score += penalty
    reasons.push(`Suspicious keywords: ${suspiciousKeywords.join(', ')}`)
  }

  const lookalike = checkLookalike(hostname)
  if (lookalike) {
    score += 25
    reasons.push(`Domain looks like a typosquat of "${lookalike}"`)
  }

  const excessiveLength = href.length > 75
  if (excessiveLength) {
    score += 5
    reasons.push(`URL length ${href.length} characters (threshold 75)`)
  }

  const encRatio = percentEncodingRatio(href)
  const excessiveEncoding = encRatio > 0.15
  if (excessiveEncoding) {
    score += 8
    reasons.push(`Excessive percent-encoding (${(encRatio * 100).toFixed(0)}%)`)
  }

  const noHttps = protocol !== 'https:'
  if (noHttps) {
    score += 10
    reasons.push('No HTTPS')
  }

  const highEntropy = hasHighEntropy(hostname, pathname)
  if (highEntropy) {
    score += 10
    reasons.push('High entropy / random-looking subdomain or path')
  }

  return {
    score: Math.min(score, 100),
    reasons,
    details: {
      ipDomain, excessiveSubdomains, shortener, suspiciousKeywords,
      lookalike, excessiveLength, excessiveEncoding, noHttps, highEntropy,
    },
  }
}

export function getVerdict(score: number): 'safe' | 'suspicious' | 'malicious' {
  if (score >= 50) return 'malicious'
  if (score >= 20) return 'suspicious'
  return 'safe'
}
