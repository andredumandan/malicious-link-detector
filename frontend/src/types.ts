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
  }
}

export interface SafeBrowsingResult {
  flagged: boolean
  threats: { threatType: string; platformType: string; threatEntryType: string }[]
  error?: string
}

export interface VirusTotalResult {
  positives: number
  total: number
  permalink: string | null
  error?: string
}

export interface ChainEntry {
  url: string
  statusCode: number
}

export interface ScanResult {
  url: string
  resolvedUrl: string
  redirected: boolean
  redirectChain: ChainEntry[]
  score: number
  verdict: 'safe' | 'suspicious' | 'malicious'
  reasons: string[]
  heuristic: HeuristicResult
  safeBrowsing: SafeBrowsingResult
  virusTotal: VirusTotalResult
}
