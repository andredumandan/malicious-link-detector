import { describe, it, expect } from 'vitest'
import { analyzeUrlHeuristics, getVerdict } from './heuristics.ts'

describe('getVerdict', () => {
  it('returns safe for score < 20', () => {
    expect(getVerdict(0)).toBe('safe')
    expect(getVerdict(19)).toBe('safe')
  })
  it('returns suspicious for 20-49', () => {
    expect(getVerdict(20)).toBe('suspicious')
    expect(getVerdict(35)).toBe('suspicious')
    expect(getVerdict(49)).toBe('suspicious')
  })
  it('returns malicious for score >= 50', () => {
    expect(getVerdict(50)).toBe('malicious')
    expect(getVerdict(100)).toBe('malicious')
  })
})

describe('analyzeUrlHeuristics', () => {
  it('returns score 0 for a clean HTTPS URL', () => {
    const result = analyzeUrlHeuristics('https://github.com/opencode-ai/opencode')
    expect(result.score).toBe(0)
    expect(result.reasons).toHaveLength(0)
    expect(result.details.noHttps).toBe(false)
  })

  it('flags IP-based domains', () => {
    const result = analyzeUrlHeuristics('http://192.168.1.1/admin')
    expect(result.details.ipDomain).toBe(true)
    expect(result.score).toBeGreaterThanOrEqual(25)
  })

  it('flags excessive subdomains', () => {
    const result = analyzeUrlHeuristics('https://a.b.c.d.example.com/login')
    expect(result.details.excessiveSubdomains).toBe(true)
    expect(result.score).toBeGreaterThanOrEqual(10)
  })

  it('flags known URL shorteners', () => {
    const result = analyzeUrlHeuristics('https://bit.ly/3abcDEF')
    expect(result.details.shortener).toBe(true)
    expect(result.score).toBeGreaterThanOrEqual(15)
  })

  it('flags suspicious keywords', () => {
    const result = analyzeUrlHeuristics('https://sketchy-site.xyz/login/verify')
    expect(result.details.suspiciousKeywords.length).toBeGreaterThan(0)
    expect(result.score).toBeGreaterThanOrEqual(8)
  })

  it('does NOT flag brand keywords for legitimate brand domains', () => {
    const result = analyzeUrlHeuristics('https://paypal.com/signin')
    expect(result.details.suspiciousKeywords).toHaveLength(0)
    expect(result.score).toBe(0)
  })

  it('flags typosquat domains', () => {
    const result = analyzeUrlHeuristics('https://go0gle.com/login')
    expect(result.details.lookalike).not.toBeNull()
    expect(result.score).toBeGreaterThanOrEqual(25)
  })

  it('flags long URLs', () => {
    const long = 'https://example.com/' + 'a'.repeat(80)
    const result = analyzeUrlHeuristics(long)
    expect(result.details.excessiveLength).toBe(true)
    expect(result.score).toBeGreaterThanOrEqual(5)
  })

  it('flags excessive percent-encoding', () => {
    const result = analyzeUrlHeuristics('https://example.com/' + '%20'.repeat(30))
    expect(result.details.excessiveEncoding).toBe(true)
    expect(result.score).toBeGreaterThanOrEqual(8)
  })

  it('flags missing HTTPS', () => {
    const result = analyzeUrlHeuristics('http://example.com')
    expect(result.details.noHttps).toBe(true)
    expect(result.score).toBeGreaterThanOrEqual(10)
  })

  it('flags high entropy subdomains', () => {
    const result = analyzeUrlHeuristics('https://x7q2m9k4p1.example.com/login')
    expect(result.details.highEntropy).toBe(true)
    expect(result.score).toBeGreaterThanOrEqual(10)
  })

  it('handles invalid URLs gracefully', () => {
    const result = analyzeUrlHeuristics('not a url at all')
    expect(result.score).toBe(0)
    expect(result.reasons).toContain('Invalid URL')
  })
})
