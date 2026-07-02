import { useState, useCallback } from 'react'
import type { ScanResult } from './types.ts'

function RiskMeter({ score }: { score: number }) {
  const color = score >= 50 ? 'bg-alert' : score >= 20 ? 'bg-caution' : 'bg-safe'
  return (
    <div className="w-full bg-line rounded-full h-[3px] overflow-hidden">
      <div
        className={`risk-bar ${color}`}
        style={{ width: `${score}%` }}
      />
    </div>
  )
}

function VerdictStamp({ verdict }: { verdict: 'safe' | 'suspicious' | 'malicious' }) {
  const config = {
    safe: { label: 'Safe', color: 'text-safe border-safe' },
    suspicious: { label: 'Suspicious', color: 'text-caution border-caution' },
    malicious: { label: 'Malicious', color: 'text-alert border-alert' },
  }
  const c = config[verdict]
  return (
    <span className={`stamp ${c.color}`}>{c.label}</span>
  )
}

function classForFinding(text: string): string {
  const lower = text.toLowerCase()
  if (lower.includes('flag') || lower.includes('malicious') || lower.includes('threat')) return 'level-alert'
  if (lower.includes('suspicious') || lower.includes('keyword') || lower.includes('shortener')) return 'level-caution'
  return 'level-info'
}

function App() {
  const [url, setUrl] = useState('')
  const [result, setResult] = useState<ScanResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [history, setHistory] = useState<ScanResult[]>([])
  const [copied, setCopied] = useState(false)

  const isValidUrl = (s: string) => {
    try {
      const u = s.trim()
      new URL(u.startsWith('http') ? u : `http://${u}`)
      return u.includes('.')
    } catch {
      return false
    }
  }

  const handleScan = useCallback(async () => {
    const trimmed = url.trim()
    if (!trimmed || !isValidUrl(trimmed)) {
      setError('Enter a valid URL to analyze')
      return
    }

    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const apiBase = import.meta.env.VITE_API_URL || ''
      const res = await fetch(`${apiBase}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: trimmed }),
      })
      if (!res.ok) throw new Error(`Server error: ${res.status}`)
      const data: ScanResult = await res.json()
      setResult(data)
      setHistory(prev => [data, ...prev].slice(0, 5))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Analysis failed')
    } finally {
      setLoading(false)
    }
  }, [url])

  const copyResult = async () => {
    if (!result) return
    const text = [
      `URL: ${result.url}`,
      `Verdict: ${result.verdict} (${result.score}/100)`,
      ...result.reasons.map(r => `- ${r}`),
    ].join('\n')
    await navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const clearAll = () => {
    setUrl('')
    setResult(null)
    setError(null)
  }

  return (
    <div className="min-h-screen bg-deep text-body font-mono antialiased">
      <main className="max-w-2xl mx-auto px-4 py-12 md:py-20">

        {/* Header */}
        <div className="flex items-center justify-between mb-10 md:mb-14">
          <h1 className="text-accent text-[11px] tracking-[0.2em] uppercase font-display font-semibold">
            Link Analysis
          </h1>
          <span className="text-muted/50 text-[11px]">v1</span>
        </div>

        {/* Hero input */}
        <div className="bg-panel border border-line rounded-lg scan-card">
          <div className="p-5 md:p-7 pb-0">
            <input
              type="text"
              value={url}
              onChange={(e) => { setUrl(e.target.value); setError(null) }}
              onKeyDown={(e) => e.key === 'Enter' && handleScan()}
              placeholder="https://example.com"
              className="w-full bg-transparent text-body text-xl md:text-2xl font-display font-semibold placeholder:text-muted/30 focus:outline-none"
              spellCheck={false}
              autoComplete="off"
              autoCorrect="off"
            />
          </div>
          <div className="flex items-center justify-between px-5 md:px-7 pb-5 md:pb-7 pt-4">
            <div className="flex-1 min-w-0 mr-3">
              {error && (
                <p className="text-alert text-xs truncate">{error}</p>
              )}
            </div>
            <div className="flex gap-2 shrink-0">
              {(result || error) && (
                <button
                  onClick={clearAll}
                  className="text-muted hover:text-body text-xs px-3 py-1.5 rounded border border-line transition-colors"
                >
                  Clear
                </button>
              )}
              <button
                onClick={handleScan}
                disabled={loading || !url.trim()}
                className="bg-accent hover:bg-accent-dim disabled:bg-line disabled:text-muted/50 disabled:cursor-not-allowed text-white text-xs font-semibold px-5 py-1.5 rounded transition-colors"
              >
                {loading ? (
                  <span className="flex items-center gap-1.5">
                    <span className="loading-dot" />
                    <span className="loading-dot" />
                    <span className="loading-dot" />
                  </span>
                ) : 'Scan'}
              </button>
            </div>
          </div>
        </div>

        {/* Error inline (outside card) */}
        {error && (
          <div className="mt-3 text-alert text-xs font-mono flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-alert shrink-0" />
            {error}
          </div>
        )}

        {/* Loading state */}
        {loading && (
          <div className="mt-6 bg-panel border border-line rounded-lg p-5 result-enter">
            <div className="text-muted text-xs font-mono">
              <p className="mb-3 text-muted/50">
                $ scan --url {url.length > 50 ? url.slice(0, 50) + '...' : url}
              </p>
              <div className="space-y-2">
                {[
                  { label: 'Local heuristics' },
                  { label: 'Google Safe Browsing' },
                  { label: 'VirusTotal' },
                  { label: 'Redirect analysis' },
                ].map((step, i) => (
                  <div key={i} className="flex items-center gap-3 text-xs">
                    <span className={`w-4 text-center ${i === 0 ? 'text-accent' : 'text-muted/30'}`}>
                      {i === 0 ? '\u25CC' : '\u25CB'}
                    </span>
                    <span className={i === 0 ? 'text-body' : 'text-muted/50'}>{step.label}</span>
                    {i === 0 && (
                      <span className="flex gap-1 ml-auto">
                        <span className="loading-dot" />
                        <span className="loading-dot" />
                        <span className="loading-dot" />
                      </span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Results */}
        {result && (
          <div className="mt-6 space-y-4 result-enter">

            {/* Verdict + Score */}
            <div className="bg-panel border border-line rounded-lg p-5 md:p-7">
              <div className="flex items-start justify-between gap-4 flex-wrap">
                <VerdictStamp verdict={result.verdict} />
                <div className="text-right">
                  <span className="text-2xl font-display font-bold">{result.score}</span>
                  <span className="text-muted text-xs ml-1">/ 100</span>
                  <p className="text-muted/60 text-[10px] uppercase tracking-widest mt-0.5 font-mono">risk score</p>
                </div>
              </div>
              <div className="mt-4">
                <RiskMeter score={result.score} />
              </div>
              <div className="mt-3 flex justify-end">
                <button
                  onClick={copyResult}
                  className="text-muted hover:text-body text-[11px] transition-colors"
                >
                  {copied ? 'Copied' : 'Copy report'}
                </button>
              </div>
            </div>

            {/* Redirect chain */}
            {result.redirected && (
              <div className="bg-panel border border-line rounded-lg p-5">
                <h3 className="text-[11px] text-muted uppercase tracking-[0.15em] font-display font-semibold mb-3">
                  Redirect chain
                </h3>
                <div className="font-mono text-xs space-y-1.5">
                  {result.redirectChain.map((r, i) => (
                    <div key={i} className="flex items-start gap-2">
                      {i > 0 && <span className="text-muted/30 mt-0.5 shrink-0">{'\u21B3'}</span>}
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold leading-none ${
                        r.statusCode >= 300 && r.statusCode < 400
                          ? 'bg-caution/15 text-caution'
                          : r.statusCode === 200
                          ? 'bg-safe/15 text-safe'
                          : 'bg-line text-muted'
                      }`}>
                        {r.statusCode || '?'}
                      </span>
                      <span className="text-muted break-all">{r.url}</span>
                    </div>
                  ))}
                  <p className="text-accent text-[11px] mt-2 break-all font-semibold">
                    {'\u2192'} {result.resolvedUrl}
                  </p>
                </div>
              </div>
            )}

            {/* Findings */}
            <div className="bg-panel border border-line rounded-lg p-5">
              <h3 className="text-[11px] text-muted uppercase tracking-[0.15em] font-display font-semibold mb-3">
                Findings <span className="text-muted/50">({result.reasons.length})</span>
              </h3>
              {result.reasons.length > 0 ? (
                <ul className="findings-list text-sm">
                  {result.reasons.map((r, i) => (
                    <li key={i} className={classForFinding(r) + ' text-body/90'}>
                      {r}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-safe text-sm flex items-center gap-2">
                  <span className="text-base leading-none">{'\u2713'}</span>
                  No threats or suspicious patterns detected.
                </p>
              )}
            </div>

            {/* External sources */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="bg-panel border border-line rounded-lg p-5">
                <h3 className="text-[11px] text-muted uppercase tracking-[0.15em] font-display font-semibold mb-3">
                  Safe Browsing
                </h3>
                {result.safeBrowsing.error ? (
                  <p className="text-caution text-xs flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-caution shrink-0" />
                    {result.safeBrowsing.error}
                  </p>
                ) : result.safeBrowsing.flagged ? (
                  <div className="space-y-1.5">
                    <p className="text-alert text-sm flex items-center gap-2">
                      <span className="w-1.5 h-1.5 rounded-full bg-alert shrink-0" />
                      Threat detected
                    </p>
                    {result.safeBrowsing.threats.map((t, i) => (
                      <p key={i} className="text-muted text-xs font-mono ml-3.5">{t.threatType}</p>
                    ))}
                  </div>
                ) : (
                  <p className="text-safe text-sm flex items-center gap-2">
                    <span className="text-base leading-none">{'\u2713'}</span>
                    No threats
                  </p>
                )}
              </div>

              <div className="bg-panel border border-line rounded-lg p-5">
                <h3 className="text-[11px] text-muted uppercase tracking-[0.15em] font-display font-semibold mb-3">
                  VirusTotal
                </h3>
                {result.virusTotal.error ? (
                  <p className="text-caution text-xs flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-caution shrink-0" />
                    {result.virusTotal.error}
                  </p>
                ) : (
                  <div className="space-y-2">
                    <div className="flex items-baseline gap-1.5">
                      <span className="text-2xl font-display font-bold">{result.virusTotal.positives}</span>
                      <span className="text-muted">/ {result.virusTotal.total}</span>
                      <span className="text-muted/60 text-[11px] ml-1 font-mono">flagged</span>
                    </div>
                    {result.virusTotal.permalink && (
                      <a
                        href={result.virusTotal.permalink}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-accent text-xs hover:text-body transition-colors"
                      >
                        Full report {'\u2192'}
                      </a>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Recent scans */}
        {history.length > 1 && (
          <div className="mt-8 bg-panel border border-line rounded-lg p-5">
            <h3 className="text-[11px] text-muted uppercase tracking-[0.15em] font-display font-semibold mb-3">
              Recent
            </h3>
            <div className="space-y-0.5">
              {history.slice(1, 5).map((h, i) => (
                <button
                  key={i}
                  onClick={() => { setResult(h); setUrl(h.url) }}
                  className="w-full text-left text-sm text-muted hover:text-body hover:bg-elevated p-2 rounded transition-colors flex items-center gap-3 truncate"
                >
                  <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                    h.verdict === 'malicious' ? 'bg-alert' : h.verdict === 'suspicious' ? 'bg-caution' : 'bg-safe'
                  }`} />
                  <span className="font-mono text-[11px] text-muted/50 shrink-0 w-6 text-right">{h.score}</span>
                  <span className="truncate">{h.url}</span>
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Footer */}
        <footer className="mt-16 text-center">
          <p className="text-muted/30 text-[11px] font-mono">
            Results are for reference. Exercise caution with unknown links.
          </p>
        </footer>
      </main>
    </div>
  )
}

export default App
