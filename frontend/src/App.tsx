import { useState } from 'react'
import type { ScanResult } from './types.ts'

const badgeStyles: Record<string, string> = {
  safe: 'bg-green-600',
  suspicious: 'bg-yellow-500',
  malicious: 'bg-red-600',
}

function App() {
  const [url, setUrl] = useState('')
  const [result, setResult] = useState<ScanResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleScan = async () => {
    if (!url.trim()) return
    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const apiBase = import.meta.env.VITE_API_URL || ''
      const res = await fetch(`${apiBase}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url.trim() }),
      })
      if (!res.ok) {
        throw new Error(`Server error: ${res.status}`)
      }
      const data: ScanResult = await res.json()
      setResult(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Scan failed')
    } finally {
      setLoading(false)
    }
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') handleScan()
  }

  return (
    <main className="min-h-screen bg-gray-950 text-gray-100 flex flex-col items-center p-4">
      <div className="w-full max-w-2xl space-y-6 mt-16">
        <h1 className="text-3xl font-bold text-center">Malicious Link Detector</h1>

        <div className="flex gap-2">
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Paste a URL to scan..."
            className="flex-1 px-4 py-2 rounded-lg bg-gray-800 border border-gray-700 focus:outline-none focus:border-blue-500 text-sm"
          />
          <button
            onClick={handleScan}
            disabled={loading}
            className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 disabled:cursor-not-allowed font-medium text-sm transition-colors whitespace-nowrap"
          >
            {loading ? 'Scanning...' : 'Scan'}
          </button>
        </div>

        {loading && (
          <div className="flex items-center justify-center gap-2 text-gray-400 text-sm">
            <span className="animate-spin h-4 w-4 border-2 border-blue-500 border-t-transparent rounded-full" />
            Running heuristics and checking threat databases...
          </div>
        )}

        {error && (
          <div className="bg-red-900/50 border border-red-700 rounded-lg p-3 text-sm text-red-200">
            {error}
          </div>
        )}

        {result && (
          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <span className={`px-3 py-1 rounded-full text-sm font-medium ${badgeStyles[result.verdict]}`}>
                {result.verdict.charAt(0).toUpperCase() + result.verdict.slice(1)}
              </span>
              <span className="text-sm text-gray-400">Risk Score:</span>
              <span className="text-lg font-mono">{result.score}/100</span>
            </div>

            {result.redirected && (
              <div className="bg-gray-800 rounded-lg p-3">
                <p className="text-xs text-gray-500 mb-1">Resolved URL:</p>
                <p className="text-sm text-blue-400 break-all">{result.resolvedUrl}</p>
                {result.redirectChain.length > 1 && (
                  <div className="mt-2 space-y-1">
                    <p className="text-xs text-gray-500">Redirect chain:</p>
                    {result.redirectChain.map((r, i) => (
                      <p key={i} className="text-xs text-gray-400 truncate">
                        {i > 0 && <span className="text-gray-600 mr-1">→</span>}
                        {r.statusCode} {r.url}
                      </p>
                    ))}
                  </div>
                )}
              </div>
            )}

            <div className="bg-gray-800 rounded-lg p-4 space-y-2">
              <p className="text-sm font-medium text-gray-400">Flags triggered:</p>
              {result.reasons.length > 0 ? (
                <ul className="space-y-1">
                  {result.reasons.map((r, i) => (
                    <li key={i} className="text-sm text-gray-300 flex items-start gap-2">
                      <span className="text-red-400 mt-0.5 shrink-0">&#10060;</span>
                      {r}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-sm text-green-400 flex items-center gap-2">
                  <span>&#10004;</span>
                  No threats detected.
                </p>
              )}
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="bg-gray-800 rounded-lg p-4">
                <p className="text-sm font-medium text-gray-400 mb-2">Google Safe Browsing</p>
                {result.safeBrowsing.error ? (
                  <p className="text-xs text-yellow-400">{result.safeBrowsing.error}</p>
                ) : result.safeBrowsing.flagged ? (
                  <div>
                    <p className="text-sm text-red-400 mb-1">Threat detected</p>
                    {result.safeBrowsing.threats.map((t, i) => (
                      <p key={i} className="text-xs text-gray-400">{t.threatType}</p>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-green-400">
                    <span>&#10004;</span> No threats
                  </p>
                )}
              </div>

              <div className="bg-gray-800 rounded-lg p-4">
                <p className="text-sm font-medium text-gray-400 mb-2">VirusTotal</p>
                {result.virusTotal.error ? (
                  <p className="text-xs text-yellow-400">{result.virusTotal.error}</p>
                ) : (
                  <div>
                    <p className="text-sm text-gray-300">
                      {result.virusTotal.positives}/{result.virusTotal.total} vendors flagged
                    </p>
                    {result.virusTotal.permalink && (
                      <a
                        href={result.virusTotal.permalink}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-xs text-blue-400 hover:underline mt-1 inline-block"
                      >
                        View on VirusTotal &rarr;
                      </a>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </main>
  )
}

export default App
