import { Router } from 'express'
import { analyzeUrlHeuristics, getVerdict } from '../services/heuristics.js'
import { checkSafeBrowsing } from '../services/safeBrowsing.js'
import { checkVirusTotal } from '../services/virusTotal.js'
import { followRedirects } from '../services/redirects.js'
import { cacheGet, cacheSet } from '../services/cache.js'

const router = Router()

router.post('/', async (req, res) => {
  const { url } = req.body

  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'url is required' })
  }

  // Check cache
  const cacheKey = `scan:${url}`
  const cached = cacheGet<object>(cacheKey)
  if (cached) {
    return res.json(cached)
  }

  try {
    const [heuristicResult, safeBrowsingResult, virusTotalResult, redirectResult] = await Promise.all([
      Promise.resolve(analyzeUrlHeuristics(url)),
      checkSafeBrowsing(url),
      checkVirusTotal(url),
      followRedirects(url).catch(() => ({ finalUrl: url, chain: [{ url, statusCode: 0 }] })),
    ])

    let combinedScore = heuristicResult.score
    const finalReasons = [...heuristicResult.reasons]

    if (safeBrowsingResult.flagged) {
      combinedScore += 30
      finalReasons.push(`Flagged by Google Safe Browsing (${safeBrowsingResult.threats.map(t => t.threatType).join(', ')})`)
    }

    if (virusTotalResult.positives > 0) {
      const vtScore = Math.min(virusTotalResult.positives * 10, 30)
      combinedScore += vtScore
      finalReasons.push(`Flagged by ${virusTotalResult.positives}/${virusTotalResult.total} VirusTotal vendors`)
    }

    if (virusTotalResult.error && !virusTotalResult.error.includes('No API key')) {
      finalReasons.push(`VirusTotal: ${virusTotalResult.error}`)
    }

    if (safeBrowsingResult.error && !safeBrowsingResult.error.includes('No API key')) {
      finalReasons.push(`Safe Browsing: ${safeBrowsingResult.error}`)
    }

    const finalScore = Math.min(combinedScore, 100)
    const redirected = redirectResult.finalUrl !== url

    const response = {
      url,
      resolvedUrl: redirectResult.finalUrl,
      redirected,
      redirectChain: redirectResult.chain,
      score: finalScore,
      verdict: getVerdict(finalScore),
      reasons: finalReasons,
      heuristic: heuristicResult,
      safeBrowsing: safeBrowsingResult,
      virusTotal: virusTotalResult,
    }

    // Cache result for 1 hour
    cacheSet(cacheKey, response)

    res.json(response)
  } catch (error) {
    console.error('Scan error:', error)
    res.status(500).json({ error: 'Internal server error' })
  }
})

export default router
