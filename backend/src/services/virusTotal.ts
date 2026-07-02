import axios from 'axios'

export interface VirusTotalResult {
  positives: number
  total: number
  permalink: string | null
  error?: string
}

function getUrlIdentifier(url: string): string {
  return Buffer.from(url).toString('base64url')
}

async function pollAnalysis(
  analysisId: string,
  urlId: string,
  apiKey: string
): Promise<VirusTotalResult> {
  // Wait 3s before first poll, then poll with 5s intervals (up to ~90s total)
  await new Promise(r => setTimeout(r, 3000))

  for (let attempt = 0; attempt < 18; attempt++) {
    try {
      const analysisRes = await axios.get(
        `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
        {
          headers: { 'x-apikey': apiKey },
          timeout: 10000,
        }
      )

      const status: string | undefined = analysisRes.data?.data?.attributes?.status
      if (status === 'completed') {
        const stats: Record<string, number> = analysisRes.data?.data?.attributes?.stats || {}
        const positives = (stats.malicious || 0) + (stats.suspicious || 0)
        const total = Object.values(stats).reduce((a: number, b: number) => a + b, 0)

        return {
          positives,
          total,
          permalink: `https://www.virustotal.com/gui/url/${urlId}`,
        }
      }
    } catch (pollError: unknown) {
      if (axios.isAxiosError(pollError) && pollError.response?.status === 429) {
        await new Promise(r => setTimeout(r, 5000))
        continue
      }
    }

    await new Promise(r => setTimeout(r, 5000))
  }

  return { positives: 0, total: 0, permalink: null, error: 'Analysis timed out' }
}

export async function checkVirusTotal(url: string): Promise<VirusTotalResult> {
  const apiKey = process.env.VIRUSTOTAL_API_KEY
  if (!apiKey) {
    return { positives: 0, total: 0, permalink: null, error: 'No API key configured' }
  }

  const urlId = getUrlIdentifier(url)

  try {
    // First, try to get existing analysis (faster, saves API quota)
    const existingRes = await axios.get(
      `https://www.virustotal.com/api/v3/urls/${urlId}`,
      {
        headers: { 'x-apikey': apiKey },
        timeout: 10000,
      }
    )

    const existingStats: Record<string, number> | undefined = existingRes.data?.data?.attributes?.last_analysis_stats
    if (existingStats) {
      const positives = (existingStats.malicious || 0) + (existingStats.suspicious || 0)
      const total = Object.values(existingStats).reduce((a: number, b: number) => a + b, 0)

      return {
        positives,
        total,
        permalink: `https://www.virustotal.com/gui/url/${urlId}`,
      }
    }
  } catch {
    // If no existing analysis, submit a new one
  }

  try {
    const submitRes = await axios.post(
      'https://www.virustotal.com/api/v3/urls',
      `url=${encodeURIComponent(url)}`,
      {
        headers: {
          'x-apikey': apiKey,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        timeout: 10000,
      }
    )

    const analysisId: string | undefined = submitRes.data?.data?.id
    if (!analysisId) {
      return { positives: 0, total: 0, permalink: null, error: 'Failed to submit URL' }
    }

    return await pollAnalysis(analysisId, urlId, apiKey)
  } catch (error: unknown) {
    if (axios.isAxiosError(error)) {
      if (error.response?.status === 401) {
        return { positives: 0, total: 0, permalink: null, error: 'Invalid API key' }
      }
      return { positives: 0, total: 0, permalink: null, error: `API error: ${error.response?.status || error.message}` }
    }
    return { positives: 0, total: 0, permalink: null, error: 'API request failed' }
  }
}
