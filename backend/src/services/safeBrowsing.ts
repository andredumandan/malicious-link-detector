import axios from 'axios'

export interface SafeBrowsingResult {
  flagged: boolean
  threats: { threatType: string; platformType: string; threatEntryType: string }[]
  error?: string
}

export async function checkSafeBrowsing(url: string): Promise<SafeBrowsingResult> {
  const apiKey = process.env.SAFE_BROWSING_API_KEY
  if (!apiKey) {
    return { flagged: false, threats: [], error: 'No API key configured' }
  }

  try {
    const response = await axios.post(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
      {
        client: {
          clientId: 'malicious-link-detector',
          clientVersion: '1.0.0',
        },
        threatInfo: {
          threatTypes: [
            'MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE',
            'POTENTIALLY_HARMFUL_APPLICATION',
          ],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }],
        },
      },
      { timeout: 10000 }
    )

    const matches = response.data?.matches
    if (!matches || matches.length === 0) {
      return { flagged: false, threats: [] }
    }

    return {
      flagged: true,
      threats: matches.map((m: { threatType: string; platformType: string; threatEntryType: string }) => ({
        threatType: m.threatType,
        platformType: m.platformType,
        threatEntryType: m.threatEntryType,
      })),
    }
  } catch (error: unknown) {
    if (axios.isAxiosError(error) && error.response?.status === 403) {
      return { flagged: false, threats: [], error: 'Invalid API key' }
    }
    return { flagged: false, threats: [], error: 'API request failed' }
  }
}
