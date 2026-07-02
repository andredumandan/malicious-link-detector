import axios from 'axios'

export interface RedirectResult {
  finalUrl: string
  chain: { url: string; statusCode: number }[]
}

export async function followRedirects(url: string): Promise<RedirectResult> {
  const chain: { url: string; statusCode: number }[] = []
  let currentUrl = url

  for (let i = 0; i < 10; i++) {
    try {
      const response = await axios.get(currentUrl, {
        maxRedirects: 0,
        timeout: 10000,
        validateStatus: () => true,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          Accept: '*/*',
        },
      })

      chain.push({ url: currentUrl, statusCode: response.status })

      const location = response.headers['location'] as string | undefined
      if (!location || response.status < 300 || response.status >= 400) {
        break
      }

      currentUrl = new URL(location, currentUrl).href
    } catch {
      if (chain.length === 0) {
        chain.push({ url: currentUrl, statusCode: 0 })
      }
      break
    }
  }

  return { finalUrl: currentUrl, chain }
}
