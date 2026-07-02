interface CacheEntry<T> {
  data: T
  expiresAt: number
}

const store = new Map<string, CacheEntry<unknown>>()
const TTL_MS = 60 * 60 * 1000 // 1 hour

export function cacheGet<T>(key: string): T | null {
  const entry = store.get(key)
  if (!entry) return null
  if (Date.now() > entry.expiresAt) {
    store.delete(key)
    return null
  }
  return entry.data as T
}

export function cacheSet<T>(key: string, data: T, ttlMs = TTL_MS): void {
  store.set(key, { data, expiresAt: Date.now() + ttlMs })
}

export function hasCached(key: string): boolean {
  return cacheGet(key) !== null
}
