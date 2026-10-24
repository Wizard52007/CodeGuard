// Empty by default: requests are same-origin and proxied by Vite in development.
export const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL ?? '').replace(
  /\/+$/,
  '',
)

export const MAX_FILE_BYTES = 512 * 1024
export const HEALTH_POLL_MS = 15000
export const REQUEST_TIMEOUT_MS = 30000
