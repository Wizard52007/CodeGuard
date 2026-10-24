import { API_BASE_URL, REQUEST_TIMEOUT_MS } from '../config.js'

const VERDICTS = new Set(['allow', 'block'])
const DECISIONS = new Set(['allow', 'block', 'error'])

/**
 * kind:
 *  - offline           the backend could not be reached
 *  - timeout           no response within the allowed time
 *  - aborted           cancelled by the user
 *  - http              the backend answered with an error status
 *  - invalid_response  the answer does not match the agreed contract
 */
export class ApiError extends Error {
  constructor(kind, message, { status = null } = {}) {
    super(message)
    this.name = 'ApiError'
    this.kind = kind
    this.status = status
  }
}

function invalid(message) {
  return new ApiError('invalid_response', message)
}

function isPositiveInteger(value) {
  return Number.isInteger(value) && value >= 1
}

/** Validate a response from POST /evaluate. The data is never altered. */
export function parseAssessment(data) {
  if (data === null || typeof data !== 'object' || Array.isArray(data)) {
    throw invalid('The backend returned an unexpected response.')
  }

  if (!VERDICTS.has(data.verdict)) {
    throw invalid('The backend returned an invalid verdict.')
  }

  if (
    typeof data.risk_score !== 'number' ||
    !Number.isFinite(data.risk_score) ||
    data.risk_score < 0 ||
    data.risk_score > 1
  ) {
    throw invalid('The backend returned an invalid risk score.')
  }

  if (
    !Array.isArray(data.categories) ||
    data.categories.some((category) => typeof category !== 'string')
  ) {
    throw invalid('The backend returned invalid threat categories.')
  }

  if (typeof data.code_language !== 'string') {
    throw invalid('The backend returned an invalid language label.')
  }

  if (typeof data.reason !== 'string') {
    throw invalid('The backend returned an invalid explanation.')
  }

  if (
    !Array.isArray(data.vulnerable_lines) ||
    !data.vulnerable_lines.every(isPositiveInteger)
  ) {
    throw invalid('The backend returned invalid line numbers.')
  }

  return data
}

/** Validate a response from POST /demo/intercept. */
export function parseGateResult(data) {
  if (data === null || typeof data !== 'object' || Array.isArray(data)) {
    throw invalid('The backend returned an unexpected response.')
  }

  const { assessment, interception, approved_operation_calls: calls } = data

  if (
    interception === null ||
    typeof interception !== 'object' ||
    !DECISIONS.has(interception.decision) ||
    typeof interception.analysis_complete !== 'boolean' ||
    typeof interception.operation_called !== 'boolean' ||
    typeof interception.reason !== 'string'
  ) {
    throw invalid('The backend returned an invalid execution-gate result.')
  }

  if (!Number.isInteger(calls) || calls < 0) {
    throw invalid('The backend returned an invalid operation counter.')
  }

  return {
    assessment:
      assessment === null || assessment === undefined
        ? null
        : parseAssessment(assessment),
    interception,
    approved_operation_calls: calls,
  }
}

function errorMessageFromBody(body) {
  if (body && typeof body.detail === 'string' && body.detail.trim()) {
    return body.detail
  }

  return null
}

async function request(
  path,
  { method = 'GET', body, signal, timeoutMs = REQUEST_TIMEOUT_MS } = {},
) {
  const controller = new AbortController()
  let timedOut = false

  const timer = setTimeout(() => {
    timedOut = true
    controller.abort()
  }, timeoutMs)

  const forwardAbort = () => controller.abort()

  if (signal) {
    if (signal.aborted) {
      controller.abort()
    } else {
      signal.addEventListener('abort', forwardAbort, { once: true })
    }
  }

  try {
    let response

    try {
      response = await fetch(`${API_BASE_URL}${path}`, {
        method,
        headers:
          body === undefined
            ? { Accept: 'application/json' }
            : { Accept: 'application/json', 'Content-Type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: controller.signal,
      })
    } catch {
      if (timedOut) {
        throw new ApiError(
          'timeout',
          'The backend did not respond in time. No result was produced.',
        )
      }

      if (controller.signal.aborted) {
        throw new ApiError('aborted', 'The request was cancelled.')
      }

      throw new ApiError(
        'offline',
        'Cannot reach the CodeGuard backend. No analysis was performed.',
      )
    }

    let data = null
    let parsed = true

    try {
      data = await response.json()
    } catch {
      parsed = false
    }

    if (!response.ok) {
      const detail = parsed ? errorMessageFromBody(data) : null

      // A proxy answers with an empty or non-JSON error when the backend is down.
      if (!detail && response.status >= 500) {
        throw new ApiError(
          'offline',
          'Cannot reach the CodeGuard backend. No analysis was performed.',
          { status: response.status },
        )
      }

      throw new ApiError(
        'http',
        detail ?? `The backend rejected the request (HTTP ${response.status}).`,
        { status: response.status },
      )
    }

    if (!parsed) {
      throw invalid('The backend returned a response that is not valid JSON.')
    }

    return data
  } finally {
    clearTimeout(timer)
    signal?.removeEventListener('abort', forwardAbort)
  }
}

/** Resolve true only when GET /health answers {"status": "ok"}. */
export async function checkHealth({ signal } = {}) {
  try {
    const data = await request('/health', { signal, timeoutMs: 5000 })

    return data !== null && typeof data === 'object' && data.status === 'ok'
  } catch {
    return false
  }
}

/** POST /evaluate. The request body contains only the `code` field. */
export async function evaluateCode(code, { signal } = {}) {
  const data = await request('/evaluate', {
    method: 'POST',
    body: { code },
    signal,
  })

  return parseAssessment(data)
}

/** POST /demo/intercept: static analysis followed by the execution gate. */
export async function interceptCode(code, { signal } = {}) {
  const data = await request('/demo/intercept', {
    method: 'POST',
    body: { code },
    signal,
  })

  return parseGateResult(data)
}
