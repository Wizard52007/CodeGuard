import { afterEach, describe, expect, it, vi } from 'vitest'

import { ApiError, checkHealth, evaluateCode, parseAssessment } from './client.js'

const ALLOW = {
  verdict: 'allow',
  risk_score: 0,
  categories: [],
  code_language: 'python',
  reason: 'No configured security rules detected a threat.',
  vulnerable_lines: [],
}

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('evaluateCode', () => {
  it('posts only the code field to /evaluate', async () => {
    const fetchMock = vi.fn(async () => jsonResponse(ALLOW))
    vi.stubGlobal('fetch', fetchMock)

    await evaluateCode('print(1)')

    const [url, options] = fetchMock.mock.calls[0]
    expect(url).toBe('/evaluate')
    expect(options.method).toBe('POST')
    expect(JSON.parse(options.body)).toEqual({ code: 'print(1)' })
  })

  it('returns the backend verdict without altering it', async () => {
    const block = {
      ...ALLOW,
      verdict: 'block',
      risk_score: 0.75,
      categories: ['destructive_command'],
      vulnerable_lines: [1],
    }
    vi.stubGlobal('fetch', vi.fn(async () => jsonResponse(block)))

    expect(await evaluateCode('rm -rf x')).toEqual(block)
  })

  it('reports an offline backend without inventing a result', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => {
      throw new TypeError('Failed to fetch')
    }))

    await expect(evaluateCode('x')).rejects.toMatchObject({ kind: 'offline' })
  })

  it('rejects responses that break the contract', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => jsonResponse({ ...ALLOW, verdict: 'maybe' })),
    )

    await expect(evaluateCode('x')).rejects.toBeInstanceOf(ApiError)
    await expect(evaluateCode('x')).rejects.toMatchObject({
      kind: 'invalid_response',
    })
  })

  it('surfaces the backend detail for an HTTP error', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        jsonResponse({ detail: 'Security analysis unavailable.' }, 503),
      ),
    )

    await expect(evaluateCode('x')).rejects.toMatchObject({
      kind: 'http',
      message: 'Security analysis unavailable.',
    })
  })
})

describe('checkHealth', () => {
  it('is true only for an ok status', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => jsonResponse({ status: 'ok' })))
    expect(await checkHealth()).toBe(true)
  })

  it('is false when the backend is unreachable', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => {
      throw new TypeError('Failed to fetch')
    }))
    expect(await checkHealth()).toBe(false)
  })
})

describe('parseAssessment', () => {
  it('accepts the agreed schema', () => {
    expect(parseAssessment(ALLOW)).toEqual(ALLOW)
  })

  it('rejects unsorted or non-positive line numbers', () => {
    expect(() => parseAssessment({ ...ALLOW, vulnerable_lines: [0] })).toThrow()
    expect(() => parseAssessment({ ...ALLOW, risk_score: 1.5 })).toThrow()
  })
})
