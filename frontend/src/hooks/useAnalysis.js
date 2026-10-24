import { useCallback, useEffect, useRef, useState } from 'react'

import { ApiError, evaluateCode, interceptCode } from '../api/client.js'

const INITIAL = {
  status: 'idle', // idle | loading | success | error | cancelled
  mode: null, // static | gate
  assessment: null,
  gate: null,
  error: null,
  elapsedMs: null,
  analyzedCode: null,
}

/**
 * Runs one analysis at a time. The backend verdict is stored exactly as it
 * was received; nothing here recomputes or overrides it.
 */
export function useAnalysis() {
  const [state, setState] = useState(INITIAL)
  const controllerRef = useRef(null)

  useEffect(
    () => () => {
      controllerRef.current?.abort()
    },
    [],
  )

  const run = useCallback(async (code, mode) => {
    if (controllerRef.current) {
      return
    }

    const controller = new AbortController()
    controllerRef.current = controller

    setState({ ...INITIAL, status: 'loading', mode })

    const started = performance.now()

    try {
      let assessment
      let gate = null

      if (mode === 'gate') {
        const response = await interceptCode(code, { signal: controller.signal })

        assessment = response.assessment
        gate = {
          interception: response.interception,
          approvedOperationCalls: response.approved_operation_calls,
        }
      } else {
        assessment = await evaluateCode(code, { signal: controller.signal })
      }

      if (controllerRef.current !== controller) {
        return
      }

      setState({
        status: 'success',
        mode,
        assessment,
        gate,
        error: null,
        elapsedMs: performance.now() - started,
        analyzedCode: code,
      })
    } catch (error) {
      // A reset or newer request has superseded this one.
      if (controllerRef.current !== controller) {
        return
      }

      if (error instanceof ApiError && error.kind === 'aborted') {
        setState({ ...INITIAL, status: 'cancelled', mode })
      } else {
        setState({
          ...INITIAL,
          status: 'error',
          mode,
          error:
            error instanceof ApiError
              ? error
              : new ApiError('invalid_response', 'Unexpected error.'),
        })
      }
    } finally {
      if (controllerRef.current === controller) {
        controllerRef.current = null
      }
    }
  }, [])

  const cancel = useCallback(() => {
    controllerRef.current?.abort()
  }, [])

  const reset = useCallback(() => {
    controllerRef.current?.abort()
    controllerRef.current = null
    setState(INITIAL)
  }, [])

  return { ...state, run, cancel, reset }
}
