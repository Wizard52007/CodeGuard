import { useCallback, useEffect, useRef, useState } from 'react'

import { checkHealth } from '../api/client.js'
import { HEALTH_POLL_MS } from '../config.js'

/** 'checking' until the first answer, then 'online' or 'offline'. */
export function useBackendHealth(intervalMs = HEALTH_POLL_MS) {
  const [status, setStatus] = useState('checking')
  const controllerRef = useRef(null)

  const check = useCallback(async () => {
    controllerRef.current?.abort()

    const controller = new AbortController()
    controllerRef.current = controller

    const online = await checkHealth({ signal: controller.signal })

    if (!controller.signal.aborted) {
      setStatus(online ? 'online' : 'offline')
    }
  }, [])

  useEffect(() => {
    check()

    const timer = setInterval(check, intervalMs)

    return () => {
      clearInterval(timer)
      controllerRef.current?.abort()
    }
  }, [check, intervalMs])

  return { status, recheck: check }
}
