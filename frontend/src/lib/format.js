export function formatScore(score) {
  return score.toFixed(2)
}

/** The backend score is 0-1; this is only a secondary 0-100 presentation. */
export function scoreOutOf100(score) {
  return Math.round(score * 100)
}

export function formatLatency(milliseconds) {
  if (milliseconds === null || milliseconds === undefined) {
    return null
  }

  return milliseconds < 1000
    ? `${Math.max(1, Math.round(milliseconds))} ms`
    : `${(milliseconds / 1000).toFixed(2)} s`
}

/** Split the backend's joined explanation into its individual sentences. */
export function splitReason(reason) {
  const parts = reason
    .split(/(?<=[.!?])\s+(?=[A-Z])/)
    .map((part) => part.trim())
    .filter(Boolean)

  return parts.length > 0 ? parts : [reason]
}

export function countLines(text) {
  return text === '' ? 0 : text.split(/\r\n|\r|\n/).length
}

export function lineText(code, lineNumber) {
  return code.split(/\r\n|\r|\n/)[lineNumber - 1] ?? ''
}

/** Valid, sorted, unique line numbers that exist in a document. */
export function visibleLines(lines, lineCount) {
  return [
    ...new Set(
      lines.filter(
        (line) => Number.isInteger(line) && line >= 1 && line <= lineCount,
      ),
    ),
  ].sort((a, b) => a - b)
}
