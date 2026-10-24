// Languages the CodeGuard backend labels. `monaco` is the editor's identifier.
export const LANGUAGES = [
  { id: 'python', label: 'Python', monaco: 'python', extensions: ['.py'] },
  {
    id: 'javascript',
    label: 'JavaScript',
    monaco: 'javascript',
    extensions: ['.js'],
  },
  {
    id: 'bash',
    label: 'Bash / Shell',
    monaco: 'shell',
    extensions: ['.sh', '.bash'],
  },
  { id: 'sql', label: 'SQL', monaco: 'sql', extensions: ['.sql'] },
  { id: 'yaml', label: 'YAML', monaco: 'yaml', extensions: ['.yaml', '.yml'] },
  {
    id: 'markdown',
    label: 'Markdown',
    monaco: 'markdown',
    extensions: ['.md', '.markdown'],
  },
]

export const SUPPORTED_EXTENSIONS = LANGUAGES.flatMap(
  (language) => language.extensions,
)

const BY_ID = new Map(LANGUAGES.map((language) => [language.id, language]))

/** Map a backend language label to a Monaco language identifier. */
export function monacoLanguageFor(languageId) {
  return BY_ID.get(languageId)?.monaco ?? 'plaintext'
}

export function languageLabel(languageId) {
  if (languageId === 'unknown') {
    return 'Unknown'
  }

  return BY_ID.get(languageId)?.label ?? languageId
}

export function extensionOf(filename) {
  const index = filename.lastIndexOf('.')

  return index === -1 ? '' : filename.slice(index).toLowerCase()
}

/** Return the backend language id for a file name, or null when unsupported. */
export function languageFromFilename(filename) {
  const extension = extensionOf(filename)

  return (
    LANGUAGES.find((language) => language.extensions.includes(extension))
      ?.id ?? null
  )
}

/**
 * A lightweight guess used only to choose syntax highlighting before the
 * backend has reported a language. It plays no part in any security decision.
 */
export function guessLanguageForHighlighting(code) {
  const text = code.trim()

  if (!text) {
    return null
  }

  if (/^#!.*\b(?:ba)?sh\b/.test(text)) {
    return 'bash'
  }

  if (/^#!.*\bpython/.test(text)) {
    return 'python'
  }

  if (/^\s*(?:import\s+\w|from\s+[\w.]+\s+import\s|def\s+\w+\(|class\s+\w+)/m.test(text)) {
    return 'python'
  }

  if (/\b(?:const|let|var)\s+\w+\s*=|\bfunction\s+\w+\s*\(|=>|\brequire\(/.test(text)) {
    return 'javascript'
  }

  if (
    /\b(?:SELECT\b[\s\S]*\bFROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|DROP\s+TABLE|CREATE\s+TABLE|TRUNCATE\s+TABLE)\b/i.test(
      text,
    )
  ) {
    return 'sql'
  }

  if (/^#{1,6}\s+\S/m.test(text) || /^```/m.test(text)) {
    return 'markdown'
  }

  if (/^\s*(?:rm|curl|wget|chmod|sudo|echo|mkdir|cd|ls|export|cat)\s/m.test(text)) {
    return 'bash'
  }

  if (/^[\w.-]+:\s*\S*/m.test(text)) {
    return 'yaml'
  }

  return null
}
