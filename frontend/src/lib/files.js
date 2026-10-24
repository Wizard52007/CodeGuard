import { MAX_FILE_BYTES } from '../config.js'
import {
  SUPPORTED_EXTENSIONS,
  extensionOf,
  languageFromFilename,
} from './languages.js'

export class FileLoadError extends Error {
  constructor(message) {
    super(message)
    this.name = 'FileLoadError'
  }
}

function readBytes(file) {
  if (typeof file.arrayBuffer === 'function') {
    return file.arrayBuffer()
  }

  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => resolve(reader.result)
    reader.onerror = () => reject(reader.error)
    reader.readAsArrayBuffer(file)
  })
}

/**
 * Read a supported source file as UTF-8 text. The file is only read; it is
 * never executed or uploaded anywhere.
 */
export async function readSourceFile(file, { maxBytes = MAX_FILE_BYTES } = {}) {
  const extension = extensionOf(file.name)

  if (!SUPPORTED_EXTENSIONS.includes(extension)) {
    throw new FileLoadError(
      `Unsupported file type${extension ? ` "${extension}"` : ''}. ` +
        `Supported: ${SUPPORTED_EXTENSIONS.join(', ')}.`,
    )
  }

  if (file.size > maxBytes) {
    throw new FileLoadError(
      `${file.name} is too large (${Math.ceil(file.size / 1024)} KB). ` +
        `The limit is ${Math.floor(maxBytes / 1024)} KB.`,
    )
  }

  let bytes

  try {
    bytes = await readBytes(file)
  } catch {
    throw new FileLoadError(`${file.name} could not be read.`)
  }

  let text

  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    throw new FileLoadError(`${file.name} is not valid UTF-8 text.`)
  }

  if (text.includes('\u0000')) {
    throw new FileLoadError(`${file.name} looks like a binary file.`)
  }

  if (!text.trim()) {
    throw new FileLoadError(`${file.name} is empty.`)
  }

  return { name: file.name, text, language: languageFromFilename(file.name) }
}
