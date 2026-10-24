import Editor from '@monaco-editor/react'
import { useEffect, useRef, useState } from 'react'

import { monacoLanguageFor } from '../lib/languages.js'
import { visibleLines } from '../lib/format.js'
import '../monaco/setup.js'

const THEME = 'codeguard-dark'
const FOCUS_FLASH_MS = 1600

function defineTheme(monaco) {
  monaco.editor.defineTheme(THEME, {
    base: 'vs-dark',
    inherit: true,
    rules: [],
    colors: {
      'editor.background': '#0e1216',
      'editor.lineHighlightBackground': '#161c23',
      'editorLineNumber.foreground': '#4a5563',
      'editorLineNumber.activeForeground': '#9aa6b5',
      'editorGutter.background': '#0e1216',
      'editorCursor.foreground': '#e6e9ee',
      'editor.selectionBackground': '#27456b',
      'scrollbarSlider.background': '#2a323c80',
    },
  })
}

export default function CodeEditor({
  value,
  onChange,
  onSubmit,
  language,
  highlightedLines,
  revealRequest,
}) {
  const editorRef = useRef(null)
  const monacoRef = useRef(null)
  const vulnerabilityRef = useRef(null)
  const focusRef = useRef(null)
  const submitRef = useRef(onSubmit)
  const flashTimer = useRef(null)
  const [ready, setReady] = useState(false)

  useEffect(() => {
    submitRef.current = onSubmit
  }, [onSubmit])

  useEffect(
    () => () => {
      clearTimeout(flashTimer.current)
    },
    [],
  )

  function handleMount(editor, monaco) {
    editorRef.current = editor
    monacoRef.current = monaco
    vulnerabilityRef.current = editor.createDecorationsCollection()
    focusRef.current = editor.createDecorationsCollection()

    editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.Enter, () => {
      submitRef.current?.()
    })

    setReady(true)
  }

  useEffect(() => {
    const editor = editorRef.current
    const monaco = monacoRef.current

    if (!ready || !editor || !monaco) {
      return
    }

    const model = editor.getModel()
    const lines = visibleLines(highlightedLines, model ? model.getLineCount() : 0)

    vulnerabilityRef.current.set(
      lines.map((line) => ({
        range: new monaco.Range(line, 1, line, 1),
        options: {
          isWholeLine: true,
          className: 'cg-flagged-line',
          glyphMarginClassName: 'cg-flagged-glyph',
          glyphMarginHoverMessage: { value: 'Flagged by CodeGuard' },
          overviewRuler: {
            color: '#ef4444',
            position: monaco.editor.OverviewRulerLane.Full,
          },
        },
      })),
    )
  }, [highlightedLines, ready, value])

  useEffect(() => {
    const editor = editorRef.current
    const monaco = monacoRef.current

    if (!ready || !revealRequest || !editor || !monaco) {
      return
    }

    const model = editor.getModel()

    if (!model || revealRequest.line > model.getLineCount()) {
      return
    }

    editor.revealLineInCenter(revealRequest.line)
    editor.setPosition({ lineNumber: revealRequest.line, column: 1 })
    editor.focus()

    focusRef.current.set([
      {
        range: new monaco.Range(revealRequest.line, 1, revealRequest.line, 1),
        options: { isWholeLine: true, className: 'cg-focused-line' },
      },
    ])

    clearTimeout(flashTimer.current)
    flashTimer.current = setTimeout(
      () => focusRef.current?.clear(),
      FOCUS_FLASH_MS,
    )
  }, [revealRequest, ready])

  return (
    <Editor
      height="100%"
      language={monacoLanguageFor(language)}
      value={value}
      theme={THEME}
      beforeMount={defineTheme}
      onMount={handleMount}
      onChange={(next) => onChange(next ?? '')}
      loading={<div className="editor-loading">Loading editor…</div>}
      options={{
        ariaLabel: 'Code to analyze',
        automaticLayout: true,
        fontFamily:
          "'Cascadia Code', 'JetBrains Mono', Consolas, 'SF Mono', monospace",
        fontSize: 14,
        glyphMargin: true,
        lineNumbers: 'on',
        minimap: { enabled: false },
        padding: { top: 12, bottom: 12 },
        renderLineHighlight: 'line',
        scrollBeyondLastLine: false,
        smoothScrolling: true,
        tabSize: 4,
        wordWrap: 'off',
      }}
    />
  )
}
