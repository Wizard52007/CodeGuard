import { useRef } from 'react'

import { SAMPLES } from '../data/samples.js'
import { countLines } from '../lib/format.js'
import { LANGUAGES, SUPPORTED_EXTENSIONS } from '../lib/languages.js'
import CodeEditor from './CodeEditor.jsx'

const SAMPLE_GROUPS = ['Benign', 'Suspicious']

export default function EditorPanel({
  code,
  onCodeChange,
  syntax,
  onSyntaxChange,
  effectiveLanguage,
  sampleId,
  onSampleSelect,
  onFileSelected,
  fileName,
  notice,
  mode,
  onModeChange,
  loading,
  onAnalyze,
  onCancel,
  onClear,
  highlightedLines,
  revealRequest,
}) {
  const fileInput = useRef(null)
  const lineCount = countLines(code)

  function handleFile(event) {
    const [file] = event.target.files ?? []

    // Allow choosing the same file again later.
    event.target.value = ''

    if (file) {
      onFileSelected(file)
    }
  }

  return (
    <section className="panel editor-panel" aria-labelledby="input-heading">
      <div className="panel-header">
        <h2 id="input-heading">Code input</h2>
        <span className="panel-hint">
          Paste code, load a demonstration example, or upload a file.
        </span>
      </div>

      <div className="toolbar">
        <label className="field">
          <span>Demonstration example</span>
          <select
            value={sampleId}
            onChange={(event) => onSampleSelect(event.target.value)}
            disabled={loading}
          >
            <option value="">Choose an example…</option>
            {SAMPLE_GROUPS.map((group) => (
              <optgroup key={group} label={group}>
                {SAMPLES.filter((sample) => sample.group === group).map(
                  (sample) => (
                    <option key={sample.id} value={sample.id}>
                      {sample.title}
                    </option>
                  ),
                )}
              </optgroup>
            ))}
          </select>
        </label>

        <label className="field">
          <span>Syntax highlighting</span>
          <select
            value={syntax}
            onChange={(event) => onSyntaxChange(event.target.value)}
          >
            <option value="auto">Auto</option>
            {LANGUAGES.map((language) => (
              <option key={language.id} value={language.id}>
                {language.label}
              </option>
            ))}
          </select>
        </label>

        <div className="field">
          <span>Source file</span>
          <button
            type="button"
            className="button secondary"
            onClick={() => fileInput.current?.click()}
            disabled={loading}
          >
            Upload file…
          </button>
          <input
            ref={fileInput}
            type="file"
            hidden
            data-testid="file-input"
            aria-label="Upload a source file"
            accept={SUPPORTED_EXTENSIONS.join(',')}
            onChange={handleFile}
          />
        </div>
      </div>

      {notice && (
        <p
          className={`notice notice-${notice.kind}`}
          role={notice.kind === 'error' ? 'alert' : 'status'}
        >
          {notice.text}
        </p>
      )}

      <div className="editor-frame">
        <CodeEditor
          value={code}
          onChange={onCodeChange}
          onSubmit={onAnalyze}
          language={effectiveLanguage}
          highlightedLines={highlightedLines}
          revealRequest={revealRequest}
        />
      </div>

      <div className="editor-footer">
        <div className="editor-stats">
          {fileName && <span className="file-name">{fileName}</span>}
          <span>
            {lineCount} {lineCount === 1 ? 'line' : 'lines'}
          </span>
          <span>{code.length.toLocaleString()} characters</span>
        </div>

        <div className="actions">
          <div className="segmented" role="group" aria-label="Analysis mode">
            <button
              type="button"
              aria-pressed={mode === 'static'}
              onClick={() => onModeChange('static')}
              disabled={loading}
            >
              Static analysis
            </button>
            <button
              type="button"
              aria-pressed={mode === 'gate'}
              onClick={() => onModeChange('gate')}
              disabled={loading}
              title="Run the code through the execution gate (no submitted code is executed)"
            >
              Execution gate demo
            </button>
          </div>

          <button
            type="button"
            className="button ghost"
            onClick={onClear}
            disabled={loading}
          >
            Clear
          </button>

          {loading ? (
            <button type="button" className="button danger" onClick={onCancel}>
              Cancel
            </button>
          ) : null}

          <button
            type="button"
            className="button primary"
            onClick={onAnalyze}
            disabled={loading}
          >
            {loading
              ? 'Analyzing…'
              : mode === 'gate'
                ? 'Run through gate'
                : 'Analyze'}
            {!loading && <kbd>Ctrl ↵</kbd>}
          </button>
        </div>
      </div>
    </section>
  )
}
