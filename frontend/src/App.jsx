import { useMemo, useState } from 'react'

import Header from './components/Header.jsx'
import EditorPanel from './components/EditorPanel.jsx'
import GatePanel from './components/GatePanel.jsx'
import { SAMPLES, findSample } from './data/samples.js'
import { useAnalysis } from './hooks/useAnalysis.js'
import { useBackendHealth } from './hooks/useBackendHealth.js'
import { readSourceFile } from './lib/files.js'
import {
  guessLanguageForHighlighting,
  languageLabel,
} from './lib/languages.js'
import {
  formatLatency,
  scoreOutOf100,
  splitReason,
  visibleLines,
} from './lib/format.js'

export default function App() {
  const [code, setCode] = useState(SAMPLES[0]?.code ?? '')
  const [syntax, setSyntax] = useState('auto')
  const [sampleId, setSampleId] = useState(SAMPLES[0]?.id ?? '')
  const [fileName, setFileName] = useState('')
  const [notice, setNotice] = useState(null)
  const [revealRequest, setRevealRequest] = useState(null)
  const [selectedMode, setSelectedMode] = useState('static')

  const analysis = useAnalysis()
  const backend = useBackendHealth()

  const assessment = analysis.assessment
  const gate = analysis.gate

  const effectiveLanguage = useMemo(() => {
    if (syntax !== 'auto') return syntax
    if (assessment?.code_language && analysis.analyzedCode === code) {
      return assessment.code_language
    }
    return guessLanguageForHighlighting(code) ?? 'python'
  }, [syntax, assessment, analysis.analyzedCode, code])

  const highlightedLines = useMemo(() => {
    if (analysis.analyzedCode !== code || !assessment) return []
    return visibleLines(assessment.vulnerable_lines, code.split(/\r\n|\r|\n/).length)
  }, [analysis.analyzedCode, assessment, code])

  function updateCode(value) {
    setCode(value)
    setSampleId('')
    setFileName('')
    setNotice(null)
    setRevealRequest(null)
  }

  function chooseSample(id) {
    const sample = findSample(id)
    if (!sample) return

    analysis.reset()
    setCode(sample.code)
    setSyntax(sample.language)
    setSampleId(id)
    setFileName('')
    setNotice({ kind: 'info', text: `${sample.title} loaded. Click Analyze to inspect it.` })
    setRevealRequest(null)
  }

  async function chooseFile(file) {
    try {
      const loaded = await readSourceFile(file)
      analysis.reset()
      setCode(loaded.text)
      setSyntax(loaded.language ?? 'auto')
      setSampleId('')
      setFileName(loaded.name)
      setNotice({
        kind: 'info',
        text: `${loaded.name} loaded locally. Its contents have not been executed.`,
      })
      setRevealRequest(null)
    } catch (error) {
      setNotice({
        kind: 'error',
        text: error instanceof Error ? error.message : 'Could not read this file.',
      })
    }
  }

  function runAnalysis() {
    if (!code.trim()) {
      setNotice({ kind: 'error', text: 'Enter some code before analyzing.' })
      return
    }
    setNotice(null)
    setRevealRequest(null)
    analysis.run(code, selectedMode)
  }

  function clearEditor() {
    analysis.reset()
    setCode('')
    setSampleId('')
    setFileName('')
    setNotice(null)
    setRevealRequest(null)
  }

  function chooseMode(mode) {
    setSelectedMode(mode)
    analysis.reset()
  }

  function showLine(line) {
    setRevealRequest({ line, key: Date.now() })
  }

  const isCurrentResult =
    analysis.status === 'success' && analysis.analyzedCode === code
  const isBlocked = isCurrentResult && assessment?.verdict === 'block'

  return (
    <main className="app-shell">
      <Header
        backendStatus={backend.status}
        onRecheck={backend.recheck}
      />

      <section className="intro">
        <div>
          <p className="eyebrow">PRE-EXECUTION SECURITY</p>
          <h2>Inspect first. Execute later.</h2>
          <p className="intro-copy">
            Analyze potentially risky code before it reaches an execution
            environment. CodeGuard uses static analysis; submitted code is
            never run by this interface.
          </p>
        </div>

        <div className="trust-card">
          <span className="trust-indicator" />
          <div>
            <strong>Static analysis only</strong>
            <p>No submitted code execution</p>
          </div>
        </div>
      </section>

      <div className="workspace">
        <EditorPanel
          code={code}
          onCodeChange={updateCode}
          syntax={syntax}
          onSyntaxChange={setSyntax}
          effectiveLanguage={effectiveLanguage}
          sampleId={sampleId}
          onSampleSelect={chooseSample}
          onFileSelected={chooseFile}
          fileName={fileName}
          notice={notice}
          mode={selectedMode}
          onModeChange={chooseMode}
          loading={analysis.status === 'loading'}
          onAnalyze={runAnalysis}
          onCancel={analysis.cancel}
          onClear={clearEditor}
          highlightedLines={highlightedLines}
          revealRequest={revealRequest}
        />

        <section className="panel results-panel" aria-labelledby="results-heading">
          <div className="panel-header">
            <h2 id="results-heading">Security assessment</h2>
            <span className="panel-hint">Results from the backend</span>
          </div>

          {analysis.status === 'idle' || analysis.status === 'cancelled' ? (
            <div className="empty-state">
              <div className="empty-icon">⌕</div>
              <h3>Ready to inspect</h3>
              <p>
                Select an example or enter code, then choose Analyze to receive
                a security assessment.
              </p>
              <div className="mini-stats">
                <span>6 languages</span>
                <span>Static analysis</span>
                <span>API-backed results</span>
              </div>
            </div>
          ) : null}

          {analysis.status === 'loading' && (
            <div className="empty-state" role="status">
              <div className="spinner" />
              <h3>Analyzing code…</h3>
              <p>Waiting for the CodeGuard backend. The submitted code is not executed.</p>
            </div>
          )}

          {analysis.status === 'error' && (
            <div className="error-card" role="alert">
              <span className="result-label">ASSESSMENT UNAVAILABLE</span>
              <h3>No security verdict produced</h3>
              <p>{analysis.error?.message ?? 'The request failed.'}</p>
              <p className="muted">
                Check that the backend is running and online, then try again.
              </p>
              <button className="button secondary" onClick={backend.recheck}>
                Check backend
              </button>
            </div>
          )}

          {isCurrentResult && assessment && (
            <div className="assessment">
              <div className={`verdict-card ${isBlocked ? 'verdict-block' : 'verdict-allow'}`}>
                <div>
                  <span className="result-label">SECURITY VERDICT</span>
                  <h3>{isBlocked ? 'Code blocked' : 'No blocking risk detected'}</h3>
                  <p>
                    {isBlocked
                      ? 'Do not pass this code to an execution environment without reviewing the findings.'
                      : 'The detector did not identify a blocking risk in this submission.'}
                  </p>
                </div>
                <span className="verdict-badge">
                  {assessment.verdict.toUpperCase()}
                </span>
              </div>

              <div className="metric-grid">
                <article className="metric-card">
                  <span>Risk score</span>
                  <strong>{scoreOutOf100(assessment.risk_score)}<small>/100</small></strong>
                  <div className="score-track">
                    <span style={{ width: `${scoreOutOf100(assessment.risk_score)}%` }} />
                  </div>
                </article>
                <article className="metric-card">
                  <span>Language</span>
                  <strong className="metric-language">
                    {languageLabel(assessment.code_language)}
                  </strong>
                  <small>Detected by backend</small>
                </article>
                <article className="metric-card">
                  <span>Analysis time</span>
                  <strong>{formatLatency(analysis.elapsedMs) ?? '—'}</strong>
                  <small>Request duration</small>
                </article>
              </div>

              <section className="subsection">
                <div className="section-title-row">
                  <h3>Why this verdict?</h3>
                  <span className="count-badge">{assessment.categories.length} categories</span>
                </div>
                <div className="reason-list">
                  {splitReason(assessment.reason).map((reason, index) => (
                    <p key={`${index}-${reason}`}>{reason}</p>
                  ))}
                </div>
              </section>

              <section className="subsection">
                <div className="section-title-row">
                  <h3>Detected threat categories</h3>
                  <span className="count-badge">{assessment.categories.length}</span>
                </div>
                {assessment.categories.length ? (
                  <div className="category-list">
                    {assessment.categories.map((category) => (
                      <span className="category-chip" key={category}>
                        {category.replaceAll('_', ' ')}
                      </span>
                    ))}
                  </div>
                ) : (
                  <p className="muted">No threat categories were reported.</p>
                )}
              </section>

              <section className="subsection">
                <div className="section-title-row">
                  <h3>Flagged lines</h3>
                  <span className="count-badge">{highlightedLines.length}</span>
                </div>
                {highlightedLines.length ? (
                  <div className="line-list">
                    {highlightedLines.map((line) => (
                      <button
                        className="line-item"
                        type="button"
                        key={line}
                        onClick={() => showLine(line)}
                      >
                        <span>Line {line}</span>
                        <code>{code.split(/\r\n|\r|\n/)[line - 1]?.trim() || '(blank line)'}</code>
                        <span aria-hidden="true">↗</span>
                      </button>
                    ))}
                  </div>
                ) : (
                  <p className="muted">No vulnerable lines were reported.</p>
                )}
              </section>

              {selectedMode === 'gate' && gate && (
                <GatePanel gate={gate} assessment={assessment} />
              )}

              <p className="disclaimer">
                A static-analysis result is not a guarantee that code is safe.
                Review findings before execution, especially in production.
              </p>
            </div>
          )}
        </section>
      </div>

      <footer className="app-footer">
        <span>CodeGuard · AI Code Security Firewall</span>
        <span>Analyze as text. Never execute submitted code.</span>
      </footer>
    </main>
  )
}
