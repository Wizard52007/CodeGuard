const DECISION_TEXT = {
  allow: 'Allowed',
  block: 'Blocked',
  error: 'Approved operation failed',
}

export default function GatePanel({ gate, assessment }) {
  const { interception, approvedOperationCalls } = gate
  const decisionClass =
    interception.decision === 'allow'
      ? 'allow'
      : interception.decision === 'block'
        ? 'block'
        : 'warn'

  return (
    <section className="subsection gate" aria-labelledby="gate-heading">
      <h3 id="gate-heading">Execution gate</h3>

      <ol className="gate-steps">
        <li>
          <span className="step-label">1. Static analysis</span>
          <span className="step-value">
            {assessment
              ? `Verdict ${assessment.verdict.toUpperCase()}`
              : 'No complete assessment'}
          </span>
        </li>
        <li>
          <span className="step-label">2. Gate decision</span>
          <span className={`step-value tone-${decisionClass}`}>
            {DECISION_TEXT[interception.decision]}
          </span>
        </li>
        <li>
          <span className="step-label">3. Approved operation</span>
          <span
            className={`step-value ${
              interception.operation_called ? 'tone-allow' : 'tone-block'
            }`}
          >
            {interception.operation_called ? 'Called' : 'Not called'}
          </span>
        </li>
      </ol>

      <dl className="gate-facts">
        <div>
          <dt>Analysis complete</dt>
          <dd>{interception.analysis_complete ? 'Yes' : 'No (failed closed)'}</dd>
        </div>
        <div>
          <dt>Operation counter</dt>
          <dd>{approvedOperationCalls}</dd>
        </div>
      </dl>

      <p className="gate-reason">{interception.reason}</p>

      <p className="fine-print">
        The submitted code was analyzed as text and was not executed, even if
        allowed. The approved operation is a pre-approved, harmless counter
        that receives no submitted code. The counter above is read from that
        operation itself.
      </p>
    </section>
  )
}
