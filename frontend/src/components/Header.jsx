import { LANGUAGES } from '../lib/languages.js'

const STATUS_TEXT = {
  checking: 'Checking backend…',
  online: 'Backend online',
  offline: 'Backend offline',
}

function Logo() {
  return (
    <svg
      className="logo"
      viewBox="0 0 32 32"
      width="32"
      height="32"
      fill="none"
      aria-hidden="true"
    >
      <path
        d="M16 3 5 7v8c0 7 4.6 12.2 11 14 6.4-1.8 11-7 11-14V7L16 3Z"
        fill="#11151a"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinejoin="round"
      />
      <path
        d="m11.5 16.5 3.2 3.2 6-6.4"
        stroke="currentColor"
        strokeWidth="2.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}

export default function Header({ backendStatus, onRecheck }) {
  return (
    <header className="app-header">
      <div className="brand">
        <Logo />
        <div>
          <h1>CodeGuard</h1>
          <p>AI Code Security Firewall</p>
        </div>
      </div>

      <div className="header-meta">
        <p className="static-note">
          Static analysis. Submitted code is never executed.
        </p>
        <ul className="language-list" aria-label="Supported languages">
          {LANGUAGES.map((language) => (
            <li key={language.id}>{language.label}</li>
          ))}
        </ul>
      </div>

      <button
        type="button"
        className={`status-pill status-${backendStatus}`}
        onClick={onRecheck}
        title="Click to check the backend again"
      >
        <span className="status-dot" aria-hidden="true" />
        <span>{STATUS_TEXT[backendStatus]}</span>
      </button>
    </header>
  )
}
