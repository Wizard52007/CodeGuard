import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

import App from './App.jsx'
import { SAMPLES } from './data/samples.js'

vi.mock('./hooks/useBackendHealth.js', () => ({
  useBackendHealth: () => ({ status: 'online', recheck: vi.fn() }),
}))

vi.mock('./hooks/useAnalysis.js', () => ({
  useAnalysis: () => ({
    status: 'success',
    mode: 'static',
    assessment: {
      verdict: 'block',
      risk_score: 0.75,
      categories: ['destructive_command'],
      code_language: 'bash',
      reason: 'A recursive or forced file-removal command may delete important data.',
      vulnerable_lines: [1],
    },
    gate: null,
    error: null,
    elapsedMs: 12,
    analyzedCode: SAMPLES[0].code,
    run: vi.fn(),
    cancel: vi.fn(),
    reset: vi.fn(),
  }),
}))

vi.mock('@monaco-editor/react', () => ({
  loader: { config: vi.fn() },
  default: ({ value, onChange }) => (
    <textarea
      aria-label="Code to analyze"
      value={value}
      onChange={(event) => onChange(event.target.value)}
    />
  ),
}))

describe('verdict display', () => {
  it('shows the backend BLOCK verdict, score, category and flagged line', () => {
    render(<App />)

    expect(screen.getByText('BLOCK')).toBeTruthy()
    expect(screen.getByText('Code blocked')).toBeTruthy()
    expect(screen.getByText('75')).toBeTruthy()
    expect(screen.getByText('destructive command')).toBeTruthy()
    expect(screen.getByText('Line 1')).toBeTruthy()
  })
})
