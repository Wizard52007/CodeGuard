import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import App from './App.jsx'

vi.mock('./hooks/useBackendHealth.js', () => ({
useBackendHealth: () => ({
status: 'online',
recheck: vi.fn(),
}),
}))

vi.mock('./hooks/useAnalysis.js', () => ({
useAnalysis: () => ({
status: 'idle',
mode: null,
assessment: null,
gate: null,
error: null,
elapsedMs: null,
analyzedCode: null,
run: vi.fn(),
cancel: vi.fn(),
reset: vi.fn(),
}),
}))

vi.mock('@monaco-editor/react', () => ({
loader: {
config: vi.fn(),
},
default: ({ value, onChange }) => (
<textarea
aria-label="Code to analyze"
value={value}
onChange={(event) => onChange(event.target.value)}
/>
),
}))

describe('CodeGuard frontend', () => {
it('renders the CodeGuard dashboard', () => {
render(<App />)


expect(screen.getByText('CodeGuard')).toBeTruthy()
expect(screen.getByText('Security assessment')).toBeTruthy()
expect(screen.getByText('Inspect first. Execute later.')).toBeTruthy()


})

it('loads a benign example into the editor', () => {
render(<App />)


const selectors = screen.getAllByLabelText('Demonstration example')

fireEvent.change(selectors[0], {
  target: { value: 'benign-python' },
})

const editors = screen.getAllByLabelText('Code to analyze')

expect(
  editors.some((editor) => editor.value.includes('def greet')),
).toBe(true)


})

it('loads a suspicious example as text without executing it', () => {
render(<App />)


const selectors = screen.getAllByLabelText('Demonstration example')

fireEvent.change(selectors[0], {
  target: { value: 'destructive-shell' },
})

const editors = screen.getAllByLabelText('Code to analyze')

expect(
  editors.some((editor) => editor.value.includes('rm -rf')),
).toBe(true)


})
})
