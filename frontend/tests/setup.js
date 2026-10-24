import '@testing-library/jest-dom/vitest'

// JSDOM does not implement this browser API, which Monaco Editor expects.
if (!document.queryCommandSupported) {
  document.queryCommandSupported = () => false
}
