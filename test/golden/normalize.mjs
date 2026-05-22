#!/usr/bin/env node
/**
 * Stream-normalize CLI output for golden-file comparison.
 *
 * Strips fields that vary every run so byte-identity is achievable
 * across runs and across refactors. We are NOT comparing
 * timestamps/durations — we are comparing structure and copy.
 *
 * Substitutions (applied to both human and JSON output):
 *   - ISO timestamps                  → <TIMESTAMP>
 *   - "durationMs": <number>          → "durationMs": <DURATION>
 *   - "timestamp": "..."              → "timestamp": "<TIMESTAMP>"
 *   - "last report: 1m ago" etc       → "last report: <AGO>"
 *   - tmp paths like /var/folders/... → <TMPDIR>
 *   - $HOME absolute paths            → <HOME>
 */
import { stdin, stdout, env } from 'node:process'

const HOME = env.HOME || ''

let buf = ''
stdin.setEncoding('utf8')
stdin.on('data', (c) => { buf += c })
stdin.on('end', () => {
  let out = buf

  // ISO 8601 timestamps (with or without milliseconds, with Z)
  out = out.replace(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z/g, '<TIMESTAMP>')

  // JSON-style durationMs
  out = out.replace(/"durationMs":\s*\d+/g, '"durationMs": <DURATION>')

  // JSON-style timestamp value (already covered by ISO regex, but be safe)
  out = out.replace(/"timestamp":\s*"[^"]+"/g, '"timestamp": "<TIMESTAMP>"')

  // Threat-intel "Xm ago", "Xh ago", "just now"
  out = out.replace(/last report: (just now|\d+[smhd] ago)/g, 'last report: <AGO>')

  // macOS mktemp paths
  out = out.replace(/\/var\/folders\/[^\s"'`]+/g, '<TMPDIR>')
  out = out.replace(/\/tmp\/[A-Za-z0-9._-]+/g, '<TMPDIR>')

  // Absolute HOME paths (must come last; trailing-slash safe)
  if (HOME) {
    const escapedHome = HOME.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    out = out.replace(new RegExp(escapedHome, 'g'), '<HOME>')
  }

  stdout.write(out)
})
