import fs from 'fs'
import path from 'path'
import os from 'os'
import https from 'https'
function uuidv4(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0
    const v = c === 'x' ? r : (r & 0x3) | 0x8
    return v.toString(16)
  })
}
import crypto from 'crypto'
import { SandboxResult, Signal } from './types'

const CONFIG_DIR = path.join(os.homedir(), '.safenpm')
const CONFIG_FILE = path.join(CONFIG_DIR, 'config.json')
const REPORT_HOST = 'safenpm.vercel.app'
const REPORT_PATH = '/api/v1/signal'

// get or create a stable anonymous machine ID
// this is purely so we can deduplicate signals from the same machine
// it contains no identifying information
function getMachineId(): string {
  try {
    if (!fs.existsSync(CONFIG_DIR)) {
      fs.mkdirSync(CONFIG_DIR, { recursive: true })
    }

    if (fs.existsSync(CONFIG_FILE)) {
      const config = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'))
      if (config.machineId) return config.machineId
    }

    const machineId = uuidv4()
    fs.writeFileSync(CONFIG_FILE, JSON.stringify({ machineId }, null, 2))
    return machineId
  } catch {
    return 'anonymous'
  }
}

function buildSignal(result: SandboxResult): Signal {
  return {
    machineId: getMachineId(),
    package: result.pkg.name,
    version: result.pkg.version,
    hook: result.pkg.hook,
    // Include both a content hash of the full script (for dedup/matching)
    // and a truncated preview. The hash ensures the threat intel network
    // can correlate identical payloads even if they exceed the preview length.
    script: result.pkg.script.slice(0, 500),
    scriptHash: crypto.createHash('sha256').update(result.pkg.script).digest('hex'),
    scriptLength: result.pkg.script.length,
    reason: result.reason,
    timestamp: new Date().toISOString(),
    platform: `${os.platform()}/${os.arch()}`,
  }
}

function post(signal: Signal): Promise<void> {
  return new Promise((resolve) => {
    const body = JSON.stringify(signal)

    const req = https.request(
      {
        hostname: REPORT_HOST,
        path: REPORT_PATH,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
          'User-Agent': 'safenpm/0.1.0',
        },
        timeout: 5000,
      },
      (res) => {
        res.resume() // drain response
        resolve()
      }
    )

    req.on('error', () => resolve()) // never throw — reporting is best-effort
    req.on('timeout', () => { req.destroy(); resolve() })
    req.write(body)
    req.end()
  })
}

export async function reportBlocked(results: SandboxResult[]): Promise<void> {
  const blocked = results.filter(r => r.blocked)
  if (blocked.length === 0) return

  // fire and forget — don't await, don't block install
  const sends = blocked.map(r => post(buildSignal(r)))
  await Promise.allSettled(sends)
}
