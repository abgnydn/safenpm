/**
 * Static scan for `.node` native addons. A package can ship
 * pre-compiled shared libraries that Node loads via `dlopen` at
 * `require()` time — the install sandbox can't introspect what
 * happens inside that binary, and once loaded the code runs with
 * full Node permissions.
 *
 * Approach: parse-free symbol scan. Both Mach-O (macOS) and ELF
 * (Linux/Windows-DLL) store imported symbol names as
 * null-terminated strings in a string table. A naive byte search
 * for `<symname>\0` catches references regardless of file format.
 *
 * False positives: a symbol name embedded in a string literal
 * inside the binary (not actually imported) would match. False-
 * positive cost is low — we surface a warning, not a block — and a
 * package shipping `execvp` as a literal string is itself
 * noteworthy.
 *
 * False negatives: stripped binaries, symbols renamed via
 * obfuscation, or syscalls invoked directly via `syscall(2)` won't
 * appear. Worth knowing; not a reason to skip the cheap check.
 */
import crypto from 'crypto'
import fs from 'fs'
import path from 'path'

export type NativeRisk = 'critical' | 'high' | 'medium'

export interface NativeSymbolMatch {
  name: string
  risk: NativeRisk
  category: 'exec' | 'network' | 'load'
}

export interface NativeAddon {
  /** Path relative to node_modules. */
  relPath: string
  /** Owning package name. */
  pkg: string
  /** File size in bytes. */
  size: number
  /** sha256 of the file contents (for registry comparison later). */
  sha256: string
  /** Suspicious imported symbol names found in the binary. */
  symbols: NativeSymbolMatch[]
}

export interface NativeAuditResult {
  scanned: number
  /** Addons containing at least one critical or high-risk symbol. */
  suspicious: NativeAddon[]
}

/**
 * Symbols we treat as suspicious when they appear in a native
 * addon's string table. Categorised by what the binary could do
 * with them — `exec` = spawn a new process, `network` = open a
 * socket / connect somewhere, `load` = pull in further code via
 * dlopen/dlsym.
 */
const DANGEROUS_SYMBOLS: ReadonlyArray<NativeSymbolMatch> = [
  // exec — direct process spawning. Critical because a single call
  // turns the native module into a beachhead for arbitrary binaries.
  { name: 'execvp',       risk: 'critical', category: 'exec' },
  { name: 'execve',       risk: 'critical', category: 'exec' },
  { name: 'execl',        risk: 'critical', category: 'exec' },
  { name: 'system',       risk: 'critical', category: 'exec' },
  { name: 'popen',        risk: 'critical', category: 'exec' },
  { name: 'fork',         risk: 'high',     category: 'exec' },
  { name: 'vfork',        risk: 'high',     category: 'exec' },
  { name: 'posix_spawn',  risk: 'high',     category: 'exec' },
  { name: 'CreateProcessA', risk: 'critical', category: 'exec' }, // win32
  { name: 'CreateProcessW', risk: 'critical', category: 'exec' },

  // network — raw socket APIs. Critical for the same reason: native
  // code can open a socket the JS sandbox doesn't see.
  { name: 'socket',  risk: 'critical', category: 'network' },
  { name: 'connect', risk: 'critical', category: 'network' },
  { name: 'sendto',  risk: 'high',     category: 'network' },
  { name: 'recvfrom',risk: 'medium',   category: 'network' },
  { name: 'bind',    risk: 'high',     category: 'network' },
  { name: 'getaddrinfo', risk: 'medium', category: 'network' },
  { name: 'gethostbyname',risk: 'medium',category: 'network' },

  // dynamic loading — load further code at runtime. Critical because
  // it's the simplest way to bypass static analysis: load a second
  // .node file that has the real payload.
  { name: 'dlopen', risk: 'critical', category: 'load' },
  { name: 'dlsym',  risk: 'critical', category: 'load' },
  { name: 'LoadLibraryA', risk: 'critical', category: 'load' }, // win32
  { name: 'LoadLibraryW', risk: 'critical', category: 'load' },
  { name: 'GetProcAddress', risk: 'high', category: 'load' },
]

const MAX_FILE_BYTES = 50 * 1024 * 1024 // 50 MB — beyond this it's almost certainly not a normal addon

/**
 * Audit every `.node` file under `nodeModulesPath`.
 */
export function auditNativeAddons(nodeModulesPath: string): NativeAuditResult {
  const addons: NativeAddon[] = []
  if (!fs.existsSync(nodeModulesPath)) return { scanned: 0, suspicious: [] }

  walkForNodeFiles(nodeModulesPath, nodeModulesPath, addons)

  const suspicious = addons.filter((a) =>
    a.symbols.some((s) => s.risk === 'critical' || s.risk === 'high'),
  )
  return { scanned: addons.length, suspicious }
}

function walkForNodeFiles(root: string, current: string, out: NativeAddon[]): void {
  let entries: fs.Dirent[]
  try {
    entries = fs.readdirSync(current, { withFileTypes: true })
  } catch {
    return
  }
  for (const e of entries) {
    const full = path.join(current, e.name)
    if (e.isSymbolicLink()) continue // symlinks audited separately by symlinks.ts
    if (e.isDirectory()) {
      walkForNodeFiles(root, full, out)
      continue
    }
    if (!e.isFile() || !e.name.endsWith('.node')) continue
    const addon = scanAddon(full, root)
    if (addon) out.push(addon)
  }
}

function scanAddon(filePath: string, nmRoot: string): NativeAddon | null {
  let stat: fs.Stats
  try {
    stat = fs.statSync(filePath)
  } catch {
    return null
  }
  if (stat.size > MAX_FILE_BYTES) return null

  let buf: Buffer
  try {
    buf = fs.readFileSync(filePath)
  } catch {
    return null
  }

  const sha256 = crypto.createHash('sha256').update(buf).digest('hex')
  const symbols = scanSymbols(buf)
  const relPath = path.relative(nmRoot, filePath)
  const pkg = packageOfRelPath(relPath)
  return { relPath, pkg, size: stat.size, sha256, symbols }
}

/**
 * Scan a binary buffer for the dangerous-symbol set. Match form is
 * `<name>\0` so we hit string-table entries; appending a NUL makes
 * a substring inside another identifier (e.g. `socketpair_internal`
 * matching `socket`) impossible.
 */
export function scanSymbols(buf: Buffer): NativeSymbolMatch[] {
  const hits: NativeSymbolMatch[] = []
  for (const s of DANGEROUS_SYMBOLS) {
    const needle = Buffer.from(`${s.name}\0`, 'utf8')
    if (buf.includes(needle)) hits.push(s)
  }
  return hits
}

function packageOfRelPath(relPath: string): string {
  // node_modules/foo/build/Release/foo.node → foo
  // node_modules/@scope/foo/x.node → @scope/foo
  const parts = relPath.split(/[\\/]/)
  if (parts.length === 0) return '<root>'
  if (parts[0]!.startsWith('@') && parts.length >= 2) return `${parts[0]}/${parts[1]}`
  return parts[0]!
}
