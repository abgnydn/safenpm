"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getBackend = getBackend;
exports.isSandboxAvailable = isSandboxAvailable;
exports.backendName = backendName;
exports.runInSandbox = runInSandbox;
const child_process_1 = require("child_process");
const path_1 = __importDefault(require("path"));
const os_1 = __importDefault(require("os"));
const fs_1 = __importDefault(require("fs"));
// ── macOS sandbox-exec profile ──
// Deny all network. Restrict filesystem: allow writes only to the
// package dir and /tmp, deny reads to sensitive directories.
function buildSandboxProfile(pkgPath) {
    // sandbox-exec uses TinyScheme — paths need to be literal strings
    const escaped = pkgPath.replace(/"/g, '\\"');
    const home = os_1.default.homedir().replace(/"/g, '\\"');
    return `
(version 1)
(deny default)

;; ── process: allow execution of shell and common tools ──
(allow process-exec
  (literal "/bin/sh")
  (literal "/bin/bash")
  (literal "/usr/bin/env")
  (literal "/usr/bin/node")
  (literal "/usr/local/bin/node")
  (subpath "${escaped}")
)
(allow process-fork)
(allow process-exec-interpreter)

;; ── signals & sysctl: allow basic process management ──
(allow signal (target self))
(allow sysctl-read)

;; ── mach / ipc: allow minimal system services ──
(allow mach-lookup)
(allow ipc-posix-shm-read*)
(allow ipc-posix-shm-write-data)

;; ── filesystem: read access ──
;; allow reads to system libraries, the package dir, and /tmp
(allow file-read*
  (subpath "/usr")
  (subpath "/bin")
  (subpath "/sbin")
  (subpath "/Library")
  (subpath "/System")
  (subpath "/private/var")
  (subpath "/dev")
  (subpath "/tmp")
  (subpath "/private/tmp")
  (subpath "${escaped}")
  ;; allow reading node_modules for require() resolution
  (subpath "${escaped}/../")
)

;; ── filesystem: explicitly deny sensitive locations ──
;; (must come after general read allows to take precedence)
(deny file-read-data
  (subpath "${home}/.ssh")
  (subpath "${home}/.aws")
  (subpath "${home}/.gnupg")
  (subpath "${home}/.config")
  (subpath "${home}/.npmrc")
  (subpath "${home}/.netrc")
  (subpath "${home}/.docker")
  (subpath "${home}/.kube")
  (literal "${home}/.bash_history")
  (literal "${home}/.zsh_history")
  (literal "${home}/.env")
)

;; ── filesystem: write access ──
;; only allow writes to: package dir, /tmp, /dev/null
(allow file-write*
  (subpath "${escaped}")
  (subpath "/tmp")
  (subpath "/private/tmp")
  (literal "/dev/null")
  (literal "/dev/zero")
  (literal "/dev/random")
  (literal "/dev/urandom")
)

;; ── network: deny everything ──
(deny network-outbound)
(deny network-inbound)
(deny network-bind)
(deny network*)
`;
}
// ── Network-only profile (less restrictive, for --loose mode) ──
// Uses allow default since --loose explicitly opts out of filesystem restrictions
const NETWORK_ONLY_PROFILE = `
(version 1)
(allow default)
(deny network-outbound)
(deny network-inbound)
(deny network-bind)
(deny network*)
`;
// Note: --loose mode intentionally uses (allow default) since it only restricts
// network. Users should be warned that credentials on disk can still be read.
// ── Patterns that indicate a network attempt was blocked ──
const NETWORK_VIOLATION_PATTERNS = [
    /sandbox.*deny.*network/i,
    /Operation not permitted/i,
    /ECONNREFUSED/i,
    /ENETUNREACH/i,
    /getaddrinfo.*EAI_AGAIN/i,
    /connect EACCES/i,
    /An attempt was made to access a socket/i, // Windows
    /firewall.*block/i, // Windows
    /network is unreachable/i, // WSL
];
// ── Patterns that indicate a filesystem violation ──
const FS_VIOLATION_PATTERNS = [
    /sandbox.*deny.*file/i,
    /EACCES.*\.ssh/i,
    /EACCES.*\.aws/i,
    /Permission denied/i,
    /Access is denied/i, // Windows
];
// ── Sensitive env vars to strip from child processes ──
const STRIPPED_ENV_KEYS = [
    'npm_config_authtoken',
    'NPM_TOKEN',
    'GITHUB_TOKEN',
    'GH_TOKEN',
    'GITLAB_TOKEN',
    'AWS_SECRET_ACCESS_KEY',
    'AWS_ACCESS_KEY_ID',
    'AWS_SESSION_TOKEN',
    'AZURE_CLIENT_SECRET',
    'GOOGLE_APPLICATION_CREDENTIALS',
];
function cleanEnv() {
    const env = { ...process.env };
    for (const key of STRIPPED_ENV_KEYS) {
        env[key] = undefined;
    }
    return env;
}
function detectBackend() {
    const platform = os_1.default.platform();
    if (platform === 'darwin') {
        const r = (0, child_process_1.spawnSync)('which', ['sandbox-exec'], { encoding: 'utf8' });
        if (r.status === 0)
            return 'sandbox-exec';
    }
    if (platform === 'linux') {
        const r = (0, child_process_1.spawnSync)('which', ['firejail'], { encoding: 'utf8' });
        if (r.status === 0)
            return 'firejail';
    }
    if (platform === 'win32') {
        // Check 1: PowerShell with admin (can create firewall rules)
        if (isWindowsAdmin())
            return 'windows-firewall';
        // Check 2: WSL with firejail available
        if (isWslFirejailAvailable())
            return 'wsl-firejail';
    }
    return 'none';
}
/**
 * Check if running as administrator on Windows.
 * Uses `net session` which only succeeds when elevated.
 */
function isWindowsAdmin() {
    try {
        const r = (0, child_process_1.spawnSync)('net', ['session'], {
            encoding: 'utf8',
            stdio: 'pipe',
            timeout: 5000,
        });
        return r.status === 0;
    }
    catch {
        return false;
    }
}
/**
 * Check if WSL is available and firejail is installed inside it.
 */
function isWslFirejailAvailable() {
    try {
        const r = (0, child_process_1.spawnSync)('wsl', ['which', 'firejail'], {
            encoding: 'utf8',
            stdio: 'pipe',
            timeout: 10000,
        });
        return r.status === 0;
    }
    catch {
        return false;
    }
}
let _cachedBackend = null;
function getBackend() {
    if (_cachedBackend === null) {
        _cachedBackend = detectBackend();
    }
    return _cachedBackend;
}
function isSandboxAvailable() {
    return getBackend() !== 'none';
}
function backendName() {
    const b = getBackend();
    if (b === 'sandbox-exec')
        return 'sandbox-exec (macOS)';
    if (b === 'firejail')
        return 'firejail (Linux)';
    if (b === 'windows-firewall')
        return 'Windows Firewall + ACLs (admin)';
    if (b === 'wsl-firejail')
        return 'firejail via WSL (Windows)';
    return 'none';
}
// ── Run a script in the appropriate sandbox ──
function runInSandbox(pkg, strict = true) {
    const backend = getBackend();
    switch (backend) {
        case 'sandbox-exec':
            return runWithSandboxExec(pkg, strict);
        case 'firejail':
            return runWithFirejail(pkg, strict);
        case 'windows-firewall':
            return runWithWindowsFirewall(pkg, strict);
        case 'wsl-firejail':
            return runWithWslFirejail(pkg, strict);
        default:
            return runUnsandboxed(pkg);
    }
}
function runWithSandboxExec(pkg, strict) {
    const start = Date.now();
    const profile = strict
        ? buildSandboxProfile(pkg.path)
        : NETWORK_ONLY_PROFILE;
    const result = (0, child_process_1.spawnSync)('sandbox-exec', ['-p', profile, 'sh', '-c', pkg.script], {
        cwd: pkg.path,
        env: cleanEnv(),
        timeout: 30000,
        encoding: 'utf8',
    });
    return classify(pkg, result, Date.now() - start);
}
function runWithFirejail(pkg, strict) {
    const start = Date.now();
    const home = os_1.default.homedir();
    // firejail args: --net=none disables networking
    const fjArgs = [
        '--net=none',
        '--quiet',
        '--noprofile',
    ];
    if (strict) {
        // filesystem restrictions
        fjArgs.push(`--blacklist=${home}/.ssh`, `--blacklist=${home}/.aws`, `--blacklist=${home}/.gnupg`, `--blacklist=${home}/.npmrc`, `--blacklist=${home}/.netrc`, `--blacklist=${home}/.docker`, `--blacklist=${home}/.kube`, `--blacklist=${home}/.bash_history`, `--blacklist=${home}/.zsh_history`, `--blacklist=${home}/.env`, `--read-only=${home}`);
    }
    fjArgs.push('--', 'sh', '-c', pkg.script);
    const result = (0, child_process_1.spawnSync)('firejail', fjArgs, {
        cwd: pkg.path,
        env: cleanEnv(),
        timeout: 30000,
        encoding: 'utf8',
    });
    return classify(pkg, result, Date.now() - start);
}
// ── Windows: Firewall + ACLs backend ──
/**
 * Windows sandbox using:
 * 1. New-NetFirewallRule to block outbound network for node.exe
 * 2. icacls to deny access to sensitive directories
 *
 * Requires elevated (admin) privileges.
 */
function runWithWindowsFirewall(pkg, strict) {
    const start = Date.now();
    const home = os_1.default.homedir();
    const ruleName = `safenpm-block-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const sensitiveDirs = [
        path_1.default.join(home, '.ssh'),
        path_1.default.join(home, '.aws'),
        path_1.default.join(home, '.gnupg'),
        path_1.default.join(home, '.docker'),
        path_1.default.join(home, '.kube'),
    ];
    const sensibleFiles = [
        path_1.default.join(home, '.npmrc'),
        path_1.default.join(home, '.netrc'),
        path_1.default.join(home, '.bash_history'),
        path_1.default.join(home, '.env'),
    ];
    const allSensitivePaths = [...sensitiveDirs, ...sensibleFiles];
    // Step 1: Create firewall rule to block outbound for node.exe
    const nodeExe = process.execPath;
    const createRuleScript = `
    New-NetFirewallRule -DisplayName '${ruleName}' -Direction Outbound -Action Block -Program '${nodeExe.replace(/'/g, "''")}' -Enabled True -ErrorAction Stop | Out-Null
  `;
    const ruleResult = (0, child_process_1.spawnSync)('powershell', ['-NoProfile', '-Command', createRuleScript], {
        encoding: 'utf8',
        stdio: 'pipe',
        timeout: 10000,
    });
    if (ruleResult.status !== 0) {
        // Fallback: run without firewall but still with ACLs
        return runWindowsWithAclsOnly(pkg, strict, allSensitivePaths, start);
    }
    // Step 2: Deny ACLs on sensitive paths (if strict mode)
    const aclsApplied = [];
    const username = os_1.default.userInfo().username;
    // Use try/finally to guarantee cleanup even if safenpm crashes
    let result;
    try {
        if (strict) {
            for (const p of allSensitivePaths) {
                if (fs_1.default.existsSync(p)) {
                    const r = (0, child_process_1.spawnSync)('icacls', [p, '/deny', `${username}:(R,W)`, '/T', '/C'], {
                        encoding: 'utf8',
                        stdio: 'pipe',
                        timeout: 5000,
                    });
                    if (r.status === 0)
                        aclsApplied.push(p);
                }
            }
        }
        // Step 3: Run the script
        result = (0, child_process_1.spawnSync)('cmd.exe', ['/c', pkg.script], {
            cwd: pkg.path,
            env: cleanEnv(),
            timeout: 30000,
            encoding: 'utf8',
        });
    }
    finally {
        // Step 4: Cleanup — ALWAYS remove firewall rule
        (0, child_process_1.spawnSync)('powershell', [
            '-NoProfile', '-Command',
            `Remove-NetFirewallRule -DisplayName '${ruleName}' -ErrorAction SilentlyContinue`,
        ], { stdio: 'pipe', timeout: 10000 });
        // Step 5: Cleanup — ALWAYS restore ACLs
        if (aclsApplied.length > 0) {
            for (const p of aclsApplied) {
                (0, child_process_1.spawnSync)('icacls', [p, '/remove:d', username, '/T', '/C'], {
                    stdio: 'pipe',
                    timeout: 5000,
                });
            }
        }
    }
    return classify(pkg, result, Date.now() - start);
}
/**
 * Fallback: ACLs only (if firewall rule creation fails).
 */
function runWindowsWithAclsOnly(pkg, strict, sensitivePaths, start) {
    const aclsApplied = [];
    const username = os_1.default.userInfo().username;
    // Use try/finally to guarantee ACL cleanup even on crash
    let result;
    try {
        if (strict) {
            for (const p of sensitivePaths) {
                if (fs_1.default.existsSync(p)) {
                    const r = (0, child_process_1.spawnSync)('icacls', [p, '/deny', `${username}:(R,W)`, '/T', '/C'], {
                        encoding: 'utf8',
                        stdio: 'pipe',
                        timeout: 5000,
                    });
                    if (r.status === 0)
                        aclsApplied.push(p);
                }
            }
        }
        result = (0, child_process_1.spawnSync)('cmd.exe', ['/c', pkg.script], {
            cwd: pkg.path,
            env: cleanEnv(),
            timeout: 30000,
            encoding: 'utf8',
        });
    }
    finally {
        // ALWAYS restore ACLs
        for (const p of aclsApplied) {
            (0, child_process_1.spawnSync)('icacls', [p, '/remove:d', username, '/T', '/C'], {
                stdio: 'pipe',
                timeout: 5000,
            });
        }
    }
    return classify(pkg, result, Date.now() - start);
}
// ── Windows: WSL + firejail backend ──
/**
 * Run scripts through WSL's firejail for Windows users without admin.
 * Converts Windows paths to WSL paths automatically.
 */
function runWithWslFirejail(pkg, strict) {
    const start = Date.now();
    // Convert Windows path to WSL path
    const wslPath = windowsToWslPath(pkg.path);
    const wslHome = windowsToWslPath(os_1.default.homedir());
    const fjArgs = [
        'firejail',
        '--net=none',
        '--quiet',
        '--noprofile',
    ];
    if (strict) {
        fjArgs.push(`--blacklist=${wslHome}/.ssh`, `--blacklist=${wslHome}/.aws`, `--blacklist=${wslHome}/.gnupg`, `--blacklist=${wslHome}/.npmrc`, `--blacklist=${wslHome}/.netrc`, `--blacklist=${wslHome}/.docker`, `--blacklist=${wslHome}/.kube`, `--read-only=${wslHome}`);
    }
    fjArgs.push('--', 'sh', '-c', pkg.script);
    const result = (0, child_process_1.spawnSync)('wsl', fjArgs, {
        cwd: pkg.path,
        env: cleanEnv(),
        timeout: 30000,
        encoding: 'utf8',
    });
    return classify(pkg, result, Date.now() - start);
}
/**
 * Convert a Windows path like C:\Users\foo\bar to /mnt/c/Users/foo/bar
 */
function windowsToWslPath(winPath) {
    // Use wsl command for accurate conversion
    try {
        const r = (0, child_process_1.spawnSync)('wsl', ['wslpath', '-u', winPath], {
            encoding: 'utf8',
            stdio: 'pipe',
            timeout: 5000,
        });
        if (r.status === 0 && r.stdout.trim()) {
            return r.stdout.trim();
        }
    }
    catch { /* fall through */ }
    // Manual fallback: C:\Users\foo → /mnt/c/Users/foo
    const normalized = winPath.replace(/\\/g, '/');
    const match = normalized.match(/^([A-Z]):\/(.*)$/i);
    if (match) {
        return `/mnt/${match[1].toLowerCase()}/${match[2]}`;
    }
    return normalized;
}
function runUnsandboxed(pkg) {
    const start = Date.now();
    // Use cmd.exe on Windows, sh elsewhere
    const shell = os_1.default.platform() === 'win32' ? 'cmd.exe' : 'sh';
    const shellArgs = os_1.default.platform() === 'win32' ? ['/c', pkg.script] : ['-c', pkg.script];
    const result = (0, child_process_1.spawnSync)(shell, shellArgs, {
        cwd: pkg.path,
        env: cleanEnv(),
        timeout: 30000,
        encoding: 'utf8',
    });
    const durationMs = Date.now() - start;
    const output = [result.stdout, result.stderr].filter(Boolean).join('\n');
    return {
        pkg,
        blocked: false,
        skipped: false,
        reason: 'clean',
        output,
        durationMs,
    };
}
// ── Classify result from any backend ──
// Exit codes that strongly indicate sandbox violations:
// - 65 (EX_DATAERR) is used by sandbox-exec on macOS for policy violations
// - Signal-based kills (SIGKILL=137, SIGTERM=143) from firejail denials
const SANDBOX_VIOLATION_EXIT_CODES = new Set([65, 126, 137, 143]);
function classify(pkg, result, durationMs) {
    const output = [result.stdout, result.stderr].filter(Boolean).join('\n');
    const failed = result.status !== 0;
    const timedOut = result.signal === 'SIGTERM' && durationMs >= 29000;
    if (!failed) {
        return { pkg, blocked: false, skipped: false, reason: 'clean', output, durationMs };
    }
    // Layer 1: Pattern matching on output (locale-dependent but catches most cases)
    const looksLikeNetwork = NETWORK_VIOLATION_PATTERNS.some(p => p.test(output));
    const looksLikeFs = FS_VIOLATION_PATTERNS.some(p => p.test(output));
    // Layer 2: Exit code analysis (more reliable, locale-independent)
    const exitCode = result.status ?? 0;
    const suspiciousExitCode = SANDBOX_VIOLATION_EXIT_CODES.has(exitCode);
    // Layer 3: If the process was killed by signal, it's likely a sandbox enforcement
    const killedBySignal = result.signal === 'SIGKILL' || result.signal === 'SIGTERM';
    let reason = 'error';
    if (looksLikeNetwork) {
        reason = 'network';
    }
    else if (looksLikeFs) {
        reason = 'filesystem';
    }
    else if (suspiciousExitCode || killedBySignal) {
        // Sandbox likely killed the process but output was empty/unhelpful.
        // Mark as blocked — better to have a false positive than miss an attack.
        reason = 'network';
    }
    else if (timedOut) {
        // Timeout could mean the script was hanging on a blocked socket.
        reason = 'network';
    }
    // If we're blocking due to exit code/signal alone (no pattern match), note it
    const blocked = reason !== 'error' || suspiciousExitCode || killedBySignal;
    const detectionNote = (!looksLikeNetwork && !looksLikeFs && blocked)
        ? `\n[safenpm] Blocked based on exit code ${exitCode}${result.signal ? ` (signal: ${result.signal})` : ''} — pattern matching inconclusive`
        : '';
    return {
        pkg,
        blocked,
        skipped: false,
        reason,
        output: output + detectionNote,
        durationMs,
    };
}
