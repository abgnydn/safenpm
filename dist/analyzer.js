"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.analyzeScript = analyzeScript;
exports.analyzeAll = analyzeAll;
exports.riskLevel = riskLevel;
// ── Static analysis rules ──
// Each rule matches against the raw script string
const RULES = [
    // ── High severity: likely malicious ──
    {
        id: 'net-curl',
        severity: 'high',
        description: 'Uses curl/wget to fetch remote content',
        pattern: /\b(curl|wget)\s+/i,
    },
    {
        id: 'net-nc',
        severity: 'high',
        description: 'Uses netcat (nc) — common exfiltration tool',
        pattern: /\bnc\s+-/i,
    },
    {
        id: 'net-node-http',
        severity: 'high',
        description: 'Node.js HTTP/HTTPS request in install script',
        pattern: /require\s*\(\s*['"]https?['"]\s*\)/,
    },
    {
        id: 'net-node-fetch',
        severity: 'high',
        description: 'Uses fetch() or node-fetch in install script',
        pattern: /\bfetch\s*\(/,
    },
    {
        id: 'net-dns',
        severity: 'high',
        description: 'DNS resolution — possible DNS exfiltration',
        pattern: /require\s*\(\s*['"]dns['"]\s*\)/,
    },
    {
        id: 'exfil-env',
        severity: 'high',
        description: 'Reads environment variables (potential credential theft)',
        pattern: /process\.env\b/,
    },
    {
        id: 'exfil-ssh',
        severity: 'high',
        description: 'Accesses SSH keys or config',
        pattern: /[~$].*\.ssh\b|\/\.ssh\//i,
    },
    {
        id: 'exfil-credentials',
        severity: 'high',
        description: 'Accesses credential files or directories',
        pattern: /\.(aws|npmrc|netrc|docker|kube)\b|\/\.aws\//i,
    },
    {
        id: 'exec-eval',
        severity: 'high',
        description: 'Uses eval() — dynamic code execution',
        pattern: /\beval\s*\(/,
    },
    {
        id: 'exec-base64',
        severity: 'high',
        description: 'Base64 encoding/decoding — possible obfuscated payload',
        pattern: /\bbase64\b|atob\s*\(|btoa\s*\(|Buffer\.from\s*\([^)]*,\s*['"]base64['"]/i,
    },
    {
        id: 'exec-pipe-sh',
        severity: 'high',
        description: 'Pipes remote content to shell (curl | sh pattern)',
        pattern: /\|\s*(sh|bash|zsh|node|python)\b/,
    },
    // ── Medium severity: suspicious but sometimes legit ──
    {
        id: 'fs-read-etc',
        severity: 'medium',
        description: 'Reads system files (/etc/passwd, /etc/hosts)',
        pattern: /\/etc\/(passwd|shadow|hosts|resolv)/i,
    },
    {
        id: 'fs-home-read',
        severity: 'medium',
        description: 'Reads from home directory',
        pattern: /\$HOME\b|~\//,
    },
    {
        id: 'exec-child-process',
        severity: 'medium',
        description: 'Spawns child processes from Node',
        pattern: /require\s*\(\s*['"]child_process['"]\s*\)|exec\s*\(|execSync\s*\(/,
    },
    {
        id: 'obfuscation-hex',
        severity: 'medium',
        description: 'Hex-encoded strings — possible obfuscation',
        pattern: /\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){3,}/i,
    },
    {
        id: 'obfuscation-unicode',
        severity: 'medium',
        description: 'Unicode escape sequences — possible obfuscation',
        pattern: /\\u[0-9a-f]{4}(\\u[0-9a-f]{4}){3,}/i,
    },
    {
        id: 'net-socket',
        severity: 'medium',
        description: 'Raw socket access',
        pattern: /require\s*\(\s*['"](net|dgram)['"]\s*\)/,
    },
    // ── Low severity: worth noting ──
    {
        id: 'script-node-gyp',
        severity: 'low',
        description: 'Native compilation (node-gyp) — expected for native addons',
        pattern: /node-gyp\s+rebuild/,
    },
    {
        id: 'script-prebuild',
        severity: 'low',
        description: 'Uses prebuild-install — downloads prebuilt binaries',
        pattern: /prebuild-install\b/,
    },
    {
        id: 'script-node-pre-gyp',
        severity: 'low',
        description: 'Uses node-pre-gyp — downloads prebuilt binaries',
        pattern: /node-pre-gyp\s+install/,
    },
];
const SEVERITY_WEIGHT = { high: 30, medium: 15, low: 5 };
function analyzeScript(pkg) {
    const warnings = [];
    const script = pkg.script;
    for (const rule of RULES) {
        const m = rule.pattern.exec(script);
        if (m) {
            warnings.push({
                rule: rule.id,
                severity: rule.severity,
                description: rule.description,
                match: m[0].slice(0, 60),
            });
        }
    }
    // risk score: sum of weights, capped at 100
    const raw = warnings.reduce((sum, w) => sum + SEVERITY_WEIGHT[w.severity], 0);
    const riskScore = Math.min(100, raw);
    return { pkg, warnings, riskScore };
}
function analyzeAll(scripts) {
    return scripts.map(analyzeScript);
}
function riskLevel(score) {
    if (score >= 60)
        return 'critical';
    if (score >= 30)
        return 'suspicious';
    if (score > 0)
        return 'low';
    return 'clean';
}
