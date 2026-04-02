"use strict";
/**
 * Community threat intelligence — query the safenpm network
 * to check if any packages have been flagged by other users.
 * Also report back when we block packages to help others.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.checkThreatIntel = checkThreatIntel;
exports.mockThreatIntel = mockThreatIntel;
const https_1 = __importDefault(require("https"));
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const os_1 = __importDefault(require("os"));
const INTEL_HOST = 'safenpm.dev';
const INTEL_PATH = '/api/v1/intel';
const CACHE_DIR = path_1.default.join(os_1.default.homedir(), '.safenpm', 'intel-cache');
const CACHE_TTL = 3600000; // 1 hour
/**
 * Check packages against the community threat intel database.
 * Uses a local cache to avoid hammering the API on every install.
 * Falls back gracefully if the network is unavailable.
 */
async function checkThreatIntel(packages) {
    if (packages.length === 0)
        return [];
    // Check local cache first
    const results = [];
    const uncached = [];
    for (const pkg of packages) {
        const cached = readCache(pkg.name, pkg.version);
        if (cached) {
            results.push(cached);
        }
        else {
            uncached.push(pkg);
        }
    }
    // Fetch uncached from the network
    if (uncached.length > 0) {
        const fetched = await fetchIntel(uncached);
        for (const r of fetched) {
            writeCache(r);
            results.push(r);
        }
    }
    return results;
}
/**
 * Fetch threat intel from the safenpm API.
 * POST /api/v1/intel with a list of package names.
 */
async function fetchIntel(packages) {
    return new Promise((resolve) => {
        const body = JSON.stringify({
            packages: packages.map(p => ({ name: p.name, version: p.version })),
        });
        const req = https_1.default.request({
            hostname: INTEL_HOST,
            path: INTEL_PATH,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(body),
                'User-Agent': 'safenpm/0.4.0',
            },
            timeout: 5000,
        }, (res) => {
            let data = '';
            res.on('data', (chunk) => { data += chunk.toString(); });
            res.on('end', () => {
                try {
                    const parsed = JSON.parse(data);
                    if (Array.isArray(parsed.results)) {
                        resolve(parsed.results);
                        return;
                    }
                }
                catch {
                    logIntelWarning('threat intel API returned unparseable response');
                }
                // Fallback: return empty results for all packages
                resolve(packages.map(p => unflagged(p.name, p.version, false)));
            });
        });
        req.on('error', (err) => {
            // Network unavailable — return unflagged for all, but mark as stale
            logIntelWarning(`threat intel API unreachable: ${err.message}`);
            resolve(packages.map(p => unflagged(p.name, p.version, false)));
        });
        req.on('timeout', () => {
            req.destroy();
            logIntelWarning('threat intel API timed out');
            resolve(packages.map(p => unflagged(p.name, p.version, false)));
        });
        req.write(body);
        req.end();
    });
}
function unflagged(name, version, dataFresh = true) {
    return {
        name,
        version,
        flagged: false,
        reportCount: 0,
        firstSeen: null,
        lastSeen: null,
        topReasons: [],
        dataFresh,
    };
}
/**
 * Log a warning about threat intel degradation.
 * Writes to stderr so it doesn't pollute JSON output, and
 * appends to the audit log so users can see when checks failed.
 */
function logIntelWarning(message) {
    const logDir = path_1.default.join(os_1.default.homedir(), '.safenpm');
    const logFile = path_1.default.join(logDir, 'intel-warnings.log');
    const entry = `${new Date().toISOString()} ${message}\n`;
    try {
        if (!fs_1.default.existsSync(logDir))
            fs_1.default.mkdirSync(logDir, { recursive: true });
        fs_1.default.appendFileSync(logFile, entry, 'utf8');
    }
    catch { /* best effort */ }
    process.stderr.write(`  [safenpm] warning: ${message}\n`);
}
// ── Local cache ──
function cacheKey(name, version) {
    return `${name}@${version}`.replace(/[^a-zA-Z0-9@._-]/g, '_');
}
function readCache(name, version) {
    try {
        const file = path_1.default.join(CACHE_DIR, cacheKey(name, version) + '.json');
        if (!fs_1.default.existsSync(file))
            return null;
        const stat = fs_1.default.statSync(file);
        if (Date.now() - stat.mtimeMs > CACHE_TTL)
            return null;
        return JSON.parse(fs_1.default.readFileSync(file, 'utf8'));
    }
    catch {
        return null;
    }
}
function writeCache(result) {
    try {
        if (!fs_1.default.existsSync(CACHE_DIR)) {
            fs_1.default.mkdirSync(CACHE_DIR, { recursive: true });
        }
        const file = path_1.default.join(CACHE_DIR, cacheKey(result.name, result.version) + '.json');
        fs_1.default.writeFileSync(file, JSON.stringify(result), 'utf8');
    }
    catch {
        // cache write is best-effort
    }
}
/**
 * Simulate threat intel for testing/offline mode.
 * In production this would be replaced by the real API.
 */
function mockThreatIntel(packages) {
    return packages.map(p => unflagged(p.name, p.version));
}
