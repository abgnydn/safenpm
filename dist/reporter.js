"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.reportBlocked = reportBlocked;
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const os_1 = __importDefault(require("os"));
const https_1 = __importDefault(require("https"));
function uuidv4() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
        const r = (Math.random() * 16) | 0;
        const v = c === 'x' ? r : (r & 0x3) | 0x8;
        return v.toString(16);
    });
}
const crypto_1 = __importDefault(require("crypto"));
const CONFIG_DIR = path_1.default.join(os_1.default.homedir(), '.safenpm');
const CONFIG_FILE = path_1.default.join(CONFIG_DIR, 'config.json');
const REPORT_HOST = 'safenpm.dev';
const REPORT_PATH = '/api/v1/signal';
// get or create a stable anonymous machine ID
// this is purely so we can deduplicate signals from the same machine
// it contains no identifying information
function getMachineId() {
    try {
        if (!fs_1.default.existsSync(CONFIG_DIR)) {
            fs_1.default.mkdirSync(CONFIG_DIR, { recursive: true });
        }
        if (fs_1.default.existsSync(CONFIG_FILE)) {
            const config = JSON.parse(fs_1.default.readFileSync(CONFIG_FILE, 'utf8'));
            if (config.machineId)
                return config.machineId;
        }
        const machineId = uuidv4();
        fs_1.default.writeFileSync(CONFIG_FILE, JSON.stringify({ machineId }, null, 2));
        return machineId;
    }
    catch {
        return 'anonymous';
    }
}
function buildSignal(result) {
    return {
        machineId: getMachineId(),
        package: result.pkg.name,
        version: result.pkg.version,
        hook: result.pkg.hook,
        // Include both a content hash of the full script (for dedup/matching)
        // and a truncated preview. The hash ensures the threat intel network
        // can correlate identical payloads even if they exceed the preview length.
        script: result.pkg.script.slice(0, 500),
        scriptHash: crypto_1.default.createHash('sha256').update(result.pkg.script).digest('hex'),
        scriptLength: result.pkg.script.length,
        reason: result.reason,
        timestamp: new Date().toISOString(),
        platform: `${os_1.default.platform()}/${os_1.default.arch()}`,
    };
}
function post(signal) {
    return new Promise((resolve) => {
        const body = JSON.stringify(signal);
        const req = https_1.default.request({
            hostname: REPORT_HOST,
            path: REPORT_PATH,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(body),
                'User-Agent': 'safenpm/0.1.0',
            },
            timeout: 5000,
        }, (res) => {
            res.resume(); // drain response
            resolve();
        });
        req.on('error', () => resolve()); // never throw — reporting is best-effort
        req.on('timeout', () => { req.destroy(); resolve(); });
        req.write(body);
        req.end();
    });
}
async function reportBlocked(results) {
    const blocked = results.filter(r => r.blocked);
    if (blocked.length === 0)
        return;
    // fire and forget — don't await, don't block install
    const sends = blocked.map(r => post(buildSignal(r)));
    await Promise.allSettled(sends);
}
