"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.writeAuditLog = writeAuditLog;
exports.readAuditLog = readAuditLog;
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const os_1 = __importDefault(require("os"));
const AUDIT_DIR = path_1.default.join(os_1.default.homedir(), '.safenpm');
const AUDIT_FILE = path_1.default.join(AUDIT_DIR, 'audit.log');
const MAX_LOG_SIZE = 5 * 1024 * 1024; // 5MB — rotate after this
function writeAuditLog(results, analyses, backend) {
    try {
        ensureDir();
        rotateIfNeeded();
        const analysisMap = new Map(analyses.map(a => [a.pkg.name, a]));
        const packages = results.map(r => {
            const analysis = analysisMap.get(r.pkg.name);
            return {
                name: r.pkg.name,
                version: r.pkg.version,
                hook: r.pkg.hook,
                result: r.blocked ? 'blocked' : r.skipped ? 'allowed' : 'clean',
                reason: r.reason,
                durationMs: r.durationMs,
                riskScore: analysis?.riskScore,
                warnings: analysis?.warnings.map(w => w.rule),
            };
        });
        const entry = {
            timestamp: new Date().toISOString(),
            cwd: process.cwd(),
            backend,
            packages,
            summary: {
                total: results.length,
                blocked: results.filter(r => r.blocked).length,
                allowed: results.filter(r => r.skipped).length,
                clean: results.filter(r => !r.blocked && !r.skipped).length,
            },
        };
        const line = JSON.stringify(entry) + '\n';
        fs_1.default.appendFileSync(AUDIT_FILE, line, 'utf8');
    }
    catch {
        // audit logging is best-effort — never fail the install
    }
}
function ensureDir() {
    if (!fs_1.default.existsSync(AUDIT_DIR)) {
        fs_1.default.mkdirSync(AUDIT_DIR, { recursive: true });
    }
}
function rotateIfNeeded() {
    try {
        if (!fs_1.default.existsSync(AUDIT_FILE))
            return;
        const stat = fs_1.default.statSync(AUDIT_FILE);
        if (stat.size > MAX_LOG_SIZE) {
            const rotated = AUDIT_FILE + '.1';
            // keep one rotation — overwrite previous
            if (fs_1.default.existsSync(rotated))
                fs_1.default.unlinkSync(rotated);
            fs_1.default.renameSync(AUDIT_FILE, rotated);
        }
    }
    catch {
        // ignore rotation errors
    }
}
function readAuditLog(limit = 20) {
    try {
        if (!fs_1.default.existsSync(AUDIT_FILE))
            return [];
        const content = fs_1.default.readFileSync(AUDIT_FILE, 'utf8');
        const lines = content.trim().split('\n').filter(Boolean);
        const entries = lines.map(l => {
            try {
                return JSON.parse(l);
            }
            catch {
                return null;
            }
        }).filter((e) => e !== null);
        return entries.slice(-limit);
    }
    catch {
        return [];
    }
}
