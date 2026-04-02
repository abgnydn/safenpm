"use strict";
/**
 * Behavioral diffing — compares install scripts between the previously
 * installed version and the new version. Detects when a package suddenly
 * adds network calls, eval, or credential access that wasn't there before.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.cacheScripts = cacheScripts;
exports.diffScripts = diffScripts;
exports.significantDiffs = significantDiffs;
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const os_1 = __importDefault(require("os"));
const analyzer_1 = require("./analyzer");
const CACHE_DIR = path_1.default.join(os_1.default.homedir(), '.safenpm', 'script-cache');
/**
 * Build a cache key that incorporates both the project directory
 * and the lockfile content, so switching branches invalidates the cache.
 */
function buildCacheKey() {
    const cwd = process.cwd();
    const cwdHash = simpleHash(cwd);
    // Include lockfile hash if available so branch switches invalidate cache
    const lockfilePath = path_1.default.join(cwd, 'package-lock.json');
    let lockfileHash = 'none';
    try {
        if (fs_1.default.existsSync(lockfilePath)) {
            const content = fs_1.default.readFileSync(lockfilePath, 'utf8');
            lockfileHash = simpleHash(content).slice(0, 8);
        }
    }
    catch { /* use 'none' */ }
    return `${cwdHash}-${lockfileHash}`;
}
/**
 * Cache the current install scripts for future diffing.
 * Called after a successful install so the next install can compare.
 */
function cacheScripts(scripts) {
    try {
        if (!fs_1.default.existsSync(CACHE_DIR)) {
            fs_1.default.mkdirSync(CACHE_DIR, { recursive: true });
        }
        const cacheKey = buildCacheKey();
        const cacheFile = path_1.default.join(CACHE_DIR, `${cacheKey}.json`);
        const cache = {};
        for (const s of scripts) {
            cache[s.name] = {
                version: s.version,
                script: s.script,
                hook: s.hook,
            };
        }
        fs_1.default.writeFileSync(cacheFile, JSON.stringify(cache, null, 2), 'utf8');
    }
    catch {
        // caching is best-effort
    }
}
/**
 * Load previously cached scripts for this project.
 * Tries current lockfile-aware key first, falls back to legacy cwd-only key.
 */
function loadCache() {
    try {
        // Try lockfile-aware cache key first
        const cacheKey = buildCacheKey();
        const cacheFile = path_1.default.join(CACHE_DIR, `${cacheKey}.json`);
        if (fs_1.default.existsSync(cacheFile)) {
            return JSON.parse(fs_1.default.readFileSync(cacheFile, 'utf8'));
        }
        // Fallback: legacy cache key (cwd-only) for backward compatibility
        const legacyKey = simpleHash(process.cwd());
        const legacyFile = path_1.default.join(CACHE_DIR, `${legacyKey}.json`);
        if (fs_1.default.existsSync(legacyFile)) {
            return JSON.parse(fs_1.default.readFileSync(legacyFile, 'utf8'));
        }
        return {};
    }
    catch {
        return {};
    }
}
/**
 * Compare current scripts against the cached previous versions.
 */
function diffScripts(currentScripts) {
    const previous = loadCache();
    const results = [];
    for (const current of currentScripts) {
        const prev = previous[current.name];
        if (!prev) {
            // Brand new package with install scripts — note it
            const analysis = (0, analyzer_1.analyzeScript)(current);
            results.push({
                name: current.name,
                previousVersion: null,
                currentVersion: current.version,
                previousScript: null,
                currentScript: current.script,
                scriptChanged: true,
                newWarnings: analysis.warnings.map(w => w.rule),
                riskDelta: analysis.riskScore,
                isNewPackage: true,
            });
            continue;
        }
        // Same version, same script — no change
        if (prev.version === current.version && prev.script === current.script) {
            results.push({
                name: current.name,
                previousVersion: prev.version,
                currentVersion: current.version,
                previousScript: prev.script,
                currentScript: current.script,
                scriptChanged: false,
                newWarnings: [],
                riskDelta: 0,
                isNewPackage: false,
            });
            continue;
        }
        // Script changed — diff the analysis
        const prevAnalysis = (0, analyzer_1.analyzeScript)({
            ...current,
            version: prev.version,
            script: prev.script,
        });
        const currAnalysis = (0, analyzer_1.analyzeScript)(current);
        const prevRules = new Set(prevAnalysis.warnings.map(w => w.rule));
        const newWarnings = currAnalysis.warnings
            .filter(w => !prevRules.has(w.rule))
            .map(w => w.rule);
        results.push({
            name: current.name,
            previousVersion: prev.version,
            currentVersion: current.version,
            previousScript: prev.script,
            currentScript: current.script,
            scriptChanged: true,
            newWarnings,
            riskDelta: currAnalysis.riskScore - prevAnalysis.riskScore,
            isNewPackage: false,
        });
    }
    return results;
}
/**
 * Filter to only meaningful diffs (script changed or new warnings)
 */
function significantDiffs(diffs) {
    return diffs.filter(d => d.scriptChanged && (d.newWarnings.length > 0 || d.riskDelta > 0));
}
function simpleHash(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        const char = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash |= 0;
    }
    return Math.abs(hash).toString(36);
}
