"use strict";
/**
 * Maintainer change detection — queries the npm registry to check
 * if the publisher of a package version is different from the
 * previous version. A sudden maintainer swap can signal account
 * takeover or malicious publish.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.checkMaintainerChanges = checkMaintainerChanges;
exports.flaggedMaintainerChanges = flaggedMaintainerChanges;
exports.mockMaintainerInfo = mockMaintainerInfo;
const https_1 = __importDefault(require("https"));
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const os_1 = __importDefault(require("os"));
const CACHE_DIR = path_1.default.join(os_1.default.homedir(), '.safenpm', 'maintainer-cache');
const CACHE_TTL = 86400000; // 24 hours
/**
 * Check maintainer changes for a set of packages.
 * Queries the npm registry for version metadata.
 */
async function checkMaintainerChanges(packages) {
    const results = [];
    for (const pkg of packages) {
        const cached = readCache(pkg.name);
        if (cached && cached.version === pkg.version) {
            results.push(cached);
            continue;
        }
        const info = await fetchMaintainerInfo(pkg.name, pkg.version);
        writeCache(info);
        results.push(info);
    }
    return results;
}
/**
 * Fetch version metadata from npm registry and extract publisher info.
 * GET https://registry.npmjs.org/{name} — abbreviated metadata
 */
async function fetchMaintainerInfo(name, version) {
    return new Promise((resolve) => {
        const encodedName = name.replace('/', '%2f');
        const req = https_1.default.get(`https://registry.npmjs.org/${encodedName}`, {
            headers: {
                Accept: 'application/json',
                'User-Agent': 'safenpm/0.4.0',
            },
            timeout: 8000,
        }, (res) => {
            let data = '';
            res.on('data', (chunk) => { data += chunk.toString(); });
            res.on('end', () => {
                try {
                    const parsed = JSON.parse(data);
                    resolve(extractMaintainerInfo(name, version, parsed));
                }
                catch {
                    resolve(unknownInfo(name, version));
                }
            });
        });
        req.on('error', (err) => {
            process.stderr.write(`  [safenpm] warning: maintainer check failed for ${name}: ${err.message}\n`);
            resolve(unknownInfo(name, version));
        });
        req.on('timeout', () => {
            req.destroy();
            process.stderr.write(`  [safenpm] warning: maintainer check timed out for ${name}\n`);
            resolve(unknownInfo(name, version));
        });
    });
}
/**
 * Extract publisher info from the npm registry response.
 * The `time` field gives us version publish dates.
 * The `versions[v]._npmUser` field gives us who published each version.
 */
function extractMaintainerInfo(name, version, registryData) {
    const versions = registryData.versions || {};
    const time = registryData.time || {};
    // Get all version strings sorted by publish time
    const sortedVersions = Object.keys(time)
        .filter(v => v !== 'created' && v !== 'modified' && versions[v])
        .sort((a, b) => {
        const ta = new Date(time[a]).getTime();
        const tb = new Date(time[b]).getTime();
        return ta - tb;
    });
    // Extract publisher (_npmUser.name) for each version
    const publishers = [];
    for (const v of sortedVersions) {
        const npmUser = versions[v]?._npmUser;
        if (npmUser?.name) {
            publishers.push({ version: v, publisher: npmUser.name });
        }
    }
    const currentIdx = publishers.findIndex(p => p.version === version);
    const currentPublisher = currentIdx >= 0 ? publishers[currentIdx].publisher : null;
    const previousPublisher = currentIdx > 0 ? publishers[currentIdx - 1].publisher : null;
    // Distinct publisher history (last 10)
    const distinctPublishers = [...new Set(publishers.map(p => p.publisher))].slice(-10);
    const maintainerChanged = !!(currentPublisher &&
        previousPublisher &&
        currentPublisher !== previousPublisher);
    return {
        name,
        version,
        currentPublisher,
        previousPublisher,
        maintainerChanged,
        isNewPackage: publishers.length <= 1,
        publisherHistory: distinctPublishers,
        accountAge: null, // Would need separate API call
    };
}
function unknownInfo(name, version) {
    return {
        name,
        version,
        currentPublisher: null,
        previousPublisher: null,
        maintainerChanged: false,
        isNewPackage: false,
        publisherHistory: [],
        accountAge: null,
    };
}
// ── Local cache ──
function readCache(name) {
    try {
        const file = path_1.default.join(CACHE_DIR, safeName(name) + '.json');
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
function writeCache(info) {
    try {
        if (!fs_1.default.existsSync(CACHE_DIR)) {
            fs_1.default.mkdirSync(CACHE_DIR, { recursive: true });
        }
        const file = path_1.default.join(CACHE_DIR, safeName(info.name) + '.json');
        fs_1.default.writeFileSync(file, JSON.stringify(info), 'utf8');
    }
    catch {
        // best effort
    }
}
function safeName(name) {
    return name.replace(/[^a-zA-Z0-9@._-]/g, '_');
}
/**
 * Filter to only packages with maintainer changes.
 */
function flaggedMaintainerChanges(results) {
    return results.filter(r => r.maintainerChanged);
}
/**
 * Mock maintainer info for offline/testing.
 */
function mockMaintainerInfo(packages) {
    return packages.map(p => unknownInfo(p.name, p.version));
}
