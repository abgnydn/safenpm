"use strict";
/**
 * Dependency graph reputation scoring — evaluates the overall health
 * of a project's dependency tree based on:
 *   - Package age (older = more trusted)
 *   - Number of maintainers (bus factor)
 *   - Weekly download counts (popularity)
 *   - Dependency depth (deep trees = more attack surface)
 *   - Presence of install scripts
 *   - Known vulnerability signals
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.scoreReputationFromNodeModules = scoreReputationFromNodeModules;
exports.quickReputationCheck = quickReputationCheck;
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const os_1 = __importDefault(require("os"));
const CACHE_DIR = path_1.default.join(os_1.default.homedir(), '.safenpm', 'reputation-cache');
const CACHE_TTL = 86400000; // 24 hours
/**
 * Score a full dependency tree. Reads node_modules to build the graph.
 */
function scoreReputationFromNodeModules(nodeModulesDir) {
    const packages = discoverPackages(nodeModulesDir);
    const reputations = packages.map(p => scorePackage(p));
    return summarize(reputations);
}
/**
 * Walk node_modules to discover all installed packages.
 */
function discoverPackages(nodeModulesDir) {
    const results = [];
    if (!fs_1.default.existsSync(nodeModulesDir))
        return results;
    const entries = fs_1.default.readdirSync(nodeModulesDir);
    for (const entry of entries) {
        if (entry.startsWith('.'))
            continue;
        if (entry.startsWith('@')) {
            // Scoped packages
            const scopeDir = path_1.default.join(nodeModulesDir, entry);
            try {
                const scopeEntries = fs_1.default.readdirSync(scopeDir);
                for (const scopeEntry of scopeEntries) {
                    const pkg = readPkgInfo(path_1.default.join(scopeDir, scopeEntry), `${entry}/${scopeEntry}`);
                    if (pkg)
                        results.push(pkg);
                }
            }
            catch { /* skip */ }
        }
        else {
            const pkg = readPkgInfo(path_1.default.join(nodeModulesDir, entry), entry);
            if (pkg)
                results.push(pkg);
        }
    }
    return results;
}
function readPkgInfo(pkgDir, name) {
    try {
        const pkgJsonPath = path_1.default.join(pkgDir, 'package.json');
        if (!fs_1.default.existsSync(pkgJsonPath))
            return null;
        const pkgJson = JSON.parse(fs_1.default.readFileSync(pkgJsonPath, 'utf8'));
        const scripts = pkgJson.scripts || {};
        const hasInstallScripts = !!(scripts.preinstall || scripts.install || scripts.postinstall || scripts.prepare);
        const deps = pkgJson.dependencies || {};
        const maintainers = Array.isArray(pkgJson.maintainers) ? pkgJson.maintainers.length : 0;
        return {
            name: pkgJson.name || name,
            version: pkgJson.version || '0.0.0',
            description: pkgJson.description || '',
            maintainers,
            hasInstallScripts,
            dependencyCount: Object.keys(deps).length,
            pkgJson,
        };
    }
    catch {
        return null;
    }
}
/**
 * Score a single package based on available metadata.
 *
 * IMPORTANT: This is an offline heuristic based solely on package.json metadata.
 * It does NOT query the npm registry for download counts, vulnerability data,
 * publish history, or real-time maintainer changes. Scores should be treated as
 * a rough signal, not a definitive security assessment.
 *
 * Future improvements:
 * - Fetch weekly download counts from registry.npmjs.org/-/v1/search
 * - Check npm audit advisories for known vulnerabilities
 * - Track publish frequency and detect anomalous gaps
 * - Integrate with Socket.dev or Snyk for deeper analysis
 */
function scorePackage(pkg) {
    const factors = [];
    let score = 50; // start at neutral
    // ── Maintainer count ──
    if (pkg.maintainers >= 3) {
        factors.push({ factor: 'maintainers', value: `${pkg.maintainers} maintainers`, impact: 15 });
        score += 15;
    }
    else if (pkg.maintainers === 1) {
        factors.push({ factor: 'maintainers', value: 'single maintainer', impact: -5 });
        score -= 5;
    }
    else if (pkg.maintainers === 0) {
        factors.push({ factor: 'maintainers', value: 'no maintainer info', impact: -10 });
        score -= 10;
    }
    // ── Install scripts ──
    if (pkg.hasInstallScripts) {
        factors.push({ factor: 'install-scripts', value: 'has install scripts', impact: -15 });
        score -= 15;
    }
    else {
        factors.push({ factor: 'install-scripts', value: 'no install scripts', impact: 5 });
        score += 5;
    }
    // ── Dependency count (attack surface) ──
    if (pkg.dependencyCount === 0) {
        factors.push({ factor: 'dependencies', value: 'zero dependencies', impact: 10 });
        score += 10;
    }
    else if (pkg.dependencyCount <= 3) {
        factors.push({ factor: 'dependencies', value: `${pkg.dependencyCount} deps`, impact: 5 });
        score += 5;
    }
    else if (pkg.dependencyCount > 10) {
        factors.push({ factor: 'dependencies', value: `${pkg.dependencyCount} deps (heavy)`, impact: -10 });
        score -= 10;
    }
    // ── Description quality (proxy for maintenance) ──
    if (!pkg.description || pkg.description.length < 10) {
        factors.push({ factor: 'description', value: 'missing/sparse', impact: -5 });
        score -= 5;
    }
    // ── License ──
    const license = pkg.pkgJson.license || pkg.pkgJson.licence || '';
    if (!license) {
        factors.push({ factor: 'license', value: 'no license specified', impact: -10 });
        score -= 10;
    }
    else if (['MIT', 'ISC', 'BSD-2-Clause', 'BSD-3-Clause', 'Apache-2.0'].includes(license)) {
        factors.push({ factor: 'license', value: license, impact: 5 });
        score += 5;
    }
    // ── Repository ──
    const repo = pkg.pkgJson.repository;
    if (repo) {
        const repoUrl = typeof repo === 'string' ? repo : repo.url || '';
        if (repoUrl.includes('github.com') || repoUrl.includes('gitlab.com')) {
            factors.push({ factor: 'repository', value: 'public repo', impact: 5 });
            score += 5;
        }
    }
    else {
        factors.push({ factor: 'repository', value: 'no repository', impact: -5 });
        score -= 5;
    }
    // ── Version ──
    const majorVersion = parseInt(pkg.version.split('.')[0], 10);
    if (majorVersion >= 1) {
        factors.push({ factor: 'maturity', value: `v${pkg.version}`, impact: 5 });
        score += 5;
    }
    else {
        factors.push({ factor: 'maturity', value: `pre-1.0 (${pkg.version})`, impact: -5 });
        score -= 5;
    }
    // Clamp score
    score = Math.max(0, Math.min(100, score));
    return {
        name: pkg.name,
        version: pkg.version,
        score,
        factors,
        tier: scoreTier(score),
    };
}
function scoreTier(score) {
    if (score >= 80)
        return 'trusted';
    if (score >= 60)
        return 'established';
    if (score >= 40)
        return 'emerging';
    if (score >= 20)
        return 'unknown';
    return 'risky';
}
/**
 * Aggregate individual scores into a project summary.
 */
function summarize(reputations) {
    if (reputations.length === 0) {
        return {
            overallScore: 100,
            totalPackages: 0,
            tiers: {},
            riskiest: [],
            averageScore: 100,
        };
    }
    const tiers = {};
    let totalScore = 0;
    for (const r of reputations) {
        tiers[r.tier] = (tiers[r.tier] || 0) + 1;
        totalScore += r.score;
    }
    const averageScore = Math.round(totalScore / reputations.length);
    // Overall score: weighted toward the worst packages
    const sorted = [...reputations].sort((a, b) => a.score - b.score);
    const bottom10pct = sorted.slice(0, Math.max(1, Math.floor(sorted.length * 0.1)));
    const bottomAvg = bottom10pct.reduce((s, r) => s + r.score, 0) / bottom10pct.length;
    const overallScore = Math.round(averageScore * 0.6 + bottomAvg * 0.4);
    // Top 5 riskiest packages
    const riskiest = sorted.slice(0, 5);
    return {
        overallScore,
        totalPackages: reputations.length,
        tiers,
        riskiest,
        averageScore,
    };
}
/**
 * Quick reputation check for a list of package names
 * (reads from node_modules in cwd).
 */
function quickReputationCheck(nodeModulesDir, packageNames) {
    const allPackages = discoverPackages(nodeModulesDir);
    const nameSet = new Set(packageNames);
    const filtered = allPackages.filter(p => nameSet.has(p.name));
    return filtered.map(p => scorePackage(p));
}
