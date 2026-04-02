"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.install = install;
const child_process_1 = require("child_process");
const path_1 = __importDefault(require("path"));
const logger_1 = require("./logger");
const scripts_1 = require("./scripts");
const sandbox_1 = require("./sandbox");
const reporter_1 = require("./reporter");
const allowlist_1 = require("./allowlist");
const analyzer_1 = require("./analyzer");
const audit_1 = require("./audit");
const typosquat_1 = require("./typosquat");
const diffing_1 = require("./diffing");
const threatintel_1 = require("./threatintel");
const maintainer_1 = require("./maintainer");
const lockfile_1 = require("./lockfile");
const reputation_1 = require("./reputation");
const packages_1 = require("./packages");
async function install(opts) {
    const { packages, dryRun, allow, noReport, json, interactive, loose, scan } = opts;
    const allowlist = (0, allowlist_1.loadAllowlist)(allow);
    // ── dry run mode ──
    if (dryRun) {
        return dryRunFlow(packages, allowlist, json, scan);
    }
    if (!json) {
        logger_1.logger.banner();
        logger_1.logger.backendInfo((0, sandbox_1.backendName)());
        logger_1.logger.allowlistInfo(allowlist.size);
    }
    // 1 — check sandbox is available
    if (!(0, sandbox_1.isSandboxAvailable)()) {
        if (!json) {
            logger_1.logger.warn('no sandbox backend found');
            logger_1.logger.warn('macOS: sandbox-exec (built-in)');
            logger_1.logger.warn('Linux: install firejail → sudo apt install firejail');
            logger_1.logger.warn('falling back to plain npm install (no sandboxing)');
            console.log();
        }
        (0, child_process_1.spawnSync)('npm', ['install', ...packages], { stdio: json ? 'pipe' : 'inherit' });
        return;
    }
    // 2 — run npm install with scripts disabled
    if (!json)
        logger_1.logger.step('installing packages (scripts disabled)...');
    const npmResult = (0, child_process_1.spawnSync)('npm', ['install', '--ignore-scripts', ...packages], { stdio: json ? 'pipe' : 'inherit' });
    if (npmResult.status !== 0) {
        process.exit(npmResult.status ?? 1);
    }
    // 3 — find all packages that have install scripts
    const nodeModulesPath = path_1.default.join(process.cwd(), 'node_modules');
    const scripts = (0, scripts_1.findInstallScripts)(nodeModulesPath);
    // ── v0.4.0: typosquat detection (runs on ALL installed packages) ──
    let typosquats = [];
    if (scan) {
        const allPkgNames = (0, packages_1.getAllPackageNames)(nodeModulesPath);
        typosquats = (0, typosquat_1.checkAllTyposquats)(allPkgNames);
        if (!json && typosquats.length > 0) {
            logger_1.logger.typosquatHeader();
            for (const t of typosquats) {
                logger_1.logger.typosquatResult(t);
            }
        }
    }
    // ── v0.4.0: lockfile integrity audit ──
    let lockfileResult = null;
    if (scan) {
        lockfileResult = (0, lockfile_1.auditLockfile)(process.cwd());
        if (!json) {
            const significant = (0, lockfile_1.significantLockfileIssues)(lockfileResult);
            if (significant.length > 0 || !lockfileResult.exists) {
                logger_1.logger.lockfileHeader();
                logger_1.logger.lockfileResult(lockfileResult);
            }
        }
    }
    // ── v0.4.0: reputation scoring ──
    let reputationSummary = null;
    if (scan) {
        reputationSummary = (0, reputation_1.scoreReputationFromNodeModules)(nodeModulesPath);
        if (!json && reputationSummary.totalPackages > 0) {
            logger_1.logger.reputationHeader();
            logger_1.logger.reputationResult(reputationSummary);
        }
    }
    if (scripts.length === 0) {
        if (json) {
            outputJson([], [], (0, sandbox_1.backendName)(), typosquats, lockfileResult, reputationSummary, [], [], []);
        }
        else {
            logger_1.logger.success('no install scripts found — nothing to sandbox');
            logger_1.logger.summary(0, 0);
        }
        return;
    }
    // 4 — static analysis
    const analyses = (0, analyzer_1.analyzeAll)(scripts);
    const totalWarnings = analyses.reduce((sum, a) => sum + a.warnings.length, 0);
    if (!json && totalWarnings > 0) {
        logger_1.logger.analysisHeader();
        for (const a of analyses) {
            if (a.warnings.length > 0) {
                logger_1.logger.analysisResult(a);
            }
        }
        console.log();
    }
    // ── v0.4.0: behavioral diffing ──
    let diffs = [];
    if (scan) {
        const allDiffs = (0, diffing_1.diffScripts)(scripts);
        diffs = (0, diffing_1.significantDiffs)(allDiffs);
        if (!json && diffs.length > 0) {
            logger_1.logger.diffHeader();
            for (const d of diffs) {
                logger_1.logger.diffResult(d);
            }
        }
    }
    // ── Threat intel: always runs (core security feature) ──
    let threatResults = [];
    {
        threatResults = await (0, threatintel_1.checkThreatIntel)(scripts.map(s => ({ name: s.name, version: s.version })));
        const flagged = threatResults.filter(r => r.flagged);
        if (!json && flagged.length > 0) {
            logger_1.logger.threatIntelHeader();
            for (const r of flagged) {
                logger_1.logger.threatIntelResult(r);
            }
        }
    }
    // ── v0.4.0: maintainer change detection ──
    let maintainerResults = [];
    if (scan) {
        maintainerResults = await (0, maintainer_1.checkMaintainerChanges)(scripts.map(s => ({ name: s.name, version: s.version })));
        const changed = (0, maintainer_1.flaggedMaintainerChanges)(maintainerResults);
        if (!json && changed.length > 0) {
            logger_1.logger.maintainerHeader();
            for (const m of changed) {
                logger_1.logger.maintainerResult(m);
            }
        }
    }
    if (!json) {
        logger_1.logger.step(`found ${scripts.length} install script${scripts.length !== 1 ? 's' : ''} — running in sandbox...`);
        console.log();
    }
    // 5 — run each script
    const results = [];
    let skippedCount = 0;
    const strict = !loose;
    for (const pkg of scripts) {
        if ((0, allowlist_1.isAllowed)(pkg.name, allowlist)) {
            if (!json)
                logger_1.logger.skipped(pkg.name, pkg.version);
            const start = Date.now();
            const r = (0, child_process_1.spawnSync)('sh', ['-c', pkg.script], {
                cwd: pkg.path,
                timeout: 30000,
                encoding: 'utf8',
                stdio: 'pipe',
            });
            results.push({
                pkg,
                blocked: false,
                skipped: true,
                reason: 'allowed',
                output: [r.stdout, r.stderr].filter(Boolean).join('\n'),
                durationMs: Date.now() - start,
            });
            skippedCount++;
            continue;
        }
        const result = (0, sandbox_1.runInSandbox)(pkg, strict);
        results.push(result);
        if (result.blocked) {
            if (!json)
                logger_1.logger.blocked(pkg.name, pkg.version, pkg.hook, result.reason);
            // ── interactive mode ──
            if (interactive && !json && process.stdin.isTTY) {
                const choice = logger_1.logger.interactivePrompt(pkg.name, pkg.version, pkg.hook);
                if (choice === 'r') {
                    if (!json)
                        logger_1.logger.step(`retrying ${pkg.name} without sandbox...`);
                    const start = Date.now();
                    const retry = (0, child_process_1.spawnSync)('sh', ['-c', pkg.script], {
                        cwd: pkg.path,
                        timeout: 30000,
                        encoding: 'utf8',
                        stdio: 'pipe',
                    });
                    results[results.length - 1] = {
                        pkg,
                        blocked: false,
                        skipped: true,
                        reason: 'allowed',
                        output: [retry.stdout, retry.stderr].filter(Boolean).join('\n'),
                        durationMs: Date.now() - start,
                    };
                    if (!json)
                        logger_1.logger.success(`${pkg.name} ran without sandbox`);
                }
                else if (choice === 'a') {
                    if (!json)
                        logger_1.logger.error('aborted by user');
                    process.exit(1);
                }
            }
        }
        else {
            if (!json)
                logger_1.logger.allowed(pkg.name, pkg.version);
        }
    }
    // 6 — cache scripts for future diffing
    if (scan) {
        (0, diffing_1.cacheScripts)(scripts);
    }
    // 7 — report blocked signals
    const blockedCount = results.filter(r => r.blocked).length;
    if (blockedCount > 0 && !noReport) {
        await (0, reporter_1.reportBlocked)(results);
    }
    // 8 — audit log
    (0, audit_1.writeAuditLog)(results, analyses, (0, sandbox_1.backendName)());
    if (!json)
        logger_1.logger.auditInfo();
    // 9 — output
    if (json) {
        outputJson(results, analyses, (0, sandbox_1.backendName)(), typosquats, lockfileResult, reputationSummary, diffs, threatResults, maintainerResults);
    }
    else {
        logger_1.logger.summary(scripts.length, blockedCount, skippedCount, totalWarnings);
    }
    if (blockedCount > 0) {
        process.exit(1);
    }
}
// ── JSON output for CI ──
function outputJson(results, analyses, backend, typosquats, lockfileResult, reputationSummary, diffs, threatResults, maintainerResults) {
    const analysisMap = new Map(analyses.map(a => [a.pkg.name, a]));
    const threatMap = new Map(threatResults.map(r => [r.name, r]));
    const maintainerMap = new Map(maintainerResults.map(r => [r.name, r]));
    const diffMap = new Map(diffs.map(d => [d.name, d]));
    const pkgResults = results.map(r => {
        const analysis = analysisMap.get(r.pkg.name);
        const threat = threatMap.get(r.pkg.name);
        const maint = maintainerMap.get(r.pkg.name);
        const diff = diffMap.get(r.pkg.name);
        const base = {
            name: r.pkg.name,
            version: r.pkg.version,
            hook: r.pkg.hook,
            script: r.pkg.script,
            result: r.blocked ? 'blocked' : r.skipped ? 'allowed' : 'clean',
            reason: r.reason,
            durationMs: r.durationMs,
            riskScore: analysis?.riskScore ?? 0,
            warnings: (analysis?.warnings ?? []).map(w => ({
                rule: w.rule,
                severity: w.severity,
                description: w.description,
            })),
        };
        if (threat) {
            base.threatIntel = { flagged: threat.flagged, reportCount: threat.reportCount, topReasons: threat.topReasons };
        }
        if (maint) {
            base.maintainerChanged = maint.maintainerChanged;
        }
        if (diff) {
            base.behaviorDiff = { newWarnings: diff.newWarnings, riskDelta: diff.riskDelta };
        }
        return base;
    });
    const jsonTyposquats = typosquats.map(t => ({
        suspect: t.suspect,
        target: t.target,
        distance: t.distance,
        technique: t.technique,
        confidence: t.confidence,
    }));
    const jsonLockfile = lockfileResult ? {
        exists: lockfileResult.exists,
        format: lockfileResult.format,
        totalPackages: lockfileResult.totalPackages,
        score: lockfileResult.score,
        issues: lockfileResult.issues.map(i => ({
            severity: i.severity,
            type: i.type,
            package: i.package,
            detail: i.detail,
        })),
    } : null;
    const jsonReputation = reputationSummary ? {
        overallScore: reputationSummary.overallScore,
        totalPackages: reputationSummary.totalPackages,
        averageScore: reputationSummary.averageScore,
        tiers: reputationSummary.tiers,
        riskiest: reputationSummary.riskiest.map(r => ({
            name: r.name,
            version: r.version,
            score: r.score,
            tier: r.tier,
        })),
    } : null;
    const output = {
        version: '0.5.0',
        backend,
        timestamp: new Date().toISOString(),
        packages: pkgResults,
        typosquats: jsonTyposquats,
        lockfileAudit: jsonLockfile,
        reputationSummary: jsonReputation,
        summary: {
            total: results.length,
            blocked: results.filter(r => r.blocked).length,
            allowed: results.filter(r => r.skipped).length,
            clean: results.filter(r => !r.blocked && !r.skipped).length,
            warnings: analyses.reduce((sum, a) => sum + a.warnings.length, 0),
            typosquats: typosquats.length,
            maintainerChanges: maintainerResults.filter(m => m.maintainerChanged).length,
            lockfileIssues: lockfileResult?.issues.length ?? 0,
            reputationScore: reputationSummary?.overallScore ?? 100,
        },
    };
    console.log(JSON.stringify(output, null, 2));
}
// ── Dry run ──
function dryRunFlow(packages, allowlist, json, scan) {
    if (!json) {
        logger_1.logger.dryRunBanner();
        logger_1.logger.backendInfo((0, sandbox_1.backendName)());
        logger_1.logger.allowlistInfo(allowlist.size);
    }
    if (!json) {
        if (packages.length > 0) {
            logger_1.logger.step(`would run: npm install --ignore-scripts ${packages.join(' ')}`);
        }
        else {
            logger_1.logger.step('would run: npm install --ignore-scripts');
        }
    }
    const nodeModulesPath = path_1.default.join(process.cwd(), 'node_modules');
    const scripts = (0, scripts_1.findInstallScripts)(nodeModulesPath);
    // v0.4.0 scans in dry run too
    let typosquats = [];
    let lockfileResult = null;
    let reputationSummary = null;
    if (scan) {
        const allPkgNames = (0, packages_1.getAllPackageNames)(nodeModulesPath);
        typosquats = (0, typosquat_1.checkAllTyposquats)(allPkgNames);
        lockfileResult = (0, lockfile_1.auditLockfile)(process.cwd());
        reputationSummary = (0, reputation_1.scoreReputationFromNodeModules)(nodeModulesPath);
        if (!json) {
            if (typosquats.length > 0) {
                logger_1.logger.typosquatHeader();
                for (const t of typosquats)
                    logger_1.logger.typosquatResult(t);
            }
            const significant = (0, lockfile_1.significantLockfileIssues)(lockfileResult);
            if (significant.length > 0 || !lockfileResult.exists) {
                logger_1.logger.lockfileHeader();
                logger_1.logger.lockfileResult(lockfileResult);
            }
            if (reputationSummary.totalPackages > 0) {
                logger_1.logger.reputationHeader();
                logger_1.logger.reputationResult(reputationSummary);
            }
        }
    }
    if (scripts.length === 0) {
        if (json) {
            outputJson([], [], (0, sandbox_1.backendName)(), typosquats, lockfileResult, reputationSummary, [], [], []);
        }
        else {
            console.log();
            logger_1.logger.success('no install scripts found in current node_modules');
            console.log();
        }
        return;
    }
    // Static analysis in dry run too
    const analyses = (0, analyzer_1.analyzeAll)(scripts);
    if (json) {
        const pkgResults = scripts.map(pkg => {
            const analysis = analyses.find(a => a.pkg.name === pkg.name);
            const allowed = (0, allowlist_1.isAllowed)(pkg.name, allowlist);
            return {
                name: pkg.name,
                version: pkg.version,
                hook: pkg.hook,
                script: pkg.script,
                result: allowed ? 'allowed' : 'clean',
                reason: allowed ? 'allowlisted' : 'would-sandbox',
                durationMs: 0,
                riskScore: analysis?.riskScore ?? 0,
                warnings: (analysis?.warnings ?? []).map(w => ({
                    rule: w.rule,
                    severity: w.severity,
                    description: w.description,
                })),
            };
        });
        const output = {
            version: '0.5.0',
            backend: (0, sandbox_1.backendName)(),
            timestamp: new Date().toISOString(),
            packages: pkgResults,
            typosquats: typosquats.map(t => ({ suspect: t.suspect, target: t.target, distance: t.distance, technique: t.technique, confidence: t.confidence })),
            lockfileAudit: lockfileResult ? { exists: lockfileResult.exists, format: lockfileResult.format, totalPackages: lockfileResult.totalPackages, score: lockfileResult.score, issues: lockfileResult.issues.map(i => ({ severity: i.severity, type: i.type, package: i.package, detail: i.detail })) } : null,
            reputationSummary: reputationSummary ? { overallScore: reputationSummary.overallScore, totalPackages: reputationSummary.totalPackages, averageScore: reputationSummary.averageScore, tiers: reputationSummary.tiers, riskiest: reputationSummary.riskiest.map(r => ({ name: r.name, version: r.version, score: r.score, tier: r.tier })) } : null,
            summary: {
                total: scripts.length,
                blocked: 0,
                allowed: pkgResults.filter(p => p.result === 'allowed').length,
                clean: pkgResults.filter(p => p.result === 'clean').length,
                warnings: analyses.reduce((sum, a) => sum + a.warnings.length, 0),
                typosquats: typosquats.length,
                maintainerChanges: 0,
                lockfileIssues: lockfileResult?.issues.length ?? 0,
                reputationScore: reputationSummary?.overallScore ?? 100,
            },
        };
        console.log(JSON.stringify(output, null, 2));
        return;
    }
    // Analysis output
    const totalWarnings = analyses.reduce((sum, a) => sum + a.warnings.length, 0);
    if (totalWarnings > 0) {
        logger_1.logger.analysisHeader();
        for (const a of analyses) {
            if (a.warnings.length > 0) {
                logger_1.logger.analysisResult(a);
            }
        }
    }
    console.log();
    logger_1.logger.step(`${scripts.length} install script${scripts.length !== 1 ? 's' : ''} found in node_modules:`);
    console.log();
    let wouldSandbox = 0;
    let wouldAllow = 0;
    for (const pkg of scripts) {
        const allowed = (0, allowlist_1.isAllowed)(pkg.name, allowlist);
        logger_1.logger.dryRunItem(pkg.name, pkg.version, pkg.hook, pkg.script, allowed);
        if (allowed)
            wouldAllow++;
        else
            wouldSandbox++;
    }
    console.log();
    logger_1.logger.info(`${wouldSandbox} would be sandboxed, ${wouldAllow} would be allowlisted`);
    logger_1.logger.info('run without --dry-run to execute');
    console.log();
}
