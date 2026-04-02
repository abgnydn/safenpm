#!/usr/bin/env node
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const install_1 = require("./install");
const audit_1 = require("./audit");
const typosquat_1 = require("./typosquat");
const lockfile_1 = require("./lockfile");
const reputation_1 = require("./reputation");
const doctor_1 = require("./doctor");
const autofix_1 = require("./autofix");
const pkgdiff_1 = require("./pkgdiff");
const logger_1 = require("./logger");
const packages_1 = require("./packages");
const path_1 = __importDefault(require("path"));
const fs_1 = __importDefault(require("fs"));
const [, , command, ...rawArgs] = process.argv;
function parseInstallArgs(args) {
    const packages = [];
    const allow = [];
    let dryRun = false;
    let noReport = false;
    let json = false;
    let interactive = false;
    let loose = false;
    let scan = false;
    let i = 0;
    while (i < args.length) {
        const arg = args[i];
        if (arg === '--dry-run' || arg === '-n') {
            dryRun = true;
        }
        else if (arg === '--allow') {
            i++;
            if (i < args.length) {
                for (const name of args[i].split(',')) {
                    const trimmed = name.trim();
                    if (!trimmed)
                        continue;
                    const err = (0, packages_1.validatePackageName)(trimmed);
                    if (err) {
                        logger_1.logger.error(`invalid --allow value: ${err}`);
                        process.exit(1);
                    }
                    allow.push(trimmed);
                }
            }
        }
        else if (arg.startsWith('--allow=')) {
            const val = arg.slice('--allow='.length);
            for (const name of val.split(',')) {
                const trimmed = name.trim();
                if (!trimmed)
                    continue;
                const err = (0, packages_1.validatePackageName)(trimmed);
                if (err) {
                    logger_1.logger.error(`invalid --allow value: ${err}`);
                    process.exit(1);
                }
                allow.push(trimmed);
            }
        }
        else if (arg === '--no-report') {
            noReport = true;
        }
        else if (arg === '--json') {
            json = true;
        }
        else if (arg === '--interactive' || arg === '-I') {
            interactive = true;
        }
        else if (arg === '--loose') {
            loose = true;
        }
        else if (arg === '--scan' || arg === '-S') {
            scan = true;
        }
        else if (!arg.startsWith('-')) {
            packages.push(arg);
        }
        i++;
    }
    return { packages, dryRun, allow, noReport, json, interactive, loose, scan };
}
async function main() {
    switch (command) {
        case 'install':
        case 'i': {
            const opts = parseInstallArgs(rawArgs);
            await (0, install_1.install)(opts);
            break;
        }
        case 'scan': {
            const jsonFlag = rawArgs.includes('--json');
            const nodeModulesPath = path_1.default.join(process.cwd(), 'node_modules');
            if (!fs_1.default.existsSync(nodeModulesPath)) {
                if (jsonFlag) {
                    console.log(JSON.stringify({ error: 'no node_modules found' }));
                }
                else {
                    logger_1.logger.error('no node_modules found — run npm install first');
                }
                process.exit(1);
            }
            if (!jsonFlag) {
                logger_1.logger.banner();
                console.log();
            }
            const allNames = (0, packages_1.getAllPackageNames)(nodeModulesPath);
            const typosquats = (0, typosquat_1.checkAllTyposquats)(allNames);
            if (!jsonFlag && typosquats.length > 0) {
                logger_1.logger.typosquatHeader();
                for (const t of typosquats)
                    logger_1.logger.typosquatResult(t);
            }
            else if (!jsonFlag && typosquats.length === 0) {
                logger_1.logger.success('no typosquat suspects found');
            }
            const lockResult = (0, lockfile_1.auditLockfile)(process.cwd());
            if (!jsonFlag) {
                logger_1.logger.lockfileHeader();
                logger_1.logger.lockfileResult(lockResult);
            }
            const repSummary = (0, reputation_1.scoreReputationFromNodeModules)(nodeModulesPath);
            if (!jsonFlag && repSummary.totalPackages > 0) {
                logger_1.logger.reputationHeader();
                logger_1.logger.reputationResult(repSummary);
            }
            if (jsonFlag) {
                console.log(JSON.stringify({
                    typosquats: typosquats.map(t => ({ suspect: t.suspect, target: t.target, technique: t.technique, confidence: t.confidence })),
                    lockfile: { exists: lockResult.exists, format: lockResult.format, score: lockResult.score, issues: lockResult.issues.length },
                    reputation: { overallScore: repSummary.overallScore, totalPackages: repSummary.totalPackages, tiers: repSummary.tiers },
                }, null, 2));
            }
            else {
                console.log();
            }
            break;
        }
        case 'doctor': {
            const jsonFlag = rawArgs.includes('--json');
            const projectDir = process.cwd();
            if (!jsonFlag) {
                logger_1.logger.banner();
                console.log();
                logger_1.logger.step('running health check...');
                console.log();
            }
            const report = (0, doctor_1.runDoctor)(projectDir);
            if (jsonFlag) {
                console.log(JSON.stringify((0, doctor_1.doctorToJson)(report), null, 2));
            }
            else {
                printDoctorReport(report);
            }
            // Exit non-zero if grade is D or F
            if (report.score < 60)
                process.exit(1);
            break;
        }
        case 'fix': {
            const jsonFlag = rawArgs.includes('--json');
            const dryRun = rawArgs.includes('--dry-run') || rawArgs.includes('-n');
            const projectDir = process.cwd();
            const nodeModulesPath = path_1.default.join(projectDir, 'node_modules');
            if (!fs_1.default.existsSync(nodeModulesPath)) {
                if (jsonFlag) {
                    console.log(JSON.stringify({ error: 'no node_modules found' }));
                }
                else {
                    logger_1.logger.error('no node_modules found — run npm install first');
                }
                process.exit(1);
            }
            if (!jsonFlag) {
                logger_1.logger.banner();
                console.log();
                logger_1.logger.step('scanning for fixable issues...');
                console.log();
            }
            // Find typosquats
            const allNames = (0, packages_1.getAllPackageNames)(nodeModulesPath);
            const typosquats = (0, typosquat_1.checkAllTyposquats)(allNames);
            // Generate fixes (no blocked results available outside install flow)
            const fixes = (0, autofix_1.generateFixes)(typosquats, []);
            if (fixes.length === 0) {
                if (jsonFlag) {
                    console.log(JSON.stringify({ fixes: [], applied: 0 }));
                }
                else {
                    logger_1.logger.success('no fixable issues found');
                    console.log();
                }
                break;
            }
            if (dryRun) {
                if (jsonFlag) {
                    console.log(JSON.stringify({ fixes: fixes.map(f => ({ type: f.type, package: f.package, replacement: f.replacement, detail: f.detail })), dryRun: true }));
                }
                else {
                    logger_1.logger.step(`${fixes.length} fix${fixes.length > 1 ? 'es' : ''} available:`);
                    console.log();
                    for (const f of fixes) {
                        printFixAction(f);
                    }
                    console.log();
                    logger_1.logger.info('run `safenpm fix` without --dry-run to apply');
                    console.log();
                }
                break;
            }
            // Apply fixes
            if (!jsonFlag) {
                logger_1.logger.step(`applying ${fixes.length} fix${fixes.length > 1 ? 'es' : ''}...`);
                console.log();
            }
            const applied = (0, autofix_1.applyAllFixes)(fixes, projectDir);
            const successCount = applied.filter(f => f.applied).length;
            if (jsonFlag) {
                console.log(JSON.stringify({
                    fixes: applied.map(f => ({ type: f.type, package: f.package, replacement: f.replacement, applied: f.applied, detail: f.detail })),
                    applied: successCount,
                }, null, 2));
            }
            else {
                for (const f of applied) {
                    printFixAction(f);
                }
                console.log();
                if (successCount === applied.length) {
                    logger_1.logger.success(`all ${successCount} fixes applied`);
                }
                else {
                    logger_1.logger.warn(`${successCount}/${applied.length} fixes applied`);
                }
                console.log();
            }
            break;
        }
        case 'diff': {
            const jsonFlag = rawArgs.includes('--json');
            const snapshotFlag = rawArgs.includes('--snapshot');
            const nodeModulesPath = path_1.default.join(process.cwd(), 'node_modules');
            if (!fs_1.default.existsSync(nodeModulesPath)) {
                if (jsonFlag) {
                    console.log(JSON.stringify({ error: 'no node_modules found' }));
                }
                else {
                    logger_1.logger.error('no node_modules found — run npm install first');
                }
                process.exit(1);
            }
            if (snapshotFlag) {
                const count = (0, pkgdiff_1.snapshotAllPackages)(nodeModulesPath);
                if (jsonFlag) {
                    console.log(JSON.stringify({ action: 'snapshot', packages: count }));
                }
                else {
                    logger_1.logger.success(`snapshot saved for ${count} packages`);
                    logger_1.logger.info('future runs of `safenpm diff` will compare against this baseline');
                    console.log();
                }
                break;
            }
            if (!jsonFlag) {
                logger_1.logger.banner();
                console.log();
                logger_1.logger.step('comparing packages against previous snapshot...');
                console.log();
            }
            const diffs = (0, pkgdiff_1.diffAllPackages)(nodeModulesPath);
            if (diffs.length === 0) {
                if (jsonFlag) {
                    console.log(JSON.stringify({ diffs: [], message: 'no changes detected' }));
                }
                else {
                    logger_1.logger.success('no changes detected since last snapshot');
                    logger_1.logger.info('run `safenpm diff --snapshot` to save current state');
                    console.log();
                }
                break;
            }
            if (jsonFlag) {
                console.log(JSON.stringify({
                    diffs: diffs.map(d => ({
                        name: d.name,
                        previousVersion: d.previousVersion,
                        currentVersion: d.currentVersion,
                        summary: d.summary,
                        scriptDiff: d.scriptDiff ? {
                            hook: d.scriptDiff.hook,
                            added: d.scriptDiff.added,
                            removed: d.scriptDiff.removed,
                            changed: d.scriptDiff.changed,
                        } : null,
                        depsDiff: d.depsDiff,
                        fileDiff: d.fileDiff ? {
                            added: d.fileDiff.added.length,
                            removed: d.fileDiff.removed.length,
                        } : null,
                    })),
                }, null, 2));
            }
            else {
                for (const d of diffs) {
                    console.log((0, pkgdiff_1.formatDiffForTerminal)(d));
                    console.log();
                }
                logger_1.logger.info(`${diffs.length} package${diffs.length > 1 ? 's' : ''} changed since last snapshot`);
                console.log();
            }
            break;
        }
        case 'audit': {
            const limit = parseInt(rawArgs[0]) || 20;
            const jsonFlag = rawArgs.includes('--json');
            const entries = (0, audit_1.readAuditLog)(limit);
            if (entries.length === 0) {
                if (jsonFlag) {
                    console.log(JSON.stringify([]));
                }
                else {
                    console.log('  no audit entries found');
                    console.log('  run safenpm install to generate audit data');
                }
                break;
            }
            if (jsonFlag) {
                console.log(JSON.stringify(entries, null, 2));
            }
            else {
                console.log();
                console.log(`  \x1b[1mlast ${entries.length} safenpm runs:\x1b[0m`);
                console.log();
                for (const entry of entries) {
                    const date = new Date(entry.timestamp).toLocaleString();
                    const blocked = entry.summary.blocked;
                    const color = blocked > 0 ? '\x1b[31m' : '\x1b[32m';
                    console.log(`  ${date}  ${color}${blocked} blocked\x1b[0m  ${entry.summary.total} total  \x1b[2m${entry.cwd}\x1b[0m`);
                    if (blocked > 0) {
                        for (const pkg of entry.packages) {
                            if (pkg.result === 'blocked') {
                                console.log(`    \x1b[31m✕\x1b[0m ${pkg.name}@${pkg.version} [${pkg.reason}]`);
                            }
                        }
                    }
                }
                console.log();
            }
            break;
        }
        case '--version':
        case '-v':
            console.log('safenpm 0.5.0');
            break;
        case '--help':
        case '-h':
        case undefined:
            console.log(`
  safenpm — sandboxed npm installs

  usage:
    safenpm install [packages...] [options]
    safenpm i [packages...] [options]
    safenpm doctor [--json]
    safenpm fix [--dry-run] [--json]
    safenpm diff [--snapshot] [--json]
    safenpm scan [--json]
    safenpm audit [--json]

  options:
    --dry-run, -n         show what would be sandboxed/fixed without running
    --allow <pkg,...>     skip sandboxing for trusted packages
    --json                machine-readable JSON output (for CI)
    --interactive, -I     prompt on each blocked package: retry / skip / abort
    --loose               network-only sandbox (no filesystem restrictions)
    --scan, -S            enable deep scan (typosquat, diffing, intel, lockfile, reputation)
    --no-report           disable anonymous signal reporting

  commands:
    install / i           install packages with sandboxing
    doctor                health report card with letter grade + actionable fixes
    fix                   auto-fix typosquats and remove malicious packages
    diff                  show what changed in dependencies since last snapshot
    diff --snapshot       save current state as baseline for future diffs
    scan                  standalone deep scan (no install)
    audit                 view recent safenpm run history

  examples:
    safenpm install axios
    safenpm i --scan                         (full security scan)
    safenpm doctor                           (project health grade)
    safenpm doctor --json                    (CI-friendly health check)
    safenpm fix --dry-run                    (preview auto-fixes)
    safenpm fix                              (apply fixes)
    safenpm diff --snapshot                  (save baseline)
    safenpm diff                             (show changes since baseline)
    safenpm i --allow bcrypt,sharp           (trust specific packages)
    safenpm i --interactive                  (prompt on blocks)
    safenpm i --json                         (CI-friendly output)
    safenpm scan --json                      (analysis only)
    safenpm audit                            (view recent runs)
      `);
            break;
        default:
            console.error(`  unknown command: ${command}`);
            console.error(`  run safenpm --help for usage`);
            process.exit(1);
    }
}
// ── Doctor report printer ──
function printDoctorReport(report) {
    const RESET = '\x1b[0m';
    const BOLD = '\x1b[1m';
    const DIM = '\x1b[2m';
    const RED = '\x1b[31m';
    const GREEN = '\x1b[32m';
    const YELLOW = '\x1b[33m';
    const CYAN = '\x1b[36m';
    const BLUE = '\x1b[34m';
    // Grade display
    const gradeColor = report.score >= 80 ? GREEN : report.score >= 60 ? YELLOW : RED;
    console.log(`  ${gradeColor}${BOLD}Grade: ${report.grade}${RESET}  ${DIM}(${report.score}/100)${RESET}`);
    console.log(`  ${DIM}${report.summary}${RESET}`);
    console.log();
    // Section details
    for (const section of report.sections) {
        const sColor = section.status === 'pass' ? GREEN : section.status === 'warn' ? YELLOW : RED;
        const sIcon = section.status === 'pass' ? '✓' : section.status === 'warn' ? '!' : '✕';
        console.log(`  ${sColor}${sIcon}${RESET} ${BOLD}${section.name}${RESET} ${DIM}${section.score}/100${RESET}`);
        for (const finding of section.findings) {
            const fColor = finding.severity === 'critical' ? RED
                : finding.severity === 'warning' ? YELLOW
                    : finding.severity === 'pass' ? GREEN : DIM;
            const fIcon = finding.severity === 'critical' ? '  ✕'
                : finding.severity === 'warning' ? '  !'
                    : finding.severity === 'pass' ? '  ✓' : '  ·';
            console.log(`  ${fColor}${fIcon}${RESET} ${finding.message}`);
            if (finding.fix) {
                console.log(`      ${CYAN}fix:${RESET} ${DIM}${finding.fix}${RESET}`);
            }
        }
        console.log();
    }
    // Auto-fix suggestions
    if (report.fixes.length > 0) {
        console.log(`  ${CYAN}→${RESET} ${report.fixes.length} auto-fixable issue${report.fixes.length > 1 ? 's' : ''} found`);
        console.log(`  ${DIM}run \`safenpm fix\` to apply, or \`safenpm fix --dry-run\` to preview${RESET}`);
        console.log();
    }
}
// ── Fix action printer ──
function printFixAction(fix) {
    const RESET = '\x1b[0m';
    const BOLD = '\x1b[1m';
    const DIM = '\x1b[2m';
    const RED = '\x1b[31m';
    const GREEN = '\x1b[32m';
    const CYAN = '\x1b[36m';
    if (fix.type === 'replace-typosquat') {
        const status = fix.applied ? `${GREEN}✓${RESET}` : `${CYAN}→${RESET}`;
        console.log(`  ${status} ${RED}${fix.package}${RESET} → ${GREEN}${fix.replacement}${RESET} ${DIM}(typosquat)${RESET}`);
    }
    else {
        const status = fix.applied ? `${GREEN}✓${RESET}` : `${CYAN}→${RESET}`;
        console.log(`  ${status} remove ${RED}${fix.package}@${fix.version}${RESET} ${DIM}(${fix.detail})${RESET}`);
    }
}
main().catch(err => {
    console.error('  error:', err.message);
    process.exit(1);
});
