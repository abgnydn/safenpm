"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.logger = void 0;
const analyzer_1 = require("./analyzer");
function timeSince(iso) {
    const ms = Date.now() - new Date(iso).getTime();
    const mins = Math.floor(ms / 60000);
    if (mins < 1)
        return 'just now';
    if (mins < 60)
        return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24)
        return `${hrs}h ago`;
    const days = Math.floor(hrs / 24);
    return `${days}d ago`;
}
const RESET = '\x1b[0m';
const DIM = '\x1b[2m';
const BOLD = '\x1b[1m';
const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const CYAN = '\x1b[36m';
const BLUE = '\x1b[34m';
const MAGENTA = '\x1b[35m';
exports.logger = {
    info(msg) {
        console.log(`${DIM}  ${msg}${RESET}`);
    },
    step(msg) {
        console.log(`${CYAN}  →${RESET} ${msg}`);
    },
    success(msg) {
        console.log(`${GREEN}  ✓${RESET} ${msg}`);
    },
    warn(msg) {
        console.log(`${YELLOW}  ⚠${RESET}  ${msg}`);
    },
    error(msg) {
        console.log(`${RED}  ✕${RESET} ${msg}`);
    },
    blocked(pkgName, version, hook, reason = 'network') {
        console.log();
        console.log(`${RED}  ✕ blocked${RESET}  ${BOLD}${pkgName}@${version}${RESET}`);
        console.log(`${DIM}    hook:   ${hook}${RESET}`);
        const reasonText = reason === 'network'
            ? 'attempted network access during install'
            : reason === 'filesystem'
                ? 'attempted to access restricted files'
                : `script exited with error (${reason})`;
        console.log(`${DIM}    reason: ${reasonText}${RESET}`);
        console.log(`${DIM}    signal: reported anonymously to safenpm network${RESET}`);
        console.log();
    },
    allowed(pkgName, version) {
        console.log(`${GREEN}  ✓ clean${RESET}   ${pkgName}@${version}`);
    },
    skipped(pkgName, version) {
        console.log(`${BLUE}  ↳ allow${RESET}   ${pkgName}@${version} ${DIM}(allowlisted)${RESET}`);
    },
    // ── Analysis output ──
    analysisHeader() {
        console.log();
        console.log(`${CYAN}  →${RESET} static analysis of install scripts...`);
        console.log();
    },
    analysisResult(result) {
        const level = (0, analyzer_1.riskLevel)(result.riskScore);
        const color = level === 'critical' ? RED
            : level === 'suspicious' ? YELLOW
                : level === 'low' ? BLUE
                    : GREEN;
        const icon = level === 'critical' ? '⚠'
            : level === 'suspicious' ? '!'
                : level === 'low' ? '·'
                    : '✓';
        console.log(`  ${color}${icon}${RESET} ${BOLD}${result.pkg.name}@${result.pkg.version}${RESET} ${DIM}risk: ${result.riskScore}/100${RESET}`);
        for (const w of result.warnings) {
            const wColor = w.severity === 'high' ? RED : w.severity === 'medium' ? YELLOW : DIM;
            console.log(`    ${wColor}${w.severity.toUpperCase().padEnd(6)}${RESET} ${w.description}`);
        }
    },
    // ── Typosquat output ──
    typosquatHeader() {
        console.log();
        console.log(`${CYAN}  →${RESET} typosquat detection...`);
        console.log();
    },
    typosquatResult(r) {
        const color = r.confidence === 'high' ? RED : r.confidence === 'medium' ? YELLOW : BLUE;
        const icon = r.confidence === 'high' ? '⚠' : r.confidence === 'medium' ? '!' : '?';
        console.log(`  ${color}${icon}${RESET} ${BOLD}${r.suspect}${RESET} → looks like ${CYAN}${r.target}${RESET}`);
        console.log(`    ${DIM}technique: ${r.technique}  distance: ${r.distance}  confidence: ${r.confidence}${RESET}`);
    },
    // ── Behavioral diff output ──
    diffHeader() {
        console.log();
        console.log(`${CYAN}  →${RESET} behavioral diffing...`);
        console.log();
    },
    diffResult(d) {
        if (d.isNewPackage) {
            console.log(`  ${YELLOW}!${RESET} ${BOLD}${d.name}@${d.currentVersion}${RESET} ${DIM}(new package with install scripts)${RESET}`);
        }
        else {
            console.log(`  ${RED}⚠${RESET} ${BOLD}${d.name}${RESET} ${DIM}${d.previousVersion} → ${d.currentVersion}${RESET}`);
        }
        if (d.newWarnings.length > 0) {
            console.log(`    ${RED}new warnings:${RESET} ${d.newWarnings.join(', ')}`);
        }
        if (d.riskDelta > 0) {
            console.log(`    ${RED}risk increased:${RESET} +${d.riskDelta}`);
        }
    },
    // ── Threat intel output ──
    threatIntelHeader() {
        console.log();
        console.log(`${CYAN}  →${RESET} querying threat intelligence network...`);
        console.log();
    },
    threatIntelResult(r) {
        if (r.flagged) {
            console.log(`  ${RED}⚠ COMMUNITY ALERT${RESET}  ${BOLD}${r.name}@${r.version}${RESET}`);
            console.log(`    ${MAGENTA}INTEL ${RESET} ${r.reportCount} report${r.reportCount !== 1 ? 's' : ''} from other developers`);
            if (r.topReasons.length > 0) {
                console.log(`    ${MAGENTA}INTEL ${RESET} top reason: ${r.topReasons[0]}`);
                if (r.topReasons.length > 1) {
                    console.log(`    ${DIM}       also: ${r.topReasons.slice(1).join(', ')}${RESET}`);
                }
            }
            if (r.firstSeen && r.lastSeen) {
                const ago = timeSince(r.lastSeen);
                console.log(`    ${DIM}       first seen: ${r.firstSeen.split('T')[0]}  last report: ${ago}${RESET}`);
            }
            console.log(`    ${YELLOW}→${RESET} This package was flagged by the safenpm community network.`);
            console.log(`    ${YELLOW}→${RESET} Consider removing it or verifying it is legitimate.`);
            console.log();
        }
    },
    // ── Maintainer change output ──
    maintainerHeader() {
        console.log();
        console.log(`${CYAN}  →${RESET} maintainer change detection...`);
        console.log();
    },
    maintainerResult(r) {
        if (r.maintainerChanged) {
            console.log(`  ${RED}⚠${RESET} ${BOLD}${r.name}@${r.version}${RESET} publisher changed`);
            console.log(`    ${DIM}${r.previousPublisher} → ${RED}${r.currentPublisher}${RESET}`);
        }
    },
    // ── Lockfile audit output ──
    lockfileHeader() {
        console.log();
        console.log(`${CYAN}  →${RESET} lockfile integrity audit...`);
        console.log();
    },
    lockfileResult(result) {
        if (!result.exists) {
            console.log(`  ${YELLOW}!${RESET} no package-lock.json found`);
            return;
        }
        const color = result.score >= 80 ? GREEN : result.score >= 50 ? YELLOW : RED;
        console.log(`  ${color}score: ${result.score}/100${RESET} ${DIM}(${result.totalPackages} packages, ${result.format})${RESET}`);
        const significant = result.issues.filter(i => i.severity === 'high' || i.severity === 'medium');
        for (const issue of significant.slice(0, 5)) {
            const iColor = issue.severity === 'high' ? RED : YELLOW;
            console.log(`    ${iColor}${issue.severity.toUpperCase().padEnd(6)}${RESET} ${issue.package}: ${issue.detail}`);
        }
        if (significant.length > 5) {
            console.log(`    ${DIM}...and ${significant.length - 5} more${RESET}`);
        }
    },
    // ── Reputation output ──
    reputationHeader() {
        console.log();
        console.log(`${CYAN}  →${RESET} dependency reputation scoring...`);
        console.log();
    },
    reputationResult(summary) {
        const color = summary.overallScore >= 70 ? GREEN : summary.overallScore >= 40 ? YELLOW : RED;
        console.log(`  ${color}overall: ${summary.overallScore}/100${RESET} ${DIM}(${summary.totalPackages} packages, avg ${summary.averageScore})${RESET}`);
        const tierLine = Object.entries(summary.tiers)
            .map(([tier, count]) => {
            const c = tier === 'trusted' ? GREEN : tier === 'established' ? BLUE : tier === 'risky' ? RED : DIM;
            return `${c}${count} ${tier}${RESET}`;
        })
            .join(', ');
        if (tierLine)
            console.log(`  ${DIM}tiers:${RESET} ${tierLine}`);
        if (summary.riskiest.length > 0 && summary.riskiest[0].score < 40) {
            console.log(`  ${DIM}riskiest:${RESET}`);
            for (const r of summary.riskiest.slice(0, 3)) {
                if (r.score < 40) {
                    console.log(`    ${RED}${r.score}${RESET} ${r.name}@${r.version} ${DIM}(${r.tier})${RESET}`);
                }
            }
        }
    },
    // ── Dry run ──
    dryRunItem(pkgName, version, hook, script, isAllowed) {
        const status = isAllowed
            ? `${BLUE}allow${RESET}`
            : `${YELLOW}sandbox${RESET}`;
        console.log(`  ${status}  ${BOLD}${pkgName}@${version}${RESET}`);
        console.log(`${DIM}          [${hook}] ${script}${RESET}`);
    },
    banner() {
        console.log();
        console.log(`${BOLD}  safenpm${RESET} ${DIM}— sandboxed installs${RESET}`);
        console.log();
    },
    dryRunBanner() {
        console.log();
        console.log(`${BOLD}  safenpm${RESET} ${DIM}— dry run (no scripts will be executed)${RESET}`);
        console.log();
    },
    summary(total, blocked, skippedCount = 0, warningCount = 0) {
        console.log();
        const parts = [];
        if (blocked > 0) {
            parts.push(`${RED}${blocked} blocked${RESET}`);
        }
        if (skippedCount > 0) {
            parts.push(`${BLUE}${skippedCount} allowlisted${RESET}`);
        }
        const clean = total - blocked - skippedCount;
        if (clean > 0) {
            parts.push(`${GREEN}${clean} clean${RESET}`);
        }
        if (warningCount > 0) {
            parts.push(`${YELLOW}${warningCount} warnings${RESET}`);
        }
        if (blocked === 0) {
            console.log(`${GREEN}  ${BOLD}all clear${RESET} — ${total} script${total !== 1 ? 's' : ''} processed${parts.length ? ` (${parts.join(', ')})` : ''}`);
        }
        else {
            console.log(`${RED}  ${BOLD}${blocked} blocked${RESET}${RED} out of ${total} install script${total !== 1 ? 's' : ''}${RESET}`);
            if (parts.length) {
                console.log(`${DIM}  breakdown: ${parts.join(', ')}${RESET}`);
            }
            console.log(`${DIM}  signals reported to safenpm network${RESET}`);
        }
        console.log();
    },
    backendInfo(name) {
        console.log(`${DIM}  sandbox: ${name}${RESET}`);
    },
    allowlistInfo(count) {
        if (count > 0) {
            console.log(`${DIM}  allowlist: ${count} package${count !== 1 ? 's' : ''} whitelisted${RESET}`);
        }
    },
    auditInfo() {
        console.log(`${DIM}  audit log: ~/.safenpm/audit.log${RESET}`);
    },
    // ── Interactive prompt ──
    interactivePrompt(pkgName, version, hook) {
        const readline = require('readline');
        const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
        console.log();
        console.log(`${YELLOW}  ⚠${RESET}  ${BOLD}${pkgName}@${version}${RESET} was ${RED}blocked${RESET} [${hook}]`);
        console.log(`${DIM}    choose: [r]etry without sandbox / [s]kip / [a]bort${RESET}`);
        // synchronous prompt — we use spawnSync trick
        const result = require('child_process').spawnSync('bash', ['-c', 'read -n 1 -p "    > " choice && echo $choice'], {
            stdio: ['inherit', 'pipe', 'inherit'],
            encoding: 'utf8',
        });
        const choice = (result.stdout || '').trim().toLowerCase();
        console.log();
        return choice;
    },
};
