"use strict";
/**
 * Auto-fix — when a typosquat or malicious package is detected,
 * automatically replace it with the legitimate version.
 *
 * Handles:
 *   - Typosquat replacement: remove suspect, install target
 *   - Malicious package removal: uninstall blocked packages
 *   - package.json cleanup: update deps/devDeps entries
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateFixes = generateFixes;
exports.applyFix = applyFix;
exports.applyAllFixes = applyAllFixes;
exports.previewFixes = previewFixes;
const child_process_1 = require("child_process");
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
/**
 * Generate fix actions from scan/install results.
 * Does NOT apply them — call applyFixes() to execute.
 */
function generateFixes(typosquats, blockedResults) {
    const fixes = [];
    // Typosquat replacements
    for (const t of typosquats) {
        if (t.confidence === 'high' || t.confidence === 'medium') {
            fixes.push({
                type: 'replace-typosquat',
                package: t.suspect,
                version: 'latest',
                replacement: t.target,
                applied: false,
                detail: `Replace ${t.suspect} with ${t.target} (${t.technique}, ${t.confidence} confidence)`,
            });
        }
    }
    // Remove blocked malicious packages
    for (const r of blockedResults) {
        if (r.blocked && (r.reason === 'network' || r.reason === 'filesystem')) {
            fixes.push({
                type: 'remove-malicious',
                package: r.pkg.name,
                version: r.pkg.version,
                replacement: null,
                applied: false,
                detail: `Remove ${r.pkg.name}@${r.pkg.version} (blocked: ${r.reason})`,
            });
        }
    }
    return fixes;
}
/**
 * Apply a single fix action.
 * Returns updated action with applied=true/false.
 */
function applyFix(fix, projectDir) {
    const pkgJsonPath = path_1.default.join(projectDir, 'package.json');
    switch (fix.type) {
        case 'replace-typosquat': {
            // Step 1: Remove the typosquat from node_modules and package.json
            const removeResult = (0, child_process_1.spawnSync)('npm', ['uninstall', fix.package], {
                cwd: projectDir,
                encoding: 'utf8',
                stdio: 'pipe',
                timeout: 30000,
            });
            if (removeResult.status !== 0) {
                // Try manual removal if npm uninstall fails
                manualRemove(fix.package, projectDir, pkgJsonPath);
            }
            // Step 2: Install the legitimate package
            if (fix.replacement) {
                const installResult = (0, child_process_1.spawnSync)('npm', ['install', '--ignore-scripts', fix.replacement], {
                    cwd: projectDir,
                    encoding: 'utf8',
                    stdio: 'pipe',
                    timeout: 60000,
                });
                fix.applied = installResult.status === 0;
            }
            else {
                fix.applied = true;
            }
            break;
        }
        case 'remove-malicious': {
            const result = (0, child_process_1.spawnSync)('npm', ['uninstall', fix.package], {
                cwd: projectDir,
                encoding: 'utf8',
                stdio: 'pipe',
                timeout: 30000,
            });
            if (result.status !== 0) {
                manualRemove(fix.package, projectDir, pkgJsonPath);
            }
            fix.applied = true;
            break;
        }
    }
    return fix;
}
/**
 * Apply all fixes in sequence.
 */
function applyAllFixes(fixes, projectDir) {
    return fixes.map(f => applyFix(f, projectDir));
}
/**
 * Manual removal: delete from node_modules and strip from package.json.
 * Used when npm uninstall fails (e.g., corrupted state).
 */
function manualRemove(name, projectDir, pkgJsonPath) {
    // Remove from node_modules
    const nmPath = name.startsWith('@')
        ? path_1.default.join(projectDir, 'node_modules', name)
        : path_1.default.join(projectDir, 'node_modules', name);
    try {
        if (fs_1.default.existsSync(nmPath)) {
            fs_1.default.rmSync(nmPath, { recursive: true, force: true });
        }
    }
    catch { /* best effort */ }
    // Strip from package.json
    try {
        if (fs_1.default.existsSync(pkgJsonPath)) {
            const pkgJson = JSON.parse(fs_1.default.readFileSync(pkgJsonPath, 'utf8'));
            let changed = false;
            for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
                if (pkgJson[field] && pkgJson[field][name]) {
                    delete pkgJson[field][name];
                    changed = true;
                }
            }
            if (changed) {
                fs_1.default.writeFileSync(pkgJsonPath, JSON.stringify(pkgJson, null, 2) + '\n', 'utf8');
            }
        }
    }
    catch { /* best effort */ }
}
/**
 * Preview what would be fixed without applying anything.
 */
function previewFixes(fixes) {
    return fixes.map(f => {
        if (f.type === 'replace-typosquat') {
            return `replace ${f.package} → ${f.replacement}`;
        }
        return `remove ${f.package}@${f.version}`;
    });
}
