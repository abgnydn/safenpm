"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.findInstallScripts = findInstallScripts;
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const HOOKS = ['preinstall', 'install', 'postinstall', 'prepare'];
function findInstallScripts(nodeModulesPath) {
    const results = [];
    if (!fs_1.default.existsSync(nodeModulesPath))
        return results;
    const entries = fs_1.default.readdirSync(nodeModulesPath, { withFileTypes: true });
    for (const entry of entries) {
        if (!entry.isDirectory())
            continue;
        if (entry.name.startsWith('.'))
            continue;
        if (entry.name.startsWith('@')) {
            // scoped package — go one level deeper
            const scopePath = path_1.default.join(nodeModulesPath, entry.name);
            const scoped = fs_1.default.readdirSync(scopePath, { withFileTypes: true });
            for (const s of scoped) {
                if (!s.isDirectory())
                    continue;
                probe(path_1.default.join(scopePath, s.name), `${entry.name}/${s.name}`, results);
            }
        }
        else {
            probe(path_1.default.join(nodeModulesPath, entry.name), entry.name, results);
        }
    }
    return results;
}
function probe(pkgPath, fallbackName, out) {
    const pkgJsonPath = path_1.default.join(pkgPath, 'package.json');
    if (!fs_1.default.existsSync(pkgJsonPath))
        return;
    let pkg;
    try {
        pkg = JSON.parse(fs_1.default.readFileSync(pkgJsonPath, 'utf8'));
    }
    catch {
        return;
    }
    for (const hook of HOOKS) {
        const script = pkg?.scripts?.[hook];
        if (typeof script === 'string' && script.trim()) {
            out.push({
                name: pkg.name ?? fallbackName,
                version: pkg.version ?? 'unknown',
                path: pkgPath,
                script,
                hook,
            });
            break; // only take the first matching hook per package
        }
    }
}
