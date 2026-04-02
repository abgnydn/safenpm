"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.loadAllowlist = loadAllowlist;
exports.isAllowed = isAllowed;
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const os_1 = __importDefault(require("os"));
const RC_FILENAME = '.safenpmrc';
/**
 * Load the allowlist from all sources:
 *  1. --allow flags passed on the CLI
 *  2. .safenpmrc in the project root (cwd)
 *  3. ~/.safenpmrc in the home directory
 *
 * File format: one package name per line, # comments, blank lines ignored
 *
 * Example .safenpmrc:
 *   # native addons we trust
 *   bcrypt
 *   sharp
 *   @mapbox/node-pre-gyp
 */
function loadAllowlist(cliAllows) {
    const set = new Set();
    // CLI flags first
    for (const name of cliAllows) {
        set.add(name.trim());
    }
    // Project-level rc
    const projectRc = path_1.default.join(process.cwd(), RC_FILENAME);
    mergeFromFile(projectRc, set);
    // User-level rc
    const userRc = path_1.default.join(os_1.default.homedir(), RC_FILENAME);
    mergeFromFile(userRc, set);
    return set;
}
function mergeFromFile(filePath, set) {
    try {
        if (!fs_1.default.existsSync(filePath))
            return;
        const content = fs_1.default.readFileSync(filePath, 'utf8');
        for (const raw of content.split('\n')) {
            const line = raw.trim();
            if (!line || line.startsWith('#'))
                continue;
            set.add(line);
        }
    }
    catch {
        // silently ignore unreadable rc files
    }
}
function isAllowed(packageName, allowlist) {
    if (allowlist.has(packageName))
        return true;
    // support scope-level wildcards: --allow @mycompany/*
    for (const entry of allowlist) {
        if (entry.endsWith('/*')) {
            const scope = entry.slice(0, -2);
            if (packageName.startsWith(scope + '/'))
                return true;
        }
    }
    return false;
}
