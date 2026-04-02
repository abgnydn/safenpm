"use strict";
/**
 * Shared utility for discovering package names from node_modules.
 * Extracted to avoid duplication across cli.ts, install.ts, and doctor.ts.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getAllPackageNames = getAllPackageNames;
exports.validatePackageName = validatePackageName;
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
/**
 * Get all package names from a node_modules directory.
 * Handles both flat packages and scoped (@scope/pkg) packages.
 */
function getAllPackageNames(nodeModulesPath) {
    const names = [];
    try {
        const entries = fs_1.default.readdirSync(nodeModulesPath);
        for (const entry of entries) {
            if (entry.startsWith('.'))
                continue;
            if (entry.startsWith('@')) {
                try {
                    const scopeEntries = fs_1.default.readdirSync(path_1.default.join(nodeModulesPath, entry));
                    for (const se of scopeEntries) {
                        if (!se.startsWith('.')) {
                            names.push(`${entry}/${se}`);
                        }
                    }
                }
                catch { /* skip unreadable scope dirs */ }
            }
            else {
                names.push(entry);
            }
        }
    }
    catch { /* skip if node_modules unreadable */ }
    return names;
}
/**
 * Validate a package name against npm naming rules.
 * Returns null if valid, or an error message if invalid.
 */
function validatePackageName(name) {
    // npm package name rules:
    // - max 214 chars
    // - can't start with . or _
    // - no uppercase
    // - URL-safe characters only
    // - scoped packages: @scope/name
    const VALID_PKG_NAME = /^(@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;
    if (name.length > 214) {
        return `Package name too long (${name.length} chars, max 214)`;
    }
    if (name.length === 0) {
        return 'Package name cannot be empty';
    }
    // Allow glob wildcards for allowlist entries (e.g. @scope/*)
    const nameForValidation = name.replace(/\/\*$/, '/placeholder');
    if (!VALID_PKG_NAME.test(nameForValidation)) {
        return `Invalid package name: ${name}`;
    }
    return null;
}
