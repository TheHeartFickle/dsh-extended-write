/**
 * Extended sandboxed filesystem: the stock `SandboxedFileSystem` whose
 * mutation fence also honors `policy.extraWriteRoots` (canonical roots from
 * the extended sandbox policy). Containment mechanics mirror the stock fence:
 * canonical lexical prefix first, filesystem identity as the alias-safe
 * fallback for Windows 8.3 names and casing.
 *
 * @module @the-heart-fickle/dsh-extended-write/fs
 */
import { FsError } from "@deepseek-ai/dsh-fs";
import { writableRoots } from "@deepseek-ai/dsh-sandbox";
import { SandboxedFileSystem } from "@deepseek-ai/dsh-fs-sandbox";
import { stat } from "node:fs/promises";
import { dirname, sep } from "node:path";

const MISSING_CODES = new Set(["ENOENT", "ENOTDIR"]);
function comparablePath(path, caseSensitive) {
	return caseSensitive ? path : path.toLowerCase();
}
function isLexicallyUnder(path, root, caseSensitive) {
	const comparableTarget = comparablePath(path, caseSensitive);
	const comparableRoot = comparablePath(root, caseSensitive);
	if (comparableTarget === comparableRoot) return true;
	const prefix = comparableRoot.endsWith(sep) ? comparableRoot : comparableRoot + sep;
	return comparableTarget.startsWith(prefix);
}
async function statIfPresent(path) {
	try {
		return await stat(path, { bigint: true });
	} catch (error) {
		if (MISSING_CODES.has(error.code)) return void 0;
		throw error;
	}
}
function sameIdentity(left, right) {
	return left.dev === right.dev && left.ino === right.ino;
}
/**
 * Whether a canonical target is a root or lies beneath it (call-for-call
 * mirror of the stock fence's containment helper).
 */
async function isPathUnder(path, root, caseSensitive = process.platform !== "win32") {
	if (isLexicallyUnder(path, root, caseSensitive)) return true;
	const rootInfo = await statIfPresent(root);
	if (!rootInfo) return false;
	let ancestor = path;
	while (true) {
		const ancestorInfo = await statIfPresent(ancestor);
		if (ancestorInfo && sameIdentity(ancestorInfo, rootInfo)) return true;
		const parent = dirname(ancestor);
		if (parent === ancestor) return false;
		ancestor = parent;
	}
}

export default class ExtendedSandboxedFileSystem extends SandboxedFileSystem {
	/**
	 * The stock fence widened by `policy.extraWriteRoots`: the fresh resolved
	 * target must fall under a stock writable root or a configured extra root;
	 * the fresh target is returned so the checked identity is the mutated one.
	 */
	async checkedTarget(target, sandboxPolicy) {
		const policy = sandboxPolicy ?? this.ctx.sandboxPolicy.resolve();
		const { mode } = policy;
		if (mode === "danger-full-access") return target;
		if (mode === "read-only") throw new FsError(`cannot write "${target.displayPath}": file access denied under read-only mode`, "FS_SANDBOX_DENIED");
		const extraRoots = policy.extraWriteRoots ?? [];
		const roots = extraRoots.length === 0 ? writableRoots(policy) : [...writableRoots(policy), ...extraRoots];
		const fresh = await this.resolve(target.displayPath);
		for (const root of roots) if (await isPathUnder(fresh.targetKey, root)) return fresh;
		throw new FsError(`cannot write "${target.displayPath}": file access denied under ${mode} mode`, "FS_SANDBOX_DENIED");
	}
}
