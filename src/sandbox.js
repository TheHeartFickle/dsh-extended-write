/**
 * Extended local sandbox provider: the stock `LocalSandboxProvider` whose
 * per-runner profiles bind the policy's `extraWriteRoots` alongside the
 * workspace, and whose windows-acl rung wraps a runner accepting repeatable
 * `--extra-root <dir>`. Extra roots share the workspace capability SID, so
 * the restricted token's restricting-SID list is unchanged from stock and the
 * standing ACEs reuse the workspace grant.
 *
 * Failure posture: whenever the extension machinery is not usable — grant
 * internals missing after an in-family upgrade, no usable extra roots, a
 * `runnerCommand`-configured deployment — the stock argv builder takes over,
 * so the tier degrades to the official profile instead of failing every
 * command. A stock-argv fallback requires the stock builders themselves; if
 * those disappeared, confinement fails loudly (never silently unconfined).
 *
 * Known limitation inherited from the stock shape: a configured
 * `runnerCommand` bypasses the platform profiles and never carries extra
 * roots (the stock private builder speaks plain bwrap only).
 *
 * @module @the-heart-fickle/dsh-extended-write/sandbox
 */
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { grantArgs } from "@deepseek-ai/node-addon-system/landlock-run";
import { canonicalPath, writableRoots } from "@deepseek-ai/dsh-sandbox";
import { LocalSandboxProvider } from "@deepseek-ai/dsh-sandbox-local";
import { workspaceWriteSid } from "@deepseek-ai/dsh-sandbox-windows-acl";

/** Quote one path as an SBPL string literal (stock dialect). */
function sbplString(path) {
	return `"${path.replaceAll("\\", String.raw`\\`).replaceAll("\"", String.raw`\"`)}"`;
}
function bwrapProfileArgs(policy, extraRoots) {
	const args = [
		"--ro-bind", "/", "/",
		"--dev", "/dev",
		"--unshare-pid",
		"--proc", "/proc",
		"--die-with-parent"
	];
	if (policy.mode === "workspace-write") {
		args.push("--tmpfs", "/tmp");
		args.push("--bind", policy.workspaceRoot, policy.workspaceRoot);
		for (const root of extraRoots) args.push("--bind", root, root);
	}
	return args;
}
function landlockProfileArgs(policy, extraRoots) {
	const readWrite = ["/dev/null"];
	if (policy.mode === "workspace-write") readWrite.push("/tmp", policy.workspaceRoot, ...extraRoots);
	return grantArgs({
		readOnly: ["/"],
		readWrite
	});
}
function seatbeltProfileArgs(policy, extraRoots) {
	const forms = [
		"(version 1)",
		"(allow default)",
		"(deny file-write*)",
		`(allow file-write* (literal ${sbplString("/dev/null")}))`
	];
	const roots = [...writableRoots(policy), ...extraRoots];
	if (roots.length > 0) forms.push(`(allow file-write* ${roots.map((root) => `(subpath ${sbplString(root)})`).join(" ")})`);
	return ["-p", forms.join(" ")];
}

export default class ExtendedLocalSandboxProvider extends LocalSandboxProvider {
	// Ordinary property, never a #private field: cordis exposes services
	// through proxies, and a proxy cannot carry a private-field brand.
	warnedMissingRoots = new Set();
	warnedFallbacks = new Set();
	constructor(ctx, config) {
		super(ctx, config);
		this.internals.windowsAclRunnerArgs = [process.execPath, fileURLToPath(new URL("./runner.js", import.meta.url))];
	}
	/** Warn once per key; loading never throws on a degraded extension. */
	warnOnce(key, message) {
		if (this.warnedFallbacks.has(key)) return;
		this.warnedFallbacks.add(key);
		this.ctx.logger?.warn(`extended-write: ${message}`);
	}
	/**
	 * Usable extra roots for one policy: canonical and existing,
	 * `workspace-write` only, and only while the grant machinery they rely on
	 * is present. A not-yet-existing root (a first tool run creates it)
	 * degrades that root to denied instead of failing every command.
	 */
	extraRootsOf(policy) {
		const configured = policy.extraWriteRoots;
		if (configured === void 0 || configured.length === 0 || policy.mode !== "workspace-write") return [];
		const usable = [];
		for (const root of configured) {
			const canonical = canonicalPath(root);
			if (!existsSync(canonical)) {
				if (!this.warnedMissingRoots.has(canonical)) {
					this.warnedMissingRoots.add(canonical);
					this.ctx.logger?.warn(`extended-write: extra write root does not exist yet; writes there stay denied until it appears: ${canonical}`);
				}
				continue;
			}
			usable.push(canonical);
		}
		return usable;
	}
	/**
	 * Extra roots that may be woven into a runner profile: `extraRootsOf`
	 * plus an integrity check on the grant machinery they ride on. When the
	 * machinery is gone (in-family stock drift), the extension drops to zero
	 * roots and the caller falls back to the pure stock profile.
	 */
	usableExtraRoots(policy) {
		const extras = this.extraRootsOf(policy);
		if (extras.length === 0) return [];
		if (typeof super.materializeAclGrant !== "function" || !(this.workspaceGrants instanceof Map)) {
			this.warnOnce("grant-machinery", "stock grant machinery unavailable; falling back to the stock profile without extra roots");
			return [];
		}
		return extras;
	}
	/** Stock dispatch with the extra roots woven into each runner's profile. */
	runnerArgv(runner, policy) {
		if (runner === "windows-acl") {
			const extraRoots = this.usableExtraRoots(policy);
			if (extraRoots.length === 0) return super.windowsAclRunnerArgv(policy);
			return this.extendedWindowsAclRunnerArgv(policy, extraRoots);
		}
		const extraRoots = this.extraRootsOf(policy);
		switch (runner) {
			case "bwrap": return ["bwrap", ...bwrapProfileArgs(policy, extraRoots)];
			case "landlock":
				if (typeof super.landlockLauncher !== "function") return super.runnerArgv(runner, policy);
				return [this.landlockLauncher(), ...landlockProfileArgs(policy, extraRoots)];
			case "seatbelt":
				if (typeof super.seatbeltExec !== "function") return super.runnerArgv(runner, policy);
				return [this.seatbeltExec(), ...seatbeltProfileArgs(policy, extraRoots)];
			default: return super.runnerArgv(runner, policy);
		}
	}
	/**
	 * The stock windows-acl argv plus one `--extra-root <dir>` repeat per
	 * usable extra root. The capability SIDs are unchanged: extras share the
	 * workspace SID, which the runner grants onto every writable directory.
	 */
	extendedWindowsAclRunnerArgv(policy, extraRoots) {
		const sessionId = policy.sessionId;
		if (sessionId === void 0 || policy.mode === "read-only") {
			return [
				...this.windowsAclRunnerInvocation(),
				"--workspace", policy.workspaceRoot,
				"--temp", tmpdir(),
				"--mode", policy.mode,
				...extraRoots.flatMap((root) => ["--extra-root", root])
			];
		}
		const temp = this.materializeAclGrant(sessionId, policy.workspaceRoot, extraRoots);
		return [
			...this.windowsAclRunnerInvocation(),
			"--workspace", policy.workspaceRoot,
			"--temp", temp.dir,
			"--mode", policy.mode,
			"--write-sid", workspaceWriteSid(policy.workspaceRoot),
			"--temp-write-sid", temp.writeSid,
			...extraRoots.flatMap((root) => ["--extra-root", root])
		];
	}
	/**
	 * The stock grant materialization: the standing workspace grant
	 * additionally carries an ACE per extra root (same capability SID; `add`
	 * is idempotent, so repeated confines skip already-standing ACEs).
	 */
	materializeAclGrant(sessionId, workspaceRoot, extraRoots = []) {
		const temp = super.materializeAclGrant(sessionId, workspaceRoot);
		if (extraRoots.length > 0) {
			const grant = this.workspaceGrants.get(workspaceRoot);
			for (const root of extraRoots) grant.add(root, true);
		}
		return temp;
	}
}
