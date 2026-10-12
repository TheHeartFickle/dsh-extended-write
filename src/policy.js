/**
 * Extended sandbox policy: the stock `SandboxPolicyService` plus a configured
 * list of extra writable roots that ride the resolved policy while the calling
 * session's effective permission preset is the configured extended preset (or
 * unconditionally under `always`).
 *
 * Writes no new session vocabulary: the mode stays the stock
 * `workspace-write`, and the switch rides the stock `permission/preset`
 * event's plain-string preset identity (`permissionStateSchema.preset` is
 * `z.string()`), so a stock build replays every session and derives a normal
 * preset from the unchanged knob values.
 *
 * @module @the-heart-fickle/dsh-extended-write/policy
 */
import { canonicalPath } from "@deepseek-ai/dsh-sandbox";
import { SandboxPolicyService } from "@deepseek-ai/dsh-sandbox-policy";
import z from "@deepseek-ai/schemastery";

export default class ExtendedSandboxPolicyService extends SandboxPolicyService {
	static Config = z.object({
		mode: z.union(["read-only", "workspace-write", "danger-full-access"]).default("workspace-write"),
		workspaceRoot: z.string(),
		/** Absolute directories writable alongside the workspace while extended. */
		extraWriteRoots: z.array(z.string()).default([]),
		/** The permission preset name that activates the extra roots per session. */
		extendedPreset: z.string().default("extended-write"),
		/** Activate the extra roots for every confining session, ignoring the preset. */
		always: z.boolean().default(false)
	});
	// Ordinary properties, never #private fields: cordis exposes services
	// through proxies, and a proxy cannot carry a private-field brand.
	extendedWriteRoots;
	extendedPreset;
	always;
	constructor(ctx, config) {
		super(ctx, config);
		this.extendedWriteRoots = config.extraWriteRoots;
		this.extendedPreset = config.extendedPreset;
		this.always = config.always;
	}
	/**
	 * Resolve the per-call policy: stock resolution first; when the extension
	 * applies (`always`, or the calling session's preset matches) and the mode
	 * confines, the canonical extra roots ride the resolved policy. Any
	 * projection-reading failure degrades to the stock policy — losing the
	 * extension never loses the official behavior.
	 * @param request - optional session and approved mode override.
	 * @returns the stock policy plus `extraWriteRoots` exactly when extended.
	 */
	resolve(request = {}) {
		const resolved = super.resolve(request);
		if (this.extendedWriteRoots.length === 0 || resolved.mode !== "workspace-write") return resolved;
		if (this.always) return this.withExtraRoots(resolved);
		try {
			const session = request.session;
			if (session !== void 0 && this.ctx.sessionProjections.stateOf(session, "permissions")?.preset === this.extendedPreset) return this.withExtraRoots(resolved);
		} catch (error) {
			this.ctx.logger?.warn(`extended-write: permission projection unavailable; treating the session as non-extended (${error instanceof Error ? error.message : String(error)})`);
		}
		return resolved;
	}
	/** The stock policy carrying the canonical, deduplicated extra roots. */
	withExtraRoots(resolved) {
		return { ...resolved, extraWriteRoots: [...new Set(this.extendedWriteRoots.map(canonicalPath))] };
	}
}
