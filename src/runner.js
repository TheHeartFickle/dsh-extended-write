/**
 * Extended windows-acl confinement runner: the stock runner argv contract
 * plus repeatable `--extra-root <dir>` under workspace-write. Extra roots
 * join `writableDirs` with the WORKSPACE capability SID in both flows, so the
 * restricted token's restricting-SID list is unchanged from stock and the
 * caller-side workspace grant carries a standing ACE per extra root.
 *
 * Unlike stock, the workspace-write child keeps the CALLER's integrity level
 * (Medium): confinement is restricted-SID + DACL only, and the stock Low
 * mandatory-label pair (token lowering + target relabeling) is deliberately
 * not honored — a Medium token ignores the stamped labels.
 *
 * Failure contract (stock): every runner-side failure prints
 * `windows-acl-run: <detail>` to stderr and exits 127; the child is NEVER
 * spawned unrestricted.
 *
 * @module @the-heart-fickle/dsh-extended-write/runner
 */
import { AclSandbox, assertTempRootOutsideWorkspace, tempWriteSid, workspaceWriteSid } from "@deepseek-ai/dsh-sandbox-windows-acl";
import { Win32Error, allocPtrSlot, allocUint32, decodePtr, decodeUint32, isNullPtr, loadWin32ProcessBindings, throwLastError, throwWin32 } from "@deepseek-ai/dsh-win32-process";
import { closeSync, existsSync, mkdtempSync, realpathSync, rmSync, statSync } from "node:fs";
import { isAbsolute, join, relative, sep } from "node:path";
import { SUBPROCESS_CONTROL_ENV, SUBPROCESS_CONTROL_FD } from "@deepseek-ai/dsh-subprocess/control";
import koffi from "koffi";

const PROCESS_QUERY_INFORMATION = 1024;
const SE_GROUP_LOGON_ID = 3221225472;
const FILE_ALL_ACCESS = 2032127;
const TOKEN_GROUPS = 2;
const TOKEN_DEFAULT_DACL = 6;

/** ACL/token binding table layered on the shared Win32 process bindings (stock `bindings()` shape). */
function buildApiTable() {
	const kernel32 = koffi.load("kernel32.dll");
	const advapi32 = koffi.load("advapi32.dll");
	const PVOID = koffi.pointer("void");
	const PPVOID = koffi.pointer(PVOID);
	const bind = (lib, name, result, args) => lib.func("__stdcall", name, result, args);
	return {
		...loadWin32ProcessBindings(),
		openProcess: bind(kernel32, "OpenProcess", PVOID, ["uint32", "int", "uint32"]),
		openProcessToken: bind(advapi32, "OpenProcessToken", "int", [PVOID, "uint32", PPVOID]),
		localAlloc: bind(kernel32, "LocalAlloc", PVOID, ["uint32", "size_t"]),
		localFree: bind(kernel32, "LocalFree", PVOID, [PVOID]),
		convertStringSidToSidW: bind(advapi32, "ConvertStringSidToSidW", "int", ["str16", PPVOID]),
		createWellKnownSid: bind(advapi32, "CreateWellKnownSid", "int", ["int", PVOID, PVOID, koffi.pointer("uint32")]),
		isValidSid: bind(advapi32, "IsValidSid", "int", [PVOID]),
		getLengthSid: bind(advapi32, "GetLengthSid", "uint32", [PVOID]),
		copySid: bind(advapi32, "CopySid", "int", ["uint32", PVOID, PVOID]),
		getTokenInformation: bind(advapi32, "GetTokenInformation", "int", [PVOID, "int", PVOID, "uint32", koffi.pointer("uint32")]),
		setTokenInformation: bind(advapi32, "SetTokenInformation", "int", [PVOID, "int", PVOID, "uint32"]),
		createRestrictedToken: bind(advapi32, "CreateRestrictedToken", "int", [PVOID, "uint32", "uint32", PVOID, "uint32", PVOID, "uint32", PVOID, PPVOID]),
		setEntriesInAclW: bind(advapi32, "SetEntriesInAclW", "uint32", ["uint32", PVOID, PVOID, PPVOID]),
		setNamedSecurityInfoW: bind(advapi32, "SetNamedSecurityInfoW", "uint32", ["str16", "int", "uint32", PVOID, PVOID, PVOID, PVOID]),
		getNamedSecurityInfoW: bind(advapi32, "GetNamedSecurityInfoW", "uint32", ["str16", "int", "uint32", PPVOID, PPVOID, PPVOID, PPVOID]),
		setConsoleCtrlHandler: bind(kernel32, "SetConsoleCtrlHandler", "int", [PVOID, "int"]),
		setEnvironmentVariableW: bind(kernel32, "SetEnvironmentVariableW", "int", ["str16", "str16"])
	};
}
/** Copy one well-known SID into a freshly allocated native block. */
function makeWellKnownSid(api, type) {
	const sid = koffi.alloc("uint8", 68);
	const sizeSlot = allocUint32();
	encodeUint32(sizeSlot, 68);
	if (api.createWellKnownSid(type, null, sid, sizeSlot) === 0) throwLastError(api, "CreateWellKnownSid", `type ${type}`);
	if (api.isValidSid(sid) === 0) throwLastError(api, "IsValidSid", `CreateWellKnownSid type ${type}`);
	return sid;
}
function encodeUint32(slot, value) {
	koffi.encode(slot, "uint32", value);
}
/** Numeric address of a SID that is either a decoded BigInt or a koffi allocation. */
function sidAddress(sid) {
	return typeof sid === "bigint" ? sid : BigInt(koffi.address(sid));
}
/** One packed EXPLICIT_ACCESS entry (GRANT/DENY/REVOKE + permissions + inheritance). */
function buildExplicitAccess(sidPtr, mode, permissions, inheritance = 3) {
	const entry = Buffer.alloc(48);
	entry.writeUInt32LE(permissions, 0);
	entry.writeUInt32LE(mode, 4);
	entry.writeUInt32LE(inheritance, 8);
	entry.writeBigUInt64LE(sidAddress(sidPtr), 40);
	return entry;
}
/** Pack `SID_AND_ATTRIBUTES[count]` (16-byte stride; Attributes stay 0). */
function buildRestrictingSids(api, sids) {
	const buffer = Buffer.alloc(16 * sids.length);
	sids.forEach((sid, index) => {
		const address = sidAddress(sid);
		if (api.isValidSid(address) === 0) fail(`restricting SID ${index} is invalid (address ${address})`);
		buffer.writeBigUInt64LE(address, 16 * index);
	});
	return buffer;
}

const RUNNER_SIGNATURE = "windows-acl-run";
const RUNNER_FAILURE_EXIT = 127;
class RunnerFailure extends Error {}
/** Print the runner-failure signature line and unwind. */
function fail(detail) {
	process.stderr.write(`${RUNNER_SIGNATURE}: ${detail}\n`);
	throw new RunnerFailure(detail);
}
function parseArgs(raw) {
	let workspace;
	let temp;
	let mode;
	let writeSid;
	let parsedTempWriteSid;
	const extraRoots = [];
	let index = 0;
	for (; index < raw.length; index++) {
		const token = raw[index];
		if (token === "--") {
			index++;
			break;
		}
		index++;
		const value = raw[index];
		if (value === void 0) fail(`missing value after ${token}`);
		switch (token) {
			case "--workspace": workspace = value; break;
			case "--temp": temp = value; break;
			case "--mode": mode = value; break;
			case "--write-sid": writeSid = value; break;
			case "--temp-write-sid": parsedTempWriteSid = value; break;
			case "--extra-root": extraRoots.push(value); break;
			default: fail(`unknown argument: ${token}`);
		}
	}
	if (workspace === void 0) fail("missing --workspace");
	if (temp === void 0) fail("missing --temp");
	if (mode !== "read-only" && mode !== "workspace-write") fail(`unknown mode: ${String(mode)}`);
	if (mode === "read-only" && extraRoots.length > 0) fail("read-only does not accept --extra-root");
	const argv = raw.slice(index);
	const command = argv[0];
	if (command === void 0) fail("missing command after --");
	return {
		workspace,
		temp,
		mode,
		writeSid,
		tempWriteSid: parsedTempWriteSid,
		extraRoots,
		command,
		args: argv.slice(1)
	};
}
function requireDirectory(label, path) {
	if (!existsSync(path) || !statSync(path).isDirectory()) fail(`${label} is not an existing directory: ${path}`);
}
/** Open the current process's token with the rights CreateRestrictedToken requires. */
function openCurrentProcessToken(api) {
	const processHandle = api.openProcess(PROCESS_QUERY_INFORMATION, 0, process.pid);
	if (isNullPtr(processHandle)) throwLastError(api, "OpenProcess", `pid ${process.pid}`);
	const tokenSlot = allocPtrSlot();
	if (api.openProcessToken(processHandle, 139, tokenSlot) === 0) {
		const win32Code = api.getLastError();
		api.closeHandle(processHandle);
		throwWin32(api, "OpenProcessToken", win32Code, `pid ${process.pid}`);
	}
	if (api.closeHandle(processHandle) === 0) throwLastError(api, "CloseHandle", "OpenProcess process handle");
	const token = decodePtr(tokenSlot);
	if (token === null) throwWin32(api, "OpenProcessToken", api.getLastError(), "null token handle");
	return token;
}
/** Find and copy the token's logon session SID (SE_GROUP_LOGON_ID attribute). */
function findLogonSid(api, token) {
	const neededSlot = allocUint32();
	api.getTokenInformation(token, TOKEN_GROUPS, null, 0, neededSlot);
	const needed = decodeUint32(neededSlot);
	if (needed === 0) throwLastError(api, "GetTokenInformation", "TokenGroups size query");
	if (needed < 8) throwWin32(api, "GetTokenInformation", api.getLastError(), `implausible TokenGroups size ${needed}`);
	const groups = Buffer.alloc(needed);
	if (api.getTokenInformation(token, TOKEN_GROUPS, groups, groups.length, neededSlot) === 0) throwLastError(api, "GetTokenInformation", "TokenGroups");
	const groupCount = groups.readUInt32LE(0);
	for (let index = 0; index < groupCount; index++) {
		const sidPtr = koffi.decode(groups, 8 + index * 16, koffi.pointer("void"));
		const isLogonId = (groups.readUInt32LE(8 + index * 16 + 8) & SE_GROUP_LOGON_ID) >>> 0 === SE_GROUP_LOGON_ID >>> 0;
		if (sidPtr === null || !isLogonId) continue;
		const sidLength = api.getLengthSid(sidPtr);
		if (sidLength === 0) throwLastError(api, "GetLengthSid", `logon SID group ${index}`);
		const copy = koffi.alloc("uint8", sidLength);
		if (api.copySid(sidLength, copy, sidPtr) === 0) throwLastError(api, "CopySid", `logon SID group ${index}`);
		return copy;
	}
	throw new Error(`CreateRestrictedToken prerequisite failed: no logon SID found among ${groupCount} token groups`);
}
/** Merge one full-access allow ACE for `sidPtr` into the token's DEFAULT DACL. */
function setTokenDefaultDaclGrant(api, token, sidPtr) {
	const neededSlot = allocUint32();
	api.getTokenInformation(token, TOKEN_DEFAULT_DACL, null, 0, neededSlot);
	const needed = decodeUint32(neededSlot);
	if (needed === 0) throwLastError(api, "GetTokenInformation", "TokenDefaultDacl size query");
	const buffer = Buffer.alloc(needed);
	if (api.getTokenInformation(token, TOKEN_DEFAULT_DACL, buffer, buffer.length, neededSlot) === 0) throwLastError(api, "GetTokenInformation", "TokenDefaultDacl");
	const currentDacl = koffi.decode(buffer, 0, koffi.pointer("void"));
	if (currentDacl === null) throw new Error("setTokenDefaultDaclGrant: the token carries no default DACL to extend");
	const newDaclSlot = allocPtrSlot();
	const result = api.setEntriesInAclW(1, buildExplicitAccess(sidPtr, 1, FILE_ALL_ACCESS), currentDacl, newDaclSlot);
	if (result !== 0) throwWin32(api, "SetEntriesInAclW", result, "default DACL merge");
	const newDacl = decodePtr(newDaclSlot);
	if (newDacl === null) throwWin32(api, "SetEntriesInAclW", result, "null merged default DACL");
	const info = Buffer.alloc(8);
	info.writeBigUInt64LE(BigInt(newDacl), 0);
	if (api.setTokenInformation(token, TOKEN_DEFAULT_DACL, info, info.length) === 0) {
		const win32Code = api.getLastError();
		api.localFree(newDacl);
		throwWin32(api, "SetTokenInformation", win32Code, "TokenDefaultDacl");
	}
	api.localFree(newDacl);
}
/** Create the restricted token WITHOUT the stock Low integrity lowering. */
function createRestrictedToken(api, currentToken, logonSid, writeSids, worldSid, mode) {
	const restrictingSids = buildRestrictingSids(api, mode === "read-only" ? [logonSid, worldSid] : writeSids.length === 0 ? (() => {
		throw new Error("createRestrictedToken: workspace-write restricting list requires at least one write SID");
	})() : [
		logonSid,
		worldSid,
		...writeSids
	]);
	const tokenSlot = allocPtrSlot();
	if (api.createRestrictedToken(currentToken, 13, 0, null, 0, null, restrictingSids.length / 16, restrictingSids, tokenSlot) === 0) throwLastError(api, "CreateRestrictedToken", `restricting SIDs: ${restrictingSids.length / 16}`);
	const token = decodePtr(tokenSlot);
	if (token === null) throwWin32(api, "CreateRestrictedToken", api.getLastError(), "null token handle");
	return token;
}
/** Reject any overlap (either inheritance direction) between the private temp dir and the writable dirs. */
function assertPrivateTempDisjointFromWritable(writableDirs, tempDir) {
	for (const writableDir of writableDirs) {
		const base = realpathSync.native(writableDir);
		const candidate = realpathSync.native(tempDir);
		const relation = relative(base, candidate);
		if (relation === "" || !isAbsolute(relation) && relation !== ".." && !relation.startsWith(`..${sep}`)) throw new Error(`AclSandbox private temp directory must be disjoint from writable directories: writable=${writableDir}; temp=${tempDir}`);
	}
}
/** Merge a full-access DACL allow ACE for `sidPtr` into `path` — NO mandatory label. */
function grantWriteDaclOnly(api, path, sidPtr) {
	const daclSlot = allocPtrSlot();
	if (api.getNamedSecurityInfoW(path, 1, 4, null, null, daclSlot, null) !== 0) fail(`GetNamedSecurityInfoW failed (Win32 ${api.getLastError()}): grantWrite(${path})`);
	const oldAcl = decodePtr(daclSlot);
	if (oldAcl === null) fail(`GetNamedSecurityInfoW returned a null DACL: grantWrite(${path})`);
	const newDaclSlot = allocPtrSlot();
	const result = api.setEntriesInAclW(1, buildExplicitAccess(sidPtr, 1, FILE_ALL_ACCESS), oldAcl, newDaclSlot);
	if (result !== 0) fail(`SetEntriesInAclW failed (Win32 ${result}): grantWrite(${path})`);
	const newDacl = decodePtr(newDaclSlot);
	if (newDacl === null) fail(`SetEntriesInAclW returned a null DACL: grantWrite(${path})`);
	if (api.setNamedSecurityInfoW(path, 1, 4, null, null, newDacl, null) !== 0) {
		const win32Code = api.getLastError();
		api.localFree(newDacl);
		fail(`SetNamedSecurityInfoW failed (Win32 ${win32Code}): grantWrite(${path})`);
	}
	api.localFree(newDacl);
}
/**
 * The stock `AclSandbox` with the Low integrity pair removed: init() builds
 * the restricted token WITHOUT lowering it (the child keeps the caller's
 * Medium integrity; confinement is restricted-SID + DACL only) and its
 * `manageDacls` grants write DACL ACEs without stamping mandatory labels.
 * Spawn/dispose are inherited unchanged.
 */
class MediumIntegrityAclSandbox extends AclSandbox {
	async init() {
		if (this.api !== void 0) throw new Error("AclSandbox is already initialized");
		this.grantedPaths ??= [];
		this.sidAllocations ??= [];
		const api = buildApiTable();
		const currentToken = openCurrentProcessToken(api);
		let currentTokenOpen = true;
		let restrictedToken;
		try {
			const parseSid = (sid) => {
				const sidSlot = allocPtrSlot();
				if (api.convertStringSidToSidW(sid, sidSlot) === 0) throwLastError(api, "ConvertStringSidToSidW", sid);
				const parsedSid = decodePtr(sidSlot);
				if (parsedSid === null) throw new Win32Error("ConvertStringSidToSidW", api.getLastError(), sid);
				return parsedSid;
			};
			this.writeSidPtr = this.writeSid === void 0 ? void 0 : parseSid(this.writeSid);
			this.tempWriteSidPtr = this.tempWriteSid === void 0 ? void 0 : parseSid(this.tempWriteSid);
			const tempDir = this.mode === "read-only" || this.tempDirOption === null ? null : this.tempDirOption;
			if (tempDir === void 0) throw new Error("AclSandbox workspace-write temp directory was not resolved");
			if (tempDir !== null) {
				if (!existsSync(tempDir) || !statSync(tempDir).isDirectory()) throw new Error(`AclSandbox temp dir does not exist or is not a directory: ${tempDir}`);
				assertPrivateTempDisjointFromWritable(this.writableDirs, tempDir);
			}
			this.tempDirResolved = tempDir;
			const worldSid = makeWellKnownSid(api, 1);
			this.sidAllocations.push(worldSid);
			if (this.manageDacls) {
				if (this.writeSidPtr !== void 0) {
					for (const path of this.writableDirs) grantWriteDaclOnly(api, path, this.writeSidPtr);
					if (tempDir !== null && this.tempWriteSidPtr !== void 0) {
						this.grantedPaths.push({
							path: tempDir,
							sidPtr: this.tempWriteSidPtr
						});
						grantWriteDaclOnly(api, tempDir, this.tempWriteSidPtr);
					}
				}
			}
			const logonSid = findLogonSid(api, currentToken);
			this.sidAllocations.push(logonSid);
			restrictedToken = createRestrictedToken(api, currentToken, logonSid, [this.writeSidPtr, this.tempWriteSidPtr].filter((sid) => sid !== void 0), worldSid, this.mode);
			// No integrity lowering: the token keeps the caller's Medium level.
			this.token = restrictedToken;
			setTokenDefaultDaclGrant(api, restrictedToken, this.tempWriteSidPtr ?? this.writeSidPtr ?? worldSid);
			if (api.closeHandle(currentToken) === 0) throwLastError(api, "CloseHandle", "current process token");
			currentTokenOpen = false;
			this.api = api;
		} catch (error) {
			const cleanupFailures = [];
			if (currentTokenOpen && api.closeHandle(currentToken) === 0) cleanupFailures.push(new Win32Error("CloseHandle", api.getLastError(), "current process token after init failure"));
			if (restrictedToken !== void 0 && api.closeHandle(restrictedToken) === 0) cleanupFailures.push(new Win32Error("CloseHandle", api.getLastError(), "restricted token after init failure"));
			for (const grant of this.grantedPaths) try {
				const daclSlot = allocPtrSlot();
				if (api.getNamedSecurityInfoW(grant.path, 1, 4, null, null, daclSlot, null) !== 0) throw new Error(`GetNamedSecurityInfoW (Win32 ${api.getLastError()})`);
				const oldAcl = decodePtr(daclSlot);
				if (oldAcl === null) throw new Error("null DACL");
				const newDaclSlot = allocPtrSlot();
				const result = api.setEntriesInAclW(1, buildExplicitAccess(grant.sidPtr, 4, 0), oldAcl, newDaclSlot);
				if (result !== 0) throw new Error(`SetEntriesInAclW (Win32 ${result})`);
				const newDacl = decodePtr(newDaclSlot);
				if (newDacl === null) throw new Error("null DACL after revoke");
				if (api.setNamedSecurityInfoW(grant.path, 1, 4, null, null, newDacl, null) !== 0) throw new Error(`SetNamedSecurityInfoW (Win32 ${api.getLastError()})`);
				api.localFree(newDacl);
			} catch (cleanupError) {
				cleanupFailures.push(cleanupError);
			}
			for (const sidPtr of this.sidAllocations.splice(0)) try {
				api.localFree(sidPtr);
			} catch (cleanupError) {
				cleanupFailures.push(cleanupError);
			}
			for (const [label, sidPtr] of [["workspace write SID", this.writeSidPtr], ["temp write SID", this.tempWriteSidPtr]]) try {
				api.localFree(sidPtr);
			} catch (cleanupError) {
				cleanupFailures.push(cleanupError);
			}
			this.writeSidPtr = void 0;
			this.tempWriteSidPtr = void 0;
			this.grantedPaths = [];
			throw error;
		}
	}
}
async function main() {
	const parsed = parseArgs(process.argv.slice(2));
	requireDirectory("--workspace", parsed.workspace);
	requireDirectory("--temp", parsed.temp);
	for (const root of parsed.extraRoots) requireDirectory("--extra-root", root);
	const seamManaged = parsed.writeSid !== void 0 || parsed.tempWriteSid !== void 0;
	if (parsed.mode === "read-only" && seamManaged) fail("read-only does not accept --write-sid or --temp-write-sid");
	if (parsed.mode === "workspace-write" && parsed.writeSid === void 0 !== (parsed.tempWriteSid === void 0)) fail("workspace-write requires --write-sid and --temp-write-sid together");
	if (parsed.mode === "workspace-write") assertTempRootOutsideWorkspace(parsed.workspace, parsed.temp);
	let ownedTempDir;
	let sandbox;
	let initialized = false;
	try {
		let privateTempDir = null;
		let writeSid;
		let privateTempSid;
		if (parsed.mode === "workspace-write") {
			writeSid = workspaceWriteSid(parsed.workspace);
			if (seamManaged) {
				if (parsed.writeSid !== writeSid) fail("--write-sid does not match --workspace");
				privateTempDir = parsed.temp;
				privateTempSid = tempWriteSid(privateTempDir);
				if (parsed.tempWriteSid !== privateTempSid) fail("--temp-write-sid does not match --temp");
			} else {
				ownedTempDir = mkdtempSync(join(parsed.temp, "dsh-"));
				privateTempDir = ownedTempDir;
				privateTempSid = tempWriteSid(privateTempDir);
			}
		}
		const writableDirs = parsed.mode === "workspace-write" ? [parsed.workspace, ...parsed.extraRoots] : [];
		sandbox = new MediumIntegrityAclSandbox({
			writableDirs,
			tempDir: privateTempDir,
			mode: parsed.mode,
			...writeSid === void 0 ? {} : { writeSid },
			...privateTempSid === void 0 ? {} : { tempWriteSid: privateTempSid },
			manageDacls: !seamManaged
		});
		await sandbox.init();
		initialized = true;
		const api = sandbox.api;
		if (api.setConsoleCtrlHandler(null, 1) === 0) fail(`SetConsoleCtrlHandler failed (Win32 ${api.getLastError()})`);
		if (privateTempDir !== null) {
			if (api.setEnvironmentVariableW("TMP", privateTempDir) === 0) fail(`SetEnvironmentVariableW TMP failed (Win32 ${api.getLastError()})`);
			if (api.setEnvironmentVariableW("TEMP", privateTempDir) === 0) fail(`SetEnvironmentVariableW TEMP failed (Win32 ${api.getLastError()})`);
		}
		const child = sandbox.spawn({
			command: parsed.command,
			args: parsed.args,
			stdio: "inherit",
			...process.env[SUBPROCESS_CONTROL_ENV] === "pipe" ? { controlFileDescriptor: SUBPROCESS_CONTROL_FD } : {}
		});
		if (process.env[SUBPROCESS_CONTROL_ENV] === "pipe") closeSync(SUBPROCESS_CONTROL_FD);
		return (await child.wait()).exitCode;
	} finally {
		if (initialized) try {
			sandbox?.dispose();
		} catch (error) {
			process.stderr.write(`${RUNNER_SIGNATURE}: cleanup: ${error instanceof Error ? error.message : String(error)}\n`);
		}
		if (ownedTempDir !== void 0) try {
			rmSync(ownedTempDir, {
				recursive: true,
				force: true
			});
		} catch (error) {
			process.stderr.write(`${RUNNER_SIGNATURE}: cleanup: ${error instanceof Error ? error.message : String(error)}\n`);
		}
	}
}
main().then((exitCode) => {
	process.exitCode = exitCode;
}, (error) => {
	if (!(error instanceof RunnerFailure)) process.stderr.write(`${RUNNER_SIGNATURE}: ${error instanceof Error ? error.message : String(error)}\n`);
	process.exitCode = RUNNER_FAILURE_EXIT;
});
