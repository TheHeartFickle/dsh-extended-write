# dsh-extended-write

把 DSH 的**工作区内修改**档位在执行层悄悄加宽：`workspace-write` 的官方可写边界 ∪ 配置的额外写根（各包管理器缓存等）。**伪装语义**——预设身份完全不变（键仍是 `workspace-write`，`/permission workspace-write` 照旧），下拉里仍是官方三档 + Auto review，但该档显示名改为「**工作区扩展**」：

- **档位名即健康指示灯**：插件生效时显示「工作区扩展」；插件失效（整层跳过、patch 未加载）时回落官方「工作区内修改」——名字没变就是插件哑了；
- 插件生效时，`工作区扩展` = 工作区 ∪ 额外缓存根可写。构建类命令（pnpm/cargo/pip/gradle…）写缓存直接放行，不再逐条审批；
- **子进程保持调用方的完整性级别（Medium），不降完整性**——边界完全由 capability SID 的 DACL 决定，官方的"令牌压低 + 目录盖低标"配对机制被整个绕开（runner 自建受限令牌序列，跳过压低步骤）；
- 允许清单之外（`~/.gitconfig`、`~/.ssh`、`~/.dsh`、文档等）仍被沙箱拒绝——不是 danger-full-access 的全放行；
- 危险操作仍可按次审批升级到 full-access；
- `read-only` 与 `danger-full-access` 档位行为与官方完全一致（`resolve()` 对非 workspace-write 模式短路返回官方结果）。

## 失效形态与恢复

| 形态 | 触发 | 用户可见 | 恢复 |
|---|---|---|---|
| **整层跳过**（安全） | DSH 升级后 peer 范围不满足 / 包缺失 / YAML 损坏 | stderr 一行 `skipping profile bundle …`；档位名回落「工作区内修改」；同一档位回落官方低完整性 ACL 沙盒，DSH 正常启动 | 重钉版本（见下）后重新 install_bundle |
| **运行期丢扩展**（安全） | 同版本族内 stock 私有件漂移 / 缓存根暂不存在 | 警告日志一条；扩展根退化为拒绝，档位表现同官方 workspace-write | 无需处理；或检查 extraWriteRoots |
| **runner 失败**（不安全，需手动恢复） | 版本族内 stock 无视 runner override 或 runner 契约漂移 | 沙盒命令报 `windows-acl-run: …`（exit 127），逐条失败 | Plugin Manager 禁用本 bundle（整层消失，官方沙盒回归） |
| **挂载期抛错**（不安全，需手动恢复） | 导入/构造/Config 校验在 stock 行被禁用**之后**失败 | profile 启动失败 | `dsh plugin --profile web remove @the-heart-fickle/dsh-extended-write`（CLI） |

挂载期抛错不在整层跳过的保护范围内（组合栈已禁用官方三行）。安装流程里的 `node --check`、模块冒烟导入与 `--dump-config-schema` 校验就是为把这条概率压到最低；改代码后请重跑。

**不要**在更高补丁层手写 `- id: sandbox / disabled: false` 之类再启用官方行：官方服务与本插件子类会双注册 `ctx.fs` / `ctx.sandbox`，加载直接失败。

## 版本升级

`peerDependencies`（与 `dependencies` 同步）把 7 个 `@deepseek-ai/dsh-*` 钉在 exact 版本上。DSH 升级后本插件**自动哑火并回落官方沙盒**（上表第一行），这是有意的保守取舍——本插件深度耦合 stock 内部件，宁可失效不可错位。恢复步骤：

1. 把 `package.json` 里 9 个 `@deepseek-ai/*` 版本改成新安装版对应版本；
2. 在本目录重跑 `pnpm install`；
3. 对照新版的 `dsh-sandbox-local` / `dsh-fs-sandbox` 抽查本 README 引用的内部件名仍成立；
4. `install_bundle` 重装，跑一遍验证清单。

## 组成

```
dsh-extended-write/
├── src/               # 四个执行层模块（挂载目标）
│   ├── policy.js      # SandboxPolicyService 子类：extraWriteRoots 附到 resolved policy
│   ├── fs.js          # SandboxedFileSystem 子类：写栅栏并入额外根
│   ├── sandbox.js     # LocalSandboxProvider 子类：各 runner profile 绑定额外根
│   └── runner.js      # Windows ACL runner：不压低完整性的受限令牌序列
├── locale/            # 插件自身的显示名（Plugin Manager）
├── testdata/          # 隔离 profile E2E（overlay + 引导脚本）
├── cordis.patch.yml   # bundle patch：禁用 stock 三行、改名 permission 档、插入子类三行
└── package.json
```

- `src/policy.js` — `SandboxPolicyService` 子类：`resolve()` 在扩展生效时把 `extraWriteRoots` 附到 resolved policy；投影读取失败自动降级为不扩展。
- `src/fs.js` — `SandboxedFileSystem` 子类：写栅栏把额外根并入可写根集合（词法前缀 + 文件系统身份双路判定，同 stock）。
- `src/sandbox.js` — `LocalSandboxProvider` 子类：bwrap/Landlock/Seatbelt profile 绑定额外根；Windows ACL rung 物化常驻 ACE（复用 workspace capability SID）并传 `--extra-root`；私有件缺失时自动走 stock argv。
- `src/runner.js` — 自建受限令牌序列的 runner：stock 契约 + 可重复 `--extra-root`，**不执行完整性压低**（`CreateRestrictedToken` 后直接使用，子进程保持 Medium）；失败契约不变（`windows-acl-run:` + exit 127）。
- `cordis.patch.yml` — 按 id 禁用 stock 三行（sandbox-policy / fs-sandbox / sandbox），插入子类三行；同时改写 `permission` 行，给 `workspace-write` 预设挂显示名「工作区扩展」（config 整体替换，三个预设逐字段重述，预设**键**不变）。

## 依赖与安装

`koffi` 与 `@deepseek-ai/dsh-win32-process` 是直接依赖（runner 自建令牌序列需要）。安装步骤：

1. 在本目录跑 `pnpm install`（**在自己终端跑**——dsh 会话内的 pnpm 会被沙盒正确拦截：pnpm store 在白名单外，报 `ERR_SQLITE_ERROR` 属预期）；
2. `plugin_manager install_bundle` 装进目标 profile（本地目录链接）。

若曾手工放置过 `node_modules/koffi`、`node_modules/@deepseek-ai/dsh-win32-process` 引导 shim，`pnpm install` 会自动替换为正规链接。

## 配置（`extended-sandbox-policy` 行）

```yaml
- id: extended-sandbox-policy
  config:
    mode: workspace-write          # 沿用 stock 语义
    workspaceRoot: !!js process.cwd()
    extraWriteRoots:               # 绝对路径；patch 会整体替换 config，逐字段重述
      - 'C:\Users\me\AppData\Local\npm-cache'
      - 'C:\Users\me\AppData\Local\pnpm\store'
    always: true                   # workspace-write 档即扩展档（伪装语义）
```

`extendedPreset` 配置字段仍存在（默认 `extended-write`）但伪装方案下不使用；若想要"可从 UI 退出的独立扩展档"，把它改回 per-preset 门控并恢复 permission 行预设即可。

## 已知边界

- 配置了 `runnerCommand` 的部署（自带 runner）不携带额外根（stock 私有 profile 构建器不可达）。
- 旧版本（0.1.x）记录过 `extended-write` 预设的历史会话，在伪装版下当前值显示为 `custom`（仅显示退化，行为正常）。
- `always: true` 意味着**所有** workspace-write 会话（含子代理、agentless 调用）都带缓存根写权限，UI 无独立开关——这是伪装语义的代价。
- 升级目标不含新模式：escalation 目标保持官方 `[workspace-write, danger-full-access]`，schema 稳定。
- Linux/macOS 方言（bwrap/Landlock/Seatbelt）按同一语义实现，未经 Windows 以外主机实测。
- **嵌套受限**：已经受限的进程里再调 `CreateRestrictedToken` 会报 Win32 87（实测，stock runner 同样如此）。生产不受影响——runner 由未受限的 host 进程启动；只有"在沙盒会话里再手动跑 runner"这类测试场景会遇到。
- 子进程不再受低完整性强制策略保护：能写 = DACL 允许的位置（含 Public 等弱 ACL 目录）。这是本插件的设计取舍，不是缺陷。
