# 实机记录、部分适配与恢复

[实机矩阵](../validation/RUNTIME-MATRIX.md)按三代系统和六个 PCI ID 分成 18 组，目标核心为 1.1.0。当前没有本版实机记录，全部保留“未测试”；离线测试、驱动匹配和旧核心的收件记录不填成实机通过。每个小版本的结论只属于记录里的具体构建，不能向整个大版本推广。

## 每次测试要固定的身份

使用 [会话模板](../validation/runtime-session.template.json)。记录网卡 PCI ID、完整 macOS 版本与构建号、启动会话别名、RELEASE/DEBUG、实际加载核心的二进制 SHA-256。网卡商品名、同名 kext 或系统大版本不足以确认是同一组合。

记录放到 `runtime-matrix.json` 对应格的 `runs` 数组；不同构建、启动会话或核心分别建记录，不拼接单项结果。保留失败和受阻记录。证据先脱敏，再计算 SHA-256；原始地址、SSID、身份信息留在私有原件中。

每份证据用 JSON 封装：`kind=hardware_capture`，`binding` 必须含与该次记录一致的 `pci_id`、`system_build`、`core_binary_sha256`、`boot_session_alias`。封装内保留脱敏后的观测、原始文件哈希和人工审阅说明。记录的 `evidence` 项填写封装的相对路径、ID、SHA-256 和 `kind=hardware_capture`。离线/模拟输入不能作为实机证明。

## 六项通过分别需要什么

| 项目 | 需要留下的实机证据 |
| --- | --- |
| 启动 | 冷启动成功、实际加载核心哈希与目标一致、正确 NIC 绑定对应 PCI、无 panic。单看 EFI 文件存在不算。 |
| 关联 | 明确记录 WPA2/WPA3 模式，关联成功、取得 DHCP 地址并有实际数据回传。SET20 返回 0 不等于这些都成功。 |
| 私人地址 | 明确固定/轮换模式；驱动、BSD、IORegistry 一致，AP/对端也观察到该私人地址，并确认是本地管理的单播地址。只有缓存一致不算端到端证明。 |
| AirDrop → | 对端真实收到文件；发送文件与接收文件的字节数、SHA-256 一致。队列完成、发现对端、AWDL 事件均不能替代收件。 |
| AirDrop ← | 反方向独立留下同样的接收端证据。不能用单向收件推导双向。 |
| 睡眠 | 同一配置至少三轮睡眠/唤醒，记下每轮睡眠秒数；每轮醒来重新确认关联、数据回传、私人地址状态及无 panic。仅代表这些已测周期。 |

两端不能取得哈希时，可记下收件确认，状态留为受阻或部分记录，不填完整哈希通过。`pass` 还需 `review.method=manual_hardware_evidence` 与审阅日期。工具只核对记录结构、身份绑定和留存文件完整性；不会代替人工审阅或重新执行 RF 测试。

```sh
python3 tools/runtime_evidence.py
python3 tools/runtime_evidence.py --evidence-root /path/to/redacted-evidence --require-complete
```

普通检查只验证记录；`--require-complete` 要求 18 格各有同一次会话的六项通过，当前应失败。不能把普通检查返回成功当成硬件全部通过。修改记录后用 `--render validation/RUNTIME-MATRIX.md` 更新表格。

## 收集部分 hook 和隔离状态

先按 README 的 DEBUG 方法收集日志，再保存结构化快照：

```sh
ioreg -a -r -l -c AirportBrcmCompat > ~/Desktop/AirportBrcmCompat-ioreg.plist
python3 tools/brcmctl.py diagnose --ioreg ~/Desktop/AirportBrcmCompat-ioreg.plist
```

工具只读取 `ScanCompatDiagnostics` 的已知数值字段，不写 IORegistry 或修改驱动。`Reached=false`、`Code=0xffffffff` 表示尚未到达，不能视为成功。它不会从 snapshot 推断已收件或已恢复。

| 场景 | 看哪些字段 | 源码规定的行为 | 现场需要记录 |
| --- | --- | --- | --- |
| GET11 成功、GET12 失败 | `ScanRoute=0`、`CapabilitiesRoute>0` | GET11 保留；完整扫描对未完成，关联安装不会继续；本次启动不重试安装这组路由。 | 前后快照、是否还能扫描、关联的实际结果；不要只记“hook 成功”。 |
| 私人地址路由部分成功 | `PrivateDriverRoute`、`PrivateAuthRoute`、`PrivateBSDRoute`；公开 KPI 模式另看两项 ioctl 路由 | 只有全部检查通过且 `PrivateReady=0` 才启用桥。已有路由在未 ready 时走各自原始 trampoline。 | 哪项成功、哪项未到达/拒绝、原始路径实际返回与联网状态。 |
| 变更前失败 | `PrivateGateReason`、`PrivateApplyStage`、`PrivateApplyResult` | 尚未尝试修改状态的拒绝，不会仅因这次错误建立事务隔离。 | 错误、重试前的关联/扫描状态；不能与修改后的隔离混淆。 |
| 变更后失败 | `PrivateQuarantined=1`、`PrivateApplyStage`、`PrivateApplyResult`、`PrivateEntry` | 固件 setter 一旦尝试，即按可能已改变状态处理；后续失败隔离同一 retained 主控制器，后续主接口 SET20（包括非私人请求）拒绝。 | 第一次失败、同一启动会话的重试、两份快照及实际错误。 |
| 原始关联失败但地址仍一致 | `PrivatePostResult`，同时核对隔离字段 | 原始关联错误保留；如果各缓存仍一致，不因此自动隔离，也不恢复旧 MAC/PMK。 | 地址一致与无线关联失败分开记。 |

隔离没有“Wi-Fi 开关一下就清除”的恢复接口；同一启动会话内 `finish()` 不清隔离，也不把另一控制器继承成新状态。先保存证据，恢复已知可用的 EFI/kext 组合并重启；重新测关联和所需功能后才记恢复成功。关闭私人地址、手动改 MAC、重新试一次均不能作为隔离已清除的依据。

`runtime-session.template.json` 的 `failure_scenarios` 用来记录触发前后证据、是否同一启动、重试结果、重启后的恢复结果。未观察到的行为留为 `not_run`。上述表格是源码策略，尚未作为当前版本的实机恢复通过项。

## 历史参考

已留存 Test023r2 / 25G332 / 核心 1.0.1 的接受报告：Mac→iPhone 确认收到并打开，但没有接收端哈希；iPhone→Mac 的 32 KiB 回传有哈希核对。该报告本身未核对 PCI ID，不能补成当前 1.1.0 的启动、私人地址或睡眠通过。矩阵 JSON 只保留了脱敏摘要及原报告哈希。

<details>
<summary>English</summary>

The matrix has 18 OS-generation/PCI-ID cells targeting 1.1.0. No current-release hardware runs are recorded. Each claim is tied to an exact macOS build, PCI ID, loaded core hash and boot session. Historical cores and offline tests do not qualify these cells.

Use the session template. Retain failed/blocked runs. Evidence envelopes must declare `kind=hardware_capture` and match the run's PCI ID, build, core hash and boot-session alias. Redact before hashing; keep private originals separately. The checker validates record integrity, not independent RF execution or the truth of a manual observation.

A complete run needs cold-boot binding/hash evidence; association, DHCP and traffic; a fixed/rotating private address confirmed across driver/BSD/IORegistry and AP; independently hashed receiver receipts in both AirDrop directions; and at least three documented sleep/wake cycles with reassociation, traffic and address-state checks. Sender completion, a SET20 result or local cache agreement is insufficient. A receipt without receiver hashing remains a partial observation.

`--require-complete` requires all six checks within one run for every cell. Plain validation success means the records are well formed, not that hardware passed.

For partial GET11/GET12 installation, GET11 remains active while association installation does not proceed. Private hooks remain pass-through until all required routes and readiness checks succeed. A failure after a potentially mutating private-address operation quarantines the retained primary controller for that boot; subsequent primary SET20 requests, including nonprivate ones, are refused. Retry, Wi-Fi toggling and disabling private addressing do not clear quarantine. Save before/after snapshots, restore known-good files, reboot, and record actual recovery before marking it successful. These are source policies; current-release runtime recovery remains untested.

Capture a structured snapshot with the `ioreg` command above and run `brcmctl.py diagnose`. Unknown/unreached stages remain unknown. The tool writes no driver state and never infers packet delivery or recovery. Historical Test023r2 receiver confirmation and return-file hashing remain separate from current-release validation.

</details>
