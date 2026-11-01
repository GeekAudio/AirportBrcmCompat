# macOS 27 升级准备

**当前状态：已准备未来系统的检查流程，尚无 macOS 27 Intel 移植样本。** 1.1.0 的下载包和实机矩阵仍按原有范围记录。

[苹果的 macOS 27 兼容列表](https://www.apple.com/os/macos/)只列出 Apple silicon 机型。这里准备的是社区 Intel 移植系统上的 Wi-Fi 检查；本项目本身不提供 Intel 系统移植。

## 已准备什么

- 核心没有系统构建号或内核 UUID 白名单，也没有最高系统版本限制。
- 现有配置从 Darwin 25 起选用同一份 NIC 驱动，不需要为下个版本再添加一条配置。新系统仍须通过实际接口检查。
- `upgrade-check` 会核对 EFI 副本，并直接读取目标 BootKC 中的 x86_64 内核、实际 Darwin 版本及 `IONetworkingFamily`，使用生产代码的检查函数验证公开 ioctl 入口和网络回调。不会按文件名猜测系统，也不会为通过检查而修改偏移。
- 新的合成回归用例覆盖未来版本号、未知 UUID、错误架构、旧样本冒充新系统、入口变化和错误调用目标。合成输入始终不计入实机矩阵。

## Intel 移植样本到手后

检查工具在 [main 分支源码](https://github.com/GeekAudio/AirportBrcmCompat/tree/main/tools)的 `tools/` 目录。1.1.0 发布页的 Source code 对应固定 tag，不包含这次新增工具；安装 ZIP 也不包含工具。

保留移植方案的仓库地址、提交号、完整系统构建号，以及该方案实际使用的 `BootKernelExtensions.kc`。只在 EFI 副本上运行：

```sh
python3 tools/brcmctl.py upgrade-check \
  --oc-dir /path/to/EFI-copy/OC \
  --darwin 26.0.0 \
  --kernel-collection /path/to/target/BootKernelExtensions.kc \
  --output /path/to/upgrade-report.json
```

`26.0.0` 只是命令示例，必须换成目标 Intel 移植内核的实际 `uname -r`；不能根据 macOS 显示版本推算。报告里的实际版本取自内核 `_version`，与指定目标不一致就拒绝。报告文件必须尚不存在。

| 结果 | 怎么看 |
| --- | --- |
| `not_supplied` | 缺少目标样本；配置检查通过也不算升级检查通过 |
| `rejected` | 架构、实际版本、符号或样本结构不满足要求，错误原因见 `errors` |
| `host_contracts_rejected` | 公开 KPI 备用路径不满足当前契约；其他内核路径尚未评估，需要继续分析 |
| `host_contracts_passed` | 该样本通过当前源码中的宿主接口检查；还要结合 `configuration.passed` 看 EFI 文件检查结果 |

即使总结果 `passed: true`，也只说明配置和这条宿主备用路径的离线检查通过。工具不验证移植系统来源，不确认 EFI 中核心与当前源码完全相同，也不模拟启动时的导入绑定。无线驱动与虚表检查、请求和事件格式仍在运行时独立执行。扫描、关联、私人地址、双向 AirDrop 和睡眠按[实机记录](RUNTIME-VALIDATION.md)单独验收。

不传 `--kernel-collection` 可以先检查 EFI 准备情况；命令仍返回非零状态，明确保留“缺少样本”。工具只读取输入、编译临时宿主检查程序并新建指定报告，不安装或加载驱动。

<details>
<summary>English</summary>

**Status: future-system checks are prepared; no macOS 27 Intel-port sample is available.** Existing 1.1.0 downloads and hardware records retain their original scope.

[Apple's macOS 27 compatibility list](https://www.apple.com/os/macos/) lists Apple silicon models. This work prepares Wi-Fi checks for a community Intel port; it does not provide that OS port.

The core has no OS-build/kernel-UUID allowlist or maximum OS version. Existing configuration selects the same NIC variant from Darwin 25 onward. Runtime ABI and request checks remain mandatory.

Get the tools from the [main branch](https://github.com/GeekAudio/AirportBrcmCompat/tree/main/tools). The 1.1.0 release's Source code archives follow the fixed tag and do not include these new tools. Installation ZIPs contain no tools.

Run the command above against an EFI copy and the **actual Intel port's BootKC**. Replace the example Darwin `26.0.0` with the target kernel's real `uname -r`; do not infer it from the macOS marketing version. The tool reads `_version`, rejects mismatched samples and ARM64 images, resolves kernel/networking symbols, and replays the production public-ioctl prefix and network-callback checks. Synthetic future-version regression fixtures are not hardware results.

`not_supplied` means the target sample is missing. `rejected` identifies an invalid or mismatched input. `host_contracts_rejected` means this fallback path failed; other kernel paths were not assessed. `host_contracts_passed` covers only the supplied host-side contracts; also check `configuration.passed` for EFI consistency.

An overall pass is an offline preparation result. It does not authenticate the port, establish equivalence between the staged core and this checkout, or reproduce live import binding. Wireless image/vtable pins and request/event schemas remain independent live gates. Record boot, association, private address, both AirDrop directions and sleep/wake separately in the [hardware records](RUNTIME-VALIDATION.md).

Without `--kernel-collection`, the command reports EFI preparation but exits nonzero because target evidence is missing. The tool only reads inputs, builds a temporary host probe and creates a new report. No driver is installed or loaded.

</details>
