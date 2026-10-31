# AirportBrcmCompat

博通 BCM43602 的 Wi-Fi 兼容驱动，通过 EFI 加载，不修改系统卷。自研核心以 [BSD-3-Clause](LICENSE) 开源。

当前源码及仓库内核心为 **1.1.0 自动兼容候选版**：按实际内核接口和请求格式检查兼容性，不维护系统构建号或内核 UUID 白名单。接口保持兼容时，系统更新无需单独增加版本规则。

已发布的下载版本仍为 **1.0.1-rc1**，限定 25G241／25G332；下方下载不会随源码分支变化。

## 下载

| 文件 | 用途 |
| --- | --- |
| [RELEASE 核心](https://github.com/GeekAudio/AirportBrcmCompat/releases/download/v1.0.1-rc1/AirportBrcmCompat-1.0.1-rc1-RELEASE.zip) | 不含额外无线诊断 |
| [DEBUG 核心](https://github.com/GeekAudio/AirportBrcmCompat/releases/download/v1.0.1-rc1/AirportBrcmCompat-1.0.1-rc1-DEBUG.zip) | 含无线诊断功能的调试版本 |
| [Wi-Fi 依赖与配置示例](https://github.com/GeekAudio/AirportBrcmCompat/releases/download/v1.0.1-rc1/AirportBrcmCompat-1.0.1-rc1-Dependencies-WiFi-Examples.zip) | 三个定制无线依赖及配置片段 |

核心只安装一种。将核心与依赖包中的三个 kext 放入 EFI/OC/Kexts，再将对应版本包内的配置片段合并到自己的 config.plist，保留本机其他配置。

以前打过 OCLP 无线根补丁的先撤销补丁。三个定制无线依赖必须配套使用，不能替换成原版同名文件。

## 无线依赖

| 组件 | 版本 | 用途 |
| --- | --- | --- |
| IOLegacyWFamily | 1.0 | 私有命名空间的 Skywalk 支撑层，与系统 IOSkywalkFamily 共存 |
| IO80211FamilyLegacy | 1200.12.2b1 | Wi-Fi 兼容路径使用的无线框架 |
| AirPortBrcmNIC | 1400.1.1 | 博通网卡硬件驱动 |

本项目保留系统 IOSkywalkFamily，只屏蔽系统 IO80211Family。源码中的 [Examples](Examples/README.md)
配套 1.1.0 候选核心及跨版本依赖包：共用前两个依赖，由 OpenCore 在两个 NIC 变体中自动选择一个。
1.0.1-rc1 使用其下载包内的片段。组件来源见 [NOTICE](NOTICE.md)。

蓝牙支持请参考 [Acidanthera 作者项目](https://github.com/acidanthera/BrcmPatchRAM#bluetoolfixupkext)。

## 兼容对应表

适用于 Intel x86_64。下表按 OCLP Modern Wireless 中的 Broadcom 驱动家族整理；这些 PCI ID 的 Vendor ID 为 `14e4`。
表中列出目标系统大版本，是否可用仍取决于运行时接口和请求格式检查。
**候选适配**表示当前源码仍在完善该路径。
已发布的 1.0.1-rc1 仍限定 25G241／25G332，已有功能基线的硬件是 BCM943602CDP / BCM43602。

| 网卡 / 驱动家族 | PCI Device ID | Sonoma 14 | Sequoia 15 | Tahoe 26 | 依赖方案 |
| --- | --- | --- | --- | --- | --- |
| BCM43602、BCM4350、BCM4360 | `43ba`、`43a3`、`43a0` | 候选适配 | 候选适配 | 候选适配；BCM43602 有 25G332 功能基线 | 现代 NIC |
| BCM94331、BCM943224 | `4331`、`4353` | 候选适配 | 候选适配 | 候选适配 | 现代 NIC＋可选匹配组件 |
| BCM43225、BCM4352 | `4357`、`43b1`、`43b2` | 候选适配 | 候选适配 | 候选适配 | 现代 NIC＋可选匹配组件 |

所有方案均通过 EFI/kext 加载，不替换系统无线服务。原生可用的组合保持原样；较新的 AppleBCMWLAN 家族、没有对应 Apple 驱动的芯片及 USB Wi-Fi 不在此表范围内。
PCI 匹配不等于硬件功能已验证。分类依据和各路径进展见[兼容范围与上游依据](COMPATIBILITY.md)。

- 核心和现代无线依赖的最低目标为 Darwin 23；Sonoma／Sequoia 与 Tahoe 使用各自的 NIC 依赖变体。
- 内核映像结构、关键函数实现、随包驱动及请求格式分别检查。检查失败时，不启用对应适配功能。
- 当前源码按实际博通主接口身份匹配 `en0`、`en1` 等名称；已发布的旧下载版本仍使用其原有接口限制。
- 接口没有改变的系统更新无需添加版本号和 UUID；新的内核实现或协议变化仍可能需要开发适配。
- 启动环境和底层依赖仍须支持目标系统。
- 1.0.1-rc1 的 Test023r2 在 25G332 下完成双向 AirDrop 实际收件，32 KiB 回传文件 SHA-256 一致；这是该版本的功能基线。
- 现代 NIC 路径的 SAE 接受已核对的密码载荷子集：selected auth=4096、cipher=10、密码 8–63 字节、PMK 长度 32，策略掩码保留原值。

## 源码与构建

核心位于 [src](src)，离线回归测试位于 [tests](tests)。[构建说明](BUILDING.md) 提供固定构建依赖、两种编译配置与测试命令。

[下载校验值](https://github.com/GeekAudio/AirportBrcmCompat/releases/download/v1.0.1-rc1/SHA256SUMS.txt) · [旧 25G241 版本 1.0](https://github.com/GeekAudio/AirportBrcmCompat/releases/tag/v1.0)
