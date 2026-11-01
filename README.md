# AirportBrcmCompat

基于 AirPortBrcmNIC 的博通 Wi-Fi 兼容驱动，通过 EFI 加载，不修改系统卷。自研核心以 [BSD-3-Clause](LICENSE) 开源。

当前版本为 **1.1.0**：按实际内核接口和请求格式检查兼容性，不维护系统构建号或内核 UUID 白名单。接口保持兼容时，系统更新无需单独增加版本规则。

[![Offline validation](https://github.com/GeekAudio/AirportBrcmCompat/actions/workflows/ci.yml/badge.svg)](https://github.com/GeekAudio/AirportBrcmCompat/actions/workflows/ci.yml)

## 下载与安装

**普通安装下载两份：`RELEASE.zip` ＋ `Dependencies-WiFi-Examples.zip`。**
BCM43225／BCM4352 还需下载 `Additional-Modern-Cards.zip`。以下文件均为 **1.1.0**，按 PCI ID 选择：

| 网卡 PCI ID（Vendor 为 `14e4`） | 下载哪些包 |
| --- | --- |
| `43ba`、`43a3`、`43a0`（BCM43602／BCM4350／BCM4360） | RELEASE 核心 ＋ Wi-Fi 依赖与配置示例 |
| `4357`、`43b1`、`43b2`（BCM43225／BCM4352） | 上述两份 ＋ 可选第三方网卡匹配 |

| 下载文件 | 解压后安装什么 |
| --- | --- |
| [AirportBrcmCompat-1.1.0-RELEASE.zip](https://github.com/GeekAudio/AirportBrcmCompat/releases/download/v1.1.0/AirportBrcmCompat-1.1.0-RELEASE.zip) | 普通用户选这份；复制 `AirportBrcmCompat.kext` |
| [AirportBrcmCompat-1.1.0-Dependencies-WiFi-Examples.zip](https://github.com/GeekAudio/AirportBrcmCompat/releases/download/v1.1.0/AirportBrcmCompat-1.1.0-Dependencies-WiFi-Examples.zip) | 必需；复制 `Kexts/` 下的四个 kext，并合并 `Examples/` 中的配置片段 |
| [AirportBrcmCompat-1.1.0-Additional-Modern-Cards.zip](https://github.com/GeekAudio/AirportBrcmCompat/releases/download/v1.1.0/AirportBrcmCompat-1.1.0-Additional-Modern-Cards.zip) | 仅上表第二组需要；复制整个 `AirportBrcmFixup.kext`，保留内部插件，合并 `config.additional-cards.plist` |
| [AirportBrcmCompat-1.1.0-DEBUG.zip](https://github.com/GeekAudio/AirportBrcmCompat/releases/download/v1.1.0/AirportBrcmCompat-1.1.0-DEBUG.zip) | 排查问题时替代 RELEASE 核心；二选一，其他依赖相同 |

安装步骤：

1. 备份现有 EFI。以前打过 OCLP 无线根补丁的，先撤销该补丁。
2. 将核心包的 `AirportBrcmCompat.kext` 和依赖包 `Kexts/` 下的四个 kext 复制到 `EFI/OC/Kexts/`，保留文件夹原名。两个 NIC 变体都复制，OpenCore 按系统自动选择，每次只加载一个。
3. 普通安装将依赖包中的 `Examples/config-WiFi-RELEASE.example.plist` 合并进现有 `EFI/OC/config.plist`；DEBUG 使用对应的 DEBUG 片段。片段不是完整配置，保留本机其他设置。加载顺序为：核心 → IOLegacyWFamily → IO80211FamilyLegacy → 对应 NIC。
4. 需要第三方网卡匹配包时，再复制整个 `AirportBrcmFixup.kext`，并将 `config.additional-cards.plist` 的两个加载条目加入 `Kernel → Add`，放在两个 `AirPortBrcmNIC` 条目前；内部注入器保持在主组件之后。
5. 在 EFI 副本上完成配置校验和[离线预检](tools/README.md)，再替换使用中的 EFI。

| 系统 | 配置片段自动启用的 NIC |
| --- | --- |
| Sonoma 14、Sequoia 15 | `AirPortBrcmNIC-Sonoma-Sequoia.kext` |
| Tahoe 26 | `AirPortBrcmNIC-Tahoe.kext` |

三个定制无线依赖必须配套使用，不能替换成原版同名文件。下载页的 `SHA256SUMS.txt` 和 `VALIDATION.json` 用于校验，`Source code` 用于开发，这些文件都不复制进 EFI。
依赖包附带[离线交付工具](tools/README.md)，支持核对核心包、生成配置副本、检查文件和加载顺序，以及导出检查摘要。

## 无线依赖

| 组件 | 版本 | 用途 |
| --- | --- | --- |
| IOLegacyWFamily | 1.0 | 私有命名空间的 Skywalk 支撑层，与系统 IOSkywalkFamily 共存 |
| IO80211FamilyLegacy | 1200.12.2b1 | Wi-Fi 兼容路径使用的无线框架 |
| AirPortBrcmNIC | 1400.1.1 | 博通网卡硬件驱动 |

本项目保留系统 IOSkywalkFamily，只屏蔽系统 IO80211Family。源码中的 [Examples](Examples/README.md)
配套 1.1.0 核心及跨版本依赖包：共用前两个依赖，由 OpenCore 在两个 NIC 变体中自动选择一个。
1.0.1-rc1 使用其下载包内的片段。组件来源见 [NOTICE](NOTICE.md)。

蓝牙支持请参考 [Acidanthera 作者项目](https://github.com/acidanthera/BrcmPatchRAM#bluetoolfixupkext)。

## 兼容对应表

适用于 Intel x86_64。下表按 OCLP Modern Wireless 中的 Broadcom 驱动家族整理；这些 PCI ID 的 Vendor ID 为 `14e4`。
表中列出目标系统大版本，是否可用仍取决于运行时接口和请求格式检查。
**离线验证**表示随包驱动和已实现的接口／请求格式检查通过。已有功能基线的硬件是 BCM943602CDP / BCM43602，来自 1.0.1-rc1 的 Tahoe 测试。

| 网卡 / 驱动家族 | PCI Device ID | Sonoma 14 | Sequoia 15 | Tahoe 26 | 依赖方案 |
| --- | --- | --- | --- | --- | --- |
| BCM43602、BCM4350、BCM4360 | `43ba`、`43a3`、`43a0` | 离线验证 | 离线验证 | 离线验证；BCM43602 有历史功能基线 | 现代 NIC |
| BCM43225、BCM4352 | `4357`、`43b1`、`43b2` | 离线验证 | 离线验证 | 离线验证 | 现代 NIC＋可选匹配组件 |

所有方案均通过 EFI/kext 加载，不替换系统无线服务。原生可用的组合保持原样；较新的 AppleBCMWLAN 家族、没有对应 Apple 驱动的芯片及 USB Wi-Fi 不在此表范围内。
PCI 匹配不等于硬件功能已验证。分类依据和各路径进展见[兼容范围与上游依据](COMPATIBILITY.md)。
表内六个 PCI ID 已在两种随包 NIC 的实际设备表和对应查找成功路径中核对；可选匹配组件的核心与子注入器均只保留这六项。

- 核心和现代无线依赖的最低目标为 Darwin 23；Sonoma／Sequoia 与 Tahoe 使用各自的 NIC 依赖变体。
- 内核映像结构、关键函数实现、随包驱动及请求格式分别检查。检查失败时，不启用对应适配功能。
- 当前源码按实际博通主接口身份匹配 `en0`、`en1` 等名称；已发布的旧下载版本仍使用其原有接口限制。
- 接口没有改变的系统更新无需添加版本号和 UUID；新的内核实现或协议变化仍可能需要开发适配。
- 已知内核实现优先使用现有检查；内部布局变化时，可通过公开 ioctl 调用范围和主接口回调检查建立备用路径，减少固定偏移依赖。
- 启动环境和底层依赖仍须支持目标系统。
- 1.0.1-rc1 的 Test023r2 在 25G332 下完成双向 AirDrop 实际收件，32 KiB 回传文件 SHA-256 一致；这是该版本的功能基线。
- 三种关联请求格式的 SAE 均接受已核对的密码载荷子集：selected auth=4096、cipher=10、密码 8–63 字节、PMK 长度 32，策略掩码保留原值。

## 源码与构建

核心位于 [src](src)，离线回归测试位于 [tests](tests)。[构建说明](BUILDING.md) 提供固定构建依赖、两种编译配置与测试命令。

[下载校验值](https://github.com/GeekAudio/AirportBrcmCompat/releases/download/v1.1.0/SHA256SUMS.txt) · [1.0.1-rc1](https://github.com/GeekAudio/AirportBrcmCompat/releases/tag/v1.0.1-rc1)
