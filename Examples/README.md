# Wi-Fi 配置片段

两个 plist 配套 **1.1.0 自动兼容核心**，需要合并到现有 EFI，不是完整 config.plist。RELEASE／DEBUG 的加载条目相同，核心只安装一个。1.0.1-rc1 使用其发布包内的旧片段。

加载顺序：AirportBrcmCompat → IOLegacyWFamily → IO80211FamilyLegacy → 对应的 AirPortBrcmNIC。

只屏蔽系统 IO80211Family，保留系统 IOSkywalkFamily。使用[构建工具](../BUILDING.md#wi-fi-dependency-profiles)
生成的跨版本依赖包，放入两个公共依赖和两个 NIC 变体；每次启动只加载其中一个 NIC。

| NIC 文件 | 内核范围 |
| --- | --- |
| `AirPortBrcmNIC-Sonoma-Sequoia.kext` | Darwin 23–24 |
| `AirPortBrcmNIC-Tahoe.kext` | Darwin 25 起 |

保留自己的 ACPI、SMBIOS、磁盘、显卡和 USB 配置。核心、公共依赖及屏蔽条目从 Darwin 23 开始，
NIC 条目按上表互斥选择。核心仍按实际接口决定是否启用适配，版本范围不是全部小版本的兼容证明。
片段保留 DisableLinkeditJettison=true。版本字段含义见 [OpenCore 配置文档](https://github.com/acidanthera/OpenCorePkg/blob/master/Docs/Configuration.pdf)。

DEBUG 调试参数为 `-brcmcompatdbg`，追加到已有 boot-args。分享日志前先脱敏。
