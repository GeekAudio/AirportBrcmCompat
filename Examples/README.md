# Wi-Fi 配置片段

两个 plist 配套 **1.1.0 自动兼容核心**，需要合并到现有 EFI，不是完整 config.plist。RELEASE／DEBUG 的加载条目相同，核心只安装一个。1.0.1-rc1 使用其发布包内的配置片段。

普通安装下载 `AirportBrcmCompat-1.1.0-RELEASE.zip` 和 `AirportBrcmCompat-1.1.0-Dependencies-WiFi-Examples.zip`。
将前者的 `AirportBrcmCompat.kext`、后者 `Kexts/` 下的四个 kext 复制到 `EFI/OC/Kexts/`，保留原名；两个 NIC 变体均复制。
合并 `config-WiFi-RELEASE.example.plist` 的 `Kernel` 项，保留本机其他配置。DEBUG 只替换核心，并使用对应片段。

加载顺序：AirportBrcmCompat → IOLegacyWFamily → IO80211FamilyLegacy → 对应的 AirPortBrcmNIC。

BCM43225／BCM4352（PCI ID `14e4:4357`、`14e4:43b1`、`14e4:43b2`）还需 `AirportBrcmCompat-1.1.0-Additional-Modern-Cards.zip`。
复制整个 `AirportBrcmFixup.kext`，保留内部插件；将 `config.additional-cards.plist` 中的两个加载条目加入 `Kernel → Add`，放在两个 NIC 条目前，内部注入器排在主组件之后。
BCM43602／BCM4350／BCM4360（`14e4:43ba`、`14e4:43a3`、`14e4:43a0`）使用前两份包即可。

只屏蔽系统 IO80211Family，保留系统 IOSkywalkFamily。使用[构建工具](../BUILDING.md#wi-fi-dependency-profiles)
生成的跨版本依赖包，放入两个公共依赖和两个 NIC 变体；每次启动只加载其中一个 NIC。

| NIC 文件 | 内核范围 |
| --- | --- |
| `AirPortBrcmNIC-Sonoma-Sequoia.kext` | Darwin 23–24 |
| `AirPortBrcmNIC-Tahoe.kext` | Darwin 25 起 |

保留自己的 ACPI、SMBIOS、磁盘、显卡和 USB 配置。核心、现代公共依赖及屏蔽条目从 Darwin 23 开始，
NIC 条目按上表互斥选择。
核心按实际接口决定是否启用适配，具体状态见项目兼容说明。
片段保留 DisableLinkeditJettison=true。版本字段含义见 [OpenCore 配置文档](https://github.com/acidanthera/OpenCorePkg/blob/master/Docs/Configuration.pdf)。

DEBUG 调试参数为 `-brcmcompatdbg`，追加到已有 boot-args。分享日志前先脱敏。

可使用随包 `tools/brcmctl.py configure` 生成合并后的新配置，再用 `preflight` 按目标 Darwin 版本检查 EFI 副本；命令见 [工具说明](../tools/README.md)。
