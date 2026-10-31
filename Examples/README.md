# Wi-Fi 配置片段

两个 plist 配套 **1.1.0 自动兼容核心**，需要合并到现有 EFI，不是完整 config.plist。RELEASE／DEBUG 的加载条目相同，核心只安装一个。1.0.1-rc1 使用其发布包内的旧片段。

加载顺序：AirportBrcmCompat → IOLegacyWFamily → IO80211FamilyLegacy → AirPortBrcmNIC。

只屏蔽系统 IO80211Family，保留系统 IOSkywalkFamily。三个定制无线依赖必须配套使用。

保留自己的 ACPI、SMBIOS、磁盘、显卡和 USB 配置。无线加载与屏蔽条目统一使用 MinKernel=25.0.0、MaxKernel 留空；核心按实际接口决定是否启用适配。片段保留 DisableLinkeditJettison=true。版本字段含义见 [OpenCore 配置文档](https://github.com/acidanthera/OpenCorePkg/blob/master/Docs/Configuration.pdf)。

DEBUG 调试参数为 `-brcmcompatdbg`，追加到已有 boot-args。分享日志前先脱敏。
