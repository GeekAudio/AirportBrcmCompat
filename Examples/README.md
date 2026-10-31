# Wi-Fi 配置片段

两个 plist 都是需要合并到现有 EFI 的配置片段，不是完整 config.plist。RELEASE／DEBUG 的加载条目相同，核心只安装一个。

加载顺序：AirportBrcmCompat → IOLegacyWFamily → IO80211FamilyLegacy → AirPortBrcmNIC。

只屏蔽系统 IO80211Family，保留系统 IOSkywalkFamily。三个定制无线依赖必须配套使用。

保留自己的 ACPI、SMBIOS、磁盘、显卡和 USB 配置。无线条目限定 Darwin 25.6.0；核心另行检查系统构建号与内核 UUID。片段保留 DisableLinkeditJettison=true。

DEBUG 调试参数为 `-brcmcompatdbg`，追加到已有 boot-args。分享日志前先脱敏。
