# 最简 Wi-Fi 与蓝牙配置演示

两个 plist 都是需要合并的配置片段，不是可直接启动的完整 config.plist。不要覆盖自己的配置。RELEASE／DEBUG 片段的加载条目相同，核心包和 Lilu 选择对应版本。

加载顺序：Lilu → AMFIPass → AirportBrcmCompat → BlueToolFixup → IOLegacyWFamily → IO80211FamilyLegacy → AirPortBrcmNIC。只屏蔽系统 IO80211Family，保留系统 IOSkywalkFamily。三个定制无线依赖必须配套使用。

蓝牙所在的 USB 端口必须设为内建（Internal，255）。

本例对应已测 BCM20703A2 原生固件蓝牙，只加载 BlueToolFixup；其他需上传固件的型号不在本例验证范围。macOS 12 及以上不要与 BrcmBluetoothInjector 同时加载，见[上游说明](https://github.com/acidanthera/BrcmPatchRAM#bluetoolfixupkext)。

保留自己的 ACPI、SMBIOS、磁盘、显卡和 USB 配置。本例沿用已测环境中的 AMFIPass、DisableLinkeditJettison=true 和 SecureBootModel=Disabled，未证明它们是所有机器的最低要求；不提供通用 SIP／AMFI 精简结论。

DEBUG 如需调试，将 `-liludbg -brcmcompatdbg liludump=30` 追加到已有 boot-args。RELEASE 不加这些调试参数。日志分享前先脱敏。
