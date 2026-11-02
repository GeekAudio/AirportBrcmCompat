# OpenCore 配置示例

发布包里的 `config.plist` 是一段 OpenCore 配置，不是完整 EFI。把其中的 `Kernel` 设置合并到自己的 EFI 配置，保留现有条目、ACPI、驱动和机型设置。

RELEASE 和 DEBUG 使用同一套依赖与加载顺序。三个目标系统都加载同一个 `AirPortBrcmNIC.kext`；配置里不需要按系统切换 NIC 文件。各 kext 安装在 `EFI/OC/Kexts/`。

按包内 `Kernel -> Add` 的顺序添加组件，不重复已有的 BundlePath。`Kernel -> Block` 和 `Kernel -> Quirks` 只合并相应设置，不覆盖整份配置。OpenCore 版本、目标系统和 PCI ID 应与自己的机器相符；离线配置检查不能证明实机功能。

安装步骤见[安装说明](../docs/INSTALLATION.md)。需要预览配置变更时，见[离线安装预览](../tools/README.md#offline-install-preview)。

<details>
<summary>English</summary>

The `config.plist` in each release package is an OpenCore fragment, not a complete EFI. Merge its `Kernel` settings into your own configuration and keep your existing entries, ACPI, drivers and machine-specific settings.

RELEASE and DEBUG use the same dependency set and load order. All three target macOS generations use the same `AirPortBrcmNIC.kext`; there is no OS-specific NIC selection. Install the kexts in `EFI/OC/Kexts/`.

Follow the package's `Kernel -> Add` order and do not duplicate a BundlePath. Merge only the relevant `Kernel -> Block` and `Kernel -> Quirks` settings; do not replace the full configuration. Check your OpenCore version, target system and PCI ID. Offline configuration checks do not prove hardware operation.

See the [installation guide](../docs/INSTALLATION.md) and the [offline installer preview](../tools/README.md#offline-install-preview).

</details>
