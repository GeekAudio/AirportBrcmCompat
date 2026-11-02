# AirportBrcmCompat

为指定的博通 PCIe 网卡提供 macOS Wi-Fi 兼容支持。驱动从 OpenCore EFI 加载，不修改 macOS 系统卷。

**1.1.0 · 目标系统：Sonoma 14、Sequoia 15、Tahoe 26**

## 下载

从 [GitHub Releases](https://github.com/GeekAudio/AirportBrcmCompat/releases) 选择一个完整安装包：

- **01 RELEASE**：日常安装和使用。
- **02 DEBUG**：仅在排查问题时使用；包含相同的安装组件和配置。

文件名：`01-AirportBrcmCompat-1.1.0-RELEASE.zip` 或 `02-AirportBrcmCompat-1.1.0-DEBUG.zip`。

每个包提供同一套文件，不需要按 macOS 版本挑选 kext。包内有 `Kexts/` 和 `config.plist`；源码仓库、工具和说明文件不放进安装包。

## 安装

先备份 EFI。解压所选 ZIP，把 `Kexts/` 中的 kext 复制到 `EFI/OC/Kexts/`，保留文件夹名称和内部结构。然后将包内 `config.plist` 的 `Kernel` 项合并到 EFI 现有配置中；保留原有条目，不要用这个片段覆盖整份配置。逐步操作见[安装说明](docs/INSTALLATION.md)。

从旧版升级时，移除旧的 `AirPortBrcmNIC-Sonoma-Sequoia.kext` 和 `AirPortBrcmNIC-Tahoe.kext` 文件及对应的 OpenCore 条目，避免同时加载旧、新两套依赖。以前通过 OCLP 修改过系统无线文件的，先用 OCLP 恢复系统，再使用 EFI 安装方式。

## 适用网卡与验证状态

以下 PCI ID 使用同一份安装包。离线检查通过只表示源码、依赖接口和配置经过静态核对；本版本尚无逐卡实机验证记录。

| 网卡 | PCI ID（Vendor `14e4`） | 目标系统 |
| --- | --- | --- |
| BCM43602 / BCM4350 / BCM4360 | `43ba` / `43a3` / `43a0` | Sonoma 14、Sequoia 15、Tahoe 26 |
| BCM43225 / BCM4352 | `4357` / `43b1` / `43b2` | Sonoma 14、Sequoia 15、Tahoe 26 |

核对完整边界和证据见[兼容说明](COMPATIBILITY.md)及[实机验证矩阵](validation/RUNTIME-MATRIX.md)。

## 排查问题

下载 **02 DEBUG**，按同一安装步骤替换 RELEASE 整套文件。需要收集日志时，在现有 OpenCore `boot-args` 末尾追加 `-brcmcompatdbg`，重启并复现问题，然后运行：

```sh
sudo log show --last boot --style compact --info --debug --predicate 'process == "kernel" AND eventMessage CONTAINS[c] "AirportBrcmCompat"' > ~/Desktop/AirportBrcmCompat-debug.log
ioreg -r -l -w0 -c AirportBrcmCompat > ~/Desktop/AirportBrcmCompat-ioreg.log
```

反馈时附上 macOS 版本、PCI ID 和两份日志；分享前删去个人信息。排查后换回 RELEASE 整套文件，移除 `-brcmcompatdbg` 并重启。更多恢复边界见[异常与恢复](docs/RUNTIME-VALIDATION.md)。

## 项目资料

[安装说明](docs/INSTALLATION.md) · [下载核验](docs/RELEASE-VERIFICATION.md) · [macOS 27 离线准备](docs/MACOS-27-PREPARATION.md) · [构建说明](BUILDING.md) · [版权与来源](NOTICE.md) · [BSD-3-Clause](LICENSE) · [蓝牙作者项目](https://github.com/acidanthera/BrcmPatchRAM#bluetoolfixupkext)

<details>
<summary>English</summary>

AirportBrcmCompat adds Wi-Fi compatibility for the Broadcom PCIe cards listed above. It loads through OpenCore EFI and does not modify the macOS system volume.

**1.1.0 · Target systems: Sonoma 14, Sequoia 15 and Tahoe 26**

### Downloads

Choose one complete package from [GitHub Releases](https://github.com/GeekAudio/AirportBrcmCompat/releases):

- **01 RELEASE** for normal installation and use.
- **02 DEBUG** for troubleshooting. It contains the same installation files and configuration.

The filenames are `01-AirportBrcmCompat-1.1.0-RELEASE.zip` and `02-AirportBrcmCompat-1.1.0-DEBUG.zip`.

Both packages use the same files across the listed macOS versions. There is no OS-specific kext choice. Each package contains `Kexts/` and `config.plist`; source code, tools and documentation are kept out of the installer.

### Install

Back up your EFI first. Extract the selected ZIP and copy the kexts in `Kexts/` to `EFI/OC/Kexts/`, keeping their folder names and contents intact. Merge the package's `Kernel` section from `config.plist` into your existing OpenCore configuration. Keep your existing entries; this is not a full replacement configuration. See the [installation guide](docs/INSTALLATION.md) for the steps.

When upgrading from an older package, remove the old `AirPortBrcmNIC-Sonoma-Sequoia.kext` and `AirPortBrcmNIC-Tahoe.kext` files and their OpenCore entries so the old and new dependency sets are not loaded together. If OCLP previously patched the system wireless files, revert those patches with OCLP before using the EFI installation.

### Cards and validation

The PCI IDs below use the same installer. Passing offline checks means the source, dependency interfaces and configuration were reviewed offline. This release has no per-card hardware test records.

| Cards | PCI IDs (vendor `14e4`) | Target systems |
| --- | --- | --- |
| BCM43602 / BCM4350 / BCM4360 | `43ba` / `43a3` / `43a0` | Sonoma 14, Sequoia 15, Tahoe 26 |
| BCM43225 / BCM4352 | `4357` / `43b1` / `43b2` | Sonoma 14, Sequoia 15, Tahoe 26 |

See [compatibility details](COMPATIBILITY.md) and the [hardware validation matrix](validation/RUNTIME-MATRIX.md) for scope and evidence.

### Troubleshooting

Download **02 DEBUG** and replace the complete RELEASE file set using the same installation steps. To collect logs, append `-brcmcompatdbg` to your existing OpenCore `boot-args`, restart, reproduce the issue, and run:

```sh
sudo log show --last boot --style compact --info --debug --predicate 'process == "kernel" AND eventMessage CONTAINS[c] "AirportBrcmCompat"' > ~/Desktop/AirportBrcmCompat-debug.log
ioreg -r -l -w0 -c AirportBrcmCompat > ~/Desktop/AirportBrcmCompat-ioreg.log
```

Include your macOS version, PCI ID and both logs when reporting an issue. Remove personal information before sharing. After troubleshooting, restore the complete RELEASE files, remove `-brcmcompatdbg` and restart. See [diagnostics and recovery](docs/RUNTIME-VALIDATION.md) for recovery limits.

### Project information

[Installation guide](docs/INSTALLATION.md) · [Download verification](docs/RELEASE-VERIFICATION.md) · [macOS 27 offline preparation](docs/MACOS-27-PREPARATION.md) · [Build instructions](BUILDING.md) · [Notices](NOTICE.md) · [BSD-3-Clause](LICENSE) · [Bluetooth upstream](https://github.com/acidanthera/BrcmPatchRAM#bluetoolfixupkext)

</details>
