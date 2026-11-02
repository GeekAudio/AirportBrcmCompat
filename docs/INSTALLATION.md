# 安装 AirportBrcmCompat

选择 **01 RELEASE** 作为正常安装包，或在排查问题时选择 **02 DEBUG**。两包都是完整包；只下载其中一个。它们使用相同的 kext 依赖和 `config.plist`，Sonoma 14、Sequoia 15、Tahoe 26 不需要选不同的无线依赖。

## 包里有什么

解压后打开 `Kexts/`，按包内配置安装各 kext：

```text
Kexts/
├── AirportBrcmCompat.kext/
├── AirPortBrcmNIC.kext/
└── ...
config.plist
```

两个 ZIP 都包含完整的安装文件。`AirPortBrcmNIC.kext` 只有一份，所有目标系统共用；其余依赖也使用同一套文件，不需要按 macOS 版本挑选。把 `config.plist` 列出的组件都复制到 `EFI/OC/Kexts/`。PCI 匹配范围以配置为准，不要手动扩展。

`config.plist` 是 OpenCore 配置片段，不是完整 EFI 配置。它给出需要加入的 `Kernel -> Add`、`Kernel -> Block` 和相关 `Kernel -> Quirks` 设置。按配置中的顺序加载，不要手动重排。

## 手动安装

1. 复制一份 EFI 作为备份，并在备份上操作。确认自己的 OpenCore 版本和网卡 PCI ID。
2. 从 RELEASE 或 DEBUG 包复制 `Kexts/` 下需要的 kext 到 `EFI/OC/Kexts/`。保留每个文件夹原名及其内部文件，不要把一个 kext 的文件混入另一个。
3. 打开包内 `config.plist`，把列出的 `Kernel -> Add` 项合并到 EFI 的 `config.plist`。同时合并片段列出的 `Kernel -> Block` 和 `Kernel -> Quirks` 设置。已有且符合要求的较新共享依赖可以继续使用，只保留一个加载条目。保留其他 OpenCore 设置，不要用片段覆盖整份配置。
4. 从旧版升级时，删除旧的 `AirPortBrcmNIC-Sonoma-Sequoia.kext`、`AirPortBrcmNIC-Tahoe.kext` 及其 `Kernel -> Add` 项。新包使用统一名称 `AirPortBrcmNIC.kext`；不要让新旧 NIC 驱动同时加载。
5. 用与当前 OpenCore 版本对应的 `ocvalidate` 检查修改后的配置，再从备份 EFI 启动并按实际需要验证 Wi-Fi。

如果曾经通过 OCLP 给系统卷打过无线补丁，先用 OCLP 恢复系统卷，再使用 EFI/kext 安装。AirportBrcmCompat 不要求修改 macOS 系统卷。

## 离线预览

源码仓库还提供安装预览工具。默认只读取安装包和指定的 EFI 副本，显示将复制的文件及配置变化，不写入文件：

```sh
python3 tools/install.py --archive /path/to/01-AirportBrcmCompat-1.1.0-RELEASE.zip --sha256 <release-page-sha256> --oc-dir /path/to/EFI-copy/EFI/OC --darwin "$(uname -r)"
```

只有明确加上 `--apply` 并指定 `--backup-dir` 才会写入目标 EFI 目录。第一次使用请保留默认预览，并检查目标路径和计划变更。详细参数见[安装预览工具说明](../tools/README.md#offline-install-preview)。

## DEBUG 日志

DEBUG 包只用于排查。先按上面的步骤备份并替换整套文件，再将 `-brcmcompatdbg` 追加到现有 OpenCore `boot-args`，重启后复现问题：

```sh
sudo log show --last boot --style compact --info --debug --predicate 'process == "kernel" AND eventMessage CONTAINS[c] "AirportBrcmCompat"' > ~/Desktop/AirportBrcmCompat-debug.log
ioreg -r -l -w0 -c AirportBrcmCompat > ~/Desktop/AirportBrcmCompat-ioreg.log
```

把 macOS 完整版本、网卡 PCI ID 和两份日志一起提供；分享前去掉个人信息。排查结束后换回 RELEASE 整套文件，移除 `-brcmcompatdbg` 并重启。异常后的隔离与恢复边界见[诊断与恢复说明](RUNTIME-VALIDATION.md)。

## 验证范围

同一套安装文件面向 Sonoma 14、Sequoia 15 和 Tahoe 26。离线构建与接口检查不等于在每张卡、每个系统构建上完成了实机验证；项目矩阵会按 PCI ID 和实际系统记录结果。请勿把支持目标理解成所有小版本均已实测。

<details>
<summary>English</summary>

Choose **01 RELEASE** for normal use or **02 DEBUG** for troubleshooting. Each ZIP is complete; download one. Both packages use the same kext set and `config.plist` on Sonoma 14, Sequoia 15 and Tahoe 26.

### Package contents

Install the kexts following the package configuration:

```text
Kexts/
├── AirportBrcmCompat.kext/
├── AirPortBrcmNIC.kext/
└── ...
config.plist
```

Both ZIPs contain the complete installation files. There is one `AirPortBrcmNIC.kext` for all target systems, with the same remaining dependencies; there is no OS-specific choice. Copy every component listed in `config.plist` to `EFI/OC/Kexts/`. Use only the PCI matches in the configuration.

The included `config.plist` is an OpenCore fragment, not a full EFI configuration. It contains the required `Kernel -> Add`, `Kernel -> Block` and related `Kernel -> Quirks` settings. Keep its load order.

### Manual installation

1. Make an EFI backup and work on the copy. Check your OpenCore version and card PCI ID.
2. Copy the required kexts from the ZIP's `Kexts/` folder to `EFI/OC/Kexts/`. Keep each bundle's name and internal files intact.
3. Merge the `Kernel -> Add` entries and listed `Kernel -> Block` / `Kernel -> Quirks` settings. Keep a newer shared dependency if it meets the requirements, with one load entry. Preserve other OpenCore settings; do not replace the full configuration.
4. When upgrading, remove the old `AirPortBrcmNIC-Sonoma-Sequoia.kext`, `AirPortBrcmNIC-Tahoe.kext` and their `Kernel -> Add` entries. The unified package uses `AirPortBrcmNIC.kext`; do not load both old and new NIC drivers.
5. Validate the edited configuration with the `ocvalidate` version matching your OpenCore release. Boot from the backup EFI and test Wi-Fi as needed.

If OCLP previously patched wireless files on the system volume, revert those patches with OCLP before installing through EFI. AirportBrcmCompat does not require system-volume changes.

### Offline preview

The source repository also provides an installer preview. By default, it reads the package and an EFI copy, then shows the planned files and configuration changes without writing:

```sh
python3 tools/install.py --archive /path/to/01-AirportBrcmCompat-1.1.0-RELEASE.zip --sha256 <release-page-sha256> --oc-dir /path/to/EFI-copy/EFI/OC --darwin "$(uname -r)"
```

Writing requires the explicit `--apply` option and a `--backup-dir`. Keep the default preview for the first run and review the target path and planned changes. See the [installer preview documentation](../tools/README.md#offline-install-preview).

### DEBUG logs

Use the DEBUG ZIP only for troubleshooting. Back up and replace the complete file set, append `-brcmcompatdbg` to your existing OpenCore `boot-args`, restart, reproduce the issue, and run:

```sh
sudo log show --last boot --style compact --info --debug --predicate 'process == "kernel" AND eventMessage CONTAINS[c] "AirportBrcmCompat"' > ~/Desktop/AirportBrcmCompat-debug.log
ioreg -r -l -w0 -c AirportBrcmCompat > ~/Desktop/AirportBrcmCompat-ioreg.log
```

Include the full macOS version, PCI ID and both logs in a report. Remove personal information before sharing. After troubleshooting, restore the complete RELEASE files, remove `-brcmcompatdbg` and restart. See [diagnostics and recovery](RUNTIME-VALIDATION.md) for recovery limits.

### Validation scope

The same package targets Sonoma 14, Sequoia 15 and Tahoe 26. Offline builds and interface checks do not equal hardware validation for every card and system build. See the project matrix for results tied to specific PCI IDs and systems; target scope does not mean every minor release has been tested.

</details>
