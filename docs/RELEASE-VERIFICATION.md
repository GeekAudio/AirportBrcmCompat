# 核验下载包

每个版本发布两份完整安装 ZIP：**01 RELEASE** 用于日常安装，**02 DEBUG** 用于排查。选择其中一个即可，不再另下 Wi-Fi 依赖包或网卡补充包。两个包应包含同一套 kext 和 `config.plist`，DEBUG 只用于诊断。

## 安装前核对

1. 确认下载名含有正确的版本和 `RELEASE` 或 `DEBUG` 标记。
2. 在 GitHub Release 说明中找到对应 ZIP 公布的 SHA-256，再本地核对：

   ```sh
   shasum -a 256 01-AirportBrcmCompat-1.1.0-RELEASE.zip
   ```

3. 解压后确认包内有 `Kexts/` 和 `config.plist`。应使用同一个 `AirPortBrcmNIC.kext`；不应出现旧的 `AirPortBrcmNIC-Sonoma-Sequoia.kext`、`AirPortBrcmNIC-Tahoe.kext` 或按系统区分的依赖 ZIP。
4. `config.plist` 是 OpenCore 配置片段。只合并它列出的设置，保留现有 EFI 的其他内容。
5. 有源码仓库时，可先对 EFI 副本运行[安装预览工具](../tools/README.md#offline-install-preview)。默认模式只检查并显示计划变更，不写入 EFI。

安装 ZIP 只包含用户安装所需的 kext 和配置片段。验证记录、工具、文档、源码以及单独的 TXT 文件不放进这两个 ZIP。GitHub 页面自动提供的源码归档不是安装包。

## 发布身份记录

公开发布时，分别核对下列三项；它们说明不同环节：

| 项目 | 核对内容 |
| --- | --- |
| Git tag | tag 名和指向的提交，确定发布源码快照 |
| RELEASE / DEBUG 核心 | 每个实际核心二进制的 SHA-256、Mach-O UUID 和对应构建清单 |
| 最终安装 ZIP | 重打包提交、归档 SHA-256、包内文件清单及签名核对结果 |

[当前统一包清单](../validation/unified-distribution.json)记录文件哈希与核心构建；[统一网卡核验](../validation/unified-nic.json)记录静态差异范围。

源码归档使用 GitHub 的 tag 快照。打包器或文档若在 tag 之后更新，应记录实际使用的重打包提交；不能把 tag、核心构建和最终 ZIP 当成同一个版本身份。发布流程应在 Release 说明中列出两份最终 ZIP 的 SHA-256，便于下载者逐一核对。

校验值一致能证明本地下载与发布记录一致；它不证明发布者身份，也不代表网卡已经在实机上通过启动、联网或 AirDrop 验证。兼容目标和证据范围见[兼容说明](../COMPATIBILITY.md)及[实机验证矩阵](../validation/RUNTIME-MATRIX.md)。

<details>
<summary>English</summary>

Each release provides two complete installer ZIPs: **01 RELEASE** for normal use and **02 DEBUG** for troubleshooting. Choose one; there is no separate Wi-Fi dependency or card add-on download. Both packages should contain the same kext set and `config.plist`; DEBUG is for diagnosis.

### Before installing

1. Check the version and `RELEASE` or `DEBUG` label in the filename.
2. Find the matching SHA-256 in the GitHub Release notes and compare it with the local file:

   ```sh
   shasum -a 256 01-AirportBrcmCompat-1.1.0-RELEASE.zip
   ```

3. After extraction, confirm that the package contains `Kexts/` and `config.plist`. It should use one `AirPortBrcmNIC.kext`, with no old Sonoma/Sequoia or Tahoe NIC variants and no OS-specific dependency ZIPs.
4. `config.plist` is an OpenCore fragment. Merge only its listed settings and keep the rest of your EFI configuration.
5. If you have the source checkout, run the [installer preview](../tools/README.md#offline-install-preview) against an EFI copy first. Its default mode displays planned changes without writing to EFI.

Installer ZIPs contain only the kexts and configuration fragment needed for installation. Validation records, tools, documentation, source code and standalone TXT files stay outside these two ZIPs. GitHub's automatically generated source archives are not installer packages.

### Release identity

Check these three records separately:

| Record | What it identifies |
| --- | --- |
| Git tag | The source snapshot selected for the release |
| RELEASE / DEBUG core | Each actual core binary's SHA-256, Mach-O UUID and build manifest |
| Final installer ZIP | The repackaging commit, archive SHA-256, member inventory and signature checks |

The [unified package inventory](../validation/unified-distribution.json) records member hashes and core builds; [NIC evidence](../validation/unified-nic.json) records the static delta checks.

GitHub's source archive follows the tag. If packaging code or documentation changes after the tag, record the actual repackaging commit; the tag, core build and final ZIP are separate identities. The release process should publish the SHA-256 of both final ZIPs in the Release notes.

A matching hash shows that a local download matches its release record. It does not authenticate the publisher or prove that a card passed boot, networking or AirDrop tests on hardware. See the [compatibility details](../COMPATIBILITY.md) and the [hardware validation matrix](../validation/RUNTIME-MATRIX.md) for evidence scope.

</details>
