# 离线交付工具

`brcmctl.py` 使用 Python 3.9 及以上版本，针对提供的核心 ZIP、配置文件和 EFI 副本工作。
工具位于源码仓库的 `tools/` 目录。安装 ZIP 只包含 kext 和配置片段；完整安装包使用发布页的 SHA-256 校验。

核对安装包及发布页的 SHA-256：

```sh
python3 tools/brcmctl.py probe --core 01-AirportBrcmCompat-1.1.0-RELEASE.zip --sha256 <发布校验值>
```

将 Wi-Fi 片段合并成一个新配置文件，保留原配置里的其他条目：

```sh
python3 tools/brcmctl.py configure --config /path/to/EFI/OC/config.plist \
  --fragment Examples/config-WiFi-RELEASE.example.plist --output /path/to/config.new.plist
```

输出文件必须尚不存在。合并后的驱动组保持片段中的依赖顺序，其他驱动维持原有顺序；原配置不改写。

在准备好的 EFI 副本中检查目标系统的有效条目、文件、依赖顺序、单一 NIC 选择和必要设置：

```sh
python3 tools/brcmctl.py preflight --oc-dir /path/to/EFI-copy/OC --darwin 25.0.0
python3 tools/brcmctl.py collect --oc-dir /path/to/EFI-copy/OC --darwin 25.0.0 --output preflight.json
```

Sonoma 使用 Darwin 23，Sequoia 使用 24，Tahoe 使用 25。多系统 EFI 按各目标分别检查。
摘要包含配置摘要哈希、驱动标识、版本、二进制哈希及检查结果，省略 SMBIOS、NVRAM、网络名称和地址。

这些检查验证文件和配置的一致性。OpenCore 官方配置校验、实际加载及无线功能有各自的验证范围。

## 新系统升级前检查

`upgrade-check --oc-dir EFI-copy/OC --darwin <目标内核版本> --kernel-collection <目标BootKC> --output report.json` 同时检查 EFI 副本和目标 Intel 内核样本。实际版本不符、ARM64、缺少样本或契约不符均不能算通过；不安装驱动。完整步骤、结果解释和折叠英文见 [macOS 27 准备](../docs/MACOS-27-PREPARATION.md)。

## 维护者发包

完整测试通过后，将两种核心、统一依赖和匹配组件输入交给发包器：

```sh
python3 tools/package_release.py --release-core build/ci-RELEASE.zip \
  --debug-core build/ci-DEBUG.zip --dependencies build/ci-dependencies.zip \
  --additional-cards build/ci-additional.zip --runtime build/research/Lilu-1.7.2-RELEASE.zip \
  --test-log offline-tests.log --output build/distribution
```

输入构建包必须保留构建清单，并与当前源码哈希一致。工具从固定样本重新核验统一依赖，检查签名、代码段、测试数量和零跳过结果，输出 RELEASE／DEBUG 两个完整安装 ZIP。两包使用相同配置与依赖，核心诊断开关不同。清单、版权许可和校验值放在输出目录的 `metadata/`；发布时将校验值和许可放入 Release 说明，仅上传两个 ZIP。

<a id="offline-install-preview"></a>
## 安装预览与应用

使用 Python 3.9 或更新版本。默认预览只读取指定目录，显示文件与配置变化：

```sh
python3 tools/install.py --archive /path/to/01-AirportBrcmCompat-1.1.0-RELEASE.zip \
  --sha256 <release-page-sha256> --oc-dir /path/to/EFI-copy/OC --darwin 25.6.0
```

核对后，在同一命令后追加 `--apply --backup-dir /path/to/new-backup` 才会写入。备份目录必须是新的、位于 EFI 之外的目录。工具保存原配置和待替换组件；写入前复核文件变化，失败时恢复本次修改。旧的分系统 NIC 条目会迁移为统一名称，其余设备配置保留。工具不挂载 EFI、不写 NVRAM，也不重启。

检查范围是本项目安装的 Wi-Fi 组件；完整配置仍需用对应 OpenCore 版本的 `ocvalidate` 检查。配置与签名检查通过不代表实机无线功能通过。

<details>
<summary>English</summary>

Use the command above with a downloaded ZIP, its published SHA-256, an explicit
OpenCore directory and target Darwin version. The default is a read-only preview.
Add `--apply --backup-dir /path/to/new-backup` to apply after review. The backup
must be new and outside the EFI directory. The installer keeps unrelated devices
and settings, checks for concurrent changes, and restores its changes on failure.
It never mounts EFI, changes NVRAM or restarts. Its preflight covers the Wi-Fi
installation group; validate the complete configuration separately with the
matching OpenCore `ocvalidate`.

</details>

## 查看诊断与核对安装文件

`diagnose --ioreg saved.plist` 只解释留存的结构化 IORegistry 快照；`verify --directory downloads` 逐项核对下载的安装包。未观测阶段、未检查附件及未知恢复状态保持明确标注。步骤见[诊断与恢复](../docs/RUNTIME-VALIDATION.md)和[安装包核验](../docs/RELEASE-VERIFICATION.md)。
