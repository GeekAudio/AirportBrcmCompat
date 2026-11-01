# 离线交付工具

`brcmctl.py` 使用 Python 3.9 及以上版本，针对提供的核心 ZIP、配置文件和 EFI 副本工作。
工具位于源码仓库的 `tools/` 目录。安装 ZIP 只包含 kext 和配置片段；精简核心包使用发布页的 SHA-256 校验。

核对核心包及发布页的 SHA-256：

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

## 维护者发包

完整测试通过后，将对应的两种核心和两份依赖输入交给统一发包器：

```sh
python3 tools/package_release.py --release-core build/ci-RELEASE.zip \
  --debug-core build/ci-DEBUG.zip --dependencies build/ci-dependencies.zip \
  --additional-cards build/ci-additional.zip --test-log offline-tests.log --output build/distribution
```

输入构建包必须保留构建清单，并与当前源码哈希一致。工具复核签名、依赖字节、测试数量及零跳过结果，输出四份仅含 kext 和配置片段的安装 ZIP。完整构建清单移至独立的 `06-VALIDATION.json`，版权许可移至 `07-LICENSES.md`，下载校验值位于 `05-SHA256SUMS.txt`。CI 执行同一流程，保留日志和整套产物。
