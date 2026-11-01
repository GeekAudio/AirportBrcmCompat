# 核对 tag、核心构建和安装包

这三层身份分别记录，不能互相替代：

| 层级 | `06-VALIDATION.json` 中的位置 | 表示什么 |
| --- | --- | --- |
| 发布 tag | `lineage.release.tag`、`tag_commit` | Git 标签指向的提交。没有本地 tag 时明确记录未解析，不猜 HEAD。 |
| 核心构建 | `lineage.core_builds.RELEASE/DEBUG` | 实际核心的 SHA-256、Mach-O UUID、内部构建 ZIP/清单哈希及源码逐文件核对结果。 |
| 最终附件重打包 | `lineage.repackaging`、`artifacts` | 打包工具所在提交、工作区是否有改动、四份最终 ZIP 及包内每个文件的哈希和安装位置。 |

旧核心构建器没有写入当时的提交号，`builder_recorded_source_commit` 因而保留 `null`。`source_files_match_tag=true` 只表示清单里的每份源码都与该 tag 相同，不能反推构建时刻或唯一构建提交。原有 `source_commit` 是重打包提交，另有明确的 `source_commit_role=repackaging`。

GitHub 自动附带的 Source code ZIP 对应 tag。重打包工具、文档或清单在 tag 之后更新时，以 `repackaging.source_commit` 查看对应程序，不能把 tag 和主分支当成同一个快照。历史公开下载记录的脱敏索引在 [release-lineage.json](../validation/release-lineage.json)；当前附件以其 `06-VALIDATION.json` 为准。

## 安装前怎么核对

普通安装下载 01 RELEASE、02 必装配套，以及单独提供的 05 校验值和 06 验证记录。其它型号包和 DEBUG 按需要选择，不必为了检查而下载它们。

```sh
python3 tools/brcmctl.py verify --directory /path/to/downloads \
  --asset 01-AirportBrcmCompat-1.1.0-RELEASE.zip \
  --asset 02-AirportBrcmCompat-1.1.0-WiFi-Pack.zip
```

工具先用 05 文件核对 06，再核对指定 ZIP、完整文件列表、每个文件的大小和 SHA-256，以及核心二进制与核心构建身份的一致性。省略 `--asset` 时，只检查目录中已存在的安装 ZIP；输出 `not_checked` 明确列出没检查的包，不会把两份包说成整套四份都通过。

`artifacts.<ZIP>.members` 可逐项核对。`install_path` 从 `EFI/OC/` 开始；`action=copy` 的文件属于 kext，整包复制并保留内部文件。配置文件标成 `merge_configuration`，应加入自己的配置，不能整份覆盖。`bundles` 列出标识符、版本和可执行文件哈希。

这些检查确认下载及清单的一致性，不认证发布者，也不证明实际启动、关联或收件。安装 ZIP 仍只含 kext 与配置；完整清单、版权许可、实机记录均在 ZIP 外。

## 维护者

CI 获取 tag 历史并生成同一份分层清单。发布前必须检查 tag 是否已解析、核心源码是否匹配预期引用、重打包工作区是否干净，然后公开下载核对最终附件。若 tag 尚未创建或核心源码与旧 tag 不同，清单明确保留未解析/不匹配，不能改字段伪造一致。

<details>
<summary>English</summary>

Release tags, core builds and final repackaging have separate identities. `lineage.release` records the resolved tag; `lineage.core_builds` records each actual core's binary hash, UUID, input build ZIP/manifest hashes and source-file comparison; `lineage.repackaging` records the packaging checkout and dirty state. The legacy `source_commit` field means repackaging.

Older builders did not record a build commit, so that value stays null. Source files matching a tag do not establish a unique historical build commit or time. GitHub's automatic Source code downloads follow the tag; use the recorded repackaging commit for later packaging-tool changes.

For a normal installation, download packages 01 and 02 plus checksums 05 and inventory 06, then run the command above. The verifier checks inventory/ZIP checksums, the exact member list, member sizes/hashes and the selected core's identity. Missing optional packages remain explicitly unverified. `install_path` is relative to `EFI/OC/`; configuration files must be merged. These are integrity checks, not author authentication or runtime hardware proof. Installation ZIPs remain limited to kexts and configurations.

</details>
