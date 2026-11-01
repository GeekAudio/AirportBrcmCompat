# 实机验证矩阵 / Hardware validation matrix

目标版本 / Target release: **1.1.0**。每项结论只属于记录中的具体系统构建、PCI ID、核心哈希和启动会话。
A result applies only to its recorded OS build, PCI ID, core hash and boot session. Offline tests are separate.

“—”为未测试。不同会话的单项通过不会合并成整组通过。历史结果不计入当前版本。
“—” means not tested. Results from separate runs are never combined into a complete pass.

| 系统 / OS | PCI ID | 构建 / Build | 启动 / Boot | 关联 / Join | 私人地址 / Private | AirDrop → | AirDrop ← | 睡眠 / Sleep |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Sonoma 14 | `14e4:43ba` | — | — | — | — | — | — | — |
| Sonoma 14 | `14e4:43a3` | — | — | — | — | — | — | — |
| Sonoma 14 | `14e4:43a0` | — | — | — | — | — | — | — |
| Sonoma 14 | `14e4:4357` | — | — | — | — | — | — | — |
| Sonoma 14 | `14e4:43b1` | — | — | — | — | — | — | — |
| Sonoma 14 | `14e4:43b2` | — | — | — | — | — | — | — |
| Sequoia 15 | `14e4:43ba` | — | — | — | — | — | — | — |
| Sequoia 15 | `14e4:43a3` | — | — | — | — | — | — | — |
| Sequoia 15 | `14e4:43a0` | — | — | — | — | — | — | — |
| Sequoia 15 | `14e4:4357` | — | — | — | — | — | — | — |
| Sequoia 15 | `14e4:43b1` | — | — | — | — | — | — | — |
| Sequoia 15 | `14e4:43b2` | — | — | — | — | — | — | — |
| Tahoe 26 | `14e4:43ba` | — | — | — | — | — | — | — |
| Tahoe 26 | `14e4:43a3` | — | — | — | — | — | — | — |
| Tahoe 26 | `14e4:43a0` | — | — | — | — | — | — | — |
| Tahoe 26 | `14e4:4357` | — | — | — | — | — | — | — |
| Tahoe 26 | `14e4:43b1` | — | — | — | — | — | — | — |
| Tahoe 26 | `14e4:43b2` | — | — | — | — | — | — | — |

记录方法与异常恢复 / Procedures: [RUNTIME-VALIDATION.md](../docs/RUNTIME-VALIDATION.md).

历史参考另列于 JSON 的 historical_references，未迁移为当前版本通过项。
Historical references remain separate and do not qualify the current release.
