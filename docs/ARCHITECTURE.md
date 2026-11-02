# 统一安装结构

Sonoma 14、Sequoia 15、Tahoe 26 使用同一套文件和加载顺序。RELEASE 与 DEBUG 仅核心诊断功能不同。

| 组件 | 职责 |
| --- | --- |
| AirportBrcmCompat | 扫描、关联、私人地址及事件协议适配；按实际接口契约启用功能 |
| AirPortBrcmNIC | 唯一的网卡驱动二进制，包含完整 DMA 兼容实现 |
| 无线框架依赖 | 共同的命名空间隔离提供者与无线消费者，三个原始样本中的文件内容一致 |
| 匹配与运行依赖 | 提供限定 PCI ID 的匹配和兼容核心所需接口，随整套文件分发 |

核心仍只有一个独立可执行文件。每个依赖有独立的 bundle ID，安装配置按依赖顺序加载；所有条目统一从 Darwin 23 开始，没有按系统分段的 NIC 条目。较早的分系统文件仅作为开发验证输入保留。

## 网卡二进制的选择

原始两个 NIC 的差异是 DMA 兼容代码及四个跳转位置。统一包保留完整的 DMA 兼容映像，不在已运行的驱动上拼接补丁。`verify_unified_nic.py` 从固定样本验证变化范围、跳转与返回目标、内部帮助函数、完整导入表和虚表；`unify_wifi_dependencies.py` 复核三个样本的来源、共同依赖和签名。

现有网卡接口 pins 仍检查同一固定映像。系统核心的 ABI 检查独立执行，出现未知结构或请求格式时不会因系统版本号放行。统一文件不等于保证未来系统接口不变。

## 证据范围

离线记录证明输入身份、文件一致性、静态接口关系和配置可达性。它不证明 DMA 缓冲区生命周期、分配失败后的恢复、并发收发、睡眠或实际联网。统一 NIC 在 Sonoma、Sequoia 上仍需这些运行证据；发布说明保留此范围，不沿用旧分系统二进制的实机结果作为新统一包结果。

## 发布与安装

最终只发布两个完整 ZIP。安装清单由实际 bundle 信息生成；测试检查唯一 NIC、无分系统文件名、共同版本范围和依赖顺序。构建清单与包清单单独保存，区分源码 tag、核心二进制与最终重打包提交。安装器默认预览，应用时先备份，保留无关组件并检查并发修改。

<details>
<summary>English</summary>

One flat file set and load order target Sonoma, Sequoia and Tahoe. The compatibility
core remains a separate executable, with one complete DMA-compatible NIC image
and shared dependencies. RELEASE and DEBUG differ in core diagnostics.

The original OS-specific archives remain pinned development inputs. Verification
compares common dependencies and signatures, all NIC byte changes, branches,
helper calls, imports and vtables. Runtime ABI/request guards remain independent
of the installation version range. No live NIC code rewriting is introduced.

These offline checks do not establish DMA lifetime, allocation failure recovery,
concurrent traffic, sleep or hardware operation. The unified NIC still needs
that runtime evidence on Sonoma and Sequoia. A common file set does not promise
compatibility with unknown future interfaces.

Only two complete ZIPs are published. Provenance records distinguish the source
tag, core builds and final repackaging commit. The installer previews by default,
backs up before applying, preserves unrelated components and checks concurrent
changes.

</details>
