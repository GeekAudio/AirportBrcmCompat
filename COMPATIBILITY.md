# 兼容范围与上游依据

项目目标是恢复 **Sonoma 14、Sequoia 15 和 Tahoe 26 上需要 OCLP Modern Wireless 路径的 Broadcom Wi-Fi 组合**。下表描述开发范围，不代表每种网卡或每个系统小版本都已完成支持。原生可用的组合保持原样。

## 按网卡家族区分

| 网卡 / PCI ID | 目标系统大版本 | 当前状态 |
| --- | --- | --- |
| BCM43602 `43ba`、BCM4350 `43a3`、BCM4360 `43a0` | Sonoma 14、Sequoia 15、Tahoe 26 | 随包 NIC 驱动匹配这些 ID；核心按运行时接口和请求契约检查，BCM43602 有已发布版本的 Tahoe 功能基线 |
| BCM43225 `4357`、BCM4352 `43b1` / `43b2` | Sonoma 14、Sequoia 15、Tahoe 26 | 整套安装包中的 NIC 匹配组件覆盖这些 ID；PCI 匹配本身不证明硬件功能已验证 |

表中 PCI Vendor ID 均为 `14e4`。OCLP 将第三方网卡划分为不同驱动家族；不能仅凭商品名称或 PCI 匹配推断功能。较新的 AppleBCMWLAN 驱动家族、没有对应 Apple 驱动的芯片和 USB Wi-Fi 不在本项目范围内。

## 上游依据

- [OCLP PCI 分类表](https://github.com/dortania/OpenCore-Legacy-Patcher/blob/e2107e05d9ce574e9ac3fd8b223e20a2edb7ba53/opencore_legacy_patcher/datasets/pci_data.py) 与 [Modern Wireless 条件](https://github.com/dortania/OpenCore-Legacy-Patcher/blob/e2107e05d9ce574e9ac3fd8b223e20a2edb7ba53/opencore_legacy_patcher/sys_patch/patchsets/hardware/networking/modern_wireless.py)用于确认目标网卡分类及系统范围。
- [OCLP 无线依赖和配置](https://github.com/dortania/OpenCore-Legacy-Patcher/tree/e2107e05d9ce574e9ac3fd8b223e20a2edb7ba53/payloads/Kexts/Wifi)选择 Darwin 23–24 的嵌套 AirPortBrcmNIC 与 Darwin 25 起的独立变体。上游二进制样本用于检查，不能单独证明本项目适配完成。
- [AirportBrcmFixup](https://github.com/acidanthera/AirportBrcmFixup)提供第三方网卡匹配及现有 Apple 驱动修正，可作为扩展硬件覆盖范围的依据。
- [AppleBCMWLANCompanion](https://github.com/0xFireWolf/AppleBCMWLANCompanion)是面向 BCM43602 / BCM4350 的另一条驱动路线；其公开文档和固件不覆盖本项目的全部目标。
- [BroadcomVTD-Tahoe](https://github.com/kgp-macPro/BroadcomVTD-Tahoe)处理特定已恢复驱动的 DMA/IOMMU 问题，不提供全部系统或全部芯片的无线驱动。

上游源码和 Apple 二进制各自适用其许可；本项目的 BSD-3-Clause 不覆盖第三方驱动及系统文件。

## EFI 适配路径

适配只通过 EFI/kext 提供，不替换系统卷上的无线服务或框架。当前安装包使用同一个 `AirPortBrcmNIC.kext` 和同一套独立依赖，所有目标系统共用同一份配置。原先按系统区分的归档保留为离线核验输入。

统一 NIC 采用完整的 DMA 兼容二进制，静态检查覆盖导入、虚表、补丁范围及跳转目标。它在 Sonoma、Sequoia 上的 DMA 生命周期、失败恢复及实机收发仍需要运行证据；这些项目不能由哈希或符号一致性证明。详见[统一架构与验证范围](docs/ARCHITECTURE.md)。

运行时根据已实现的接口、结构和请求格式契约决定是否启用适配，不按系统构建号或内核 UUID 白名单选择。实现或协议不符合已知契约时，相应适配会停止；没有版本上限不代表未知系统已经兼容。

已检查的官方样本中，现代请求格式如下：

| 请求格式 | Sonoma 14 | Sequoia 15 | Tahoe 26 |
| --- | ---: | ---: | ---: |
| GET11 扫描结果 | 1228 字节 | 2264 字节 | 2272 字节 |
| GET12 能力缓冲区 | 16 字节 | 19 字节 | 21 字节 |
| SET20 关联请求 | 856 字节 | 900 字节 | 908 字节 |

这些是已核对样本的格式，不是每个小版本的兼容证明。关联转换仅接受已核实的载荷子集；未知扩展和不支持的字段组合会拒绝转换。Sequoia 使用独立规范化副本，不改写用户请求。扫描、能力查询、关联分派、只读输入和复制长度均有离线回归测试；这些测试不等于网卡实机验证。

三种关联格式均可传递同一 SAE 密码子集：认证类型 4096、cipher 10、密码 8–63 字节及 PMK32。Sonoma 的字段与固定消费者前缀一致，直接保留；另两种格式按各自布局归一化。GET12 的能力补充只对已核对的 64 位请求执行。

离线卡型核对同时检查两种 NIC 的实际 `_wlc_devid` 设备表、`_wlc_chipmatch` 查找和成功返回路径，以及驱动接口 pins。表内六项均通过这些检查。配套匹配组件同时收窄核心与注入器的 PCI 匹配，不再包含其它硬件驱动家族。验证记录见[现代网卡离线检查](validation/modern-card-coverage.json)。

私有地址相关的网卡回调已按 Sonoma、Sequoia 与 Tahoe 样本核对；运行时按实现契约选择。目标样本的哈希、协议尺寸及回调验证结果记录在[契约验证清单](validation/compatibility-contracts.json)，该清单不是运行时版本白名单。

已知内核实现优先使用现有合同。布局变化时，备用路径检查公开 ioctl 入口、主接口回调的完整指令和独立解析的调用目标，再用同线程、同参数的一次性调用范围确认生命周期。它减少了对内核内部偏移的依赖；原有权限、接口身份和控制器锁检查仍然生效。完整证据及当前样本范围见[主接口回调检查](validation/modern-ifnet-callback.json)。

核心和现代无线依赖的最低目标为 Darwin 23。系统更新若仍符合已实现契约，无需单独增加版本条目；接口或协议变化仍可能需要适配开发。依赖包的加载范围不能替代接口校验。

工具和输入要求见[构建说明](BUILDING.md#wi-fi-dependency-profiles)。上游组件许可与本项目自研代码许可分别适用，详见 [NOTICE](NOTICE.md)。

## macOS 27 准备

目前尚无目标 Intel 移植样本，不列入已检查系统。现有配置无未来版本上限；新增 `brcmctl.py upgrade-check` 将目标内核实际版本、架构和公开 KPI 备用路径的生产契约一起核对，缺少样本保持未完成。步骤和检查边界见 [macOS 27 升级准备](docs/MACOS-27-PREPARATION.md)。

## 实机与恢复记录

[18 组实机矩阵](validation/RUNTIME-MATRIX.md)独立记录精确构建、PCI ID、核心哈希与启动会话，当前 1.1.0 实机项均未测试。历史 Test023r2 不迁移为当前通过项。[记录与异常恢复](docs/RUNTIME-VALIDATION.md)说明部分 hook、私人地址隔离及收件/睡眠的证据要求；源码策略与实机恢复结果分别标注。
