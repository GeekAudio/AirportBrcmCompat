# 兼容范围与上游依据

项目目标是恢复 **Sonoma 14、Sequoia 15 和 Tahoe 26 上需要 OCLP Modern Wireless 路径的 Broadcom Wi-Fi 组合**。下表描述开发范围，不代表每种网卡或每个系统小版本都已完成支持。原生可用的组合保持原样。

## 按网卡家族区分

| 网卡 / PCI ID | 目标系统大版本 | 当前状态 |
| --- | --- | --- |
| BCM43602 `43ba`、BCM4350 `43a3`、BCM4360 `43a0` | Sonoma 14、Sequoia 15、Tahoe 26 | 随包 NIC 驱动匹配这些 ID；核心按运行时接口和请求契约检查，BCM43602 有已发布版本的 Tahoe 功能基线 |
| BCM94331 `4331`、BCM943224 `4353` | Sonoma 14、Sequoia 15、Tahoe 26 | 提供可选上游修正组件及 NIC 匹配包生成工具；完整接口兼容仍在完善 |
| BCM43225 `4357`、BCM4352 `43b1` / `43b2` | Sonoma 14、Sequoia 15、Tahoe 26 | 可选 NIC 匹配包覆盖这些 ID；PCI 匹配本身不证明硬件功能已验证 |

表中 PCI Vendor ID 均为 `14e4`。OCLP 将第三方网卡划分为不同驱动家族；不能仅凭商品名称或 PCI 匹配推断功能。较新的 AppleBCMWLAN 驱动家族、没有对应 Apple 驱动的芯片和 USB Wi-Fi 不在本项目范围内。

## 上游依据

- [OCLP PCI 分类表](https://github.com/dortania/OpenCore-Legacy-Patcher/blob/e2107e05d9ce574e9ac3fd8b223e20a2edb7ba53/opencore_legacy_patcher/datasets/pci_data.py) 与 [Modern Wireless 条件](https://github.com/dortania/OpenCore-Legacy-Patcher/blob/e2107e05d9ce574e9ac3fd8b223e20a2edb7ba53/opencore_legacy_patcher/sys_patch/patchsets/hardware/networking/modern_wireless.py)用于确认目标网卡分类及系统范围。
- [OCLP 无线依赖和配置](https://github.com/dortania/OpenCore-Legacy-Patcher/tree/e2107e05d9ce574e9ac3fd8b223e20a2edb7ba53/payloads/Kexts/Wifi)选择 Darwin 23–24 的嵌套 AirPortBrcmNIC 与 Darwin 25 起的独立变体。上游二进制样本用于检查，不能单独证明本项目适配完成。
- [AirportBrcmFixup](https://github.com/acidanthera/AirportBrcmFixup)提供第三方网卡匹配及现有 Apple 驱动修正，可作为扩展硬件覆盖范围的依据。
- [AppleBCMWLANCompanion](https://github.com/0xFireWolf/AppleBCMWLANCompanion)是面向 BCM43602 / BCM4350 的另一条驱动路线；其公开文档和固件不覆盖本项目的全部目标。
- [BroadcomVTD-Tahoe](https://github.com/kgp-macPro/BroadcomVTD-Tahoe)处理特定已恢复驱动的 DMA/IOMMU 问题，不提供全部系统或全部芯片的无线驱动。

上游源码和 Apple 二进制各自适用其许可；本项目的 BSD-3-Clause 不覆盖第三方驱动及系统文件。

## EFI 适配路径

适配只通过 EFI/kext 提供，不替换系统卷上的无线服务或框架。现代依赖生成器检查 Darwin 23–24 与 Darwin 25 起的 NIC 变体、原始二进制哈希、命名空间转换及目标系统导出冲突。依赖选择与核心协议兼容是不同检查。

运行时根据已实现的接口、结构和请求格式契约决定是否启用适配，不按系统构建号或内核 UUID 白名单选择。实现或协议不符合已知契约时，相应适配会停止；没有版本上限不代表未知系统已经兼容。

已检查的官方样本中，现代请求格式如下：

| 请求格式 | Sonoma 14 | Sequoia 15 | Tahoe 26 |
| --- | ---: | ---: | ---: |
| GET11 扫描结果 | 1228 字节 | 2264 字节 | 2272 字节 |
| GET12 能力缓冲区 | 16 字节 | 19 字节 | 21 字节 |
| SET20 关联请求 | 856 字节 | 900 字节 | 908 字节 |

这些是已核对样本的格式，不是每个小版本的兼容证明。关联转换仅接受已核实的载荷子集；未知扩展和不支持的字段组合会拒绝转换。Sequoia 使用独立规范化副本，不改写用户请求。扫描、能力查询、关联分派、只读输入和复制长度均有离线回归测试；这些测试不等于网卡实机验证。

私有地址相关的网卡回调已按 Sonoma、Sequoia 与 Tahoe 样本核对；运行时按实现契约选择。目标样本的哈希、协议尺寸及回调验证结果记录在[契约验证清单](validation/compatibility-contracts.json)，该清单不是运行时版本白名单。

核心和现代无线依赖的最低目标为 Darwin 23。系统更新若仍符合已实现契约，无需单独增加版本条目；接口或协议变化仍可能需要适配开发。依赖包的加载范围不能替代接口校验。

工具和输入要求见[构建说明](BUILDING.md#wi-fi-dependency-profiles)。上游组件许可与本项目自研代码许可分别适用，详见 [NOTICE](NOTICE.md)。
