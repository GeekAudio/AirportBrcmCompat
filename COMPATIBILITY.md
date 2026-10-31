# 兼容范围与上游依据

扩展目标是 **原本需要 OCLP 恢复 Wi-Fi 的 Broadcom 网卡与系统组合**。
原生可用的组合保持原样。以下是扩展范围，不是当前核心已经完成的支持清单。

## 按驱动家族区分

| 网卡 / PCI ID | 需要恢复无线支持的系统 | 当前项目状态 |
| --- | --- | --- |
| BCM43602 `43ba`、BCM4350 `43a3`、BCM4360 `43a0` | Sonoma 14、Sequoia 15、Tahoe 26 | 随包驱动匹配三个 ID；当前核心从 Darwin 25 开始；BCM43602 有功能基线 |
| BCM94331 `4331`、BCM943224 `4353` | Sonoma 14、Sequoia 15、Tahoe 26 | 需增加对应驱动匹配和接口验证 |
| BCM43225 `4357`、BCM4352 `43b1` / `43b2` | Sonoma 14、Sequoia 15、Tahoe 26 的社区恢复路径 | 需第三方卡适配；不在当前随包匹配范围 |
| BCM94322 `432b`、BCM94328 / BCM4328 `4328` 等旧驱动家族 | Monterey 12、Ventura 13、Sonoma 14、Sequoia 15、Tahoe 26 | 需独立旧驱动和协议适配，当前未实现 |

表中 Vendor ID 均为 `14e4`。不能仅凭商品名称判断芯片。
尤其是 OCLP 的 `AirPortBrcm4331` 驱动类别与 PCI ID `4331` 不是同一个分类：
前者的代表 ID 是 `432b`，后者属于 OCLP 的 Modern Wireless 路径。

依据是 OCLP 的 [PCI 分类表](https://github.com/dortania/OpenCore-Legacy-Patcher/blob/e2107e05d9ce574e9ac3fd8b223e20a2edb7ba53/opencore_legacy_patcher/datasets/pci_data.py)、
[Legacy Wireless 条件](https://github.com/dortania/OpenCore-Legacy-Patcher/blob/e2107e05d9ce574e9ac3fd8b223e20a2edb7ba53/opencore_legacy_patcher/sys_patch/patchsets/hardware/networking/legacy_wireless.py)和
[Modern Wireless 条件](https://github.com/dortania/OpenCore-Legacy-Patcher/blob/e2107e05d9ce574e9ac3fd8b223e20a2edb7ba53/opencore_legacy_patcher/sys_patch/patchsets/hardware/networking/modern_wireless.py)。
OCLP 将第三方类别标为非官方支持；这类卡在较早系统也可能需要额外驱动修正，不能统称原生可用。

较新的 AppleBCMWLAN 驱动家族、没有对应 Apple 驱动的芯片和 USB Wi-Fi，
不能通过增加 PCI ID 自动纳入这条恢复路线。

## GitHub 中可以利用的现成结果

- [OCLP 无线依赖](https://github.com/dortania/OpenCore-Legacy-Patcher/tree/e2107e05d9ce574e9ac3fd8b223e20a2edb7ba53/payloads/Kexts/Wifi)和
  [PatcherSupportPkg 2.0.5](https://github.com/dortania/PatcherSupportPkg/tree/2.0.5/Universal-Binaries)
  提供已整理的驱动、框架及服务样本。其系统卷替换方式与本项目的 EFI 适配方式不同；
  这些样本用于分析，不能直接证明我们的协议桥已经支持同一范围。
- [OCLP 的配置](https://github.com/dortania/OpenCore-Legacy-Patcher/blob/e2107e05d9ce574e9ac3fd8b223e20a2edb7ba53/payloads/Config/config.plist)
  分别选择 Darwin 23–24 和 25 的 AirPortBrcmNIC，说明驱动组合需要分代检查。
  Legacy Wireless 还在 12.7.4、13.6.5、14.4 有用户态补丁分界，不能只放宽内核版本条件。
- [AirportBrcmFixup](https://github.com/acidanthera/AirportBrcmFixup)
  有第三方卡匹配及现有 Apple 驱动修正，可作为扩展硬件支持的依据。
- [AppleBCMWLANCompanion](https://github.com/0xFireWolf/AppleBCMWLANCompanion)
  是另一条面向 BCM43602 / BCM4350 的新驱动路线；仓库当前公开文档和固件，未提供驱动源码，
  其支持表与[已知问题](https://github.com/0xFireWolf/AppleBCMWLANCompanion/blob/main/Documentation/Issues.md)也不覆盖本项目的全部目标。
- [BroadcomVTD-Tahoe](https://github.com/kgp-macPro/BroadcomVTD-Tahoe)
  处理特定已恢复驱动的 DMA/IOMMU 问题，不提供全部系统或全部芯片的无线驱动。

上游源码和 Apple 二进制的许可分别适用；本项目的 BSD-3-Clause 不覆盖第三方驱动及系统文件。

## 已知版本与后续更新

已知驱动继续校验经过确认的偏移、指令和请求格式。后续系统按符号、接口和结构检查选择已实现的兼容路径，
不单独维护每个系统构建号或内核 UUID 白名单。接口没有变化的更新不需要新版本条目。

当前仍有私有内核函数及请求格式的精确契约；新的函数实现或协议不匹配时会停止相应适配。
因此，当前代码尚不等于上述扩展范围全部完成，也不能保证未知系统永久免适配。
扩展时需要补齐各驱动家族、原生请求格式及依赖导入的证据，再同步核心和 OpenCore 示例。
