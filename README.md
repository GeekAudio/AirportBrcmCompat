# AirportBrcmCompat

博通 BCM43602 的 Wi-Fi、AirDrop 和接力兼容驱动。通过 EFI 加载，无需运行 OCLP，不修改系统卷。核心仅提供二进制。

当前分支提供 macOS 26.7.2（25G332）专用的 1.0.1 / Baseline019 测试候选，已通过离线构建与签名检查，实机 Wi-Fi 和双向 AirDrop 待验证。候选保留有限的 PSF/MIF 数值诊断，不记录地址、名称或文件内容。下方 1.0 下载仍是已验证的 25G241 稳定版；正式 1.0.1 Release 尚未发布。

## 支持情况

| 项目 | 已验证环境 |
| --- | --- |
| 系统 | macOS 26.7.1（25G241）/ Darwin 25.6.0，Intel x86_64 |
| 网卡 | BCM943602CDP / BCM43602，Wi-Fi 接口名必须为 `en1` |
| 功能 | Wi-Fi、私人 Wi-Fi 地址、接力、AirDrop 双向传送 |

其他系统版本、网卡和长期睡眠唤醒尚未验证。

## 下载文件

| 下载 | 内容 |
| --- | --- |
| [核心包 1.0](https://github.com/GeekAudio/AirportBrcmCompat/releases/download/v1.0/AirportBrcmCompat-1.0.zip) | AirportBrcmCompat.kext、配置片段、教程 |
| [配套依赖](https://github.com/GeekAudio/AirportBrcmCompat/releases/download/v1.0/AirportBrcmCompat-Dependencies-1.0.zip) | 下表四个驱动，首次安装需一起下载 |

| 依赖 | 版本 |
| --- | --- |
| Lilu.kext | 1.7.3 |
| IOLegacyWFamily.kext | 1.0，定制版 |
| IO80211FamilyLegacy.kext | 1200.12.2b1，定制版 |
| AirPortBrcmNIC.kext | 1400.1.1，定制版 |

三个定制依赖必须配套使用，不能换成原版同名驱动。[文件校验值](https://github.com/GeekAudio/AirportBrcmCompat/releases/download/v1.0/SHA256SUMS.txt) · [依赖来源和许可](NOTICE.md)

## 安装步骤

1. 以前打过 OCLP 无线根补丁的，先撤销补丁。
2. 将核心和依赖共五个 kext 放入 `EFI/OC/Kexts`。已有 Lilu 就替换为配套版本。
3. 将 `OpenCore.fragment.plist` 合并到自己的 `config.plist`，不要覆盖整份配置。按以下顺序加载：

   ```text
   Lilu → AirportBrcmCompat → IOLegacyWFamily → IO80211FamilyLegacy → AirPortBrcmNIC
   ```

4. 屏蔽系统 `IO80211Family`，保留系统 `IOSkywalkFamily`。关闭旧方案的 Skywalk 屏蔽项，移除重复的旧无线驱动和其他无线兼容桥。
5. 按下表检查配置，保留原有硬件驱动。AirDrop 和接力需要蓝牙正常工作。重启后检查 Wi-Fi，并用小文件双向测试 AirDrop。

## 实测配置

| 项目 | 值 |
| --- | --- |
| OpenCore | 1.0.8 |
| DisableLinkeditJettison | `true` |
| SecureBootModel | `Disabled` |
| csr-active-config | `430A0000` |
| boot-args | `amfi=0x80 amfi_get_out_of_my_way=0x1 ipc_control_port_options=0` |
| AMFIPass | 保留原有 1.4.1 |

这是已测组合，并非逐项精简后的最低要求。核心无需额外启动参数；蓝牙驱动按自己的硬件配置。
