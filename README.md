# AirportBrcmCompat

博通 BCM43602 的 Wi-Fi、AirDrop 和接力兼容驱动。无需运行 OCLP，也不修改系统卷。核心只发布二进制。

## 适用范围

- macOS 26.7.1（25G241），Darwin 25.6.0，Intel x86_64。
- BCM943602CDP / BCM43602，Wi-Fi 接口名必须是 `en1`。
- 已实测 Wi-Fi、私人 Wi-Fi 地址、接力和 AirDrop 双向传送。
- 其他系统版本、网卡和长期睡眠唤醒尚未验证。

## 下载和依赖

在 [Releases](https://github.com/GeekAudio/AirportBrcmCompat/releases/latest) 下载核心包和同版依赖包。

| 文件 | 版本 | 获取方式 |
| --- | --- | --- |
| AirportBrcmCompat.kext | 0.1.16 | 核心包 |
| Lilu.kext | 1.7.3 | 依赖包 |
| IOLegacyWFamily.kext | 1.0，定制版 | 依赖包 |
| IO80211FamilyLegacy.kext | 1200.12.2b1，定制版 | 依赖包 |
| AirPortBrcmNIC.kext | 1400.1.1，定制版 | 依赖包 |

三个定制依赖必须配套使用，不能换成原版同名驱动。AirDrop 和接力还需要正常工作的蓝牙；蓝牙驱动按自己的硬件配置。

## 部署

1. 备份整份 EFI，准备能启动的备用 U 盘。以前打过 OCLP 无线根补丁的，先撤销补丁。
2. 将上表五个 kext 放入 `EFI/OC/Kexts`。已有 Lilu 就替换为依赖包版本，保留其他硬件驱动。
3. 将 `OpenCore.fragment.plist` 合并到自己的 `config.plist`，不要拿片段覆盖整份配置。加载顺序：

   ```text
   Lilu → AirportBrcmCompat → IOLegacyWFamily → IO80211FamilyLegacy → AirPortBrcmNIC
   ```

4. 片段会屏蔽系统 `IO80211Family`，保留系统 `IOSkywalkFamily`。关闭旧方案的 Skywalk 屏蔽项，移除重复的旧无线驱动和其他无线兼容桥。
5. 保持 `DisableLinkeditJettison=true`。OpenCore 实测版本为 1.0.8。
6. 重启，检查 Wi-Fi，并用一个小文件双向测试 AirDrop。

### 实测安全环境

`SecureBootModel=Disabled`，`csr-active-config=430A0000`；启动参数包含 `amfi=0x80 amfi_get_out_of_my_way=0x1 ipc_control_port_options=0`，并保留原有 AMFIPass 1.4.1。这是已测环境，并非逐项精简后的最低要求。

核心不需要额外启动参数。蓝牙和其他硬件的原有配置照常保留。

## 回滚

用备用 U 盘启动，恢复安装前的完整 EFI。升级驱动前也保留上一份可用 EFI。

依赖来源和版权见 [NOTICE](NOTICE.md)。文件校验值见 `SHA256SUMS.txt`。
