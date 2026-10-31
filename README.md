# AirportBrcmCompat

博通 BCM43602 的 Wi-Fi 兼容驱动，通过 EFI 加载，不修改系统卷。自研核心以 [BSD-3-Clause](LICENSE) 开源。

当前版本 **1.0.1-rc1**，支持 25G241／25G332 精确版本识别、即时热点扫描请求适配，以及有限的 SAE 认证兼容。

## 下载

| 文件 | 用途 |
| --- | --- |
| [RELEASE 核心](https://github.com/GeekAudio/AirportBrcmCompat/releases/download/v1.0.1-rc1/AirportBrcmCompat-1.0.1-rc1-RELEASE.zip) | 不含额外无线诊断 |
| [DEBUG 核心](https://github.com/GeekAudio/AirportBrcmCompat/releases/download/v1.0.1-rc1/AirportBrcmCompat-1.0.1-rc1-DEBUG.zip) | 含无线诊断功能的调试版本 |
| [Wi-Fi 依赖与配置示例](https://github.com/GeekAudio/AirportBrcmCompat/releases/download/v1.0.1-rc1/AirportBrcmCompat-1.0.1-rc1-Dependencies-WiFi-Examples.zip) | 三个定制无线依赖及配置片段 |

核心只安装一种。将核心与依赖包中的三个 kext 放入 EFI/OC/Kexts，再将 Examples 中对应的配置片段合并到自己的 config.plist，保留本机其他配置。

以前打过 OCLP 无线根补丁的先撤销补丁；Wi-Fi 接口需为 en1。三个定制无线依赖必须配套使用，不能替换成原版同名文件。

## 无线依赖

| 组件 | 版本 | 用途 |
| --- | --- | --- |
| IOLegacyWFamily | 1.0 | 私有命名空间的旧 Skywalk 支撑层，与系统 IOSkywalkFamily 共存 |
| IO80211FamilyLegacy | 1200.12.2b1 | 旧无线框架 |
| AirPortBrcmNIC | 1400.1.1 | 博通网卡硬件驱动 |

本项目保留系统 IOSkywalkFamily，只屏蔽系统 IO80211Family。安装片段见 [Examples](Examples/README.md)，组件来源见 [NOTICE](NOTICE.md)。

蓝牙支持请参考 [Acidanthera 作者项目](https://github.com/acidanthera/BrcmPatchRAM#bluetoolfixupkext)。

## 支持范围

- Intel x86_64，BCM943602CDP / BCM43602。
- 支持 25G241 和 25G332，各自匹配内核 UUID；其他构建不安装 hook。
- Test023r2 在 25G332 下完成双向 AirDrop 实际收件，32 KiB 回传文件 SHA-256 一致。
- SAE 接受已核对的密码载荷子集：selected auth=4096、cipher=10、密码 8–63 字节、PMK 长度 32，策略掩码保留原值。

## 源码与构建

核心位于 [src](src)，离线回归测试位于 [tests](tests)。[构建说明](BUILDING.md) 提供固定构建依赖、两种编译配置与测试命令。

[下载校验值](https://github.com/GeekAudio/AirportBrcmCompat/releases/download/v1.0.1-rc1/SHA256SUMS.txt) · [旧 25G241 版本 1.0](https://github.com/GeekAudio/AirportBrcmCompat/releases/tag/v1.0)
