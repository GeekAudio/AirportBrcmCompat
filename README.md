# AirportBrcmCompat

博通 BCM43602 的 Wi-Fi、AirDrop 和接力兼容驱动，通过 EFI 加载，不修改系统卷。核心仅提供二进制。

当前版本 **1.0.1-rc1，预发布**。增加 25G241／25G332 精确版本兼容、即时热点扫描请求适配，以及有限的 SAE 认证兼容。

## 下载

| 文件 | 用途 |
| --- | --- |
| [RELEASE 核心](https://github.com/GeekAudio/AirportBrcmCompat/releases/download/v1.0.1-rc1/AirportBrcmCompat-1.0.1-rc1-RELEASE.zip) | 日常使用候选，不编译 PSF/MIF 分窗诊断 |
| [DEBUG 核心](https://github.com/GeekAudio/AirportBrcmCompat/releases/download/v1.0.1-rc1/AirportBrcmCompat-1.0.1-rc1-DEBUG.zip) | DEBUG 编译，含有限的 PSF/MIF 分窗诊断 |
| [依赖与配置示例](https://github.com/GeekAudio/AirportBrcmCompat/releases/download/v1.0.1-rc1/AirportBrcmCompat-1.0.1-rc1-Dependencies-Bluetooth-Examples.zip) | 定制无线依赖、两种 Lilu、BlueToolFixup、AMFIPass 和最简配置片段 |

两种核心只安装一个。配套包的 Common/Kexts 全部配套放入 EFI/OC/Kexts，再选 RELEASE 或 DEBUG 目录中的 Lilu。已有同名 kext 时替换，避免重复加载。

将 Examples 中的对应配置片段合并到自己的 config.plist，保留本机其他配置。以前打过 OCLP 无线根补丁的先撤销补丁；Wi-Fi 接口需为 en1。三个定制旧无线依赖不能换成原版同名文件。

蓝牙所在的 USB 端口必须设为内建（Internal，255）。

## 支持与验证

| 项目 | 范围 |
| --- | --- |
| 架构／网卡 | Intel x86_64，BCM943602CDP / BCM43602；蓝牙 BCM20703A2 |
| 精确兼容判断 | 25G241 和 25G332，各自匹配内核 UUID；其他构建拒绝安装 hook |
| 本次功能基线 Test023r2 | 25G332 下 Wi-Fi 已连接；双向 AirDrop 各完成一次实际收件，32 KiB 回传文件 SHA-256 一致 |
| 即时热点历史基线 Test021r2 | 曾在重启 sharingd 后以 WPA2 路径连接，en1 上下行各 64 KiB、HTTP 200 |
| 尚待验证 | 两种分发编译版本分别重启、旧 25G241 新版回归、新 SAE 握手、长期稳定性及完整睡眠／重连边界 |

SAE 仅接受已核对的密码载荷子集：selected auth=4096、cipher=10、密码 8–63 字节、PMK 长度 32，策略掩码保留原值；不把 WPA2 成功算成 SAE 成功。

配套依赖版本：Lilu 1.7.3、IOLegacyWFamily 1.0、IO80211FamilyLegacy 1200.12.2b1、AirPortBrcmNIC 1400.1.1、BlueToolFixup 2.7.3、AMFIPass 1.4.1。来源与许可见 [NOTICE](NOTICE.md)，合并说明见 [Examples](Examples/README.md)。

[下载校验值](https://github.com/GeekAudio/AirportBrcmCompat/releases/download/v1.0.1-rc1/SHA256SUMS.txt) · [旧 25G241 稳定版 1.0](https://github.com/GeekAudio/AirportBrcmCompat/releases/tag/v1.0)
