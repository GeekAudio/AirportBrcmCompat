# 来源和版权

AirportBrcmCompat 仅发布编译后的驱动，不提供源码。第三方组件保留各自版权和许可。

- [Lilu](https://github.com/acidanthera/Lilu)：BSD 3-Clause。
- [MacKernelSDK](https://github.com/acidanthera/MacKernelSDK)：Apple Public Source License 2.0。
- 三个旧无线依赖取自 [Dortania OCLP 无线资源](https://github.com/dortania/OpenCore-Legacy-Patcher/tree/8da38565fa1551a8e5ce8613ea835d04dd97e089)，经命名空间调整后配套使用。感谢 Dortania 和 OCLP 贡献者。

Apple 无线组件版权归 Apple。OCLP 的 BSD 4-Clause 许可不替代 Apple 组件自身的适用条款。相关许可全文随包放在 `LICENSES`。

本次配套包额外包含：

- BlueToolFixup 2.7.3：现有已测资源快照，上游为 [acidanthera/BrcmPatchRAM](https://github.com/acidanthera/BrcmPatchRAM)，许可随包保留。不宣称这是上游同版本正式 Release。
- AMFIPass 1.4.1：保留现有验证环境的依赖原件，Copyright © 2022–2023 Dhinak G. All rights reserved；不将其归入其他组件的 BSD 许可。
- Lilu 1.7.3：RELEASE 使用既有分发快照，DEBUG 使用已测 DEBUG 快照；两者分别放置，只安装一种。不宣称是上游同版本正式 Release。

未重新分发 USB 驱动、USB 端口映射、完整 EFI、用户配置、身份信息或实机日志。
