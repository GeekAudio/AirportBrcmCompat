# 来源和版权

AirportBrcmCompat 自研核心、构建工具及回归测试以根目录 [BSD-3-Clause](LICENSE) 许可证发布，Copyright (c) 2026 GeekAudio。第三方组件保留各自版权和许可；本许可证不重新授权 Apple 无线二进制或第三方构建依赖。

三个旧无线依赖取自 [Dortania OCLP 无线资源](https://github.com/dortania/OpenCore-Legacy-Patcher/tree/8da38565fa1551a8e5ce8613ea835d04dd97e089)，经命名空间调整后配套使用。感谢 Dortania 和 OCLP 贡献者。

Apple 无线组件版权归 Apple。OCLP 的 BSD-4-Clause 许可不替代 Apple 组件自身的适用条款。第三方版权与许可文本保留在 `LICENSES`。

构建依赖由 `dependencies.lock.json` 固定到上游提交，通过 `tools/prepare_dependencies.py` 获取到本地 `vendor/`。构建方式见 [BUILDING](BUILDING.md)。

发布包不包含完整 EFI、用户配置、USB 端口映射、身份信息或实机日志。
