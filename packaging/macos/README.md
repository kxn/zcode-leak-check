# macOS 签名/公证打包配方

由 **yixiao（[Octo-o-o-o](https://github.com/Octo-o-o-o)）** 贡献，用于在 macOS 上产出
Developer ID 签名并通过 Apple 公证（notarized）的 `zcode-leak-check.app` 与 `.dmg`。

- `zcode-leak-check.spec` — PyInstaller spec（arm64 / x86_64 双架构分别构建）
- `entitlements.plist` — 空 entitlements（仅需签名，无需特殊权限）
- `build.sh` — 构建单架构（用法：`build.sh aarch64|x86_64`）
- `notarize.sh` — 提交 Apple 公证、装订 staple、打 dmg 并再次公证（用法同上）

注意：脚本中的签名身份（Developer ID 证书名）与本地钥匙串公证 Profile 需替换为你自己的；
发布公证产物的私钥与证书**不在本仓库中**。
