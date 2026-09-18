# zcode-leak-check

**检查你的电脑上，是否有工作区代码/数据被 ZCode（智谱 AI 编程桌面端）的"仓库快照"机制上传出去过，以及 ZCode 在本机哪些位置存放了数据。**

> 本工具 **100% 离线运行**：只读取本机文件做取证分析，不发起任何网络请求，不会把你的任何数据发送到任何地方。

## 下载

前往 [Releases](../../releases) 页面，GitHub Actions 会自动构建三平台可执行文件：

| 文件 | 平台 | 形态 |
|---|---|---|
| `zcode-leak-check-windows.exe` | Windows | GUI（双击运行，无控制台窗口） |
| `zcode-leak-check-1.1.0-macos-arm64-app.zip` / `...-x64-app.zip` | macOS | **GUI .app 包（推荐）**：已签名 + Apple 公证，解压后双击 `zcode-leak-check.app` 直接运行，无 Gatekeeper 拦截（Apple Silicon 选 arm64，Intel 选 x64） |
| `zcode-leak-check-1.1.0-macos-arm64.dmg` / `...-x64.dmg` | macOS | 同上的 DMG 安装镜像（拖入 Applications 即可） |
| `zcode-leak-check-macos-app.zip` | macOS | CI 构建的未签名 .app（含最新代码；首次运行需放行 Gatekeeper，见下） |
| `zcode-leak-check-macos` | macOS | GUI 单文件二进制（命令行/进阶用户） |
| `zcode-leak-check-linux` | Linux | CLI（**运行即自动开始扫描**，输出 Markdown 报告；ZCode 桌面端无 Linux GUI 场景） |

> 签名/公证版由 [@Octo-o-o-o](https://github.com/Octo-o-o-o) 基于 v1.1.0 源码构建（见下方致谢）；
> CI 构建版跟随 main 分支最新代码但未签名。公证构建配方开源在 [`packaging/macos/`](packaging/macos/)。

### macOS 首次运行说明

- **签名公证版**（`*-app.zip` / `*.dmg`）：直接双击运行，无拦截；
- **CI 未签名版**：直接双击若被 Gatekeeper 拦截，任选其一：
  - **右键点击** `zcode-leak-check.app` → **打开** → 再点"打开"；
  - 或 系统设置 → 隐私与安全性 → 底部"`zcode-leak-check` 已被阻止"→ **仍要打开**；
  - 或终端执行：`xattr -dr com.apple.quarantine /path/to/zcode-leak-check.app`

## 使用

### Windows / macOS（GUI）

打开程序，点 **"🔍 一键检查"**，等进度条走完：

- 每个数据区显示一条结论（✅ 未发现上传痕迹 / ⚠️ 可疑 / 🔴 发现上传痕迹）；
- 检查完成自动弹出**总结论**：有没有传出去 + ZCode 在本机的数据存放位置列表；
- 想看"每次上传了哪些文件、多大"，打开 **🛠 高级** 标签页：工作区详情、快照内容明细（.git/源码分类+体积）、日志证据、设置与登录状态、导出完整 Markdown 报告。

### Linux（CLI）

```bash
./zcode-leak-check-linux                 # 运行即扫：默认数据区 + 全盘搜索
./zcode-leak-check-linux --export report.md   # 同时写出报告文件
./zcode-leak-check-linux --root /mnt/data/.zcode   # 追加指定数据区
./zcode-leak-check-linux --no-drives     # 不搜索其他磁盘
```

### 源码运行（无需 PyInstaller，纯 Python 标准库，Python ≥ 3.8）

```bash
python zcode_snapshot_audit.py            # GUI
python zcode_snapshot_audit.py --cli --drives --export report.md   # CLI
```

Windows 下也可以直接双击 [`启动检查器-Windows.bat`](启动检查器-Windows.bat)；macOS/Linux 用 [`start-checker-macos-linux.sh`](start-checker-macos-linux.sh)。

## 它检查什么

背景：ZCode 桌面端在登录状态下存在"仓库快照"机制——每次发 Prompt 前与任务结束时，把工作区打包为 tar.gz（**完整 .git 历史 + 源码 + 全局配置 + Prompt 原文**），用服务端下发的 RSA 公钥信封加密（AES-256-CTR），直传阿里云 OSS。该机制不受 `repoSnapshotIndexingEnabled` / `optimizeAgentExperienceEnabled` 两个 UI 开关控制，唯一门槛是登录态 + 服务端下发上传凭证。

本工具按三层取证（详见程序内"高级 → 设置与说明"）：

1. **工件层**（最可靠）：扫描各数据区 `v2/checkpoints/`（含老版本 `repo-snapshots` 布局）中的上传清单、滞留密文、状态文件；并做全数据区**兜底扫描**，按文件名/目录名匹配快照工件，不依赖特定版本布局；
2. **日志层**：检索上传成功/凭证请求/失败滞留等证据，含版本无关标志（阿里云 OSS 端点、`x-oss-` 头、snapshot×upload 泛匹配、中文关键词）；
3. **崩溃面包屑**：Electron userData（`%APPDATA%\ZCode` 等）中 Sentry scope 里的历史运行记录。

判定逻辑的核心：**上传成功会留下明文清单（密文清理），失败/滞留会留下加密包 + 状态文件**——只要发生过且未被人为清除，本地一定有痕。

## 已知局限

- 只能看到**磁盘上还留着的证据**。日志若被应用轮转清理或人为删除，对应时间窗口无法还原；
- 检测标志主要来自对当前版本（3.11.x）的逆向，老版本换了日志措辞的部分靠工件兜底层与版本无关标志覆盖，但不能承诺 100%；
- 网络/映射盘做限时探测（每盘约 4 秒），只扫第一层。

## 致谢

- 感谢 **yixiao（[@Octo-o-o-o](https://github.com/Octo-o-o-o)）** 为本项目完成 macOS Developer ID 签名与 Apple 公证（arm64/x64 双架构的 .app 与 .dmg），贡献了修复 macOS 按钮渲染问题的补丁（macOS 原生 `tk.Button` 忽略 `bg`，导致扁平蓝底白字大按钮不可见），并开源了完整的签名/公证构建配方（见 [`packaging/macos/`](packaging/macos/)）。

## 免责声明

- 本项目为独立的本地隐私自查工具，与 ZCode/智谱官方无关，分析结论基于对客户端的逆向，可能随版本更新失效；
- 仅供检查自己设备上的数据外传痕迹，请勿用于任何恶意用途；
- 使用本项目产生的任何后果由使用者自行承担。License: [MIT](LICENSE)。
