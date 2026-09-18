#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ZCode 工作区快照外传检查器 (zcode_snapshot_audit.py)
=====================================================
本工具 100% 离线运行：只读取本机文件，不发起任何网络请求。

检查内容（基于对 ZCode 桌面端 app.asar 的逆向结果）：
  1. 定位本机全部 .zcode 数据根（默认 ~/.zcode，及 ZCODE_DATA_BASE_DIR 指定的自定义根）
  2. v2/checkpoints/ 取证：
     - manifests/*.json   每个文件对应一次"已被服务端接受"的快照上传（明文清单，
                          内含上传的每个文件路径+大小 —— 这是"什么被传走了"的直接证据）
     - pending/*.enc      打包加密后滞留本地、未成功传出的密文
     - pending/*.envelope.json  加密信封（明文 JSON，含 manifestHash/明文Sha256 等）
     - tmp/*.tar.gz       未加密明文快照残留
     - state.json         每个工作区的失败计数/上次接受状态/最近压缩体积
  3. 日志取证：v2/logs、cli/log、遗留 logs 目录中检索
     "upload accepted"/"upload-credential"/"repoSnapshot"/"repo-wiki-update"/上传失败等证据
  4. 设置与登录状态：repoSnapshotIndexingEnabled / optimizeAgentExperienceEnabled 等开关
     （注意：经逆向确认，这两个开关均不控制快照上传；唯一门槛是登录 JWT + 服务端下发凭证）

用法：
  python zcode_snapshot_audit.py            # 打开 GUI
  python zcode_snapshot_audit.py --cli      # 命令行模式，输出 Markdown 报告
  python zcode_snapshot_audit.py --cli --export report.md
  python zcode_snapshot_audit.py --root "D:\\zcode-cache\\.zcode" --cli
"""

import json
import os
import re
import sys
import threading
import queue
import datetime
from pathlib import Path

APP_NAME = "ZCode 快照外传检查器"
APP_VERSION = "1.1.1"

# ----------------------------------------------------------------------------
# 通用工具
# ----------------------------------------------------------------------------

def human_size(n):
    if n is None:
        return "—"
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(n)} B"
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def fmt_ts(ts):
    """毫秒 epoch / ISO 字符串 / 文件 mtime 统一格式化"""
    if ts is None:
        return "—"
    try:
        if isinstance(ts, (int, float)):
            return datetime.datetime.fromtimestamp(ts / 1000.0).strftime("%Y-%m-%d %H:%M:%S")
        s = str(ts)
        return s.replace("T", " ").replace("Z", "")[:19]
    except Exception:
        return str(ts)


def read_json(path, max_bytes=64 * 1024 * 1024):
    try:
        if path.stat().st_size > max_bytes:
            return None
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except Exception:
        return None


def load_jsonl_or_text_lines(path, limit=None):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            if limit:
                return f.readlines(limit)
            return f.readlines()
    except Exception:
        return []


# ----------------------------------------------------------------------------
# 数据根发现
# ----------------------------------------------------------------------------

def candidate_data_roots():
    """按 ZCode 客户端逻辑推导数据根：ZCODE_DATA_BASE_DIR 环境变量 / 用户主目录，+.zcode"""
    cands = []
    env_base = os.environ.get("ZCODE_DATA_BASE_DIR")
    if env_base and env_base.strip():
        cands.append(Path(env_base.strip()) / ".zcode")
    home = os.environ.get("HOME") or os.environ.get("USERPROFILE")
    if home:
        cands.append(Path(home) / ".zcode")
    out, seen = [], set()
    for c in cands:
        try:
            key = str(c.resolve()).lower()
        except Exception:
            key = str(c)
        if key not in seen:
            seen.add(key)
            out.append(c)
    return out


def looks_like_zcode_root(p: Path):
    return p.is_dir() and any(
        (p / sub).is_dir() for sub in ("v2", "cli", "logs")
    )


def _probe_drive_win(drv, timeout=4.0):
    """带超时的盘符探测：网络盘/死挂载的 os.path.exists 可能长时间阻塞，
    放到短命线程里跑，超时即视为不可达。返回 DRIVE 类型数字或 None。"""
    out = {}

    def run():
        try:
            if not os.path.exists(drv):
                out["type"] = None
                return
            try:
                import ctypes
                out["type"] = ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(drv))
            except Exception:
                out["type"] = 3  # 探测不出就当本地盘
        except Exception:
            out["type"] = None

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout)
    return out.get("type")


def discover_extra_roots(scan_drives=True):
    """在常见位置浅层搜索其他 .zcode 数据根（用于发现自定义 dataBaseDir 迁移的情况）。
    固定盘/可移动盘扫两层；网络/映射盘只扫第一层（顶层就是 .zcode 的情况，
    如 Z:\\.zcode），且逐盘做 4 秒超时探测，死挂载不会卡住整个扫描。"""
    found = []
    bases = []  # (路径, 是否远程盘)
    if sys.platform == "win32":
        import string
        for letter in string.ascii_uppercase:
            drv = f"{letter}:\\"
            t = _probe_drive_win(drv, timeout=4.0)
            if t is None or t in (0, 1, 5):   # 不可达/未知/无效/光驱
                continue
            bases.append((drv, t == 4))       # 4=远程/映射盘
    else:
        for b in ("/Users", "/home", "/media", "/mnt", "/Volumes", "/opt", "/srv", "/data"):
            if os.path.isdir(b):
                bases.append((b, False))
    skip_names = {
        "Windows", "Program Files", "Program Files (x86)", "ProgramData",
        "$Recycle.Bin", "System Volume Information", "node_modules",
        "AppData", "Library", ".git", "__pycache__", "site-packages",
    }
    for base, is_remote in bases:
        try:
            entries = list(os.scandir(base))
        except Exception:
            continue
        for e1 in entries:  # 第 1 层
            try:
                if not e1.is_dir() or e1.name in skip_names:
                    continue
                p1 = Path(e1.path)
                if e1.name in (".zcode", "zcode-cache"):
                    if looks_like_zcode_root(p1):
                        found.append(p1)
                    elif (p1 / ".zcode").is_dir() and looks_like_zcode_root(p1 / ".zcode"):
                        found.append(p1 / ".zcode")
                    continue
                if is_remote:
                    continue  # 网络盘只看第 1 层
                for e2 in p1.iterdir():  # 第 2 层（仅本地盘）
                    try:
                        if not e2.is_dir() or e2.name in skip_names:
                            continue
                        if e2.name == ".zcode" and looks_like_zcode_root(Path(e2.path)):
                            found.append(Path(e2.path))
                    except Exception:
                        continue
            except Exception:
                continue
    # 去重并排除已知根
    known = {str(r).lower() for r in candidate_data_roots()}
    out, seen = [], set()
    for f in found:
        k = str(f).lower()
        if k not in known and k not in seen:
            seen.add(k)
            out.append(f)
    return out


# ----------------------------------------------------------------------------
# checkpoints 取证
# ----------------------------------------------------------------------------

def classify_file(path_norm):
    if path_norm == ".git" or path_norm.startswith(".git/"):
        if path_norm.startswith(".git/objects/"):
            return ".git/objects（提交历史）"
        if path_norm.startswith(".git/lfs/"):
            return ".git/lfs（LFS 大文件缓存）"
        if path_norm.startswith(".git/logs/"):
            return ".git/logs（reflog/操作轨迹）"
        return ".git（其他元数据）"
    return "工作区源码/文档"


def parse_manifest(path: Path):
    d = read_json(path)
    if not isinstance(d, dict):
        return None
    files = d.get("files") or []
    norm = []
    for f in files:
        if isinstance(f, dict):
            norm.append({
                "path": str(f.get("path", "")),
                "sizeBytes": int(f.get("sizeBytes") or 0),
            })
    stats = d.get("stats") or {}
    return {
        "file": path,
        "mtime": path.stat().st_mtime * 1000 if path.exists() else None,
        "schema": d.get("schema"),
        "workspaceKey": d.get("workspaceKey"),
        "createdAt": d.get("createdAt"),
        "hash": path.stem,
        "files": norm,
        "fileCount": len(norm),
        "totalBytes": sum(f["sizeBytes"] for f in norm) or stats.get("includedBytes"),
        "statsIncludedBytes": stats.get("includedBytes"),
        "statsFileCount": stats.get("includedFileCount"),
    }


def estimate_upload_chain(manifests):
    """按时间顺序对相邻清单做差分，估算每次上传的传输量（与客户端增量逻辑一致：
    基线=全量，其后=新增或大小变化的文件）。返回 (每次明细, 估算总量)。"""
    out, total = [], 0
    prev_map = None
    for m in sorted(manifests, key=lambda x: (x["mtime"] or 0)):
        cur_map = {f["path"]: f["sizeBytes"] for f in m["files"]}
        if prev_map is None:
            sz, kind = m["totalBytes"] or 0, "baseline(全量)"
        else:
            sz = sum(s for p, s in cur_map.items() if prev_map.get(p) != s)
            kind = "increment(增量)"
        out.append({"manifest": m, "estBytes": sz, "kind": kind})
        total += sz
        prev_map = cur_map
    return out, total


def scan_workspace(ws_dir: Path):
    rep = {
        "dir": ws_dir,
        "workspaceKeyHash": ws_dir.name,
        "workspacePath": None,
        "state": None,
        "manifests": [],
        "extraManifests": [],
        "pendingFiles": [],      # (path, size)
        "envelopes": [],
        "tmpFiles": [],          # 明文残留
        "diskBytes": 0,
        "lastActivity": None,
        "status": "空",
        "latest": None,          # 最新清单
        "estUploads": [],
        "estTotalBytes": 0,
    }

    def add_disk(p: Path):
        try:
            rep["diskBytes"] += p.stat().st_size
        except Exception:
            pass

    # state.json
    st = read_json(ws_dir / "state.json")
    if isinstance(st, dict):
        rep["state"] = st
        rep["workspacePath"] = st.get("workspacePath")
        add_disk(ws_dir / "state.json")

    # manifests（= 已被接受的快照清单）
    mdir = ws_dir / "manifests"
    if mdir.is_dir():
        for f in sorted(mdir.glob("*.json")):
            m = parse_manifest(f)
            if m:
                rep["manifests"].append(m)
                add_disk(f)
                rep["workspacePath"] = rep["workspacePath"] or m["workspaceKey"]
    rep["manifests"].sort(key=lambda x: (x["mtime"] or 0))
    if rep["manifests"]:
        rep["latest"] = rep["manifests"][-1]

    # extra-manifests（全局配置随包上传）
    edir = ws_dir / "extra-manifests"
    if edir.is_dir():
        for f in sorted(edir.glob("*.json")):
            d = read_json(f)
            add_disk(f)
            if isinstance(d, dict):
                groups = []
                for g in d.get("groups") or []:
                    if isinstance(g, dict):
                        gf = [x.get("path") for x in (g.get("files") or []) if isinstance(x, dict)]
                        groups.append({"groupId": g.get("groupId"), "files": gf})
                rep["extraManifests"].append({
                    "file": f, "mtime": f.stat().st_mtime * 1000,
                    "schema": d.get("schema"), "groups": groups,
                })

    # pending（滞留未传出的密文）
    pdir = ws_dir / "pending"
    if pdir.is_dir():
        for f in sorted(pdir.iterdir()):
            try:
                if f.is_file():
                    add_disk(f)
                    if f.name.endswith(".enc"):
                        rep["pendingFiles"].append((f, f.stat().st_size))
                    elif f.name.endswith(".envelope.json"):
                        d = read_json(f) or {}
                        rep["envelopes"].append({
                            "file": f,
                            "kind": (d.get("aad") or {}).get("kind"),
                            "manifestHash": (d.get("aad") or {}).get("manifestHash"),
                            "baseManifestHash": (d.get("aad") or {}).get("baseManifestHash"),
                            "contentAlgorithm": d.get("contentAlgorithm"),
                            "keyWrapAlgorithm": d.get("keyWrapAlgorithm"),
                            "keyId": d.get("keyId"),
                            "plaintextSha256": d.get("plaintextSha256"),
                            "encryptedDataKey": d.get("encryptedDataKey"),
                        })
            except Exception:
                pass

    # tmp（明文残留）
    tdir = ws_dir / "tmp"
    if tdir.is_dir():
        for f in sorted(tdir.iterdir()):
            try:
                if f.is_file():
                    add_disk(f)
                    rep["tmpFiles"].append((f, f.stat().st_size))
            except Exception:
                pass

    # 最后活动时间
    times = [m["mtime"] for m in rep["manifests"] if m["mtime"]]
    times += [e["mtime"] for e in rep["extraManifests"]]
    for f, _ in rep["pendingFiles"] + rep["tmpFiles"]:
        try:
            times.append(f.stat().st_mtime * 1000)
        except Exception:
            pass
    rep["lastActivity"] = max(times) if times else None

    # 状态判定
    if rep["pendingFiles"] or rep["envelopes"]:
        rep["status"] = "🔴 滞留本地未传出"
        if rep["manifests"]:
            rep["status"] = "⚠️ 有已上传历史 + 滞留包"
    elif rep["manifests"]:
        rep["status"] = "🔴 已上传（密文已清理，仅剩清单）"
    elif rep["extraManifests"]:
        rep["status"] = "⚠️ 仅有全局配置清单"
    else:
        rep["status"] = "空/仅状态文件"

    # 上传量估算
    if rep["manifests"]:
        rep["estUploads"], rep["estTotalBytes"] = estimate_upload_chain(rep["manifests"])

    return rep


def manifest_breakdown(m, top_n=30):
    """对单个清单做分类统计 + 最大文件 Top N"""
    cats = {}
    for f in m["files"]:
        c = classify_file(f["path"])
        b = cats.get(c, {"count": 0, "bytes": 0})
        b["count"] += 1
        b["bytes"] += f["sizeBytes"]
        cats[c] = b
    top = sorted(m["files"], key=lambda f: -f["sizeBytes"])[:top_n]
    return cats, top


# ----------------------------------------------------------------------------
# 日志取证
# ----------------------------------------------------------------------------

LOG_PATTERNS = [
    ("上传成功", re.compile(r"upload[ ._-]?accepted", re.I)),
    ("凭证请求", re.compile(r"upload-credential|uploadCredential|getUploadKey", re.I)),
    ("OSS对象存储痕迹", re.compile(r"aliyuncs\.com|oss-cn-[a-z]|x-oss-|OSSAccessKeyId|postObject|PostObject", re.I)),
    ("快照上传活动", re.compile(r"repoSnapshotUploadWorker|RepoSnapshot(?!Indexing)|repo[-_]snapshot(?!Indexing)", re.I)),
    ("快照×上传泛匹配", re.compile(r"snapshot.{0,50}upload|upload.{0,50}snapshot", re.I)),
    ("任务终态捕获", re.compile(r"repo-wiki-update|captureStage|captureBeforePrompt", re.I)),
    ("上传失败/滞留", re.compile(r"object_upload_failed|payload_too_large|key_expired|failPendingUpload|discardPendingUpload|ArtifactMaxSizeExceeded", re.I)),
    ("加密工件名", re.compile(r"tar\.gz\.enc|envelope\.json|lastAcceptedManifest", re.I)),
    ("中文快照上传", re.compile(r"快照.{0,30}(上传|外传)|(上传|外传).{0,30}快照")),
    ("Wiki 索引", re.compile(r"repo-wiki\b", re.I)),
]
# 设置整行跳过（日志里会整包 dump settings JSON，含 repoSnapshotIndexingEnabled 等键名，造成误报）
LOG_SKIP = re.compile(r"writing settings|\"recentProjects\"", re.I)
TS_PATTERNS = [
    re.compile(r"^\[(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})"),
    re.compile(r'"timestamp"\s*:\s*"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})'),
]


def extract_ts(line):
    for p in TS_PATTERNS:
        m = p.search(line)
        if m:
            return m.group(1).replace("T", " ")
    return None


def electron_user_data_dirs():
    """Electron 默认 userData 目录（桌面端 App 的会话/崩溃/遥测数据，与 .zcode 数据根无关）"""
    out = []
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        if appdata:
            out.append(Path(appdata) / "ZCode")
    elif sys.platform == "darwin":
        p = Path.home() / "Library" / "Application Support" / "ZCode"
        out.append(p)
    else:
        out.append(Path.home() / ".config" / "ZCode")
    return out


def log_targets(root: Path):
    targets = []
    for sub, pat in (("v2/logs", "*.log"), ("cli/log", "*.jsonl"), ("logs", "*.jsonl"), ("logs", "*.log"), ("cli/log", "*.log")):
        d = root / sub
        if d.is_dir():
            targets += list(d.glob(pat))
    # Electron userData 里的崩溃面包屑（老版本留下的少量运行记录，跨版本有效）
    for ud in electron_user_data_dirs():
        sentry_scope = ud / "sentry" / "scope_v3.json"
        if sentry_scope.exists():
            targets.append(sentry_scope)
    # 去重
    seen, out = set(), []
    for t in targets:
        k = str(t).lower()
        if k not in seen:
            seen.add(k)
            out.append(t)
    return sorted(out)


def scan_logs(root: Path, max_hits_per_file=80, max_line=240):
    rep = {"files": [], "hits": [], "categories": {}, "first": None, "last": None, "scanned": 0}
    for f in log_targets(root):
        try:
            if f.stat().st_size > 80 * 1024 * 1024:
                continue
        except Exception:
            continue
        fstats = {"file": f, "hits": 0, "first": None, "last": None}
        try:
            with open(f, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if LOG_SKIP.search(line):
                        continue
                    ts = extract_ts(line)
                    if ts:
                        if not fstats["first"] or ts < fstats["first"]:
                            fstats["first"] = ts
                        if not fstats["last"] or ts > fstats["last"]:
                            fstats["last"] = ts
                    hit_cat = None
                    for cat, pat in LOG_PATTERNS:
                        if pat.search(line):
                            hit_cat = cat
                            break
                    if hit_cat:
                        fstats["hits"] += 1
                        rep["categories"][hit_cat] = rep["categories"].get(hit_cat, 0) + 1
                        if len(rep["hits"]) < 1000:
                            rep["hits"].append({
                                "ts": ts, "cat": hit_cat, "file": str(f),
                                "line": line.strip()[:max_line],
                            })
        except Exception:
            continue
        if fstats["hits"] or True:
            rep["files"].append(fstats)
            rep["scanned"] += 1
            if fstats["first"] and (not rep["first"] or fstats["first"] < rep["first"]):
                rep["first"] = fstats["first"]
            if fstats["last"] and (not rep["last"] or fstats["last"] > rep["last"]):
                rep["last"] = fstats["last"]
    rep["hits"].sort(key=lambda h: (h["ts"] or ""))
    return rep


# ----------------------------------------------------------------------------
# 设置与登录状态
# ----------------------------------------------------------------------------

def scan_settings(root: Path):
    out = {"exists": False, "items": [], "loggedIn": None}
    s = read_json(root / "v2" / "setting.json")
    if isinstance(s, dict):
        out["exists"] = True
        defs = [
            ("repoSnapshotIndexingEnabled", "仓库快照索引", "经逆向确认：只控制服务端索引，不控制快照上传"),
            ("optimizeAgentExperienceEnabled", "体验优化（训练数据）", "经逆向确认：不控制快照上传"),
            ("instantGrepIndexingEnabled", "即时 grep 索引", ""),
            ("memoryEnabled", "记忆功能", ""),
        ]
        for key, name, note in defs:
            if key in s:
                out["items"].append({"key": key, "name": name, "value": s.get(key), "note": note})
        fam = s.get("modelProviderFamilySelectedKeys") or {}
        out["items"].append({
            "key": "modelProviderFamilySelectedKeys", "name": "登录的账号体系",
            "value": ", ".join(f"{k}={v}" for k, v in fam.items()) or "（无）",
            "note": "存在活动提供方即视为已登录——快照通道处于可激活状态",
        })
        out["loggedIn"] = bool(fam)
    cred = root / "v2" / "credentials.json"
    out["credentialsFile"] = cred if cred.exists() else None
    cfg = read_json(root / "v2" / "config.json")
    if isinstance(cfg, dict):
        ep = json.dumps(cfg)
        m = re.search(r'"zcodeEndpointOrigin"\s*:\s*"([^"]+)"', ep)
        if m:
            out["endpointOrigin"] = m.group(1)
    return out


# ----------------------------------------------------------------------------
# 版本无关兜底扫描（防老版本/未来改版漏检）
# ----------------------------------------------------------------------------

SWEEP_DIRPAT = re.compile(r"snapshot|checkpoint", re.I)
SWEEP_FILEPAT = re.compile(r"\.tar\.gz\.enc$|\.envelope\.json$", re.I)
SWEEP_SKIP_DIRS = {
    # 大体积/与快照无关的目录，跳过以保持扫描快速
    "node_modules", ".git", "session", "Cache", "Code Cache", "GPUCache",
    "DawnGraphiteCache", "DawnWebGPUCache", "blob_storage", "IndexedDB",
    "Local Storage", "Session Storage", "Service Worker", "shared_proto_db",
    "WebStorage", "sentry", "image-cache", "db", "exec", "rollout",
    "artifacts", "agents", "bundled-agents", "plugins", "shell-snapshots",
    "acp-traffic-proxy", "crash", "locks", "logs", "cache", "tmp-cache",
}


def sweep_root_artifacts(root: Path, max_depth=5):
    """在整个数据根里按“名字”找快照工件（目录含 snapshot/checkpoint、
    *.tar.gz.enc 密文、*.envelope.json 信封、游离的 state.json），
    不依赖当前版本已知的 v2/checkpoints 布局——老版本 repo-snapshots 或
    未来改名都能兜住。已知 v2/checkpoints 内的正常命中已由 scan_workspace
    精细统计，这里过滤掉避免重复。"""
    hits = []
    root = Path(root)

    for dirpath, dirnames, filenames in os.walk(root):
        try:
            rel = Path(dirpath).relative_to(root)
            depth = len(rel.parts)
        except Exception:
            continue
        if depth >= max_depth:
            dirnames[:] = []
        dirnames[:] = [d for d in dirnames if d not in SWEEP_SKIP_DIRS]
        under_projects = len(rel.parts) >= 1 and rel.parts[0] == "projects"
        for d in dirnames:
            if SWEEP_DIRPAT.search(d):
                if under_projects:
                    # projects/*/snapshots 是 CLI 会话文件历史（本地恢复用；
                    # CLI 本体无上传快照代码，已核实），不作为可疑项
                    continue
                hits.append({"kind": "dir", "path": Path(dirpath) / d, "size": 0,
                             "note": "名字含 snapshot/checkpoint 的目录（可能是老版本布局）"})
        for f in filenames:
            if SWEEP_FILEPAT.search(f):
                p = Path(dirpath) / f
                try:
                    size = p.stat().st_size
                except Exception:
                    size = 0
                hits.append({"kind": "file", "path": p, "size": size,
                             "note": ".enc 密文 / .envelope.json 信封（快照工件，跨版本有效）"})
            elif f == "state.json":
                hits.append({"kind": "file", "path": Path(dirpath) / f, "size": 0,
                             "note": "快照状态文件 state.json"})
        if len(hits) >= 300:
            break

    known = (str(root / "v2" / "checkpoints").lower(), str(root / "v2" / "repo-snapshots").lower())
    out = []
    for h in hits:
        if str(h["path"]).lower().startswith(known):
            continue  # 已知布局内的由 scan_workspace 负责
        out.append(h)
    return out[:300]


# ----------------------------------------------------------------------------
# 根扫描 + 总判定
# ----------------------------------------------------------------------------

def scan_root(root: Path, scan_extra_drives=False, progress=None):
    rep = {
        "root": root, "exists": root.is_dir(),
        "workspaces": [], "logs": None, "settings": None,
        "checkpointsDir": root / "v2" / "checkpoints",
        "legacyDir": root / "v2" / "repo-snapshots",
        "verdict": "", "verdictLevel": "ok",
        "extraRoots": [], "sweepHits": [],
    }
    if not rep["exists"]:
        rep["verdict"] = f"数据根不存在：{root}"
        return rep

    cp = rep["checkpointsDir"] if rep["checkpointsDir"].is_dir() else (
        rep["legacyDir"] if rep["legacyDir"].is_dir() else None)
    if cp:
        for d in sorted(cp.iterdir()):
            if d.is_dir():
                if progress:
                    progress(f"分析工作区 {d.name} …")
                rep["workspaces"].append(scan_workspace(d))

    if progress:
        progress("检索日志证据 …")
    rep["logs"] = scan_logs(root)
    rep["settings"] = scan_settings(root)

    if progress:
        progress("全数据区兜底扫描（按工件名字匹配，不依赖版本布局）…")
    rep["sweepHits"] = sweep_root_artifacts(root)

    if scan_extra_drives:
        if progress:
            progress("搜索其他磁盘上的 .zcode 数据根 …")
        rep["extraRoots"] = discover_extra_roots()

    # 一句话结论 + 计数（供极简首页与总结弹窗使用）
    n_ws = len(rep["workspaces"])
    n_manifest = sum(len(w["manifests"]) for w in rep["workspaces"])
    n_pending = sum(len(w["pendingFiles"]) for w in rep["workspaces"])
    n_tmp = sum(len(w["tmpFiles"]) for w in rep["workspaces"])
    n_extra = sum(len(w["extraManifests"]) for w in rep["workspaces"])
    est_total = sum(w["estTotalBytes"] for w in rep["workspaces"])
    pending_bytes = sum(s for _, s in [p for w in rep["workspaces"] for p in w["pendingFiles"]])
    up_credential = (rep["logs"]["categories"].get("凭证请求", 0)
                     + rep["logs"]["categories"].get("上传成功", 0)
                     + rep["logs"]["categories"].get("OSS对象存储痕迹", 0))
    sweep_arts = [h for h in rep["sweepHits"] if h["kind"] == "file"]
    sweep_bytes = sum(h["size"] for h in sweep_arts)

    rep["counts"] = {
        "workspaces": n_ws, "manifests": n_manifest, "pending": n_pending,
        "tmp": n_tmp, "extra": n_extra, "estTotalBytes": est_total,
        "pendingBytes": pending_bytes, "credHits": up_credential,
        "sweepArts": len(sweep_arts), "sweepBytes": sweep_bytes,
        "sweepDirs": len(rep["sweepHits"]) - len(sweep_arts),
    }
    if n_manifest or n_pending or n_tmp:
        if n_manifest:
            s = "🔴 发现上传痕迹：已接受快照 %d 份" % n_manifest
        else:
            s = "🔴 发现上传痕迹（滞留未传出）"
        if est_total:
            s += "，估算累计上传 " + human_size(est_total)
        if n_pending:
            s += "；另有 %d 个加密包滞留本地（%s）" % (n_pending, human_size(pending_bytes))
        if n_tmp:
            s += "；发现 %d 个未加密明文残留" % n_tmp
    elif sweep_arts:
        s = "⚠️ 已知布局无上传记录，但在数据区里发现 %d 个可疑快照工件（详见高级页）" % len(sweep_arts)
    elif up_credential:
        s = "⚠️ 日志出现过上传活动，但本地无快照工件"
    else:
        s = "✅ 未发现上传痕迹（日志证据覆盖 %s ~ %s）" % (
            rep["logs"]["first"] or "—", rep["logs"]["last"] or "—")
    rep["short"] = s

    parts = []
    if n_manifest or n_pending or n_tmp:
        rep["verdictLevel"] = "alert"
        parts.append(f"⚠️ 发现快照外传痕迹：{n_ws} 个工作区目录，已被接受的快照清单 {n_manifest} 份")
        if est_total:
            parts.append(f"按清单估算累计上传量约 {human_size(est_total)}")
        if n_pending:
            parts.append(f"另有 {n_pending} 个加密包滞留本地未传出（{human_size(pending_bytes)}）")
        if n_tmp:
            parts.append(f"发现 {n_tmp} 个未加密明文快照残留（tmp 目录）！")
        if n_extra:
            parts.append(f"全局配置清单 {n_extra} 份（settings/mcp/skills 等曾随快照上传）")
    elif sweep_arts:
        rep["verdictLevel"] = "warn"
        parts.append(f"⚠️ 已知布局（v2/checkpoints）内无上传记录，但数据区兜底扫描发现 {len(sweep_arts)} 个可疑快照工件：")
        for h in sweep_arts[:10]:
            parts.append(f"  - {h['path']}" + (f"（{human_size(h['size'])}）" if h["size"] else ""))
        parts.append("（可能是老版本布局的残留，请人工确认；完整列表见报告）")
    else:
        if up_credential:
            rep["verdictLevel"] = "warn"
            parts.append("⚠️ 日志中出现过快照凭证请求/上传活动，但本地无任何快照工件（可能日志早于工件清理，建议检查自定义数据根）")
        else:
            rep["verdictLevel"] = "ok"
            first = rep["logs"]["first"] or "—"
            last = rep["logs"]["last"] or "—"
            parts.append(f"✅ 未发现快照外传痕迹（checkpoints 不存在或为空；日志证据窗口 {first} ~ {last}）")
            parts.append("注意：机制本身存在于客户端且不受 UI 开关控制，登录状态下服务端下发凭证即会激活。")
    rep["verdict"] = "\n".join(parts)
    return rep


# ----------------------------------------------------------------------------
# 报告生成
# ----------------------------------------------------------------------------

def build_markdown(result):
    L = []
    ap = L.append
    ap(f"# {APP_NAME} 报告（v{APP_VERSION}）")
    ap("")
    ap(f"- 生成时间：{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    ap("- 本工具完全离线运行，仅读取本地文件")
    ap("")
    for r in result["roots"]:
        ap(f"## 数据根：{r['root']}")
        ap("")
        ap("```")
        ap(r["verdict"])
        ap("```")
        ap("")
        s = r.get("settings") or {}
        if s.get("exists"):
            ap("### 设置与登录")
            ap("")
            ap("| 设置 | 值 | 说明 |")
            ap("|---|---|---|")
            for it in s.get("items", []):
                ap(f"| {it['name']} (`{it['key']}`) | {it['value']} | {it['note']} |")
            ap(f"| 登录凭据文件 | {'存在: ' + str(s['credentialsFile']) if s.get('credentialsFile') else '不存在'} | 存在 JWT 凭据时快照通道可被激活 |")
            if s.get("endpointOrigin"):
                ap(f"| 服务端点 | {s['endpointOrigin']} | |")
            ap("")
        if r["workspaces"]:
            ap("### 工作区快照明细")
            ap("")
            ap("| 工作区路径 | 状态 | 已接受清单 | 最新快照文件数 | 最新快照体积 | 估算累计上传 | 滞留密文 | 失败/重试 | 最后活动 |")
            ap("|---|---|---|---|---|---|---|---|---|")
            for w in r["workspaces"]:
                st = w["state"] or {}
                pend = sum(sz for _, sz in w["pendingFiles"])
                latest = w["latest"]
                ap("| {} | {} | {} | {} | {} | {} | {} | {} | {} |".format(
                    w["workspacePath"] or w["workspaceKeyHash"],
                    w["status"],
                    len(w["manifests"]),
                    latest["fileCount"] if latest else "—",
                    human_size(latest["totalBytes"]) if latest else "—",
                    human_size(w["estTotalBytes"]) if w["manifests"] else "—",
                    f"{len(w['pendingFiles'])}个/{human_size(pend)}" if w["pendingFiles"] else "—",
                    f"{st.get('failureCount', 0)}/{st.get('attemptCount', 0)}",
                    fmt_ts(w["lastActivity"]),
                ))
            ap("")
            for w in r["workspaces"]:
                if not w["manifests"] and not w["pendingFiles"]:
                    continue
                ap(f"#### {w['workspacePath'] or w['workspaceKeyHash']}")
                ap("")
                latest = w["latest"]
                if latest:
                    cats, top = manifest_breakdown(latest)
                    ap(f"最新清单 `{latest['file'].name}`（{fmt_ts(latest['mtime'])}，schema={latest['schema']}）：")
                    ap("")
                    ap("| 分类 | 文件数 | 体积 |")
                    ap("|---|---|---|")
                    for c, b in sorted(cats.items(), key=lambda kv: -kv[1]["bytes"]):
                        ap(f"| {c} | {b['count']} | {human_size(b['bytes'])} |")
                    ap("")
                    ap("最大文件 Top10：")
                    ap("")
                    for f in top[:10]:
                        ap(f"- `{f['path']}` ({human_size(f['sizeBytes'])})")
                    ap("")
                for e in w["envelopes"]:
                    ap(f"- 滞留信封 `{e['file'].name}`：kind={e['kind']} manifestHash={str(e['manifestHash'])[:16]}… 明文Sha256={str(e['plaintextSha256'])[:16]}…")
                for f, sz in w["pendingFiles"]:
                    ap(f"- 滞留密文 `{f.name}`（{human_size(sz)}）")
                ap("")
        lg = r.get("logs")
        if lg and (lg["hits"] or lg["categories"]):
            ap("### 日志证据")
            ap("")
            ap(f"扫描 {len(lg['files'])} 个日志文件，窗口 {lg['first']} ~ {lg['last']}。分类命中：")
            ap("")
            ap("| 类别 | 次数 |")
            ap("|---|---|")
            for c, n in sorted(lg["categories"].items(), key=lambda kv: -kv[1]):
                ap(f"| {c} | {n} |")
            ap("")
            ap("样例（最多 30 条）：")
            ap("")
            ap("```")
            for h in lg["hits"][:30]:
                ap(f"[{h['ts'] or '????'}] [{h['cat']}] {h['line']}")
            ap("```")
            ap("")
        for extra in r.get("extraRoots", []):
            ap(f"- 发现其他 .zcode 数据根：`{extra}`（可加 --root 参数单独扫描）")
        sweep = r.get("sweepHits") or []
        if sweep:
            ap("### 兜底扫描（按工件名匹配，不依赖版本布局）")
            ap("")
            for h in sweep[:50]:
                ap(f"- [{h['kind']}] `{h['path']}`" + (f"（{human_size(h['size'])}）" if h.get("size") else "") + f" —— {h['note']}")
            if len(sweep) > 50:
                ap(f"- … 其余 {len(sweep) - 50} 条略")
            ap("")
        ap("")
    return "\n".join(L)


# ----------------------------------------------------------------------------
# CLI 模式
# ----------------------------------------------------------------------------

def run_cli(args):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    roots = []
    if args.root:
        roots.append(Path(args.root))
    else:
        roots = candidate_data_roots()
        if args.drives:
            roots += discover_extra_roots()
    roots = [r for r in roots if r.exists()] or roots
    result = {"roots": []}
    for r in roots:
        print(f"扫描 {r} …", file=sys.stderr)
        result["roots"].append(scan_root(r, scan_extra_drives=args.drives))
    md = build_markdown(result)
    print(md)
    if args.export:
        with open(args.export, "w", encoding="utf-8") as f:
            f.write(md)
        print(f"\n报告已写入 {args.export}", file=sys.stderr)


# ----------------------------------------------------------------------------
# GUI 模式（tkinter，标准库自带）
# ----------------------------------------------------------------------------

def run_gui():
    import tkinter as tk
    import tkinter.font as tkfont
    from tkinter import ttk, filedialog

    q = queue.Queue()
    state = {"results": None}
    root = tk.Tk()
    root.title(f"{APP_NAME} v{APP_VERSION}（完全离线）")
    root.geometry("960x680")
    root.minsize(760, 540)

    f_def = tkfont.nametofont("TkDefaultFont")
    f_big_title = f_def.copy(); f_big_title.configure(size=19, weight="bold")
    f_sub = f_def.copy(); f_sub.configure(size=10)
    f_big_btn = f_def.copy(); f_big_btn.configure(size=15, weight="bold")
    f_result = f_def.copy(); f_result.configure(size=12)
    f_path = f_def.copy(); f_path.configure(size=12, weight="bold")
    f_small = f_def.copy(); f_small.configure(size=9)

    def mac_flat_button(parent, text, font, command, padx, pady):
        """macOS 的 tk.Button 固定画成浅色原生按钮、忽略 bg，白字会看不见；
        改用 Label 模拟扁平蓝色按钮（同样支持 config(state=..., text=...)）。"""
        b = tk.Label(parent, text=text, font=font, bg="#2563eb", fg="white",
                     disabledforeground="#bfdbfe", padx=padx, pady=pady, cursor="hand2")

        def on_click(_e):
            if str(b.cget("state")) != "disabled":
                command()

        def on_enter(_e):
            if str(b.cget("state")) != "disabled":
                b.config(bg="#1d4ed8")

        b.bind("<Button-1>", on_click)
        b.bind("<Enter>", on_enter)
        b.bind("<Leave>", lambda _e: b.config(bg="#2563eb"))
        return b

    nb_main = ttk.Notebook(root)
    nb_main.pack(fill="both", expand=True)

    # ================= 首页（极简） =================
    tab_home = ttk.Frame(nb_main, padding=18)
    nb_main.add(tab_home, text=" 🏠 首页 ")

    tab_home.columnconfigure(0, weight=1)
    tab_home.rowconfigure(4, weight=1)

    tk.Label(tab_home, text="ZCode 数据外传检查", font=f_big_title).grid(row=0, column=0, pady=(2, 4))
    tk.Label(tab_home, text="一键检查本机是否有工作区代码/数据被 ZCode 快照上传过，以及 ZCode 在哪些位置存放了数据",
             font=f_sub, foreground="#555", wraplength=760, justify="center").grid(row=1, column=0, pady=(0, 12))

    drive_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(tab_home, text="同时自动搜索本机所有磁盘分区，含网络/映射盘（每盘限时探测，卡不了）",
                    variable=drive_var).grid(row=2, column=0)

    if sys.platform == "darwin":
        btn_home = mac_flat_button(tab_home, "🔍  一 键 检 查", f_big_btn,
                                   lambda: do_scan(), padx=40, pady=16)
    else:
        btn_home = tk.Button(tab_home, text="🔍  一 键 检 查", font=f_big_btn,
                             bg="#2563eb", fg="white", activebackground="#1d4ed8",
                             activeforeground="white", relief="flat", cursor="hand2",
                             padx=40, pady=16, command=lambda: do_scan(), bd=0)
    btn_home.grid(row=3, column=0, pady=14)

    home_status = tk.StringVar(value="点击“一键检查”开始（完全离线运行，只读取本地文件，不联网）")
    tk.Label(tab_home, textvariable=home_status, font=f_small, foreground="#666").grid(row=5, column=0, sticky="w", pady=(4, 0))
    prog = ttk.Progressbar(tab_home, mode="indeterminate", length=220)

    txt_home = tk.Text(tab_home, font=f_result, wrap="word", relief="flat",
                       background="#f6f8fa", padx=14, pady=10, cursor="arrow", height=10)
    txt_home.tag_config("path", font=f_path, foreground="#24292f")
    txt_home.tag_config("ok", foreground="#1a7f37")
    txt_home.tag_config("warn", foreground="#9a6700")
    txt_home.tag_config("alert", foreground="#cf222e")
    txt_home.tag_config("head", foreground="#57606a")
    txt_home.grid(row=4, column=0, sticky="nsew", pady=(8, 0))

    def home_reset():
        txt_home.config(state="normal")
        txt_home.delete("1.0", "end")
        txt_home.insert("end", "ZCode 已知数据位置：\n", "head")
        for p in candidate_data_roots():
            tag = "ok" if p.exists() else "head"
            txt_home.insert("end", f"  📍 {p}\n", tag)
        txt_home.insert("end", "\n（点击“一键检查”后，这里会显示每个数据区的检查结论）\n", "head")
        txt_home.config(state="disabled")

    home_reset()

    # ================= 高级页 =================
    tab_adv = ttk.Frame(nb_main)
    nb_main.add(tab_adv, text=" 🛠 高级 ")

    adv_top = ttk.Frame(tab_adv, padding=4)
    adv_top.pack(fill="x")

    nb = ttk.Notebook(tab_adv)
    nb.pack(fill="both", expand=True)

    tab_summary = ttk.Frame(nb)
    nb.add(tab_summary, text=" 概要 ")

    txt_verdict = tk.Text(tab_summary, height=7, wrap="word", font=("Microsoft YaHei UI", 10))
    txt_verdict.pack(fill="x", padx=4, pady=4)
    txt_verdict.tag_config("ok", foreground="#1a7f37")
    txt_verdict.tag_config("warn", foreground="#b58105")
    txt_verdict.tag_config("alert", foreground="#cf222e")
    txt_verdict.config(state="disabled")

    cols = ("工作区路径", "状态", "已接受清单", "最新文件数", "最新体积", "估算累计上传", "滞留密文", "失败/重试", "最后活动")
    wrap = ttk.Frame(tab_summary)
    wrap.pack(fill="both", expand=True)
    tree_summary = ttk.Treeview(wrap, columns=cols, show="headings", height=12)
    for c in cols:
        tree_summary.heading(c, text=c)
        tree_summary.column(c, width=170 if c == "工作区路径" else 110, anchor="w")
    ysb = ttk.Scrollbar(wrap, orient="vertical", command=tree_summary.yview)
    tree_summary.configure(yscrollcommand=ysb.set)
    tree_summary.pack(side="left", fill="both", expand=True)
    ysb.pack(side="right", fill="y")

    tab_ws = ttk.Frame(nb)
    nb.add(tab_ws, text=" 工作区详情 ")
    pw = ttk.PanedWindow(tab_ws, orient="horizontal")
    pw.pack(fill="both", expand=True)
    left = ttk.Frame(pw)
    pw.add(left, weight=1)
    cols_ws = ("工作区", "状态")
    tree_ws = ttk.Treeview(left, columns=cols_ws, show="headings")
    for c in cols_ws:
        tree_ws.heading(c, text=c)
    tree_ws.column("工作区", width=330)
    tree_ws.column("状态", width=240)
    tree_ws.pack(fill="both", expand=True, side="left")
    sb1 = ttk.Scrollbar(left, orient="vertical", command=tree_ws.yview)
    tree_ws.configure(yscrollcommand=sb1.set)
    sb1.pack(side="right", fill="y")

    right = ttk.Frame(pw)
    pw.add(right, weight=2)
    txt_detail = tk.Text(right, wrap="word", font=("Consolas", 9))
    txt_detail.pack(fill="both", expand=True, side="top")

    cols_m = ("清单文件", "时间", "schema", "文件数", "体积", "类型")
    tree_manifests = ttk.Treeview(right, columns=cols_m, show="headings", height=8)
    for c in cols_m:
        tree_manifests.heading(c, text=c)
    tree_manifests.pack(fill="x", side="bottom")

    def on_ws_select(_e=None):
        sel = tree_ws.selection()
        if not sel:
            return
        w = ws_index.get(sel[0])
        if not w:
            return
        txt_detail.config(state="normal")
        txt_detail.delete("1.0", "end")
        st = w["state"] or {}

        def P(s):
            txt_detail.insert("end", s)

        P(f"工作区路径: {w['workspacePath'] or '(未知，哈希=' + w['workspaceKeyHash'] + ')'}\n")
        P(f"目录: {w['dir']}\n")
        P(f"状态: {w['status']}\n")
        P(f"最后活动: {fmt_ts(w['lastActivity'])}\n")
        P(f"本地占用: {human_size(w['diskBytes'])}\n\n")
        if st:
            P("state.json 关键字段:\n")
            P(f"  failureCount(累计失败): {st.get('failureCount', 0)}   attemptCount: {st.get('attemptCount', 0)}\n")
            lcs = st.get("lastCompressedSize") or {}
            if lcs:
                P(f"  最近一次压缩体积: 密文 {human_size(lcs.get('encryptedSizeBytes'))} / 工作区 {human_size(lcs.get('workspaceSizeBytes'))}  ({fmt_ts(lcs.get('recordedAt'))})\n")
            lam = st.get("lastAcceptedManifestHash")
            if lam:
                P(f"  最近被接受的清单: {str(lam)[:24]}…\n")
            lpu = st.get("latestPendingUpload") or {}
            if lpu:
                attr = lpu.get("attribution") or {}
                P(f"  滞留待传: kind={lpu.get('kind')} groupId={str(lpu.get('groupId'))[:30]}… 触发会话={attr.get('sessionId')} 阶段={attr.get('captureStage')}\n")
            P("\n")
        if w["manifests"]:
            ests = {id(e["manifest"]): e for e in w["estUploads"]}
            P(f"清单（每份 = 一次被接受的上传，共 {len(w['manifests'])} 份）:\n")
            for m in w["manifests"]:
                e = ests.get(id(m), {})
                P(f"  {fmt_ts(m['mtime'])}  {m['file'].name}  文件 {m['fileCount']} 个  {human_size(m['totalBytes'])}  [{e.get('kind', '')}≈{human_size(e.get('estBytes', 0))}]\n")
            if w["extraManifests"]:
                P(f"\n全局配置清单 {len(w['extraManifests'])} 份（settings.behavior.json / mcp.json / skills 等曾随快照上传）:\n")
                for em in w["extraManifests"][:10]:
                    names = ", ".join(n for g in em["groups"] for n in (g["files"] or []))
                    P(f"  {fmt_ts(em['mtime'])}  {names or em['schema']}\n")
        if w["pendingFiles"]:
            P("\n🔴 滞留本地未传出的加密包:\n")
            for f, sz in w["pendingFiles"]:
                P(f"  {f.name}  ({human_size(sz)})\n")
            for e in w["envelopes"]:
                P(f"  信封 {e['file'].name}: kind={e['kind']} 算法={e['contentAlgorithm']}/{e['keyWrapAlgorithm']} keyId={e['keyId']}\n")
            P("  （密文用服务端下发的 RSA 公钥加密，本地无法解密；文件未离开本机）\n")
        if w["tmpFiles"]:
            P("\n🔴 未加密明文快照残留（tmp）:\n")
            for f, sz in w["tmpFiles"]:
                P(f"  {f.name}  ({human_size(sz)})\n")
        txt_detail.config(state="disabled")
        clear_tree(tree_manifests)
        for m in w["manifests"]:
            e = next((x for x in w["estUploads"] if x["manifest"] is m), {})
            tree_manifests.insert("", "end", values=(
                m["file"].name, fmt_ts(m["mtime"]), m["schema"], m["fileCount"],
                human_size(m["totalBytes"]), e.get("kind", "")))

    tree_ws.bind("<<TreeviewSelect>>", on_ws_select)

    def on_manifest_dbl(_e=None):
        sel = tree_ws.selection()
        msel = tree_manifests.selection()
        if not sel or not msel:
            return
        w = ws_index.get(sel[0])
        if not w:
            return
        mname = tree_manifests.set(msel[0], "清单文件")
        m = next((x for x in w["manifests"] if x["file"].name == mname), None)
        if not m:
            return
        cats, top = manifest_breakdown(m, top_n=200)
        nb.select(tab_files)
        clear_tree(tree_files)
        roots_nodes = {}
        for c, b in sorted(cats.items(), key=lambda kv: -kv[1]["bytes"]):
            roots_nodes[c] = tree_files.insert("", "end", open=False,
                                               values=(c, f"{b['count']} 个", human_size(b["bytes"])))
        for c, node in roots_nodes.items():
            cnt = 0
            total_in_cat = sum(1 for ff in m["files"] if classify_file(ff["path"]) == c)
            for f in sorted(m["files"], key=lambda f: -f["sizeBytes"]):
                if classify_file(f["path"]) == c:
                    cnt += 1
                    if cnt > 200:
                        tree_files.insert(node, "end", values=(f"… 其余 {total_in_cat - 200} 个文件", "", ""))
                        break
                    tree_files.insert(node, "end", values=(f["path"], "", human_size(f["sizeBytes"])))
        tnode = tree_files.insert("", "end", open=True, values=("★ 最大文件 Top30", "", ""))
        for f in sorted(m["files"], key=lambda f: -f["sizeBytes"])[:30]:
            tree_files.insert(tnode, "end", values=(f["path"], "", human_size(f["sizeBytes"])))

    tree_manifests.bind("<Double-1>", on_manifest_dbl)

    tab_files = ttk.Frame(nb)
    nb.add(tab_files, text=" 快照内容明细 ")
    wrapf = ttk.Frame(tab_files)
    wrapf.pack(fill="both", expand=True)
    tree_files = ttk.Treeview(wrapf, columns=("路径", "数量", "体积"), show="headings")
    for c, wdt in (("路径", 620), ("数量", 90), ("体积", 110)):
        tree_files.heading(c, text=c)
        tree_files.column(c, width=wdt, anchor="w")
    sb2 = ttk.Scrollbar(wrapf, orient="vertical", command=tree_files.yview)
    tree_files.configure(yscrollcommand=sb2.set)
    tree_files.pack(side="left", fill="both", expand=True)
    sb2.pack(side="right", fill="y")
    ttk.Label(tab_files, text="提示：先在“工作区详情”选中工作区，再双击下方清单行查看该次上传包含的所有文件").pack(fill="x")

    tab_logs = ttk.Frame(nb)
    nb.add(tab_logs, text=" 日志证据 ")
    wrapl = ttk.Frame(tab_logs)
    wrapl.pack(fill="both", expand=True)
    cols_l = ("时间", "类别", "日志文件", "行摘录")
    tree_logs = ttk.Treeview(wrapl, columns=cols_l, show="headings")
    for c, wdt in (("时间", 150), ("类别", 110), ("日志文件", 260), ("行摘录", 560)):
        tree_logs.heading(c, text=c)
        tree_logs.column(c, width=wdt, anchor="w")
    sb3 = ttk.Scrollbar(wrapl, orient="vertical", command=tree_logs.yview)
    tree_logs.configure(yscrollcommand=sb3.set)
    tree_logs.pack(side="left", fill="both", expand=True)
    sb3.pack(side="right", fill="y")
    txt_logstat = tk.Text(tab_logs, height=4, wrap="word")
    txt_logstat.pack(fill="x")
    txt_logstat.config(state="disabled")

    tab_set = ttk.Frame(nb)
    nb.add(tab_set, text=" 设置与说明 ")
    txt_set = tk.Text(tab_set, wrap="word", font=("Microsoft YaHei UI", 10), padx=10, pady=8)
    txt_set.pack(fill="both", expand=True)

    # ================= 扫描编排 =================
    q2 = queue.Queue()
    scanning = {"flag": False}

    def adv_clear():
        for t in (tree_ws, tree_logs, tree_summary, tree_files, tree_manifests):
            clear_tree(t)
        for t in (txt_detail, txt_verdict, txt_logstat, txt_set):
            t.config(state="normal")
            t.delete("1.0", "end")
            t.config(state="disabled")

    def scan_thread(roots, use_drives):
        try:
            results = {"roots": []}
            for r in roots:
                q2.put(("status", f"正在检查 {r} …"))
                rep = scan_root(r, scan_extra_drives=use_drives,
                                progress=lambda m: q2.put(("status", m)))
                if rep["extraRoots"]:
                    for er in rep["extraRoots"]:
                        q2.put(("status", f"发现附加数据区 {er}，继续检查 …"))
                        results["roots"].append(scan_root(er))
                    rep["extraRoots"] = []
                results["roots"].append(rep)
            q2.put(("done", results))
        except Exception as e:
            q2.put(("error", f"{e.__class__.__name__}: {e}"))

    def do_scan():
        if scanning["flag"]:
            return
        roots = candidate_data_roots()          # tkinter 变量只在主线程读
        use_drives = bool(drive_var.get())
        scanning["flag"] = True
        btn_home.config(state="disabled", text="⏳ 检查中…")
        try:
            prog.grid(row=4, column=0, sticky="ew", pady=(8, 0))
            txt_home.grid_remove()
        except Exception:
            pass
        prog.start(10)
        adv_clear()
        home_status.set("正在检查…")
        threading.Thread(target=scan_thread, args=(roots, use_drives), daemon=True).start()

    def poll_queue():
        try:
            while True:
                kind, payload = q2.get_nowait()
                if kind == "status":
                    home_status.set(payload)
                elif kind == "done":
                    state["results"] = payload
                    fill_results(payload)
                    prog.stop()
                    try:
                        prog.grid_forget()
                        txt_home.grid()
                    except Exception:
                        pass
                    btn_home.config(state="normal", text="🔍  一 键 检 查")
                    scanning["flag"] = False
                    home_status.set("检查完成。详细分析见“高级”标签页。")
                    nb_main.select(tab_home)
                    show_summary_dialog(payload)
                elif kind == "error":
                    prog.stop()
                    try:
                        prog.grid_forget()
                        txt_home.grid()
                    except Exception:
                        pass
                    btn_home.config(state="normal", text="🔍  一 键 检 查")
                    scanning["flag"] = False
                    show_summary_dialog({"roots": [], "error": payload})
        except queue.Empty:
            pass
        root.after(150, poll_queue)

    def short_tag(rep):
        if rep.get("short", "").startswith("🔴"):
            return "alert"
        if rep.get("short", "").startswith("⚠️"):
            return "warn"
        return "ok"

    def fill_results(results):
        txt_home.config(state="normal")
        txt_home.delete("1.0", "end")
        txt_home.insert("end", "检查结论：\n", "head")
        for r in results["roots"]:
            tag = short_tag(r)
            txt_home.insert("end", f"\n📍 {r['root']}\n", "path")
            if not r["exists"]:
                txt_home.insert("end", "   数据区不存在\n", "head")
                continue
            txt_home.insert("end", f"   {r['short']}\n", tag)
        txt_home.insert("end", "\n（以上每条为一句话结论；想看“传了哪些文件、多大”等全部细节，请打开“高级”标签页）\n", "head")
        txt_home.config(state="disabled")

        # ---- 高级页 ----
        txt_verdict.config(state="normal")
        for r in results["roots"]:
            txt_verdict.insert("end", f"【{r['root']}】\n{r['verdict']}\n\n", r["verdictLevel"])
        txt_verdict.config(state="disabled")

        for r in results["roots"]:
            for w in r["workspaces"]:
                st = w["state"] or {}
                pend = sum(sz for _, sz in w["pendingFiles"])
                latest = w["latest"]
                tree_summary.insert("", "end", values=(
                    w["workspacePath"] or w["workspaceKeyHash"],
                    w["status"],
                    len(w["manifests"]),
                    latest["fileCount"] if latest else "—",
                    human_size(latest["totalBytes"]) if latest else "—",
                    human_size(w["estTotalBytes"]) if w["manifests"] else "—",
                    f"{len(w['pendingFiles'])}个/{human_size(pend)}" if w["pendingFiles"] else "—",
                    f"{st.get('failureCount', 0)}/{st.get('attemptCount', 0)}",
                    fmt_ts(w["lastActivity"]),
                ))
        clear_tree(tree_ws)
        ws_index.clear()
        clear_tree(tree_logs)
        txt_logstat.config(state="normal")
        txt_set.config(state="normal")
        for r in results["roots"]:
            for w in r["workspaces"]:
                rid = tree_ws.insert("", "end", values=(
                    w["workspacePath"] or ("(哈希 " + w["workspaceKeyHash"] + ")"),
                    w["status"]))
                ws_index[rid] = w
            lg = r.get("logs")
            if lg:
                for h in lg["hits"]:
                    tree_logs.insert("", "end", values=(h["ts"] or "—", h["cat"], h["file"], h["line"]))
                cats = "、".join(f"{k}×{v}" for k, v in sorted(lg["categories"].items(), key=lambda kv: -kv[1])) or "无命中"
                txt_logstat.insert("end", f"[{r['root']}] 日志窗口 {lg['first']} ~ {lg['last']}；命中分类：{cats}\n")

            def P2(t):
                txt_set.insert("end", t)

            s = r.get("settings") or {}
            P2(f"数据根：{r['root']}\n\n")
            if s.get("exists"):
                P2("设置项（v2/setting.json）：\n")
                for it in s.get("items", []):
                    P2(f"  • {it['name']}  {it['key']} = {it['value']}" + (f"   （{it['note']}）" if it["note"] else "") + "\n")
                P2(f"  • 登录凭据文件 v2/credentials.json：{'存在（快照通道可被激活）' if s.get('credentialsFile') else '不存在'}\n")
                if s.get("endpointOrigin"):
                    P2(f"  • 服务端点 zcodeEndpointOrigin = {s['endpointOrigin']}\n")
            else:
                P2("未找到 v2/setting.json\n")
            P2("\n机制说明（逆向自客户端代码）：\n")
            P2("  • 触发：每次发 Prompt 前 + 任务结束（repo-wiki-update）\n")
            P2("  • 打包：tar.gz，包含 git ls-files 清单 + 整个 .git 目录（豁免全部过滤）+ 全局配置 extra-files + prompt.json（含 Prompt 原文）\n")
            P2("  • 过滤：排除 node_modules/缓存/构建产物/密钥类文件/大于1MB/二进制（.git 除外）\n")
            P2("  • 加密：AES-256-CTR + 服务端下发 RSA 公钥(OAEP-SHA256) 包裹密钥 → 本地无法解密\n")
            P2("  • 上传：POST 表单直传阿里云 OSS，回调通知后端；首次 baseline 全量，其后增量\n")
            P2("  • 痕迹：上传成功 → manifests/*.json 留存（密文删除）；失败/滞留 → pending/*.tar.gz.enc + state.json\n")
            P2("\n")
        txt_logstat.config(state="disabled")
        txt_set.config(state="disabled")

    def aggregate(results):
        locs, alert_roots, warn_roots = [], 0, 0
        n_manifest = n_pending = n_tmp = n_ws_total = n_sweep_arts = 0
        est_total = pend_bytes = 0
        for r in results["roots"]:
            if not r["exists"]:
                continue
            c = r["counts"]
            locs.append(str(r["root"]))
            n_ws_total += c["workspaces"]
            n_manifest += c["manifests"]
            n_pending += c["pending"]
            n_tmp += c["tmp"]
            est_total += c["estTotalBytes"]
            pend_bytes += c["pendingBytes"]
            n_sweep_arts += c.get("sweepArts", 0)
            if c["manifests"] or c["pending"] or c["tmp"]:
                alert_roots += 1
            elif c.get("sweepArts", 0) or c["credHits"]:
                warn_roots += 1
        return dict(locs=locs, alert_roots=alert_roots, warn_roots=warn_roots,
                    n_ws=n_ws_total, n_manifest=n_manifest, n_pending=n_pending,
                    n_tmp=n_tmp, est_total=est_total, pend_bytes=pend_bytes,
                    n_sweep_arts=n_sweep_arts)

    def show_summary_dialog(results):
        agg = aggregate(results)
        err = results.get("error")
        tl = tk.Toplevel(root)
        tl.title("检查结论")
        tl.geometry("680x500")
        tl.transient(root)
        ftl_big = f_def.copy(); ftl_big.configure(size=15, weight="bold")
        ftl_body = f_def.copy(); ftl_body.configure(size=12)
        txt = tk.Text(tl, font=ftl_body, wrap="word", relief="flat",
                      background="#f6f8fa", padx=18, pady=14, cursor="arrow")
        txt.pack(fill="both", expand=True, padx=12, pady=(12, 4))
        txt.tag_config("ok", foreground="#1a7f37", font=ftl_big)
        txt.tag_config("warn", foreground="#9a6700", font=ftl_big)
        txt.tag_config("alert", foreground="#cf222e", font=ftl_big)
        txt.tag_config("body", font=ftl_body)
        txt.tag_config("head", foreground="#57606a")

        def P(s, tag="body"):
            txt.insert("end", s, tag)

        if err:
            P("❌ 检查过程出错\n", "alert")
            P(err + "\n")
        elif agg["alert_roots"]:
            P("❗ 你的电脑上发现工作区数据被上传的痕迹\n\n", "alert")
            P(f"共检查 {len(agg['locs'])} 处 ZCode 数据区，其中 {agg['alert_roots']} 处存在快照上传痕迹：\n")
            P(f"  • 已被接受的快照 {agg['n_manifest']} 份（覆盖 {agg['n_ws']} 个工作区目录）\n")
            if agg["est_total"]:
                P(f"  • 按清单估算累计上传约 {human_size(agg['est_total'])}\n")
            if agg["n_pending"]:
                P(f"  • 另有 {agg['n_pending']} 个加密包滞留本地未传出（{human_size(agg['pend_bytes'])}）\n")
            P("\n每一份被上传的文件路径和大小，可在“高级 → 工作区详情 / 快照内容明细”中逐项查看。\n")
        elif agg["warn_roots"]:
            P("⚠️ 未发现确定的上传工件，但有可疑迹象\n\n", "warn")
            P(f"共检查 {len(agg['locs'])} 处 ZCode 数据区。本地没有快照密文或上传清单，")
            if agg["n_sweep_arts"]:
                P(f"但兜底扫描发现了 {agg['n_sweep_arts']} 个可疑快照工件（可能是老版本布局残留），")
            P("且日志中出现过快照/上传活动的记录。\n建议在“高级 → 日志证据 / 概要”中核对详情。\n")
        else:
            P("✅ 未发现工作区数据被上传的痕迹\n\n", "ok")
            P(f"共检查 {len(agg['locs'])} 处 ZCode 数据区：没有快照密文、没有上传清单、日志中没有上传记录。\n")
        if agg["locs"]:
            P("\n━━━━━━━━━━━━━━━━━━━━━━\n\n", "head")
            P("ZCode 在本机的数据存放位置：\n", "head")
            for i, p in enumerate(agg["locs"], 1):
                P(f"  {i}. {p}\n")
        if not err:
            P("\n提示：快照机制内置于 ZCode 客户端，登录状态下即可能被激活（UI 开关管不住）；\n", "head")
            P("建议定期用本工具复查。本工具完全离线，只读取本地文件。\n", "head")
        txt.config(state="disabled")
        if sys.platform == "darwin":
            mac_flat_button(tl, "  知道了  ", ftl_body, tl.destroy, padx=22, pady=6).pack(pady=8)
        else:
            tk.Button(tl, text="  知道了  ", font=ftl_body, bg="#2563eb", fg="white",
                      relief="flat", padx=22, pady=6, cursor="hand2",
                      command=tl.destroy).pack(pady=8)
        tl.update_idletasks()
        try:
            x = root.winfo_x() + (root.winfo_width() - tl.winfo_width()) // 2
            y = root.winfo_y() + (root.winfo_height() - tl.winfo_height()) // 2
            tl.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        except Exception:
            pass
        tl.grab_set()

    # ---- 高级页工具栏按钮 ----
    def add_root():
        d = filedialog.askdirectory(title="选择 .zcode 数据根目录")
        if d:
            results = {"roots": [scan_root(Path(d))]}
            state["results"] = state["results"] or {"roots": []}
            state["results"]["roots"].append(results["roots"][0])
            fill_results(state["results"])

    def export_report():
        if not state.get("results"):
            return
        from tkinter import messagebox
        fn = filedialog.asksaveasfilename(
            title="导出报告", defaultextension=".md",
            initialfile=f"zcode_audit_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
            filetypes=[("Markdown", "*.md"), ("所有文件", "*.*")])
        if fn:
            with open(fn, "w", encoding="utf-8") as f:
                f.write(build_markdown(state["results"]))
            messagebox.showinfo("完成", f"报告已写入\n{fn}")

    ttk.Button(adv_top, text="🔍 重新扫描", command=do_scan).pack(side="left", padx=3)
    ttk.Button(adv_top, text="➕ 添加数据区路径", command=add_root).pack(side="left", padx=3)
    ttk.Button(adv_top, text="💾 导出完整报告", command=export_report).pack(side="left", padx=3)
    ttk.Label(adv_top, text="详细证据：快照清单 = 每次成功上传的文件列表；滞留密文 = 打包后未传出的加密包").pack(side="left", padx=12)

    # 底部状态栏
    bottom = ttk.Frame(root, padding=4)
    bottom.pack(fill="x")
    ttk.Label(bottom, text="本工具完全离线 · 只读本地文件 · 不联网", foreground="#666").pack(side="right")

    ws_index = {}

    def clear_tree(t):
        for iid in t.get_children():
            t.delete(iid)

    # 初始化“设置与说明”页的静态内容
    txt_set.config(state="normal")
    txt_set.insert("end", "点击“重新扫描”后，这里显示各数据区的设置与登录状态。\n\n")
    txt_set.insert("end", "背景知识（来自对 ZCode 客户端的逆向分析）：\n")
    txt_set.insert("end", "• 快照机制：每次发 Prompt 前与任务结束时，客户端把工作区打包为 tar.gz，\n")
    txt_set.insert("end", "  用服务端下发的 RSA 公钥做 AES-256-CTR 信封加密，直传阿里云 OSS。\n")
    txt_set.insert("end", "• .git 目录被无条件完整打包（提交历史/LFS/reflog/远端地址），且不受大小与二进制过滤。\n")
    txt_set.insert("end", "• 全局配置（settings.behavior.json、mcp.json、skills 等）随每次快照一并上传（尽力脱敏）。\n")
    txt_set.insert("end", "• repoSnapshotIndexingEnabled 与 optimizeAgentExperienceEnabled 均不控制上传；\n")
    txt_set.insert("end", "  唯一门槛是登录 JWT + 服务端下发上传凭证。\n")
    txt_set.insert("end", "• 数据根定位：ZCODE_DATA_BASE_DIR 环境变量或用户主目录，加 .zcode；\n")
    txt_set.insert("end", "  快照工件位于 <数据根>/v2/checkpoints/<工作区哈希>/。\n")
    txt_set.insert("end", "• 磁盘搜索范围：本地固定盘/可移动盘扫两层；网络/映射盘做 4 秒限时探测、\n")
    txt_set.insert("end", "  可达则只扫第一层（如 Z:\\.zcode），不可达自动跳过，不会卡死。\n")
    txt_set.insert("end", "• 防版本漂移的三层检测：\n")
    txt_set.insert("end", "  1) 工件层（最可靠）：找 manifests/pending/state.json 与 *.enc/*.envelope 等文件，\n")
    txt_set.insert("end", "     兜底扫描还会在整个数据区按名字匹配 snapshot/checkpoint 目录与密文文件，\n")
    txt_set.insert("end", "     老版本 repo-snapshots 布局或未来改名都能兜住；\n")
    txt_set.insert("end", "  2) 日志层：除新版本特征串外，还匹配版本无关标志（阿里云 OSS 端点 aliyuncs/oss-cn、\n")
    txt_set.insert("end", "     x-oss- 头、snapshot×upload 泛匹配、中文“快照…上传”）；\n")
    txt_set.insert("end", "  3) 崩溃面包屑：Electron userData 的 sentry/scope_v3.json（老版本运行记录的残片）。\n")
    txt_set.config(state="disabled")

    root.after(150, poll_queue)
    root.mainloop()


def main():
    args = None
    if "--cli" in sys.argv or "--selftest" in sys.argv or "-c" in sys.argv:
        import argparse
        ap = argparse.ArgumentParser(description=APP_NAME)
        ap.add_argument("--cli", action="store_true", help="命令行模式")
        ap.add_argument("--root", help="指定 .zcode 数据根路径")
        ap.add_argument("--drives", action="store_true", help="同时搜索其他磁盘上的自定义数据根")
        ap.add_argument("--export", help="将 Markdown 报告写入文件")
        args = ap.parse_args()
        run_cli(args)
        return
    try:
        run_gui()
    except Exception as e:
        print(f"GUI 启动失败（{e}），回退到命令行模式：\n", file=sys.stderr)
        import argparse
        ap = argparse.ArgumentParser(description=APP_NAME)
        ap.add_argument("--root", help="指定 .zcode 数据根路径")
        ap.add_argument("--drives", action="store_true")
        ap.add_argument("--export", help="将 Markdown 报告写入文件")
        args = ap.parse_args()
        run_cli(args)


if __name__ == "__main__":
    main()
