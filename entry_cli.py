#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""zcode-leak-check CLI 入口（Linux / 无 GUI 环境用）。

直接运行即自动开始扫描：默认扫描默认数据区 + 本机所有磁盘（含网络盘快速探测），
向标准输出打印 Markdown 报告。

可选参数：
  --root PATH     追加扫描指定的 .zcode 数据区路径
  --no-drives     不搜索其他磁盘（默认会搜）
  --export FILE   同时把 Markdown 报告写入文件
"""
import argparse

from zcode_snapshot_audit import run_cli


def main():
    ap = argparse.ArgumentParser(
        prog="zcode-leak-check",
        description="检查本机是否有工作区数据被 ZCode 快照上传过（完全离线，只读本地文件）")
    ap.add_argument("--root", metavar="PATH",
                    help="追加扫描指定的 .zcode 数据区路径")
    ap.add_argument("--no-drives", dest="drives", action="store_false",
                    help="不自动搜索其他磁盘上的数据区（默认搜索）")
    ap.add_argument("--export", metavar="FILE.md",
                    help="将 Markdown 报告写入文件")
    args = ap.parse_args()
    run_cli(args)


if __name__ == "__main__":
    main()
