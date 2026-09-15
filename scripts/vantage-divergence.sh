#!/usr/bin/env bash
# Vantage 特供版 ↔ 上游 差异一键输出
#
# 用途：合并 / 移植上游功能前刷新差异清单，替代手工扫仓库。
# 用法：bash scripts/vantage-divergence.sh [对比分支，默认 upstream/main]
#
# 对照文档：VANTAGE-DIVERGENCE.md（固化定制点清单）

set -euo pipefail

UPSTREAM="${1:-upstream/main}"
SELF="vantage-special"
BASE=$(git merge-base "$SELF" "$UPSTREAM")

echo "# Vantage 特供版 ↔ 上游差异"
echo
echo "分叉基线：$(git log --oneline -1 "$BASE")"
echo "对比上游：$(git log --oneline -1 "$UPSTREAM")"
echo "生成时间：$(date '+%Y-%m-%d %H:%M')"
echo

echo "## 我方定制提交（分叉后）"
git log --oneline "$BASE..$SELF"
echo

echo "## 文件级差异（相对分叉基线，我方侧）"
git diff --name-status "$BASE" "$SELF"
echo

echo "## 上游领先提交数"
git rev-list --count "$SELF..$UPSTREAM"
echo

echo "## 上游新增但我方没有的文件（待移植候选）"
git diff --name-status --diff-filter=A "$BASE" "$UPSTREAM" | awk '{print $2}' | while read -r f; do
  [ -f "$f" ] || echo "  $f"
done
echo

echo "## 相对当前上游的总差异统计（含上游演进）"
git diff --name-status "$UPSTREAM" "$SELF" | awk '{print $1}' | sort | uniq -c
echo
echo "> 提醒：上线前核对 VANTAGE-DIVERGENCE.md §4 固化定制点，发版必须升 manifest version。"
