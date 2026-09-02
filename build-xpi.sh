#!/usr/bin/env bash
# ============================================================
# build-xpi.sh — Vantage 安全防护 (VirusDetector 特供版) 打包脚本
#
# 用法:
#   ./build-xpi.sh              # 打包到 ~/Downloads（默认）
#   ./build-xpi.sh --lint       # 先跑 web-ext lint 再打包
#   ./build-xpi.sh --out DIR    # 输出到指定目录
#   ./build-xpi.sh --no-verify  # 跳过 zip 完整性校验
#
# 产物: ~/Downloads/vantage-security-<version>.xpi
# 命名: 从 manifest.json 自动读取 name/version
# ============================================================
set -euo pipefail

cd "$(dirname "$0")"

# ---------- 参数解析 ----------
DO_LINT=0
VERIFY=1
OUT_DIR="${HOME}/Downloads"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --lint) DO_LINT=1 ;;
    --no-verify) VERIFY=0 ;;
    --out)
      OUT_DIR="${2:?--out 需要目录参数}"
      shift ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *)
      echo "未知参数: $1 (用 --help 查看用法)" >&2
      exit 1 ;;
  esac
  shift
done

# ---------- 读取 manifest ----------
NAME=$(python3 -c "import json;print(json.load(open('manifest.json'))['name'])")
VERSION=$(python3 -c "import json;print(json.load(open('manifest.json'))['version'])")
# 产物名固定前缀（中文名安全转换不可靠），版本号自动跟随 manifest
SAFE_NAME="vantage-security"
XPI="${OUT_DIR}/${SAFE_NAME}-${VERSION}.xpi"

echo "▶ 扩展: ${NAME} v${VERSION}"

# ---------- 可选 lint ----------
if [[ $DO_LINT -eq 1 ]]; then
  echo "▶ web-ext lint ..."
  if ! npx web-ext lint --source-dir . 2>&1 | tee /tmp/vd-lint.log | grep -q "errors[[:space:]]*0"; then
    echo "❌ lint 未通过（errors > 0），中止打包" >&2
    exit 1
  fi
  echo "✅ lint 通过"
fi

# ---------- 文件清单 ----------
# 只打包运行期文件：跟踪文件 + 未跟踪的图标产物，排除开发/冗余内容
EXCLUDE='^tests/|^\.git|_backup-orb|\.svg$|^\.vscode|^package(-lock)?\.json$|^web-ext-artifacts|^node_modules|^eslint\.config|^worker|^zh_CN|\.wrangler|^build-xpi\.sh$'
mapfile -t FILES < <(
  git ls-files -co --exclude-standard | grep -vE "$EXCLUDE"
)

if [[ ${#FILES[@]} -eq 0 ]]; then
  echo "❌ 文件清单为空" >&2
  exit 1
fi

# ---------- 打包 ----------
TMP_XPI="$(mktemp -u /tmp/${SAFE_NAME}-XXXXXX.xpi)"
trap 'rm -f "$TMP_XPI"' EXIT

# mktemp -u 只生成路径不建文件；zip 要求目标不存在或为有效 zip
rm -f "$TMP_XPI"

echo "▶ 打包 ${#FILES[@]} 个文件 → ${XPI}"
# zip 需在仓库根执行（相对路径入包，manifest 在 zip 根）
printf '%s\n' "${FILES[@]}" | zip -q -X "$TMP_XPI" -@

# ---------- 完整性校验 ----------
if [[ $VERIFY -eq 1 ]]; then
  if ! unzip -t "$TMP_XPI" > /dev/null 2>&1; then
    echo "❌ zip 完整性校验失败" >&2
    exit 1
  fi
fi

# 防误覆盖确认：目标已存在时若内容相同则跳过，否则询问
if [[ -f "$XPI" ]] && ! cmp -s "$TMP_XPI" "$XPI"; then
  echo "⚠ 目标 ${XPI} 已存在且内容不同"
  read -r -p "  覆盖? [y/N] " ans
  [[ "$ans" =~ ^[Yy]$ ]] || { echo "已取消"; exit 1; }
fi

mkdir -p "$OUT_DIR"
mv "$TMP_XPI" "$XPI"
trap - EXIT

echo "✅ 完成: ${XPI}"
echo "   大小: $(du -h "$XPI" | cut -f1)  |  文件数: ${#FILES[@]}"
