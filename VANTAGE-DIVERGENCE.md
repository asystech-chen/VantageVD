# Vantage 特供版 ↔ 上游 差异固化清单

> **用途**：合并 / 移植上游功能前对照本表，不必每次重扫仓库。
> **一键刷新**：`bash scripts/vantage-divergence.sh`（默认对比 `upstream/main`）
> **最后更新**：2026-09-16

## 0. 基线信息

| 项 | 值 |
| --- | --- |
| 我方分支 | `vantage-special`（origin: `asystech-chen/VantageVD`） |
| 上游 | `upstream` = `Lolitide/VirusDetector`（只拉不推） |
| **分叉基线** | `8e0ef4d` Merge branch 'VD-firefox' into main |
| 分叉后我方提交数 | 8（另有 3 个 fork 自有同步提交，见 §2） |
| 上游领先提交数 | 86（2026-09-16 数据，随上游增长） |

## 1. 我方定制提交（分叉后，按时间序）

| 提交 | 类型 | 内容 | 主要文件 |
| --- | --- | --- | --- |
| `ff7f7fc` | feat | **Vantage 特供版**建立：品牌改名/ID、中文 UI、图标 | manifest、_locales、zh_CN、icons、service-worker、rdap-client、navigation-guard、warning、popup、options、constants、url-utils |
| `87f59b2` | feat | 同步上游品牌库 + 新品牌图标体系 + 主题默认跟随系统 | domain-database、icons/\*、options、popup、settings-schema、theme-init |
| `1f4f852` | chore | `build-xpi.sh` 一键打包脚本 | build-xpi.sh |
| `eb6e64d` | feat | **上报功能下线** + 极简徽章 + 主题跟随浏览器外观 + UI 优化 | service-worker、manifest、popup/\*、options、theme-utils（新增）、settings-schema、warning |
| `fc0d24a` | chore | **AMO 合规**：移除 WhoisCX http 回退 / 清理上报死代码 / PRIVACY.md | PRIVACY.md、whois-client、service-worker、constants、package.json、manifest、README |
| `8f419f2` | feat | 移植上游下载意图通配检测 + **完全信任域名名单** | service-worker、constants、utils/exemptions/index.js（新增） |
| `d7e2b52` | fix | **误报大修 (v2.5.3)**：分级计分 strong/weak + 误报护栏 + 品牌自有域名补全 | domain-database、scoring-engine、constants、settings-schema、README、manifest |
| `a93aaa3` | feat | **品牌库补全 49 条** + ICP 两段式查询 + 修复异步丢中文信号 | domain-database、icp-api、service-worker、url-utils |

## 2. ⚠️ fork 自有提交（不在上游 main 历史里，勿误当上游代码）

| 提交 | 说明 |
| --- | --- |
| `aab2079` | Merge pull request #59 from Lolitide/main |
| `f5ad6dc` | 准备 Firefox AMO 上架 —— 更新 gecko.id、添加隐私策略、更新 .gitignore |
| `47e03af` | Sync VD-Firefox (#280) —— 结构调整（删 `background.js` / `similarity.js` / `messaging.js` / `VirusDetectorDevFile/`） |

> 这 3 个提交与上述 4 个删除文件：**上游 main 后来也做了同样删除**，所以不算我方独有差异，但它们是 fork 独有的历史节点。

## 3. 文件级差异（相对分叉基线 `8e0ef4d`，我方侧）

### 3.1 我方新增（20）

**定制功能**
- `background/icp-api.js`（ICP 备案 API 客户端，我方引入）
- `background/site-blacklist.js`
- `utils/exemptions/index.js`（完全信任域名名单）
- `utils/theme-utils.js`

**工程 / 构建 / 质量**
- `package.json`、`package-lock.json`、`eslint.config.mjs`
- `build-xpi.sh`
- `.github/workflows/ci.yml`
- `tests/domain-database.test.mjs`、`tests/extension-safety.test.mjs`
- `.gitignore`、`README.md`、`PRIVACY.md`

**本地化 / 视觉**
- `_locales/zh_CN/messages.json`、`zh_CN/messages.json`
- `icons/vantage-shield.svg`、`icons/vantage-shield-danger.svg`
- `icons/icon-danger-16/32/48/128.png`

### 3.2 我方修改（34，按目录）

- **根**：`manifest.json`
- **background**：`cache-manager.js`、`domain-database.js`、`icp-utils.js`、`rdap-client.js`、`resource-resolver/resource-graph.js`、`scoring-engine.js`、`service-worker.js`、`whois-client.js`
- **content**：`content-script.js`、`navigation-guard.js`
- **options**：`options.css`、`options.html`、`options.js`、`theme-init.js`
- **popup**：`popup.css`、`popup.html`、`popup.js`、`theme-init.js`
- **utils**：`constants.js`、`settings-schema.js`、`trusted-platforms.js`、`url-utils.js`
- **warning**：`warning.html`、`warning.js`、`download-confirm.html`、`download-confirm.js`
- **worker**：`report-issue.js`
- **icons**：`icon16/32/48/128.png`

### 3.3 相对**当前上游 main** 的差异（含上游演进，仅供参考）

`9 A / 20 D / 54 M` —— 其中 20 D 多为上游本轮重构所删（非我方改动）。

## 4. 🎯 固化定制点（行为级 —— 合并/移植后必须逐条确认）

1. **扩展身份**：`browser_specific_settings.gecko.id = virusdetector@asystech.cn`；`name = Vantage 安全防护`；`strict_min_version = 140.0`；`data_collection_permissions.required = ["none"]`
2. **上报功能下线**：上报 UI/逻辑已移除或占位，端点指向 `asystech.cn`（后端未部署）
3. **端点替换**：`rdap.ss` 已禁用；DoH 换阿里；WhoisCX 的 http 回退已移除（AMO 合规）
4. **内置白名单**：`VANTAGE_BUILTIN_WHITELIST = ['asystech.cn']`（后缀匹配，用户删不掉）
5. **徽章 + 主题**：极简徽章；主题默认跟随浏览器外观（`utils/theme-utils.js`、两处 `theme-init.js`）
6. **检测内核**：`domain-database.js` 中文品牌为主 + strong(60)/weak(20) 分级 + 误报护栏（命名空间归属 / 低特异性词 / 去连字符二次检测）
7. **豁免体系**：`utils/exemptions/index.js` 完全信任域名名单 + `icp-utils.js` ICP 豁免表
8. **ICP 链路**：`icp-api.js` 两段式查询（主域名优先 + 完整主机名兜底）+ 34 个省级 cn 后缀回退表
9. **异步一致性**：`service-worker.js` 异步 ICP 回填必须带回 `textSignals`
10. **工程基线**：`build-xpi.sh` 打包、eslint、`node --test` 双测试、CI workflow

## 5. 上游领先（待移植候选，2026-09-16）

上游 main 领先 86 提交，其中 20 个文件我方没有：

- **全屏拦截页**：`warning/warning-fullscreen.{html,css,js}`
- **设置页动画预览**：`options/hint-rsc/*.webp`（6 张）
- **白名单通配符**：`utils/whitelist-matcher.js`
- **豁免体系拆分**：`utils/exemptions/{fully-trusted,icp-exempt,trusted-platforms}.js`
- **常量治理**：`utils/content-constants.js`
- **兜底搜索关键词**：`utils/search-keywords.js`
- **测试**：`tests/{cache-manager,constants-sync,exemptions-consistency,injection-function,report-privacy,scoring-linkage,whitelist-wildcard}.test.mjs`

## 6. 合并 / 移植操作要点

1. 动手前：`git fetch upstream && git status -sb`（仓库预检，最高优先级）
2. 刷新本清单：`bash scripts/vantage-divergence.sh`
3. 逐条对照 §4 固化定制点，确认移植后未被覆盖
4. 移植后：`node --test tests/domain-database.test.mjs tests/extension-safety.test.mjs` + `npx eslint --max-warnings=0 .`
5. 发版：**必须升 manifest version**（AMO 同版本不能重签；policies `install_url` 也靠版本号变化触发更新）
6. 上线：签名 XPI → 覆盖 `asys/vantage/vd.xpi` → commit → push（详见官网记忆）

## 7. 半分离规划（2026-09-16 桶哥拍板）

**目标**：收窄与上游的定制接触面，把上游同步从「逐文件手工合并」降为「数据/配置层零冲突 + 逻辑层按清单核对」。

**原则**：不硬分家 —— 上游的检测规则 / 品牌数据 / 误报修复是插件生命线，`upstream` 必须保持可拉可取。

### 7.1 三层划分

| 层 | 内容 | 目标形态 | 上游同步影响 |
| --- | --- | --- | --- |
| 数据层 | 品牌库 `background/domain-database.js` | 上游文件不动；我方增量独立成 `background/domain-database.vantage.js`，运行时合并 | 零冲突 |
| 配置层 | 内置白名单 / 端点 / 常量开关 | 集中到 `utils/vantage-config.js`；上游 `constants.js` 只保留引用 | 零冲突（或单点） |
| 逻辑层 | 分级计分、误报护栏、异步一致性、UI/主题 | 保留在原文件；靠 §4 固化清单核对 | 手工合并 + 清单验收 |

### 7.2 数据层落地方案

- 新建 `background/domain-database.vantage.js`：导出我方增量条目 + 需要覆盖的字段
- `domain-database.js` 内**只保留一处**定制：构建索引前合并增量（一行 import + 一次 merge 调用）
- 迁移内容：`a93aaa3` 新增的 49 条、`d7e2b52` 的品牌自有域名补全、`cc362f4` 的 `qianwen.com`
- 验收：扩展 `tests/domain-database.test.mjs` 覆盖增量条目；上游更新品牌库后该文件 `git merge` 应无冲突

### 7.3 配置层落地方案

- 新建 `utils/vantage-config.js`：`VANTAGE_BUILTIN_WHITELIST`、端点覆盖（RDAP / DoH / 上报）、功能开关
- 上游 `constants.js` 保持上游原样，仅保留一处指向 `vantage-config.js` 的引用
- 验收：`git merge upstream/main` 时 `utils/constants.js` 无冲突

### 7.4 实施时机与顺序

1. **不专门重构** —— 下次移植上游时（B 类：全屏拦截页 / 白名单通配符 / 测试）顺带执行
2. 顺序：**配置层（最简单） → 数据层 → 逻辑层清单化**
3. 每步独立提交，保证可回退

### 7.5 验收指标

- 上游同步的冲突文件数持续下降（目标：数据层 / 配置层 0 冲突）
- `bash scripts/vantage-divergence.sh` 输出中「我方修改文件数」下降
- `node --test tests/domain-database.test.mjs tests/extension-safety.test.mjs` 全绿 + `npx eslint --max-warnings=0 .`

### 7.6 风险与待定

- 数据层「运行时合并」需明确：同名条目覆盖策略、`officialDomains` 重复处理、索引构建顺序
- 可选路线：把通用改进（品牌库补全 / 误报修复）**反哺上游提 PR**，上游合并后我方自动受益，长期维护成本更低 —— 是否走此路线待桶哥决定
