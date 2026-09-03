/**
 * Virus Detector — 域名注册信息查询客户端 (Whois Client)
 *
 * 统一的域名注册信息查询入口：RDAP 协议（RFC 9082/9083）。
 * Vantage 特供版：WhoisCX HTTP 回退已移除（2026-09-03，仅支持明文 http，违反 Add-on Policies §4）。
 *
 * @module whois-client
 *
 * 查询链路：
 *   WhoisClient.lookup(domain)
 *     → PSL 域名标准化 (UrlUtils.getMainDomain)
 *     → 缓存检查
 *     → 1st: RdapClient.lookup(domain)    // RDAP 协议（主查询）
 *     → 写入缓存 → 返回 WhoisResult
 *
 * 缓存策略：
 *   - 内存 Map 缓存，TTL = 24 小时（由 constants.js 中的 WHOIS_CACHE_TTL 配置）
 *   - 缓存按域名共享（RDAP 查询结果）
 *   - 缓存命中直接返回，不发起任何网络请求
 *   - 查询失败（网络错误、超时、HTTP 异常）不缓存，下次请求重试
 *   - RDAP 404（域名未注册）不缓存
 */

import { WHOIS_CACHE_TTL } from '../utils/constants.js';
import { RdapClient } from './rdap-client.js';
import { refreshPublicSuffixDNS } from '../utils/url-utils.js';
import { UrlUtils } from '../utils/url-utils.js';

// ==================== 内存缓存 ====================

/**
 * @typedef {Object} WhoisCacheEntry
 * @property {WhoisResult} result    - 缓存的查询结果
 * @property {number}      timestamp - 缓存时间戳
 */

/** @type {Map<string, WhoisCacheEntry>} */
const _cache = new Map();

// ==================== 错误信息记录 ====================

/** @type {WhoisErrorInfo|null} 最近一次查询失败的错误详情 */
let _lastError = null;

/**
 * 记录错误信息并输出到控制台
 * @param {string} domain     - 查询的域名
 * @param {string} phase      - 失败阶段
 * @param {string} message    - 错误描述
 * @param {Object} [extra={}] - 附加调试信息
 */
function _recordError(domain, phase, message, extra = {}) {
  _lastError = {
    domain,
    phase,
    message,
    timestamp: Date.now(),
    ...extra
  };

  const phaseLabel = {
    'bootstrap':  'RDAP 引导文件错误',
    'connect':    '网络连接失败',
    'http_status': 'HTTP 状态异常',
    'parse':      '响应解析失败',
    'timeout':    '请求超时',
    'not_found':  '域名未注册',
    'invalid':    '参数无效'
  }[phase] || phase;

  const extraSummary = Object.keys(extra).length ? JSON.stringify(extra) : '';
  console.error(`[WhoisClient] ${phaseLabel} (${domain}): ${message}${extraSummary ? ' | ' + extraSummary : ''}`);
}

// ==================== 父域名回退查询（防御加固）====================

/**
 * 当标准查询路径失败时，逐级向上回退父域名。
 * 处理多级公共后缀子域名（如 a.b.github.io）等，
 * 子域名没有独立 WHOIS 记录时回退到父域名的注册信息。
 *
 * @param {string} failedDomain - 已查询失败的标准域名
 * @returns {Promise<WhoisResult|null>}
 */
async function _lookupParentDomains(failedDomain) {
  const parts = failedDomain.split('.');
  // 至少保留两级才能视为域名（如 example.com）
  if (parts.length <= 2) return null;

  console.log(`[WhoisClient] 尝试父域名回退: ${failedDomain}`);
  for (let i = 1; i < parts.length - 1; i++) {
    const parentDomain = parts.slice(i).join('.');
    if (!parentDomain.includes('.')) continue;

    // 先查 WhoisClient 缓存
    const cached = _cache.get(parentDomain);
    if (cached && (Date.now() - cached.timestamp) < WHOIS_CACHE_TTL) {
      console.log(`[WhoisClient] 父域名缓存命中: ${parentDomain}`);
      return cached.result;
    }

    // 尝试 RDAP 查询父域名
    console.log(`[WhoisClient] 回退 RDAP 查询父域名: ${parentDomain}`);
    const rdapResult = await RdapClient.lookup(parentDomain);
    if (rdapResult && !rdapResult._rdap?.unsupported && !rdapResult._rdap?.notFound) {
      const result = {
        domain: rdapResult.domain || parentDomain,
        domainSuffix: rdapResult.domainSuffix || '',
        creationDays: rdapResult.creationDays,
        validDays: rdapResult.validDays,
        creationTime: rdapResult.creationTime || '',
        expirationTime: rdapResult.expirationTime || '',
        isExpire: rdapResult.isExpire || false,
        registrarName: rdapResult.registrarName || '',
        domainStatus: rdapResult.domainStatus || [],
        nameServer: rdapResult.nameServer || [],
        queryTime: rdapResult.queryTime || new Date().toISOString()
      };
      if (result.creationDays > 0) {
        _cache.set(parentDomain, { result, timestamp: Date.now() });
      }
      console.log(`[WhoisClient] 父域名 RDAP 查询成功: ${parentDomain} (注册 ${result.creationDays}d)`);
      return result;
    }

    // WhoisCX http 回退已移除（2026-09-03）：仅支持明文 http 不合规；父域名回退仅走 RDAP（https）
  }

  console.warn(`[WhoisClient] 父域名回退完全失败: ${failedDomain}`);
  return null;
}

// ==================== 公开接口 ====================

export class WhoisClient {
  /**
   * 查询域名的注册信息（RDAP 主查询；WhoisCX http 回退已移除）
   *
   * @param {string} domain - 要查询的域名（如 "example.com" 或 "www.baidu.com"）
   * @returns {Promise<WhoisResult|null>} 查询结果，失败时返回 null
   *   （可通过 WhoisClient.lastError 获取失败详情）
   */
  static async lookup(domain) {
    // 1. 参数校验
    if (!domain || typeof domain !== 'string') {
      _recordError(String(domain || ''), 'invalid', 'domain 参数为空或类型错误', { domain });
      return null;
    }

    // 2. PSL 域名标准化：提取可注册域名
    const rawDomain = domain.toLowerCase().trim();
    const normalizedDomain = UrlUtils.getMainDomain(rawDomain);

    if (!normalizedDomain || !normalizedDomain.includes('.')) {
      _recordError(normalizedDomain || domain, 'invalid', '域名格式无效', { domain });
      return null;
    }

    if (normalizedDomain !== rawDomain) {
      console.log(`[WhoisClient] PSL 域名提取: ${rawDomain} -> ${normalizedDomain}`);
    }

    // 异步触发 DoH PSL 查询（不阻塞当前请求，预填充缓存供后续使用）
    refreshPublicSuffixDNS(rawDomain).catch(() => {});

    // 3. 检查缓存
    const cached = _cache.get(normalizedDomain);
    if (cached && (Date.now() - cached.timestamp) < WHOIS_CACHE_TTL) {
      const ageLabel = cached.result.creationDays >= 0 ? `注册${cached.result.creationDays}天` : '注册天数未知';
      console.log(`[WhoisClient] 缓存命中: ${normalizedDomain} (${ageLabel})`);
      return cached.result;
    }

    // 4. 主查询：RDAP 协议
    console.log(`[WhoisClient] 发起 RDAP 查询: ${normalizedDomain}`);
    const rdapResult = await RdapClient.lookup(normalizedDomain);

    // 5. RDAP 成功 → 缓存并返回
    if (rdapResult && !rdapResult._rdap?.unsupported && !rdapResult._rdap?.notFound) {
      const result = {
        domain: rdapResult.domain || normalizedDomain,
        domainSuffix: rdapResult.domainSuffix || '',
        creationDays: rdapResult.creationDays,
        validDays: rdapResult.validDays,
        creationTime: rdapResult.creationTime || '',
        expirationTime: rdapResult.expirationTime || '',
        isExpire: rdapResult.isExpire || false,
        registrarName: rdapResult.registrarName || '',
        domainStatus: rdapResult.domainStatus || [],
        nameServer: rdapResult.nameServer || [],
        queryTime: rdapResult.queryTime || new Date().toISOString()
      };

      if (result.creationDays > 0) {
        _cache.set(normalizedDomain, { result, timestamp: Date.now() });
        console.log(`[WhoisClient] RDAP 缓存写入: ${normalizedDomain} (creationDays=${result.creationDays})`);
      }

      _lastError = null;
      const ageLabel = result.creationDays >= 0 ? `注册 ${result.creationDays}d` : '注册时间未知';
      const validLabel = result.validDays >= 0 ? `到期 ${result.validDays}d` : '有效期未知';
      console.log(`[WhoisClient] RDAP 查询成功: ${normalizedDomain} (${ageLabel}, ${validLabel}, 注册商: ${result.registrarName || '未知'})`);
      return result;
    }

    // 6. RDAP 无结果 → 记录原因（WhoisCX http 明文回退已于 2026-09-03 移除，注册时间按“未知”中性处理）
    if (rdapResult?._rdap?.unsupported) {
      console.log(`[WhoisClient] RDAP 不支持此 TLD (.${normalizedDomain.split('.').pop()})，注册时间未知`);
    } else if (rdapResult?._rdap?.notFound) {
      console.warn(`[WhoisClient] RDAP 未找到域名: ${normalizedDomain}`);
    } else {
      const errInfo = RdapClient.lastError;
      console.warn(`[WhoisClient] RDAP 查询失败${errInfo ? ' (' + errInfo.phase + ')' : ''}: ${normalizedDomain}`);
    }

    // 7. RDAP 无结果 → 逐级向上回退父域名（仅 RDAP，https；处理 a.b.github.io 等多级后缀场景）
    const fallbackResult = await _lookupParentDomains(normalizedDomain);
    if (fallbackResult) return fallbackResult;

    console.error(`[WhoisClient] RDAP 查询失败且父域名回退无结果: ${normalizedDomain}`);
    return null;
  }

  /**
   * 从缓存中获取查询结果（不发起网络请求）
   * @param {string} domain - 域名
   * @returns {WhoisResult|null}
   */
  static getCached(domain) {
    if (!domain) return null;
    const normalizedDomain = UrlUtils.getMainDomain(domain.toLowerCase().trim());
    const cached = _cache.get(normalizedDomain);
    if (cached && (Date.now() - cached.timestamp) < WHOIS_CACHE_TTL) {
      return cached.result;
    }
    return null;
  }

  /**
   * 获取上次查询失败的错误详情
   * @returns {WhoisErrorInfo|null}
   */
  static get lastError() {
    return _lastError;
  }

  /**
   * 清空错误信息
   */
  static clearLastError() {
    _lastError = null;
  }

  /**
   * 清除指定域名的缓存
   * @param {string} domain
   */
  static clearCache(domain) {
    if (domain) {
      _cache.delete(UrlUtils.getMainDomain(domain.toLowerCase().trim()));
    }
  }

  /**
   * 清空所有缓存
   */
  static clearAllCache() {
    _cache.clear();
  }
}

// ==================== 类型定义 ====================

/**
 * @typedef {Object} WhoisResult
 * @property {string}   domain        - 查询的域名
 * @property {string}   domainSuffix  - 域名后缀（如 com, cn）
 * @property {number}   creationDays  - 域名已注册天数（-1 表示未知）
 * @property {number}   validDays     - 域名距离到期剩余天数（-1 表示未知）
 * @property {string}   creationTime  - 域名创建时间（ISO 8601 格式）
 * @property {string}   expirationTime - 域名到期时间
 * @property {boolean}  isExpire      - 是否已过期
 * @property {string}   registrarName - 注册商名称
 * @property {string[]} domainStatus  - 域名状态列表
 * @property {string[]} nameServer    - DNS 服务器列表
 * @property {string}   queryTime     - 查询时间
 */

/**
 * @typedef {Object} WhoisErrorInfo
 * @property {string} domain    - 查询的域名
 * @property {string} phase     - 失败阶段
 * @property {string} message   - 错误描述
 * @property {number} timestamp - 错误发生时间戳
 * @property {string} [url]     - 请求的完整 URL
 * @property {number} [statusCode]     - HTTP 状态码
 * @property {string} [statusText]     - HTTP 状态文本
 * @property {string} [responseBody]   - 响应体（截取前 500 字符）
 * @property {Object} [responseJson]   - 已解析的 JSON 响应
 * @property {string} [errorName]      - 异常类型名称
 * @property {string} [errorStack]     - 异常堆栈
 * @property {number} [timeoutMs]      - 超时毫秒数
 */
