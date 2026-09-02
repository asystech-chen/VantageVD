/**
 * Virus Detector — 浏览器主题解析工具
 *
 * 目标：让扩展页面（设置页/弹窗）的「跟随系统(auto)」模式真正跟随
 * Vantage 浏览器的 UI 外观，而不是操作系统配色。
 *
 * 实现：优先读取 chrome.theme.getCurrent()（浏览器真实主题），
 * 拿不到时回退到 prefers-color-scheme（系统）。
 *
 * 注意：popup.js 是普通 script（非 module），本文件仅能被 module 页面
 * 直接 import；popup 侧通过 runtime.getURL + import() 动态加载，或
 * 复制 resolveBrowserTheme 的轻量版。见 popup.js 中 resolveBrowserThemeCompat。
 */

/**
 * 解析颜色 → 亮度 (0-1)
 * 支持 '#rgb' / '#rrggbb' / 'rgb(r,g,b)' / [r,g,b] / {r,g,b} 数组形式
 * Firefox theme.getCurrent() 的 colors 值可能是字符串或数组
 */
function colorLuminance(color) {
  try {
    let r = 0, g = 0, b = 0;
    if (Array.isArray(color)) {
      // Firefox 主题可能返回 [r, g, b] 0-255
      [r, g, b] = color.slice(0, 3);
    } else if (typeof color === 'object' && color !== null) {
      r = color.r || 0; g = color.g || 0; b = color.b || 0;
    } else if (typeof color === 'string') {
      const s = color.trim().toLowerCase();
      if (s.startsWith('#')) {
        const hex = s.slice(1);
        if (hex.length === 3) {
          r = parseInt(hex[0] + hex[0], 16);
          g = parseInt(hex[1] + hex[1], 16);
          b = parseInt(hex[2] + hex[2], 16);
        } else if (hex.length >= 6) {
          r = parseInt(hex.slice(0, 2), 16);
          g = parseInt(hex.slice(2, 4), 16);
          b = parseInt(hex.slice(4, 6), 16);
        }
      } else if (s.startsWith('rgb')) {
        const m = s.match(/[\d.]+/g);
        if (m && m.length >= 3) {
          r = parseFloat(m[0]); g = parseFloat(m[1]); b = parseFloat(m[2]);
          // rgb() 可能是 0-255 或 0-1（百分比形式）
          if (r <= 1 && g <= 1 && b <= 1 && (m.some(v => v.includes('%')) || r < 2)) {
            // 已经是 0-1 或百分比
            if (m.some(v => v.includes('%'))) { r *= 2.55; g *= 2.55; b *= 2.55; }
            else if (r <= 1 && g <= 1 && b <= 1) { r *= 255; g *= 255; b *= 255; }
          }
        }
      }
    }
    // 感知亮度（WCAG）
    return (0.2126 * r + 0.7152 * g + 0.0722 * b) / 255;
  } catch (e) {
    return 0.5;
  }
}

/**
 * 判断浏览器当前主题是深色还是浅色
 * @returns {Promise<'dark'|'light'|null>} null = 无法从浏览器主题判断（调用方应回退）
 */
export async function getBrowserThemeMode() {
  try {
    // Firefox 扩展页面可读浏览器真实主题（用户选择的 Vantage UI 主题）
    if (typeof chrome !== 'undefined' && chrome.theme && typeof chrome.theme.getCurrent === 'function') {
      const theme = await chrome.theme.getCurrent();
      if (theme && theme.colors) {
        // 优先取窗口框架色（frame），这是主题最稳定的底色
        const candidates = [
          theme.colors.frame,
          theme.colors.toolbar,
          theme.colors.tab_selected,
          theme.colors.bookmark_text,
          theme.colors.popup
        ];
        for (const c of candidates) {
          if (c) {
            const lum = colorLuminance(c);
            // 亮度明显偏向一侧才采信，灰色地带回退系统
            if (lum !== null && lum < 0.35) return 'dark';
            if (lum !== null && lum > 0.6) return 'light';
          }
        }
        // 检查文字色反推（浅色主题用深色文字）
        const text = theme.colors.tab_background_text || theme.colors.bookmark_text;
        if (text) {
          const lum = colorLuminance(text);
          if (lum !== null && lum < 0.4) return 'light';   // 深色文字 → 浅色背景
          if (lum !== null && lum > 0.7) return 'dark';    // 浅色文字 → 深色背景
        }
      }
    }
  } catch (e) {
    // API 不可用或失败 → 回退
  }
  return null;
}

/**
 * 综合解析主题：浏览器主题优先，回退系统 prefers-color-scheme
 * @returns {Promise<'dark'|'light'>}
 */
export async function resolveBrowserTheme() {
  const browserMode = await getBrowserThemeMode();
  if (browserMode) return browserMode;
  // 回退：系统配色
  try {
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  } catch (e) {
    return 'dark';
  }
}
