/**
 * 同步读取 localStorage 中缓存的主题，在 CSS 加载前立即设置 data-theme。
 * 作为独立的外部脚本在 <head> 最顶部同步加载，确保零闪烁。
 * 不依赖 chrome.storage（异步），因为那会导致一帧深色残留。
 *
 * auto 语义：跟随浏览器 UI 外观（Vantage 主题）。同步阶段先用 matchMedia
 * （系统配色）快速兜底避免白屏，随后异步用 chrome.theme.getCurrent() 精确
 * 解析浏览器真实主题并纠正（theme-init.js 同款逻辑）。
 */
(function () {
  function apply(t) {
    document.documentElement.setAttribute('data-theme', t);
  }
  try {
    var t = localStorage.getItem('vt_theme') || 'auto';
    if (t === 'auto') {
      t = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }
    apply(t);
  } catch (e) {
    apply('dark');
  }
  // 异步纠正：auto 模式下跟随浏览器真实 UI 主题
  try {
    if (typeof chrome !== 'undefined' && chrome.theme && chrome.theme.getCurrent) {
      chrome.theme.getCurrent().then(function (theme) {
        if ((localStorage.getItem('vt_theme') || 'auto') !== 'auto') return;
        var c = theme && theme.colors;
        if (!c) return;
        var frame = c.frame || c.toolbar || c.tab_selected;
        var lum = null;
        if (frame) {
          if (Array.isArray(frame)) {
            lum = (0.2126 * frame[0] + 0.7152 * frame[1] + 0.0722 * frame[2]) / 255;
          } else if (typeof frame === 'string' && frame.startsWith('#')) {
            var hex = frame.slice(1);
            if (hex.length >= 6) {
              lum = (0.2126 * parseInt(hex.slice(0, 2), 16) + 0.7152 * parseInt(hex.slice(2, 4), 16) + 0.0722 * parseInt(hex.slice(4, 6), 16)) / 255;
            }
          }
        }
        if (lum === null) {
          var text = c.tab_background_text || c.bookmark_text;
          if (typeof text === 'string' && text.startsWith('#')) {
            var hex2 = text.slice(1);
            if (hex2.length >= 6) {
              lum = 1 - (0.2126 * parseInt(hex2.slice(0, 2), 16) + 0.7152 * parseInt(hex2.slice(2, 4), 16) + 0.0722 * parseInt(hex2.slice(4, 6), 16)) / 255;
            }
          }
        }
        if (lum !== null) apply(lum < 0.35 ? 'dark' : 'light');
      }).catch(function () {});
    }
  } catch (e) {}
  document.documentElement.style.display = '';
})();
