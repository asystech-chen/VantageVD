/**
 * 同步读取 localStorage 中缓存的主题和模式，在 CSS 加载前立即设置 data-theme 和 data-mode，
 * 避免页面首次渲染时出现深→浅色闪烁或侧边栏闪烁。
 * 当主题为 'auto' 时，通过 matchMedia 解析为实际深色/浅色。
 */
(function () {
  function apply(t) {
    document.documentElement.setAttribute('data-theme', t);
    document.documentElement.setAttribute('data-mode', localStorage.getItem('vt_mode') || 'basic');
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
  // 异步纠正：跟随浏览器真实 UI 主题（而非仅系统配色），避免首帧色差
  try {
    if (typeof chrome !== 'undefined' && chrome.theme && chrome.theme.getCurrent) {
      chrome.theme.getCurrent().then(function (theme) {
        var stored = localStorage.getItem('vt_theme') || 'auto';
        if (stored !== 'auto') return; // 用户手动指定深浅色时不覆盖
        var c = theme && theme.colors;
        if (!c) return;
        var frame = c.frame || c.toolbar || c.tab_selected;
        var lum = null;
        if (frame) {
          if (Array.isArray(frame)) { lum = (0.2126*frame[0] + 0.7152*frame[1] + 0.0722*frame[2]) / 255; }
          else if (typeof frame === 'string' && frame.startsWith('#')) {
            var hex = frame.slice(1);
            if (hex.length >= 6) { lum = (0.2126*parseInt(hex.slice(0,2),16) + 0.7152*parseInt(hex.slice(2,4),16) + 0.0722*parseInt(hex.slice(4,6),16)) / 255; }
          }
        }
        if (lum === null) {
          var text = c.tab_background_text || c.bookmark_text;
          if (typeof text === 'string' && text.startsWith('#')) {
            var hex2 = text.slice(1);
            if (hex2.length >= 6) { lum = 1 - (0.2126*parseInt(hex2.slice(0,2),16) + 0.7152*parseInt(hex2.slice(2,4),16) + 0.0722*parseInt(hex2.slice(4,6),16)) / 255; }
          }
        }
        if (lum !== null) apply(lum < 0.35 ? 'dark' : 'light');
      }).catch(function () {});
    }
  } catch (e) {}
  // display:none 由 body-sync.js 在所有 DOM 修正完成后解除
})();
