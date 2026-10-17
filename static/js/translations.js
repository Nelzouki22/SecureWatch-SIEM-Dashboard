window.SW_I18N = window.SW_I18N || {};
function swT(key, lang) {
  return (window.SW_I18N[lang] || {})[key] || key;
}