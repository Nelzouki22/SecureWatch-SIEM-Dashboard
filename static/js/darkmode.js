(function(){
  try {
    var saved = localStorage.getItem('sw_theme');
    var html = document.documentElement;
    if (saved && html.getAttribute('data-theme') !== saved) {
      html.setAttribute('data-theme', saved);
      document.body.classList.toggle('bg-dark', saved === 'dark');
      document.body.classList.toggle('text-light', saved === 'dark');
    }
    var cur = html.getAttribute('data-theme');
    if (cur) localStorage.setItem('sw_theme', cur);
  } catch(e) {}
})();