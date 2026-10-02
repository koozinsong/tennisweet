/* 껍데기 로더: 이 파일과 index.html/admin.html 은 바뀌지 않는다.
 * 실제 화면(app.html)·스타일(style.css)·스크립트(app.js)는 version.json(캐시 없이 읽음)의 버전을 붙여 불러오므로
 * 새로 배포하면 캐시와 무관하게 항상 최신이 뜬다. */
window.TennisweetLoader = {
  async version() {
    try { const r = await fetch('version.json?_=' + Date.now(), { cache: 'no-store' }); if (r.ok) return (await r.json()).v; } catch {}
    return 'dev' + Math.floor(Date.now() / 60000); // 로컬 개발: 1분 단위
  },
  async boot({ page }) {
    const v = await this.version(); window.TENNISWEET_VERSION = v;
    if (!document.querySelector('link[data-font]')) { const f = document.createElement('link'); f.rel = 'stylesheet'; f.dataset.font = '1'; f.href = 'https://fonts.googleapis.com/css2?family=Barlow+Condensed:wght@600;700&display=swap'; document.head.appendChild(f); }
    const css = document.createElement('link'); css.rel = 'stylesheet'; css.href = 'style.css?v=' + v; document.head.appendChild(css);
    const html = await (await fetch('app.html?v=' + v, { cache: 'no-store' })).text();
    const doc = new DOMParser().parseFromString(html, 'text/html');
    document.getElementById('boot')?.remove(); document.getElementById('gate')?.remove();
    for (const el of [...doc.body.children]) document.body.appendChild(el);
    if (page === 'admin') document.body.dataset.page = 'admin';
    await new Promise((res) => { const s = document.createElement('script'); s.src = 'app.js?v=' + v; s.onload = res; document.body.appendChild(s); });
  },
};
