/* 테니스윗 분기 대회 일정표 — 순수 JS SPA (빌드 없음)
 * 흐름: ① 선수 → ② 대회 설정(팀전/개인전) → ③ 팀 구성 → ④ 일정 생성·경기 기록 → ⑤ 순위·대진
 * 저장: localStorage (storage 계층 분리, 추후 공유 DB 교체 가능) / 공유: URL 링크 스냅샷(읽기 전용)
 */
(() => {
  'use strict';
  const GROUP_NAMES = 'ABCDEFGHIJKLMNOP'.split('');
  const DEFAULT_SETTINGS = {
    name: '', date: '', mode: 'rotation', discipline: 'doubles', teamCount: 2,
    format: 'groups', groupCount: 2, advance: 2, thirdPlace: true,
    courts: 2, startTime: '09:00', endTime: '', matchMinutes: 30, breakMinutes: 0, minWomenDoubles: 1, maxGames: 6,
    venue: { name: '', time: '', addr: '', phone: '', menu: '', note: '' }, // 회식 장소 (별도 메뉴로 표시)
    fmMenEqual: true, mustFace: '', sameNtrpGame: '', avoidPairs: '', // 특별 규칙(개인전): 혼복 남자 NTRP 동일 / 혼복 필수 대진(이름 2개) / 동일 NTRP 남복 1경기 / 같은 조 금지(이름 쌍 목록)
  };
  const emptyState = () => ({ players: [], settings: { ...DEFAULT_SETTINGS }, units: [], schedule: null, results: {}, editMode: false });

  // ================= 저장 계층 =================
  const storage = {
    key: 'tennisweet.v2',
    load() { try { const raw = localStorage.getItem(this.key); return raw ? JSON.parse(raw) : null; } catch { return null; } },
    save(s) { try { s.savedAt = new Date().toISOString(); localStorage.setItem(this.key, JSON.stringify(s)); } catch {} },
  };
  // ================= 관리자 인증 + NTRP 암호화 (AES-GCM, PBKDF2) =================
  const ADMIN_SALT = 'tennisweet-v1';
  const ADMIN_HASH = 'd662b5254226a2bc02011aa385a0e4c734fe29f7ad067728c76b149ca396fd9e'; // PBKDF2-SHA256(비밀번호, salt 'tennisweet-v1-verify', 120000회) — 느린 검증값 (오프라인 추측 비용 증가)
  const PW_KEY = 'tennisweet.pw';
  let adminKey = null; const ntrp = new Map(); // playerId -> NTRP 평문 (메모리에만)
  const b64 = (u8) => { let r = ''; for (let i = 0; i < u8.length; i += 0x8000) r += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000)); return btoa(r); }; // 큰 배열도 안전 (spread 인자 한도 회피)
  const unb64 = (str) => Uint8Array.from(atob(str), (c) => c.charCodeAt(0));
  async function sha256hex(str) { const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str)); return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join(''); }
  /** 비밀번호 검증값: PBKDF2 120k 회 (admin.html 과 동일 계산) */
  async function verifierHex(pw) {
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: new TextEncoder().encode(ADMIN_SALT + '-verify'), iterations: 120000, hash: 'SHA-256' }, base, 256);
    return [...new Uint8Array(bits)].map((b) => b.toString(16).padStart(2, '0')).join('');
  }
  async function deriveKey(pw) {
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: new TextEncoder().encode(ADMIN_SALT), iterations: 120000, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  async function encStr(str) { const iv = crypto.getRandomValues(new Uint8Array(12)); const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, adminKey, new TextEncoder().encode(str)); return b64(iv) + '.' + b64(new Uint8Array(ct)); }
  async function decStr(packed) { const [iv, ct] = packed.split('.'); return new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(iv) }, adminKey, unb64(ct))); }
  async function unlockAdmin(pw) {
    if (!pw || (await verifierHex(pw)) !== ADMIN_HASH) return false;
    adminKey = await deriveKey(pw); await decryptAll(); return true;
  }
  async function decryptAll() { ntrp.clear(); if (!adminKey) return; for (const p of state.players) if (p.ntrpEnc) { try { ntrp.set(p.id, await decStr(p.ntrpEnc)); } catch {} } }
  async function setNtrp(p, value) { const v = String(value ?? '').trim(); if (!v) { ntrp.delete(p.id); delete p.ntrpEnc; return; } ntrp.set(p.id, v); p.ntrpEnc = await encStr(v); }
  const ntrpOf = (id) => parseFloat(ntrp.get(id)) || 0;

  let state = emptyState();
  let viewOnly = false; // 공유 링크로 열린 읽기 전용 모드
  let sharedAt = null;

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
  const uid = () => Math.random().toString(36).slice(2, 9);
  const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  // 생성용 난수: 매 생성마다 새 시드(mulberry32). 시드는 schedule.seed 에 저장되어 같은 판을 구분·재현할 수 있다
  let rng = Math.random;
  function seedRng(seed) { let a = seed >>> 0; rng = () => { a = (a + 0x6D2B79F5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
  const newSeed = () => ((Date.now() ^ Math.floor(Math.random() * 0xffffffff)) >>> 0) % 1000000;
  const shuffle = (a) => { for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(rng() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; } return a; };
  function save() { if (!viewOnly) storage.save(state); }
  function commit() { save(); render(); }

  // ================= 공유 링크 (URL 스냅샷) =================
  async function compress(str) {
    const bytes = new TextEncoder().encode(str);
    if (!('CompressionStream' in window)) return 'p' + b64(bytes);
    const cs = new CompressionStream('deflate-raw');
    const buf = await new Response(new Blob([bytes]).stream().pipeThrough(cs)).arrayBuffer();
    return 'z' + b64(new Uint8Array(buf));
  }
  async function decompress(str) {
    const mode = str[0]; const bytes = Uint8Array.from(atob(str.slice(1)), (c) => c.charCodeAt(0));
    if (mode === 'p') return new TextDecoder().decode(bytes);
    const ds = new DecompressionStream('deflate-raw');
    return await new Response(new Blob([bytes]).stream().pipeThrough(ds)).text();
  }
  function typeViolations() { return (state.schedule?.matches || []).filter((m) => m.aPlayers && matchType(m)?.mismatch); }
  function assertTypesOk() { const v = typeViolations(); if (!v.length) return true; alert(`경기 종류가 일치하지 않는 경기가 ${v.length}건 있습니다 (⚠ 종류 불일치). 먼저 수정해 주세요.`); return false; }
  async function makeShareLink() {
    if (!assertTypesOk()) return;
    const snap = { ...state, editMode: false, meFilter: undefined, savedAt: undefined, basePublishedAt: undefined, ghTokenEnc: undefined, sharedAt: new Date().toISOString() };
    const enc = await compress(JSON.stringify(snap));
    const url = `${location.origin}${location.pathname}#s=${encodeURIComponent(enc)}`;
    try { await navigator.clipboard.writeText(url); alert(`공유 링크가 복사되었습니다 (${Math.round(url.length / 1024)}KB).\n카톡 등으로 전달하면 누구나 일정·결과를 읽기 전용으로 볼 수 있습니다.\n결과가 바뀌면 다시 공유하세요.`); }
    catch { prompt('아래 링크를 복사하세요', url); }
  }
  async function tryLoadShared() {
    const m = location.hash.match(/^#s=(.+)$/); if (!m) return false;
    try {
      const data = JSON.parse(await decompress(decodeURIComponent(m[1])));
      state = normalize(data); viewOnly = true; sharedAt = data.sharedAt;
      return true;
    } catch (e) { alert('공유 링크를 읽을 수 없습니다: ' + e.message); return false; }
  }

  // ================= 커버 (첫 화면) =================
  function showCover(on) {
    const cv = $('#cover'); if (!cv) return;
    cv.hidden = !on; document.body.classList.toggle('cover-on', on);
    if (on) { updateCover(); window.scrollTo(0, 0); }
  }
  /** 첫 화면 메뉴: 진행 중인 대회가 있으면 큰 버튼이 '경기 일정표', 아니면 '대회'(지난 대회) */
  function updateCover() {
    const live = liveTournament(); const s = state.settings;
    $('#cover-name').textContent = live ? (s.name || '테니스윗 대회') : '테니스윗';
    $('#cover-meta').textContent = live ? [s.date, `${state.schedule.matches.filter((m) => !m.bye).length}경기`, modeLabel()].filter(Boolean).join(' · ') : (T.index?.events?.length ? `지난 대회 ${T.index.events.length}회` : '');
    const tb = $('#cover-tour'); if (tb) { tb.dataset.go = live ? 'schedule' : 'tournament'; $('#cover-tour-text').textContent = live ? '경기 일정표' : '대회'; tb.querySelector('use')?.setAttribute('href', live ? '#i-court' : '#i-trophy'); }
    wkUpdateCover();
  }
  /** 진행 중인 대회 = 일정표가 있고 아직 같은 날짜로 보관되지 않은 대회 */
  const liveTournament = () => !!(state.schedule || (document.body.classList.contains('editor') && state.settings.name)) && !(T.index?.events || []).some((e) => e.date && e.date === state.settings.date);
  $('#cover')?.addEventListener('click', (e) => {
    const b = e.target.closest('button[data-go]'); if (!b) return;
    if (b.dataset.go === 'admin') { adminLogin(); return; }
    showCover(false); showTab(b.dataset.go); history.replaceState(null, '', '#' + b.dataset.go);
  });
  $('#btn-home')?.addEventListener('click', () => { showCover(true); history.replaceState(null, '', location.pathname); });
  $('#btn-refresh')?.addEventListener('click', () => { const b = $('#btn-refresh'); b.disabled = true; b.classList.add('spin'); location.reload(); }); // 홈 화면 앱(standalone)에는 브라우저 새로고침이 없으므로

  // ================= 탭 =================
  $$('.tabs button').forEach((b) => b.addEventListener('click', () => showTab(b.dataset.tab)));
  const TAB_GROUP = { schedule: 'tournament', standings: 'tournament', units: 'tournament', setup: 'tournament', venue: 'tournament' }; // 방문자 화면에서 숨긴 탭은 '대회' 탭 소속으로 표시
  function showTab(name) {
    $$('.tabs button').forEach((b) => { const on = b.dataset.tab === name || TAB_GROUP[name] === b.dataset.tab; b.classList.toggle('active', on); b.setAttribute('aria-current', on ? 'page' : 'false'); });
    $$('.tab').forEach((t) => t.classList.toggle('active', t.id === 'tab-' + name));
    render();
    if (name === 'weekly') weeklyRefresh(); if (name === 'tournament') tournamentRefresh();
  }

  // ================= ① 선수 =================
  const playerById = (id) => state.players.find((p) => p.id === id);
  const pname = (id) => playerById(id)?.name ?? '?';
  function addPlayer(p) { const name = (p.name || '').trim(); if (!name) return null; const np = { id: uid(), name, gender: p.gender || '', from: p.from || '', until: p.until || '', tag: (p.tag || '').trim(), note: (p.note || '').trim(), active: true }; state.players.push(np); return np; }
  const parseGender = (g) => (/^(M|남)/i.test(g || '') ? 'M' : /^(F|여)/i.test(g || '') ? 'F' : '');
  $('#form-player').addEventListener('submit', async (e) => {
    e.preventDefault(); const f = e.target;
    const np = addPlayer({ name: f.name.value, gender: f.gender.value, from: f.from.value, until: f.until.value, note: f.note.value });
    if (np && adminKey && f.ntrp.value) await setNtrp(np, f.ntrp.value);
    f.reset(); f.name.focus(); commit();
  });
  $('#form-bulk').addEventListener('submit', async (e) => {
    e.preventDefault();
    for (const l of e.target.bulk.value.split('\n').map((l) => l.trim()).filter(Boolean)) {
      const cols = l.split(/[,\t]/).map((x) => (x || '').trim());
      const name = cols[0]; const gender = parseGender(cols[1]);
      const rest = cols.slice(2); const ntrpV = rest.find((x) => /^\d(\.\d)?$/.test(x)); const from = rest.find((x) => /^\d{1,2}:\d{2}$/.test(x));
      const note = rest.filter((x) => x !== ntrpV && x !== from).join(' ');
      const np = addPlayer({ name, gender, from: from ? from.padStart(5, '0') : '', note });
      if (np && adminKey && ntrpV) await setNtrp(np, ntrpV);
    }
    e.target.reset(); commit();
  });
  $('#tbl-players').addEventListener('click', (e) => {
    const del = e.target.closest('button[data-del]');
    if (del) { const p = playerById(del.dataset.del); if (confirm(`${p.name} 선수를 삭제할까요?`)) { state.players = state.players.filter((x) => x.id !== p.id); state.units.forEach((u) => (u.playerIds = u.playerIds.filter((id) => id !== p.id))); commit(); } }
  });
  $('#tbl-players').addEventListener('change', (e) => {
    const el = e.target; const p = playerById(el.dataset.pid); if (!p) return;
    if (el.dataset.field === 'ntrp') { setNtrp(p, el.value).then(() => { save(); render(); }); return; }
    if (el.type === 'checkbox') p.active = el.checked; else p[el.dataset.field] = el.value.trim();
    save(); if (el.type === 'checkbox') render();
  });
  $('#tbl-players').addEventListener('blur', (e) => { if (e.target.dataset?.field) render(); }, true);
  $('#btn-players-all').addEventListener('click', () => { state.players.forEach((p) => (p.active = true)); commit(); });
  $('#btn-players-none').addEventListener('click', () => { state.players.forEach((p) => (p.active = false)); commit(); });
  function renderPlayers() {
    const act = state.players.filter((p) => p.active).length;
    $('#tab-players').classList.toggle('no-tour', !liveTournament()); // 대회 전용 열(참가·합류·퇴장·묶음)은 진행 중인 대회가 있을 때만
    $('#players-title').textContent = viewOnly || !liveTournament() ? `선수 명단 (${state.players.length}명)` : `선수 명단 (${state.players.length}명 · 대회 참가 ${act}명)`;
    if (viewOnly) { // 방문자: 이름·성별만 (대회 참가·합류·퇴장은 관리자 화면에서만)
      const ps = [...state.players].sort((a, b) => a.name.localeCompare(b.name, 'ko'));
      $('#tbl-players tbody').innerHTML = ps.map((p, i) => `<tr><td>${i + 1}</td><td class="only-editor"></td><td><b>${esc(p.name)}</b></td><td>${p.gender === 'M' ? '남' : p.gender === 'F' ? '여' : ''}</td><td class="only-editor"></td><td class="only-editor"></td><td class="only-editor"></td><td class="only-editor"></td><td class="only-editor"></td><td></td></tr>`).join('');
      return;
    }
    $('#tbl-players tbody').innerHTML = state.players.map((p, i) => `<tr class="${p.active ? '' : 'inactive'}">
      <td>${i + 1}</td><td class="tour-col"><input type="checkbox" data-pid="${esc(p.id)}" aria-label="${esc(p.name)} 참가" ${p.active ? 'checked' : ''}></td>
      <td><input class="cell" data-pid="${esc(p.id)}" data-field="name" value="${esc(p.name)}"></td>
      <td><select class="cell" data-pid="${esc(p.id)}" data-field="gender"><option value="">-</option><option value="M" ${p.gender === 'M' ? 'selected' : ''}>남</option><option value="F" ${p.gender === 'F' ? 'selected' : ''}>여</option></select></td>
      <td class="only-editor">${adminKey ? `<input class="cell" type="number" step="0.5" min="1" max="7" data-pid="${esc(p.id)}" data-field="ntrp" value="${esc(ntrp.get(p.id) || '')}">` : '<span class="tbd">🔒</span>'}</td>
      <td class="tour-col"><input class="cell" type="time" data-pid="${esc(p.id)}" data-field="from" value="${esc(p.from || '')}"></td>
      <td class="tour-col"><input class="cell" type="time" data-pid="${esc(p.id)}" data-field="until" value="${esc(p.until || '')}"></td>
      <td class="only-editor tour-col"><input class="cell" data-pid="${esc(p.id)}" data-field="tag" value="${esc(p.tag || '')}" placeholder="예: A" style="max-width:70px"></td>
      <td><input class="cell" data-pid="${esc(p.id)}" data-field="note" value="${esc(p.note)}"></td>
      <td><button class="small" data-del="${esc(p.id)}">삭제</button></td></tr>`).join('');
  }

  // ================= ② 대회 설정 =================
  const formSettings = $('#form-settings');
  function hydrateSettings() {
    const s = state.settings;
    for (const el of formSettings.elements) {
      if (!el.name) continue;
      if (el.type === 'radio') el.checked = el.value === String(s[el.name]);
      else if (el.type === 'checkbox') el.checked = !!s[el.name];
      else el.value = s[el.name] ?? '';
    }
    updateSettingsVisibility();
  }
  function readSettings() {
    const fd = new FormData(formSettings); const s = { ...state.settings };
    for (const [k, v] of fd.entries()) s[k] = v;
    s.thirdPlace = fd.get('thirdPlace') === 'on'; s.fmMenEqual = fd.get('fmMenEqual') === 'on';
    s.mustFace = String(s.mustFace || '').trim().slice(0, 60); s.avoidPairs = String(s.avoidPairs || '').trim().slice(0, 300); { const v = parseFloat(String(s.sameNtrpGame || '').replace(/[^\d.]/g, '')); s.sameNtrpGame = Number.isFinite(v) ? String(v) : ''; }
    for (const k of ['maxGames', 'minWomenDoubles', 'teamCount', 'groupCount', 'advance', 'courts', 'matchMinutes', 'breakMinutes']) s[k] = Math.max(0, parseInt(s[k], 10) || 0);
    s.courts = Math.max(1, s.courts); s.teamCount = Math.max(2, s.teamCount || 2); s.maxGames = Math.max(1, s.maxGames || 6); s.groupCount = Math.max(1, s.groupCount); s.advance = Math.max(1, s.advance); s.matchMinutes = Math.max(5, s.matchMinutes);
    return s;
  }
  function updateSettingsVisibility() {
    const fd = new FormData(formSettings); const mode = fd.get('mode'), format = fd.get('format');
    const rot = mode === 'rotation' || mode === 'team'; // 팀전·로테이션은 시간대 기반 복식 배정 (조/토너먼트 없음)
    $('#lbl-disc').style.display = rot ? 'none' : '';
    $('#lbl-teamcount').style.display = mode === 'team' ? '' : 'none';
    $('#fs-special').style.display = mode === 'rotation' ? '' : 'none';
    $('#fs-format').style.display = rot ? 'none' : '';
    $('#lbl-groups').style.display = !rot && format === 'groups' ? '' : 'none';
    $('#lbl-advance').style.display = !rot && format === 'groups' ? '' : 'none';
    $('#lbl-third').style.display = rot || format === 'rr' ? 'none' : '';
  }
  formSettings.addEventListener('change', updateSettingsVisibility);
  formSettings.addEventListener('submit', (e) => {
    e.preventDefault(); if (viewOnly) return; const ns = readSettings();
    const kindChanged = ns.mode !== state.settings.mode || ns.discipline !== state.settings.discipline;
    state.settings = ns;
    if (kindChanged) state.units = [];
    save(); showTab('units');
  });

  // ================= ③ 팀 구성 =================
  const activePlayers = () => state.players.filter((p) => p.active);
  const isRot = () => state.settings.mode === 'rotation';
  const unitKind = () => state.settings.mode === 'team' ? 'team' : (state.settings.discipline === 'doubles' && !isRot()) ? 'pair' : 'single';
  /** 로테이션: 참가 선수 1명 = 참가 단위 1개 (id 는 'p:'+playerId 로 고정해 재생성에도 안정) */
  function ensureRotationUnits() { state.units = activePlayers().map((p) => ({ id: 'p:' + p.id, name: '', playerIds: [p.id] })); }
  const unitLabel = () => ({ team: '팀', pair: '복식조', single: '선수' }[unitKind()]);
  const unitById = (id) => state.units.find((u) => u.id === id);
  function unitName(u) { return u.name || (u.playerIds.length ? u.playerIds.map(pname).join('·') : '(이름 없음)'); }
  function assignedIds() { return new Set(state.units.flatMap((u) => u.playerIds)); }
  function autoBuild(teamCount) {
    const kind = unitKind(); const ps = shuffle(activePlayers().map((p) => p.id));
    if (kind === 'single') state.units = ps.map((id) => ({ id: uid(), name: '', playerIds: [id] }));
    else if (kind === 'pair') { state.units = []; for (let i = 0; i + 1 < ps.length; i += 2) state.units.push({ id: uid(), name: '', playerIds: [ps[i], ps[i + 1]] }); if (ps.length % 2) state.units.push({ id: uid(), name: '', playerIds: [ps[ps.length - 1]] }); }
    else {
      // 합류 시각 → 급수 → 성별 순으로 정렬 후 지그재그(snake) 배정: 각 팀에 이른 합류자·급수가 고르게
      // 합류 구간(같은 from)별로 짝(2명: 강+약) 단위 배정 → 각 팀이 그 시간대에 복식 2명을 갖춰 코트를 최대한 사용.
      // 첫 구간은 무조건 짝 단위, 이후 구간은 팀 규모 차이가 1을 넘으면 짝을 갈라 작은 팀부터 채움. 팀 선택: 총원 적은 팀 → 구간 인원 적은 팀 → 평균 NTRP 낮은 팀
      const n = Math.max(2, teamCount || 2);
      state.units = Array.from({ length: n }, (_, i) => ({ id: uid(), name: `${i + 1}팀`, playerIds: [] }));
      const sum = Array(n).fill(0), cnt = Array(n).fill(0), fem = Array(n).fill(0);
      const avg = (i) => (cnt[i] ? sum[i] / cnt[i] : 0);
      const put = (t, p) => { state.units[t].playerIds.push(p.id); sum[t] += ntrpOf(p.id); cnt[t]++; if (p.gender === 'F') fem[t]++; };
      const blocks = {}; ps.map(playerById).forEach((p) => (blocks[p.from || ''] ??= []).push(p));
      const blockKeys = Object.keys(blocks).sort((a, b) => (toMin(a) ?? 0) - (toMin(b) ?? 0));
      const tagTeam = {}; // 묶음 태그 -> 배정된 팀
      const teamFor = (people, fallback) => { const tg = people.map((p) => p.tag).find((t) => t && tagTeam[t] != null); return tg ? tagTeam[tg] : fallback; };
      const mark = (t, people) => people.forEach((p) => { if (p.tag) tagTeam[p.tag] = t; });
      blockKeys.forEach((bk, bi) => {
        const list = shuffle(blocks[bk]).sort((a, b) => ntrpOf(b.id) - ntrpOf(a.id));
        const inBlock = Array(n).fill(0);
        let hasF = false;
        const order = () => [...Array(n).keys()].sort((x, y) => (hasF ? fem[x] - fem[y] : 0) || cnt[x] - cnt[y] || inBlock[x] - inBlock[y] || avg(x) - avg(y) || rng() - 0.5);
        // 같은팀 묶음: 같은 구간의 묶음 멤버끼리 먼저 짝 → 나머지는 강+약 짝
        const pairs = [];
        for (const tg of [...new Set(list.map((p) => p.tag).filter(Boolean))]) {
          const mem = list.filter((p) => p.tag === tg);
          while (mem.length >= 2) { const a = mem.shift(), b = mem.shift(); pairs.push([a, b]); list.splice(list.indexOf(a), 1); list.splice(list.indexOf(b), 1); }
        }
        // 여성은 남성과 짝지어(혼합 짝) 팀에 배정 → 여성 수가 팀마다 고르게 나뉘어 여복·혼복 편성이 가능
        const women = list.filter((p) => p.gender === 'F'), men = list.filter((p) => p.gender !== 'F');
        while (women.length && men.length) pairs.push([men.shift(), women.pop()]);
        const rest = [...men, ...women].sort((a, b) => ntrpOf(b.id) - ntrpOf(a.id));
        while (rest.length >= 2) pairs.push([rest.shift(), rest.pop()]); const single = rest[0];
        for (const [hi, lo] of pairs) {
          hasF = hi.gender === 'F' || lo.gender === 'F';
          const forced = teamFor([hi, lo], null);
          const t = forced ?? order()[0];
          const wouldMax = cnt[t] + 2, minOther = Math.min(...cnt.filter((_, i) => i !== t));
          if (forced != null || bi === 0 || wouldMax - minOther <= 1) { put(t, hi); put(t, lo); inBlock[t] += 2; mark(t, [hi, lo]); }
          else { // 짝을 가를 때는 여성부터 여성 수 적은 팀에, 남성은 그다음 팀에
            const [w, m] = hi.gender === 'F' ? [hi, lo] : [lo, hi];
            hasF = w.gender === 'F'; const t1 = order()[0]; put(t1, w); inBlock[t1]++; mark(t1, [w]);
            hasF = false; const t2 = order().find((x) => x !== t1) ?? t1; put(t2, m); inBlock[t2]++; mark(t2, [m]); }
        }
        if (single) { hasF = single.gender === 'F'; const t = teamFor([single], order()[0]); put(t, single); inBlock[t]++; mark(t, [single]); }
      });
    }
  }
  function renderUnits() {
    const kind = unitKind(); const lbl = unitLabel(); const view = $('#units-view');
    if (isRot()) {
      const ps = activePlayers();
      $('#units-title').textContent = '팀 구성';
      $('#units-hint').textContent = '';
      $('#units-tools').innerHTML = '';
      view.innerHTML = `<p class="hint">개인전은 팀 구성이 없습니다. 선수 탭의 참가 선수 ${ps.length}명이 매 경기 파트너·상대를 바꿔 가며 개인 순위로 경쟁합니다.</p>`;
      $('#gen-hint').textContent = ps.length < 4 ? '개인전은 4명 이상 필요합니다.' : `${ps.length}명, 코트 ${state.settings.courts}면, ${state.settings.startTime}~${state.settings.endTime || '제한 없음'} 로 라운드를 생성합니다.`;
      return;
    }
    $('#units-title').textContent = { team: '팀 구성', pair: '복식조 구성', single: '참가 선수 확정' }[kind] + ` (${lbl} ${state.units.length})`;
    $('#units-hint').textContent = {
      team: '참가 선수를 팀에 배정합니다. "균등 배정"은 합류 시각·NTRP·성별이 팀마다 고르게 섞이도록 나눕니다 (NTRP 는 관리자 로그인 시에만 반영). 이후 드롭다운으로 팀원을 옮길 수 있습니다.',
      pair: '참가 선수를 2명씩 복식조로 묶습니다. 랜덤으로 만든 뒤 개별 수정할 수 있습니다.',
      single: '참가 체크된 선수 전원이 참가 단위입니다. 필요하면 개별 제외할 수 있습니다.',
    }[kind];
    const tools = $('#units-tools');
    if (viewOnly) tools.innerHTML = '';
    else if (kind === 'team') tools.innerHTML = `<label class="inline">팀 수 <input id="inp-teamcount" type="number" min="2" value="${state.settings.teamCount || 2}" style="width:70px"></label>
      <button id="btn-auto" class="primary">균등 배정 (합류 시각·NTRP 고려)</button><button id="btn-add-unit">팀 추가</button>`;
    else if (kind === 'pair') tools.innerHTML = `<button id="btn-auto" class="primary">랜덤 복식조 구성</button><button id="btn-add-unit">복식조 추가</button>`;
    else tools.innerHTML = `<button id="btn-auto" class="primary">참가 선수 전원으로 구성</button>`;
    $('#inp-teamcount')?.addEventListener('change', (e) => { state.settings.teamCount = Math.max(2, +e.target.value || 2); save(); });
    $('#btn-auto')?.addEventListener('click', () => { if (state.units.length && !confirm('현재 구성을 지우고 다시 만들까요?')) return; if (kind === 'team') state.settings.teamCount = Math.max(2, +($('#inp-teamcount')?.value || 2)); autoBuild(state.settings.teamCount); commit(); });
    $('#btn-add-unit')?.addEventListener('click', () => { state.units.push({ id: uid(), name: kind === 'team' ? `${state.units.length + 1}팀` : '', playerIds: [] }); commit(); });

    const assigned = assignedIds(); const free = activePlayers().filter((p) => !assigned.has(p.id));
    const opt = (sel) => `<option value="">+ 선수 추가</option>${free.map((p) => `<option value="${esc(p.id)}">${esc(p.name)}${adminKey && ntrp.get(p.id) ? ` (${esc(ntrp.get(p.id))})` : ''}</option>`).join('')}`;
    const pchip = (u, pid) => { const p = playerById(pid); return `<span class="chip">${esc(p?.name ?? '?')}${adminKey && ntrp.get(p.id) ? `<small> ${esc(ntrp.get(p.id))}</small>` : ''}${p?.from ? `<small> ${esc(p.from)}~</small>` : ''}${viewOnly ? '' : `<button class="x" data-rm="${esc(u.id)}:${esc(pid)}" title="빼기" aria-label="${esc(p?.name ?? '')} 빼기">×</button>`}</span>`; };
    const dis = viewOnly ? 'disabled' : '';
    view.innerHTML = `<div class="cards">${state.units.map((u, i) => `<div class="card">
        <div class="card-head">${kind === 'team' ? `<input class="unit-name" data-uid="${esc(u.id)}" value="${esc(u.name)}" placeholder="팀명" ${dis}>` : `<b>${i + 1}. ${esc(unitName(u))}</b>`}
          ${viewOnly ? '' : `<button class="small" data-del-unit="${esc(u.id)}">삭제</button>`}</div>
        <div class="chips">${u.playerIds.map((pid) => pchip(u, pid)).join('') || '<span class="tbd">선수 없음</span>'}</div>
        ${!viewOnly && (kind === 'team' || u.playerIds.length < (kind === 'pair' ? 2 : 1)) && free.length ? `<select class="add-player" data-uid="${esc(u.id)}">${opt()}</select>` : ''}
      </div>`).join('')}</div>
      ${free.length ? `<h3>미배정 참가 선수 (${free.length})</h3><div class="chips">${free.map((p) => `<span class="chip muted">${esc(p.name)}</span>`).join('')}</div>` : ''}`;
    const n = state.units.filter((u) => u.playerIds.length).length;
    const bad = kind === 'pair' ? state.units.filter((u) => u.playerIds.length !== 2).length : kind === 'team' ? state.units.filter((u) => !u.playerIds.length).length : 0;
    $('#gen-hint').textContent = n < 2 ? `${lbl} 2개 이상이 필요합니다.` : bad ? `구성이 완전하지 않은 ${lbl}이 ${bad}개 있습니다 (그대로 진행 가능).` : `${lbl} ${n}개로 일정표를 생성합니다.`;
  }
  $('#units-view').addEventListener('click', (e) => {
    const rm = e.target.closest('button[data-rm]'); const del = e.target.closest('button[data-del-unit]');
    if (rm) { const [uidv, pid] = rm.dataset.rm.split(':'); const u = unitById(uidv); u.playerIds = u.playerIds.filter((x) => x !== pid); commit(); }
    if (del) { state.units = state.units.filter((u) => u.id !== del.dataset.delUnit); commit(); }
  });
  $('#units-view').addEventListener('change', (e) => {
    const el = e.target;
    if (el.classList.contains('add-player') && el.value) { unitById(el.dataset.uid).playerIds.push(el.value); commit(); }
    if (el.classList.contains('unit-name')) { unitById(el.dataset.uid).name = el.value.trim(); save(); }
  });
  $('#btn-generate').addEventListener('click', () => {
    if (state.schedule && Object.keys(state.results).length && !confirm('입력된 결과와 현장 수정 내용이 모두 지워집니다. 일정표를 다시 생성할까요?')) return;
    try { if (isRot()) ensureRotationUnits(); state.schedule = isRot() ? generateRotation(state.settings) : state.settings.mode === 'team' ? generateTeam(state.settings, state.units.filter((u) => u.playerIds.length)) : generate(state.settings, state.units.filter((u) => u.playerIds.length)); state.results = {}; }
    catch (err) { alert(err.message); return; }
    save(); showTab('schedule');
  });

  /** 선수 변경 후 원클릭: 팀(또는 복식조) 재배정 + 일정 재생성 */
  function regenerateAll(mode) {
    const label = { rotation: '개인전', team: '팀전' }[mode] || '';
    const seedIn = $$('.inp-seed').map((el) => el.value.trim()).find((v) => v !== ''); // 생성 번호 지정 시 재현
    const seed = seedIn !== undefined && /^\d{1,6}$/.test(seedIn) ? +seedIn : newSeed();
    if (state.schedule && Object.keys(state.results).length && !confirm(`입력된 결과와 현장 수정 내용이 모두 지워집니다. ${label} 일정을 다시 생성할까요?`)) return;
    if (mode && mode !== state.settings.mode) { state.settings.mode = mode; state.units = []; }
    if (mode === 'team' && !state.settings.endTime) { alert('팀전은 종료 시각이 필요합니다 (대회 설정).'); return; }
    try {
      seedRng(seed);
      if (state.settings.mode === 'team') autoBuild(state.settings.teamCount || 2);
      else if (isRot()) ensureRotationUnits();
      else if (!state.units.length) autoBuild();
      state.schedule = isRot() ? generateRotation(state.settings, seed) : state.settings.mode === 'team' ? generateTeam(state.settings, state.units.filter((u) => u.playerIds.length), seed) : generate(state.settings, state.units.filter((u) => u.playerIds.length));
      state.results = {};
    } catch (err) { alert(err.message); return; }
    if (state.schedule?.notes?.length) alert('일정은 생성했지만 아래 특별 규칙은 지금 인원으로는 성립하지 않아 제외했습니다:\n- ' + state.schedule.notes.join('\n- '));
    $$('.inp-seed').forEach((el) => (el.value = '')); // 다음 생성은 다시 무작위
    save(); showTab('schedule');
  }
  $$('.btn-regen').forEach((b) => b.addEventListener('click', () => {
    const all = $$('.btn-regen'); const labels = all.map((x) => x.innerHTML); all.forEach((x) => { x.disabled = true; x.textContent = '생성 중…'; });
    setTimeout(() => { try { regenerateAll(b.dataset.mode); } finally { all.forEach((x, i) => { x.disabled = false; x.innerHTML = labels[i]; }); } }, 30);
  }));
  $$('.inp-minff').forEach((el) => el.addEventListener('change', () => { state.settings.minWomenDoubles = Math.max(0, parseInt(el.value, 10) || 0); save(); render(); }));

  // ================= 일정 생성 =================
  function roundRobin(ids) {
    const arr = [...ids]; if (arr.length % 2) arr.push(null);
    const n = arr.length, rounds = [];
    for (let r = 0; r < n - 1; r++) {
      const pairs = [];
      for (let i = 0; i < n / 2; i++) { const a = arr[i], b = arr[n - 1 - i]; if (a && b) pairs.push(r % 2 ? [b, a] : [a, b]); }
      rounds.push(pairs); arr.splice(1, 0, arr.pop());
    }
    return rounds;
  }
  function seedOrder(size) { let arr = [1]; while (arr.length < size) { const m = arr.length * 2; const next = []; for (const s of arr) next.push(s, m + 1 - s); arr = next; } return arr; }
  function nextPow2(n) { let p = 1; while (p < n) p *= 2; return p; }
  function roundName(size) { return size === 2 ? '결승' : size === 4 ? '준결승' : `${size}강`; }

  const gOf = (id) => (playerById(id)?.gender === 'F' ? 'F' : 'M');
  const pairType = (a, b) => [gOf(a), gOf(b)].sort().join(''); // 'FF' 여복 / 'FM' 혼복 / 'MM' 남복
  const TYPE_LABEL = { FF: '여복', FM: '혼복', MM: '남복' };
  const sidePl = (m, side) => (m[side + 'Players'] ? m[side + 'Players'] : sideIds(m, side).flatMap((id) => unitById(id)?.playerIds || [])).filter(Boolean); // 한쪽 조의 선수 id
  /** 특별 규칙 이름 목록 파싱: "김지선, 고서영" / "김지선-고서영" / "김지선 고서영" */
  const parseNames = (str) => { const t = String(str || ''); const a = t.split(/[,/·]+/).map((x) => x.trim()).filter(Boolean); return a.length >= 2 ? a : t.split(/[\s\-]+/).map((x) => x.trim()).filter(Boolean); };
  const menDiffer = (a, b) => !!a && !!b && a !== b; // NTRP 미입력(0) 은 어느 쪽과도 짝이 됨
  /** 같은 조 금지 목록: "김지선-이석우, 박상용/송국진" → [[id, id], …] (참가 선수에 없는 이름은 무시) */
  function avoidPairIds(str, ps = activePlayers()) {
    const out = []; for (const item of String(str || '').split(/[,;\n]+/)) { const names = item.split(/[\s\-/·]+/).map((x) => x.trim()).filter(Boolean); if (names.length !== 2) continue; const P = names.map((nm) => ps.find((p) => p.name === nm)); if (P[0] && P[1] && P[0] !== P[1]) out.push([P[0].id, P[1].id]); }
    return out;
  }
  /** 금지 조합이 파트너로 묶인 경기면 그 쌍 이름, 아니면 '' */
  function avoidedPartner(m, pairs = avoidPairIds(state.settings.avoidPairs)) {
    if (!pairs.length) return ''; for (const side of ['a', 'b']) { const ids = sidePl(m, side); if (ids.length !== 2) continue; for (const [x, y] of pairs) if (ids.includes(x) && ids.includes(y)) return `${playerById(x)?.name}·${playerById(y)?.name}`; }
    return '';
  }
  /** 정기 모임 혼복 원칙: 여자 급과 무관하게 양쪽 남자 급을 맞춘다 (위반이면 true). 미입력(0)은 와일드카드 */
  const fmMixBad = (w1, m1, w2, m2) => menDiffer(m1, m2);
  /** 혼복인데 양쪽 남자 NTRP 가 다르면 true (규칙 fmMenEqual, NTRP 를 모르면 항상 false) */
  function fmMenBad(m) {
    if (state.settings.fmMenEqual === false) return false; const A = sidePl(m, 'a'), B = sidePl(m, 'b'); if (A.length !== 2 || B.length !== 2) return false;
    const men = [...A, ...B].filter((id) => gOf(id) !== 'F'); return men.length === 2 && menDiffer(ntrpOf(men[0]), ntrpOf(men[1]));
  }
  /** 특별 규칙 충족 여부 (관리자 화면 표시용) */
  function specialStatus(ms) {
    const s = state.settings, out = []; const notes = state.schedule?.notes || [];
    for (const nt of notes) out.push(`⚠ ${esc(nt)}`);
    const names = parseNames(s.mustFace);
    if (names.length === 2 && !notes.some((nt) => nt.startsWith('혼복 필수 대진'))) { const P = names.map((nm) => activePlayers().find((p) => p.name === nm)?.id); const ok = P.every(Boolean) && ms.some((m) => { const A = sidePl(m, 'a'), B = sidePl(m, 'b'); if (A.length !== 2 || B.length !== 2) return false; const fm = [...A, ...B].filter((id) => gOf(id) === 'F').length === 2 && A.filter((id) => gOf(id) === 'F').length === 1; return fm && ((A.includes(P[0]) && B.includes(P[1])) || (A.includes(P[1]) && B.includes(P[0]))); }); out.push(`${ok ? '✓' : '✗'} 혼복 ${esc(names.join(' vs '))} 대진`); }
    const v = parseFloat(s.sameNtrpGame);
    if (Number.isFinite(v) && !notes.some((nt) => nt.startsWith(`NTRP ${v} 남복`))) {
      const relaxed = notes.some((nt) => nt.startsWith(`NTRP ${v} 남자가`)); // 상위 4명으로 완화된 경우
      const ok = ms.some((m) => { const ids = [...sidePl(m, 'a'), ...sidePl(m, 'b')]; if (ids.length !== 4 || !ids.every((id) => gOf(id) !== 'F' && ntrpOf(id))) return false; if (!relaxed) return ids.every((id) => ntrpOf(id) === v); const others = activePlayers().filter((p) => p.gender !== 'F' && ntrpOf(p.id) && !ids.includes(p.id)); const low = Math.min(...ids.map(ntrpOf)); return ids.every((id) => ntrpOf(id) <= v) && others.every((p) => ntrpOf(p.id) <= low); });
      out.push(`${ok ? '✓' : '✗'} NTRP ${v}${relaxed ? ' 상위 4명' : ''} 남복`);
    }
    if (s.fmMenEqual !== false) { const bad = ms.filter(fmMenBad).length; out.push(bad ? `✗ 혼복 남자 NTRP 불일치 ${bad}경기` : '✓ 혼복 남자 NTRP 일치'); }
    const fw = {}; for (const m of ms) { const wa = sidePl(m, 'a').filter((id) => gOf(id) === 'F'), wb = sidePl(m, 'b').filter((id) => gOf(id) === 'F'); if (wa.length === 1 && wb.length === 1) { const k = [wa[0], wb[0]].sort().join('|'); fw[k] = (fw[k] || 0) + 1; } }
    const dup = Object.entries(fw).filter(([, v]) => v > 1).map(([k, v]) => k.split('|').map((id) => playerById(id)?.name || '?').join(' vs ') + ` ${v}회`);
    if (Object.keys(fw).length) out.push(dup.length ? `✗ 혼복 여성 상대 중복: ${esc(dup.join(', '))}` : '✓ 혼복 여성 상대 중복 없음');
    const ap = avoidPairIds(s.avoidPairs); if (ap.length) { const bad = ms.map((m) => avoidedPartner(m, ap)).filter(Boolean); out.push(bad.length ? `✗ 금지 조합 편성: ${esc(bad.join(', '))}` : `✓ 금지 조합 없음 (${ap.map(([x, y]) => esc(playerById(x)?.name + '·' + playerById(y)?.name)).join(', ')})`); }
    return out;
  }
  /** 경기 종류 (양쪽 조가 모두 정해졌을 때). mismatch=true 면 규칙 위반 */
  function matchType(m) {
    const a = m.aPlayers, b = m.bPlayers; if (!a || !b || a.some((x) => !x) || b.some((x) => !x)) return null;
    const ta = pairType(a[0], a[1]), tb = pairType(b[0], b[1]);
    return { label: ta === tb ? TYPE_LABEL[ta] : `${TYPE_LABEL[ta]} vs ${TYPE_LABEL[tb]}`, mismatch: ta !== tb, code: ta === tb ? ta.toLowerCase() : '' };
  }
  const toMin = (t) => { if (!t) return null; const [h, m] = t.split(':').map(Number); return h * 60 + m; };
  const slotStartMin = (s, i) => toMin(s.startTime || '09:00') + i * (s.matchMinutes + s.breakMinutes);
  function maxSlots(s) { const end = toMin(s.endTime); if (end == null) return Infinity; const start = toMin(s.startTime || '09:00'); return Math.max(0, Math.floor((end - start + s.breakMinutes) / (s.matchMinutes + s.breakMinutes))); }
  /** 시간대별 코트 수: settings.courtsByHour = { "18": 2, "20": 3 } 이면 그 시각(정시)의 값, 없으면 courts (정기 모임 전용, 대회는 courts 고정) */
  const courtsAtSlot = (s, slot) => { const cb = s.courtsByHour; if (cb && typeof cb === 'object') { const h = String(Math.floor(slotStartMin(s, slot) / 60)); const v = cb[h]; if (Number.isInteger(v) && v >= 0) return v; } return s.courts; };
  function playerAvailable(p, s, slot) {
    const t0 = slotStartMin(s, slot), t1 = t0 + s.matchMinutes;
    const from = toMin(p.from), until = toMin(p.until);
    return (from == null || from <= t0) && (until == null || until >= t1);
  }
  /** 팀전: 시간대마다 코트별로 팀 대 팀 복식 1경기. 대전 횟수 적은 팀끼리, 경기 수 적은 선수부터, 파트너 중복 최소 */
  function generateTeam(s, teams, seed = newSeed()) {
    seedRng(seed);
    if (teams.length < 2) throw new Error('팀이 2개 이상 필요합니다.');
    const n = maxSlots(s); if (!isFinite(n)) throw new Error('팀전은 종료 시각이 필요합니다 (대회 설정).');
    if (n < 1) throw new Error('시작~종료 사이에 경기 시간이 없습니다.');
    const played = {}, lastPlayed = {}, partner = {}, opp = {}, meet = {}, fmCnt = {}, mmCnt = {}, playedSlots = {};
    const key = (a, b) => (a < b ? a + '|' + b : b + '|' + a);
    teams.forEach((t) => t.playerIds.forEach((id) => { played[id] = 0; lastPlayed[id] = -1; fmCnt[id] = 0; mmCnt[id] = 0; playedSlots[id] = new Set(); }));
    let ffDone = 0; const minFF = s.minWomenDoubles || 0;
    const matches = [];
    for (let slot = 0; slot < n; slot++) {
      const usedP = new Set(); const usedT = {};
      const availOf = (t) => t.playerIds.filter((id) => !usedP.has(id) && playerById(id) && playerAvailable(playerById(id), s, slot));
      for (let c = 1; c <= s.courts; c++) {
        // 각 팀의 후보 조(경기 수 적은 선수 우선, 파트너 중복 벌점) → 남복/여복/혼복 종류가 같은 조합만 허용
        const restedLast = (id) => slot > 0 && lastPlayed[id] < slot - 1 && playerAvailable(playerById(id), s, slot - 1); // 직전 시간대 휴식 → 최우선
        const twoInRow = (id) => slot >= 2 && playedSlots[id].has(slot - 1) && playedSlots[id].has(slot - 2); // 3연속 방지
        const candPairs = (t) => {
          const cand = availOf(t).sort((a, b) => (restedLast(b) ? 1 : 0) - (restedLast(a) ? 1 : 0) || played[a] - played[b] || (twoInRow(a) ? 1 : 0) - (twoInRow(b) ? 1 : 0) || lastPlayed[a] - lastPlayed[b] || rng() - 0.5).slice(0, 8);
          const out = [];
          for (let i = 0; i < cand.length; i++) for (let j = i + 1; j < cand.length; j++)
          {
            const tp = pairType(cand[i], cand[j]);
            // 남복·혼복 골고루: 이 종류를 이미 많이 한 남성이면 벌점, 적게 했으면 가점
            const mix = [cand[i], cand[j]].filter((id) => gOf(id) === 'M').reduce((c, id) => c + (tp === 'FM' ? fmCnt[id] - mmCnt[id] : tp === 'MM' ? mmCnt[id] - fmCnt[id] : 0), 0) * 4;
            out.push({ p: [cand[i], cand[j]], type: tp, cost: (played[cand[i]] + played[cand[j]]) * 5 + (partner[key(cand[i], cand[j])] || 0) * 40 + mix + (twoInRow(cand[i]) ? 10 : 0) + (twoInRow(cand[j]) ? 10 : 0) - (restedLast(cand[i]) ? 40 : 0) - (restedLast(cand[j]) ? 40 : 0) });
          }
          return out;
        };
        let best = null, bestCost = Infinity;
        for (let i = 0; i < teams.length; i++) for (let j = i + 1; j < teams.length; j++) {
          const A = teams[i], B = teams[j];
          const pa = candPairs(A), pb = candPairs(B); if (!pa.length || !pb.length) continue;
          const teamCost = ((meet[key(A.id, B.id)] || 0) * 10 + (usedT[A.id] || 0) * 4 + (usedT[B.id] || 0) * 4) * 10;
          for (const x of pa) for (const y of pb) {
            if (x.type !== y.type) continue;
            const balCost = Math.abs(ntrpOf(x.p[0]) + ntrpOf(x.p[1]) - ntrpOf(y.p[0]) - ntrpOf(y.p[1])) * 25; // NTRP 균형(기본)
            let oppCost = 0; for (const u of x.p) for (const v of y.p) oppCost += 30 * (opp[key(u, v)] || 0); // 같은 상대 반복 회피
            const cost = teamCost + x.cost + y.cost + balCost + oppCost + rng() - (x.type === 'FF' && ffDone < minFF ? 500 : 0); // 여복 부족하면 여복 우선
            if (cost < bestCost) { bestCost = cost; best = [A, B, x.p, y.p]; }
          }
        }
        if (!best) break;
        const [A, B, pa, pb] = best;
        matches.push({ id: uid(), phase: 'rr', group: 0, round: slot, slot, court: c, aId: A.id, bId: B.id, aPlayers: pa, bPlayers: pb });
        meet[key(A.id, B.id)] = (meet[key(A.id, B.id)] || 0) + 1; usedT[A.id] = (usedT[A.id] || 0) + 1; usedT[B.id] = (usedT[B.id] || 0) + 1;
        [pa, pb].forEach(([x, y]) => { partner[key(x, y)] = (partner[key(x, y)] || 0) + 1; });
        for (const u of pa) for (const v of pb) opp[key(u, v)] = (opp[key(u, v)] || 0) + 1;
        const tpm = pairType(pa[0], pa[1]); if (tpm === 'FF') ffDone++;
        [...pa, ...pb].forEach((id) => { usedP.add(id); played[id]++; lastPlayed[id] = slot; playedSlots[id].add(slot); if (tpm === 'FM') fmCnt[id]++; else if (tpm === 'MM') mmCnt[id]++; });
      }
    }
    if (!matches.length) throw new Error('배정 가능한 경기가 없습니다. 각 팀에 같은 시각 참석 가능 선수가 2명 이상이고, 남복·여복·혼복 중 맞출 수 있는 조합이 있는지 확인하세요.');
    return { groups: [teams.map((t) => t.id)], advance: 0, matches, qualifiers: 0, extraSlots: 0, unitIds: teams.map((t) => t.id), seed };
  }
  /** 복식 로테이션: 슬롯마다 가용 선수 중 경기 수 적은 순으로 코트×4 명 선발, 파트너·상대 중복 최소 조합 */
  /** 여러 번 생성해 [상대·파트너 중복 → 연속 휴식 → 경기 수 편차 → NTRP 불균형] 이 가장 적은 판을 고른다 */
  function generateRotation(s, seed = newSeed()) {
    let best = null, bestScore = Infinity, lastErr = null; const pool = [];
    for (let k = 0; k < 60; k++) {
      const sd = (seed + k * 7919) % 1000000;
      try {
        const sch = generateRotationOnce(s, sd);
        const sc = scheduleScore(sch);
        if (GEN_HOOK) pool.push({ sch, sc });
        if (sc < bestScore) { bestScore = sc; best = sch; }
        if (sc === 0) break;
      } catch (e) { lastErr = e; }
    }
    if (!best) throw lastErr || new Error('배정 가능한 경기가 없습니다.');
    if (GEN_HOOK) { // 정기 모임: 상위 12개 판을 각각 교체 탐색으로 보정(시간대별 탐욕 선발이 놓친 판 — 예: 연속 휴식 1회 대신 전원 같은 경기 수)한 뒤 가장 좋은 판
      pool.sort((a, b) => a.sc - b.sc);
      for (const c of pool.slice(0, 12)) { repairSchedule(c.sch, s); c.sc = scheduleScore(c.sch); }
      pool.sort((a, b) => a.sc - b.sc); best = pool[0].sch;
    }
    best.seed = seed; // 재현용: 이 번호로 다시 생성하면 같은 판
    return best;
  }
  /** 생성 뒤 보정(정기 모임): 각 시간대에서 쉬는 사람 ↔ 같은 성별의 뛰는 사람을 바꿔 보고 전체 점수(scheduleScore: 경기 수·규칙·중복·휴식)가 좋아지면 채택. 이미 시작한 시간대(fromSlot 이전)는 손대지 않는다 */
  function repairSchedule(sch, s) {
    const ps = activePlayers(); const n = maxSlots(s); if (!isFinite(n)) return;
    const from = GEN_HOOK ? GEN_HOOK.fromSlot | 0 : 0;
    let base = scheduleScore(sch), improved = true, guard = 0;
    const gender = (id) => gOf(id.slice(2));
    const slotOf = (m) => m.slot; const seatsOf = (slot) => { const out = []; for (const m of sch.matches) if (m.slot === slot) for (const side of ['aIds', 'bIds']) for (let i = 0; i < 2; i++) out.push({ m, side, i }); return out; };
    const restingAt = (slot) => { const playing = new Set(sch.matches.filter((m) => m.slot === slot).flatMap((m) => [...m.aIds, ...m.bIds])); return ps.filter((p) => playerAvailable(p, s, slot) && !playing.has('p:' + p.id)).map((p) => 'p:' + p.id); };
    const tryTwo = () => { // 2단계 교체: lo(경기 적음)가 쉬는 시간대 A 에서 X 대신 들어가고, X 는 hi(경기 많음)가 뛰는 시간대 B 에 hi 대신 들어간다
      const games = {}; for (const m of sch.matches) for (const x of [...m.aIds, ...m.bIds]) games[x] = (games[x] || 0) + 1;
      const all = ps.map((p) => 'p:' + p.id); const g = (id) => games[id] || 0; const maxG = Math.max(...all.map(g));
      const los = all.filter((id) => g(id) <= maxG - 2), his = all.filter((id) => g(id) === maxG); if (!los.length) return false;
      for (const lo of los) for (let A = from; A < n; A++) { if (!restingAt(A).includes(lo)) continue;
        for (const sa of seatsOf(A)) { const X = sa.m[sa.side][sa.i]; if (gender(X) !== gender(lo)) continue;
          for (let B = from; B < n; B++) { if (B === A || !restingAt(B).includes(X)) continue;
            for (const sb of seatsOf(B)) { const hi = sb.m[sb.side][sb.i]; if (!his.includes(hi) || gender(hi) !== gender(X)) continue;
              sa.m[sa.side][sa.i] = lo; sb.m[sb.side][sb.i] = X; const sc = scheduleScore(sch);
              if (sc < base - 1e-9) { base = sc; return true; }
              sa.m[sa.side][sa.i] = X; sb.m[sb.side][sb.i] = hi;
            } } } }
      return false;
    };
    while (improved && guard++ < 30) {
      improved = false;
      if (tryTwo()) { improved = true; continue; }
      for (let slot = from; slot < n && !improved; slot++) {
        const ms = sch.matches.filter((m) => m.slot === slot); if (!ms.length) continue;
        const playing = new Set(ms.flatMap((m) => [...m.aIds, ...m.bIds]));
        const resting = ps.filter((p) => playerAvailable(p, s, slot) && !playing.has('p:' + p.id));
        for (const r of resting) {
          const rid = 'p:' + r.id;
          for (const m of ms) {
            for (const side of ['aIds', 'bIds']) for (let i = 0; i < 2; i++) {
              const q = m[side][i]; if (gOf(q.slice(2)) !== (r.gender === 'F' ? 'F' : 'M')) continue; // 성별이 같아야 종류 유지
              m[side][i] = rid; const sc = scheduleScore(sch);
              if (sc < base - 1e-9) { base = sc; improved = true; break; }
              m[side][i] = q;
            }
            if (improved) break;
          }
          if (improved) break;
        }
      }
    }
  }
  function scheduleScore(sch) {
    const k2 = (a, b) => (a < b ? a + '|' + b : b + '|' + a); const pc = {}, oc = {}, games = {};
    const ids = (side) => side.map((x) => (x.startsWith('p:') ? x.slice(2) : x));
    for (const m of sch.matches) {
      const A = ids(m.aIds || [m.aId]), B = ids(m.bIds || [m.bId]);
      if (A.length === 2) pc[k2(A[0], A[1])] = (pc[k2(A[0], A[1])] || 0) + 1; if (B.length === 2) pc[k2(B[0], B[1])] = (pc[k2(B[0], B[1])] || 0) + 1;
      for (const x of A) for (const y of B) oc[k2(x, y)] = (oc[k2(x, y)] || 0) + 1;
      for (const x of [...A, ...B]) games[x] = (games[x] || 0) + 1;
    }
    const rep = (o) => Object.values(o).reduce((a, v) => a + Math.max(0, v - 1), 0);
    const rep3 = Object.values(oc).filter((v) => v >= 3).length; // 같은 상대 3회 이상은 별도 가중 (2회는 여성 구성상 불가피할 수 있음)
    const fmW = {}; for (const m of sch.matches) { const A = ids(m.aIds || [m.aId]), B = ids(m.bIds || [m.bId]); const wa = A.filter((x) => gOf(x) === 'F'), wb = B.filter((x) => gOf(x) === 'F'); if (wa.length === 1 && wb.length === 1) fmW[k2(wa[0], wb[0])] = (fmW[k2(wa[0], wb[0])] || 0) + 1; }
    const fmWomenRep = rep(fmW); // 혼복에서 같은 여성 상대와 다시 붙은 횟수 (골고루 원칙)
    const apairs = avoidPairIds(state.settings.avoidPairs); const avoided = apairs.length ? sch.matches.filter((m) => avoidedPartner(m, apairs)).length : 0; // 같은 조 금지 위반
    const st = state.settings, nSl = maxSlots(st); let cap = 0; if (isFinite(nSl)) for (let sl = 0; sl < nSl; sl++) cap += Math.min(courtsAtSlot(st, sl), Math.floor(activePlayers().filter((p) => playerAvailable(p, st, sl)).length / 4)); // 코트 수 상한 (시도 간 상수) → 경기 수가 적은 판은 크게 불리
    const missing = Math.max(0, cap - sch.matches.length);
    const ffCnt = sch.matches.filter((m) => [...ids(m.aIds || [m.aId]), ...ids(m.bIds || [m.bId])].every((x) => gOf(x) === 'F')).length; const ffShort = Math.max(0, (st.minWomenDoubles || 0) - ffCnt); // 여복 최소 미달
    let spread, loss = 0; if (GEN_HOOK) { // 정기 모임: 전원 경기 수를 같게 (일찍 와서 더 뛴 사람은 공유 시간대에서 양보). 참석 시간대를 다 뛴 사람은 상한이라 제외
      const ps = activePlayers(); const g = (p) => games[p.id] || 0;
      const AVs = {}; ps.forEach((p) => { let av = 0; if (isFinite(nSl)) for (let sl = 0; sl < nSl; sl++) if (playerAvailable(p, st, sl)) av++; AVs[p.id] = av; });
      const maxG = ps.length ? Math.max(...ps.map(g)) : 0;
      const open = ps.filter((p) => g(p) < AVs[p.id]); // 더 뛸 수 있었던 사람
      const minG = open.length ? Math.min(...open.map(g)) : maxG;
      spread = maxG - minG; // 목표: 차이 1 이내
      loss = open.reduce((a, p) => a + Math.max(0, maxG - 1 - g(p)), 0); // 최다보다 2경기 이상 적은 사람 = 손해 (게스트 포함)
      let below = 0; for (const p of ps) { const need = Math.min(AVs[p.id], 2); if (g(p) < need) below += need - g(p); } spread += below * 20; // 최소 경기 수(2, 시간대가 1개면 1) 미달은 크게 불리
    } else { const g = Object.values(games); spread = g.length ? Math.max(...g) - Math.min(...g) : 0; }
    // 3연속 출전 횟수
    const bySlot = {}; for (const m of sch.matches) for (const x of [...ids(m.aIds || [m.aId]), ...ids(m.bIds || [m.bId])]) (bySlot[x] ??= new Set()).add(m.slot);
    let dblRest = 0; if (GEN_HOOK && isFinite(nSl)) for (const p of activePlayers()) { const set = bySlot[p.id] || new Set(); for (let sl = 1; sl < nSl; sl++) if (playerAvailable(p, st, sl - 1) && playerAvailable(p, st, sl) && !set.has(sl - 1) && !set.has(sl)) dblRest++; } // 정기 모임 하드 규칙: 참석 중인데 2시간대 연속 휴식
    let triple = 0, quad = 0; for (const set of Object.values(bySlot)) for (const sl of set) { if (set.has(sl + 1) && set.has(sl + 2)) triple++; if (set.has(sl + 1) && set.has(sl + 2) && set.has(sl + 3)) quad++; }
    let ntrpDiff = 0; for (const m of sch.matches) { const A = ids(m.aIds || [m.aId]), B = ids(m.bIds || [m.bId]); ntrpDiff += Math.abs(A.reduce((a, x) => a + ntrpOf(x), 0) - B.reduce((a, x) => a + ntrpOf(x), 0)); }
    const menBad = GEN_HOOK ? sch.matches.filter((m) => { const A = ids(m.aIds || [m.aId]), B = ids(m.bIds || [m.bId]); const wA = A.filter((x) => gOf(x) === 'F'), wB = B.filter((x) => gOf(x) === 'F'); if (wA.length !== 1 || wB.length !== 1 || A.length !== 2 || B.length !== 2) return false; const mA = A.find((x) => gOf(x) !== 'F'), mB = B.find((x) => gOf(x) !== 'F'); return fmMixBad(ntrpOf(wA[0]), ntrpOf(mA), ntrpOf(wB[0]), ntrpOf(mB)); }).length : state.settings.fmMenEqual === false ? 0 : sch.matches.filter(fmMenBad).length; // 대회: 특별 규칙 위반은 사실상 배제. 정기 모임: 혼복 원칙 위반 ×3000 ('경기 없음' 1e4 보다 가볍게)
    let mixBad = 0, mixSoft = 0; for (const m of sch.matches) { const A = ids(m.aIds || [m.aId]), B = ids(m.bIds || [m.bId]); const wa = A.filter((x) => gOf(x) === 'F').length, wb = B.filter((x) => gOf(x) === 'F').length; if (wa + wb !== 1) continue; const sumA = A.reduce((a, x) => a + ntrpOf(x), 0), sumB = B.reduce((a, x) => a + ntrpOf(x), 0); const short = (wa ? sumB : sumA) - (wa ? sumA : sumB); if (short >= 1.5) mixBad += 1; else if (short > 0) mixSoft += 60 + 80 * short; const side = wa ? A : B, other = wa ? B : A; const mate = side.find((x) => gOf(x) !== 'F'); if (mate && other.some((x) => ntrpOf(x) > ntrpOf(mate))) mixSoft += 150; } // 잡복 원칙: 여자 쪽(여자 −0.5 반영) 합 ≥ 남자 둘 합
    const spreadW = GEN_HOOK ? 150 : 60; // 정기 모임은 경기 수 균등을 중복 회피·NTRP 균형보다 앞에 둔다 (게임 수에서 손해 보는 사람이 없도록)
    return (GEN_HOOK ? menBad * 300 : menBad * 1e5) + mixBad * 2e4 + mixSoft + dblRest * 300 + avoided * 1e5 + missing * 1e4 + ffShort * 2000 + loss * 400 + fmWomenRep * 500 + rep3 * 150 + rep(oc) * 100 + rep(pc) * 100 + spread * spreadW + ntrpDiff * 60 + quad * 15 + triple * 8; // 혼복 여성 상대 중복 > 3회 이상 상대 > 중복 회피 ≈ NTRP 균형 > 경기 수 균등 > 연속 출전 완화
  }
  let GEN_HOOK = null; // 정기 모임 생성 시 { fromSlot, fixed:[이미 시작한 시간대의 경기], hist } 주입. 대회 생성은 null (동작 불변)
  function generateRotationOnce(s, seed) {
    seedRng(seed);
    const ps = activePlayers(); if (ps.length < 4) throw new Error('개인전은 참가 선수 4명 이상이 필요합니다.');
    const n = maxSlots(s); if (!isFinite(n)) throw new Error('개인전은 종료 시각이 필요합니다 (대회 설정).');
    if (n < 1) throw new Error('시작~종료 사이에 경기 시간이 없습니다.');
    const played = {}, lastPlayed = {}, partner = {}, opp = {}, fmCnt = {}, mmCnt = {}, playedSlots = {}, NT = {}, isF = {}, fmWomen = {}; // fmWomen: 혼복에서 여성끼리 상대한 횟수
    const key = (a, b) => (a < b ? a + '|' + b : b + '|' + a);
    const fmWomenKey = (c) => { const wa = c.slice(0, 2).find((x) => isF[x]), wb = c.slice(2).find((x) => isF[x]); return wa && wb && c.filter((x) => isF[x]).length === 2 ? key(wa, wb) : null; }; // 혼복 코트의 여성 상대 쌍
    ps.forEach((p) => { played[p.id] = 0; lastPlayed[p.id] = -1; fmCnt[p.id] = 0; mmCnt[p.id] = 0; playedSlots[p.id] = new Set(); NT[p.id] = ntrpOf(p.id); isF[p.id] = p.gender === 'F'; });
    let ffDone = 0; const minFF = s.minWomenDoubles || 0; // 여복 최소 경기 수
    if (GEN_HOOK) { // 정기 모임: 지난 모임 이력(가중)과 이미 시작한 시간대의 경기를 카운터에 미리 반영
      const H = GEN_HOOK.hist || {}; for (const [k, v] of Object.entries(H.partner || {})) partner[k] = (partner[k] || 0) + v * 0.5; for (const [k, v] of Object.entries(H.opp || {})) opp[k] = (opp[k] || 0) + v * 0.5; for (const [k, v] of Object.entries(H.fmWomen || {})) fmWomen[k] = (fmWomen[k] || 0) + v * 0.25;
      for (const m of GEN_HOOK.fixed) { const [a1, a2] = m.aIds.map((x) => x.slice(2)), [b1, b2] = m.bIds.map((x) => x.slice(2)); partner[key(a1, a2)] = (partner[key(a1, a2)] || 0) + 1; partner[key(b1, b2)] = (partner[key(b1, b2)] || 0) + 1; for (const x of [a1, a2]) for (const y of [b1, b2]) opp[key(x, y)] = (opp[key(x, y)] || 0) + 1; const tp = pairType(a1, a2); if (tp === 'FF') ffDone++; const wk = fmWomenKey([a1, a2, b1, b2]); if (wk) fmWomen[wk] = (fmWomen[wk] || 0) + 1; for (const x of [a1, a2, b1, b2]) { if (played[x] == null) continue; played[x]++; lastPlayed[x] = m.slot; playedSlots[x].add(m.slot); if (tp === 'FM') fmCnt[x]++; else if (tp === 'MM') mmCnt[x]++; } }
    }
    let menEq = s.fmMenEqual !== false && !GEN_HOOK; // 특별 규칙: 혼복은 양쪽 남자 NTRP 동일 (대회, 기본 켬). 정기 모임은 대신 '혼복 원칙'(courtCost) 으로 유도. 어떤 시간대에서 도저히 못 지키면 그 시간대만 풀고 경기를 만든다 (아래 slot 루프)
    const AVOID = new Set(avoidPairIds(s.avoidPairs, ps).map(([x, y]) => key(x, y))); // 특별 규칙: 같은 조 금지 (파트너로 묶지 않음)
    const avoidedCourt = (c) => AVOID.has(key(c[0], c[1])) || AVOID.has(key(c[2], c[3]));
    // 코트 비용: 파트너·상대 중복, NTRP 균형(기본), 암묵적 편성 선호, 혼복 남자 NTRP 불일치(사실상 금지)
    const nsum = (a, b) => NT[a] + NT[b];
    // 암묵적 편성 선호(데이터 필드 pref, 화면 표시 없음): p=파트너·상대가 본인 수준에 가깝게, s=파트너가 본인 이상, e=상대 조 합이 본인 조 이하
    const DEFAULT_PREF = { '김지선': 'p' }; // 데이터에 표시가 없어도 기본 적용 (화면 표시 없음)
    const CARE = {}; if (!GEN_HOOK) ps.forEach((p) => { const pr = p.pref || DEFAULT_PREF[p.name] || ''; if (pr) CARE[p.id] = { p: 'peers', s: 'strongPartner', e: 'easyOpp' }[pr]; }); // 정기 모임은 개인 선호 없이 레벨 균형만
    const careCost = (me, mate, o1, o2) => { const c = CARE[me]; if (!c) return 0; const nm = NT[me], np = NT[mate], no = (NT[o1] + NT[o2]) / 2; if (c === 'peers') return 18 * (Math.abs(np - nm) + Math.abs(no - nm)); if (c === 'strongPartner') return np < nm ? 30 * (nm - np) : 0; if (c === 'easyOpp') return (NT[o1] + NT[o2]) > (nm + np) ? 30 * ((NT[o1] + NT[o2]) - (nm + np)) : 0; return 0; };
    const courtCost = (c) => { const [a1, a2, b1, b2] = c; let cost = 150 * ((partner[key(a1, a2)] || 0) + (partner[key(b1, b2)] || 0)); for (const x of [a1, a2]) for (const y of [b1, b2]) cost += 120 * (opp[key(x, y)] || 0); const d = Math.abs(nsum(a1, a2) - nsum(b1, b2)); cost += careCost(a1, a2, b1, b2) + careCost(a2, a1, b1, b2) + careCost(b1, b2, a1, a2) + careCost(b2, b1, a1, a2); if (GEN_HOOK) { if (isF[a1] !== isF[a2] && isF[b1] !== isF[b2]) { const w1 = isF[a1] ? a1 : a2, m1 = isF[a1] ? a2 : a1, w2 = isF[b1] ? b1 : b2, m2 = isF[b1] ? b2 : b1; if (fmMixBad(NT[w1], NT[m1], NT[w2], NT[m2])) cost += 300; } } // 정기 모임 혼복 원칙 (약한 여자에게 강한 남자, 여자 동급이면 남자 동급)
      else if (menEq) { const men = c.filter((x) => !isF[x]); if (men.length === 2 && menDiffer(NT[men[0]], NT[men[1]])) cost += 1e5; } const wk = fmWomenKey(c); if (wk) cost += 600 * (fmWomen[wk] || 0); if (avoidedCourt(c)) cost += 1e5; const mixed = c.filter((x) => isF[x]).length === 1; if (mixed) { const wi = c.findIndex((x) => isF[x]); const mate = c[wi ^ 1]; const wSide = NT[c[wi]] + NT[mate], mSide = NT[c[(wi + 2) % 4]] + NT[c[(wi + 3) % 4]]; const short = mSide - wSide; if (short >= 1.5) cost += 2e4; else if (short > 0) cost += 60 + 80 * short; if (c.some((x, i) => i !== wi && NT[x] > NT[mate])) cost += 150; } return cost + d * (mixed ? 120 : 60) + (d > 0.5 ? (mixed ? 200 : 100) : 0); }; // 잡복: 균형이 같다면 여성 파트너는 최고 남자 // 잡복(여 1명)은 균형 벌점 2배: 파트너·상대를 NTRP 로 최대한 맞춘다 // 혼복 여성 상대는 골고루: 같은 여성과 다시 붙는 혼복은 강한 벌점 // NTRP 균형(기본, 우선): 양쪽 조 합 차이 0.5 = 30, 1.0 = 160 (상대 중복 120 보다 큼)
    // 선발 우선순위 (낮을수록 먼저): 경기 수 균등 > 직전 휴식자 우선 > 연속 출전 완화 > 오래 쉰 순
    const availAt = (slot) => ps.filter((p) => playerAvailable(p, s, slot));
    // 정기 모임 공정성: (a) 기대 경기 수(참석 시간대마다 자리/인원 비율 누적) 대비 부족한 사람 먼저, (b) 남은 시간대가 적은 사람(곧 가는 사람) 먼저
    const weekly = !!GEN_HOOK; let AVG_REMAIN = 0;
    const remainOf = (p, slot) => { let r = 0; for (let i = slot; i < n; i++) if (playerAvailable(p, s, i)) r++; return r; };
    const AV = {}; if (weekly) ps.forEach((p) => { AV[p.id] = remainOf(p, 0); }); // 참석 시간대 수
    // 최소 보장: 참석 시간대가 2개 이상이면 최소 2경기, 1개면 1경기. 남은 시간대를 다 뛰어야 채울 수 있으면 최우선(-300)
    const urgent = (p, slot) => { const need = Math.min(AV[p.id], 2) - played[p.id]; return need > 0 && remainOf(p, slot) <= need ? 300 : 0; };
    const prio = (p, slot) => played[p.id] * 100 + (weekly ? -100 * Math.max(0, AVG_REMAIN - remainOf(p, slot)) - urgent(p, slot) - (p.guest ? 35 : 0) : 0) + (weekly && slot > 0 && lastPlayed[p.id] < slot - 1 && playerAvailable(p, s, slot - 1) ? -80 : 0) + (weekly ? 0.6 : 1) * ((slot > 0 && lastPlayed[p.id] < slot - 1 && playerAvailable(p, s, slot - 1) ? -60 : 0) + (slot >= 2 && playedSlots[p.id].has(slot - 1) && playedSlots[p.id].has(slot - 2) ? 40 : 0) - (slot - lastPlayed[p.id])); // 정기 모임: 곧 가는 사람은 1경기 차이를 뒤집을 만큼(−100/시간대) 우선, 휴식·연속 항은 1경기(100)를 넘지 못하게 0.6 배
    const capAt = (slot) => Math.min(courtsAtSlot(s, slot), Math.floor(availAt(slot).length / 4));
    const byPrio = (arr, slot) => shuffle([...arr]).sort((a, b) => prio(a, slot) - prio(b, slot));
    const pairings4 = ([a, b, c, d]) => [[a, b, c, d], [a, c, b, d], [a, d, b, c]]; // 같은 성별 4명의 조 편성 3가지
    const bestOf = (cs) => { let best = null, bc = Infinity; for (const c of cs) { if (avoidedCourt(c)) continue; const v = courtCost(c); if (v < bc) { bc = v; best = c; } } return best; };

    // ---- 특별 규칙(필수 대진): 시도마다 가능한 시간대를 무작위로 골라, 그 시간대에 먼저 확정하고 나머지를 채운다 ----
    const forced = []; // { slot, kind: 'FM'|'MM', label, build(used) → 코트 [a1,a2,b1,b2] | null, feasibleWith(used) }
    const notes = []; // 적용하지 못한 특별 규칙 안내 (규칙이 성립하지 않으면 생성을 막지 않고 그 규칙만 뺀다)
    // 혼복 필수 대진 선수 파싱 (다른 필수 대진이 같은 시간대에 이 두 사람을 쓰지 않도록 먼저 확정)
    const faceNames = parseNames(s.mustFace); let faceIds = null;
    if (faceNames.length) {
      if (faceNames.length !== 2) throw new Error('혼복 필수 대진은 선수 2명의 이름이어야 합니다 (예: 김지선, 고서영).');
      const P = faceNames.map((nm) => ps.find((p) => p.name === nm));
      const miss = faceNames.filter((_, i) => !P[i]);
      if (miss.length) notes.push(`혼복 필수 대진 제외: ${miss.join(', ')} 이(가) 참가 선수에 없음`);
      else { faceIds = P.map((p) => p.id); if (faceIds[0] === faceIds[1]) throw new Error('혼복 필수 대진은 서로 다른 두 선수여야 합니다.'); }
    }
    // (2) 동일 NTRP 남복: 그 NTRP 남자 4명으로 남복 1경기. 4명이 안 되면 바로 아래 등급에서 상위로 채워 '상위 4명' 남복
    const sameV = parseFloat(s.sameNtrpGame);
    if (Number.isFinite(sameV)) {
      const pool = (slot, used) => availAt(slot).filter((p) => NT[p.id] === sameV && !isF[p.id] && !used.has(p.id)); // 지정 등급 남자
      const below = (slot, used) => availAt(slot).filter((p) => !isF[p.id] && !used.has(p.id) && NT[p.id] && NT[p.id] <= sameV); // 지정 등급 이하 남자
      /** 지정 등급이 4명 이상이면 그 안에서, 모자라면 다음 등급을 포함한 상위 4명 (NTRP 내림차순, 동점은 선발 우선순위) */
      const top4 = (slot, used) => { const ex = pool(slot, used); if (ex.length >= 4) return byPrio(ex, slot).slice(0, 4).map((p) => p.id); const M = byPrio(below(slot, used), slot).sort((a, b) => NT[b.id] - NT[a.id]); return M.length >= 4 ? M.slice(0, 4).map((p) => p.id) : null; };
      const exactCnt = (slot, used) => pool(slot, used).length;
      const can = (sl, used) => pool(sl, used).length >= 4 || below(sl, used).length >= 4; // 난수를 쓰지 않는 가능 여부 판정 (생성 번호 재현성 유지)
      const slots = []; for (let sl = 0; sl < n; sl++) if (capAt(sl) >= 1 && can(sl, new Set())) slots.push(sl);
      if (!slots.length) notes.push(`NTRP ${sameV} 남복 제외: 같은 시간대에 NTRP ${sameV} 이하 남자가 4명 이상 없음${adminKey ? '' : ' (관리자 로그인 필요)'}`);
      else { const full = slots.filter((sl) => exactCnt(sl, new Set()) >= 4); const pick = (full.length ? full : slots); const slot = pick[Math.floor(rng() * pick.length)]; // 지정 등급만으로 되는 시간대를 우선
      if (!full.length) notes.push(`NTRP ${sameV} 남자가 4명이 안 되어 상위 4명(다음 등급 포함)으로 남복을 편성했습니다`);
      forced.push({ slot, kind: 'MM', label: `NTRP ${sameV} 남복`, feasibleWith: (used) => can(slot, used), build(used) { const M = top4(slot, used); return M ? bestOf(pairings4(M)) : null; } }); }
    }
    // (1) 혼복 필수 대진: 두 선수가 서로 상대편 (각 조 = 여 1 + 남 1, 남자는 menEq 면 NTRP 동일)
    if (faceIds) {
      const [p1, p2] = faceIds;
      const options = (slot, used, ignoreMenEq = false) => { // 완성 후보: A 조 = p1 + 반대 성별 1명, B 조 = p2 + 반대 성별 1명
        if (used.has(p1) || used.has(p2)) return [];
        const av = availAt(slot).map((p) => p.id).filter((x) => !used.has(x) && x !== p1 && x !== p2); const out = [];
        for (const xa of av) { if (isF[xa] === isF[p1]) continue; for (const xb of av) { if (xb === xa || isF[xb] === isF[p2]) continue; const c = [p1, xa, p2, xb]; const men = c.filter((x) => !isF[x]); if (men.length !== 2) continue; if (menEq && !ignoreMenEq && menDiffer(NT[men[0]], NT[men[1]])) continue; if (avoidedCourt(c)) continue; out.push(c); } }
        return out; };
      const taken = forced.map((f) => f.slot);
      // 같은 시간대를 다른 필수 대진과 나눠 쓰려면 코트가 2면 이상이고, 이 두 사람을 뺀 뒤에도 그 대진이 성립해야 한다
      const shareOk = (sl) => !taken.includes(sl) || (capAt(sl) >= 1 + taken.filter((t) => t === sl).length && forced.every((f) => f.slot !== sl || f.feasibleWith(new Set([p1, p2]))));
      let slots = [], slotsNoRule = [];
      for (let sl = 0; sl < n; sl++) { if (![p1, p2].every((x) => playerAvailable(playerById(x), s, sl)) || capAt(sl) < 1 || !shareOk(sl)) continue; if (options(sl, new Set(), true).length) slotsNoRule.push(sl); if (options(sl, new Set()).length) slots.push(sl); }
      if (slots.some((sl) => !taken.includes(sl))) slots = slots.filter((sl) => !taken.includes(sl)); // 다른 필수 대진과 같은 시간대는 대안이 없을 때만
      if (!slots.length) notes.push(slotsNoRule.length ? `혼복 필수 대진(${faceNames.join(' vs ')}) 제외: 남자 짝을 NTRP 가 같은 남자로 채울 수 없음 (특별 규칙 '혼복 남자 NTRP 동일' 과 충돌)` : `혼복 필수 대진(${faceNames.join(' vs ')}) 제외: 두 선수가 함께 있는 시간대에 코트·상대 선수가 없음`);
      else { const slot = slots[Math.floor(rng() * slots.length)];
      forced.push({ slot, kind: 'FM', label: `혼복 필수 대진(${faceNames.join(' vs ')})`, feasibleWith: (used) => options(slot, used).length > 0, build(used) { let best = null, bc = Infinity; for (const c of shuffle(options(slot, used))) { const v = courtCost(c) + prio(playerById(c[1]), slot) + prio(playerById(c[3]), slot); if (v < bc) { bc = v; best = c; } } return best; } }); }
    }
    forced.sort((a, b) => (a.kind === 'FM' ? 0 : 1) - (b.kind === 'FM' ? 0 : 1)); // 선수가 고정된 혼복 필수 대진을 먼저 놓고, 남복은 남은 선수로
    const forcedWomenAt = (sl) => forced.filter((f) => f.slot === sl && f.kind === 'FM').length * 2; // 필수 혼복이 쓰는 여성 수 (여복 가능 시간대 계산용)

    /** 일반 편성: 가용 선수 avail 중 k 코트 분량을 선발해 코트 구성 (성별 규칙·혼복 남자 NTRP 동일·여복 최소 반영) */
    const buildCourts = (avail, k, slot) => {
      const score = (p) => prio(p, slot);
      const Wav = byPrio(avail.filter((p) => isF[p.id]), slot), Mav = byPrio(avail.filter((p) => !isF[p.id]), slot);
      // 여복 최소 경기: 남은 시간대 중 여성 4명이 모이는 슬롯 수가 부족분 이하이면 강제, 아니면 가점만 (연속 편성·편중 방지)
      const ffNeed = minFF - ffDone;
      const ffSlotsLeft = ffNeed > 0 ? Array.from({ length: n - slot }, (_, i) => slot + i).filter((sl) => (sl === slot ? Wav.length : ps.filter((p) => p.gender === 'F' && playerAvailable(p, s, sl)).length - forcedWomenAt(sl)) >= 4).length : 0; // 필수 혼복이 쓰는 여성은 제외
      const ffPossible = ffNeed > 0 && Wav.length >= 4;
      const ffForce = ffPossible && ffSlotsLeft <= ffNeed;
      const ffCount = (t, kSel, asFF) => { let ff = asFF ? 1 : 0; while (t - ff * 4 > 2 * (kSel - ff)) ff++; return ff; }; // 혼복 코트로 다 못 담으면 여복 코트 수 증가
      const pairsOf = (M) => { const cnt = {}; let wild = 0; for (const x of M) { if (!NT[x]) wild++; else cnt[NT[x]] = (cnt[NT[x]] || 0) + 1; } let pairs = 0, odd = 0; for (const v of Object.values(cnt)) { pairs += Math.floor(v / 2); odd += v % 2; } const w = Math.min(wild, odd); return pairs + w + Math.floor((wild - w) / 2); }; // 같은 NTRP 남자 짝 수 (미입력은 아무와도 짝)
      // 남자 선발: 우선순위 상위 cnt 명. menEq 면 혼복 코트 수만큼 같은 NTRP 짝이 나오도록 후순위 남자와 교체 보정
      const menFor = (t, kSel, asFF) => {
        const cnt = kSel * 4 - t; const M = Mav.slice(0, cnt).map((p) => p.id); if (!menEq || !cnt) return M;
        const fm = (t - 4 * ffCount(t, kSel, asFF)) / 2; const rest = Mav.slice(cnt).map((p) => p.id); const sc = (id) => prio(playerById(id), slot);
        for (let guard = 0; pairsOf(M) < fm && guard < 8; guard++) {
          let best = null; for (let i = 0; i < M.length; i++) for (const y of rest) { const cand = [...M]; cand[i] = y; const gain = pairsOf(cand) - pairsOf(M); if (gain <= 0) continue; const d = sc(y) - sc(M[i]); if (!best || gain > best.gain || (gain === best.gain && d < best.d)) best = { i, y, gain, d }; }
          if (!best) return null; rest.splice(rest.indexOf(best.y), 1, M[best.i]); M[best.i] = best.y;
        }
        return pairsOf(M) >= fm ? M : null;
      };
      // 1) 선발: 여성 수(짝수) 분할 후보 중 선발 우선순위 합이 최선에 가까운 것들에서 무작위 선택 (시도마다 다른 구성 탐색)
      let kSel = k, pick = null; const mixOk = !!(GEN_HOOK && GEN_HOOK.mixOk); // 정기 모임: 여성이 홀수로 남으면 잡복(여+상위 남자 vs 남+남)도 허용해 코트를 최대한 채운다
      for (; kSel >= 1; kSel--) {
        const need = kSel * 4;
        const ideal = need * Wav.length / avail.length; // 동률이면 성별 비율에 가까운 분할
        const cands = [];
        for (let t = ffForce ? 4 : 0; t <= Wav.length; t += mixOk ? 1 : 2) {
          if (need - t < 0 || need - t > Mav.length) continue;
          const fmOk = !!menFor(t, kSel, false); // 혼복 남자 짝이 안 나오면 여복 코트로 여성을 담는 변형도 후보에 (가점 없이)
          for (const asFF of ((ffPossible || !fmOk) && t >= 4 ? [false, true] : [false])) {
            const M = menFor(t, kSel, asFF); if (!M) continue;
            const sum = Wav.slice(0, t).reduce((a, p) => a + score(p), 0) + M.reduce((a, id) => a + score(playerById(id)), 0);
            cands.push({ t, asFF, M, sum: sum - (asFF ? (ffForce ? 1e9 : 150) : 0) + (t % 2 ? 80 : 0), dist: Math.abs(t - ideal) }); // 잡복이 되는 홀수 분할은 경기 수가 같을 때만 뒤로 (한 경기 뒤진 사람이 있으면 잡복으로라도 넣는다)
          }
        }
        if (cands.length) {
          cands.sort((a, b) => a.sum - b.sum || a.dist - b.dist);
          const bestSum = cands[0].sum;
          const near = cands.filter((c) => c.sum - bestSum <= 120); // 경기 수 1 차이(100) 안쪽이면 동급 후보
          pick = near[Math.floor(rng() * near.length)]; break;
        }
      }
      if (!pick) return [];
      const W = Wav.slice(0, pick.t).map((p) => p.id), M = pick.M, wantFF = pick.asFF;
      const kk = Math.floor((W.length + M.length) / 4); if (kk < 1) return [];
      // 2) 구성: 여성 2명씩 혼복 코트(양쪽 1명씩, 남자는 같은 NTRP 짝), 코트가 모자라면 여성 4명 여복 코트, 나머지는 남복 코트. 여러 번 섞어 파트너·상대 중복 최소 조합 선택
      const totalCost = (cs) => cs.reduce((a, c) => a + courtCost(c), 0);
      let best = null, bestCost = Infinity;
      for (let t = 0; t < 40; t++) {
        // 무작위 초기 배치: 남성은 혼복을 덜 한 사람이 뒤(=먼저 뽑히는 쪽)에 오도록 정렬 → 혼복 코트에 우선 배치
        const w = shuffle([...W]), m = shuffle([...M]).sort((a, b) => (fmCnt[b] - mmCnt[b]) - (fmCnt[a] - mmCnt[a]) + (rng() - 0.5) * 0.5); const courts = [];
        const ff = ffCount(W.length, kk, wantFF);
        for (let c = 0; c < ff; c++) courts.push([w.pop(), w.pop(), w.pop(), w.pop()]);
        const aside = [];
        while (w.length >= 2 && m.length) { // 혼복: 남자 x 와 같은 NTRP 의 남자 y 를 짝으로 (menEq), 짝이 없으면 남복으로
          const x = m.pop(); let j = m.length - 1;
          if (menEq) { // pairsOf 와 같은 순서로 짝을 고른다: NTRP 가 같은 남자 → (없으면) 미입력 남자. 미입력 남자는 홀수 남은 등급 → 다른 미입력 → 아무나
            j = -1; const cnt = {}; for (const y of m) if (NT[y]) cnt[NT[y]] = (cnt[NT[y]] || 0) + 1;
            const prefs = NT[x] ? [(y) => NT[y] === NT[x], (y) => !NT[y]] : [(y) => NT[y] && cnt[NT[y]] % 2 === 1, (y) => !NT[y], () => true];
            for (const ok of prefs) { for (let i = m.length - 1; i >= 0; i--) if (ok(m[i])) { j = i; break; } if (j >= 0) break; }
          }
          if (j < 0) { aside.push(x); continue; }
          const y = m.splice(j, 1)[0]; courts.push([w.pop(), x, w.pop(), y]);
        }
        if (w.length === 1 && mixOk && m.length + aside.length >= 3) {
          m.push(...aside); aside.length = 0;
          let pi = 0; for (let i = 1; i < m.length; i++) if (NT[m[i]] > NT[m[pi]] || (NT[m[i]] === NT[m[pi]] && fmCnt[m[i]] - mmCnt[m[i]] < fmCnt[m[pi]] - mmCnt[m[pi]])) pi = i;
          const partner = m.splice(pi, 1)[0]; courts.push([w.pop(), partner, m.pop(), m.pop()]);
        } // 잡복 초기 배치: 여성은 남은 남성 중 최고 NTRP와 같은 조 (이후 교환 탐색이 NTRP 균형으로 조정)
        if (w.length) continue; // 여성이 남음 → 이 배치는 실패
        m.push(...aside);
        while (courts.length < kk && m.length >= 4) courts.push([m.pop(), m.pop(), m.pop(), m.pop()]);
        if (courts.length < kk || courts.some((c) => c.some((x) => x == null))) continue;
        // 교환 탐색: 같은 성별의 두 자리를 바꿔 비용이 줄면 채택 (파트너·상대 중복, NTRP 불균형 감소; 혼복 남자 NTRP 불일치는 비용이 커서 채택되지 않음)
        const slots = []; courts.forEach((c, ci) => c.forEach((_, pi) => slots.push([ci, pi])));
        let cost = totalCost(courts);
        for (let it = 0; it < 300 && cost > 0; it++) {
          const [c1, p1] = slots[Math.floor(rng() * slots.length)], [c2, p2] = slots[Math.floor(rng() * slots.length)];
          if (c1 === c2 && p1 === p2) continue;
          const x = courts[c1][p1], y = courts[c2][p2]; if (isF[x] !== isF[y]) continue; // 성별이 같아야 종류(남복/여복/혼복) 유지
          const before = courtCost(courts[c1]) + (c1 !== c2 ? courtCost(courts[c2]) : 0);
          courts[c1][p1] = y; courts[c2][p2] = x;
          const after = courtCost(courts[c1]) + (c1 !== c2 ? courtCost(courts[c2]) : 0);
          if (after <= before) cost += after - before; else { courts[c1][p1] = x; courts[c2][p2] = y; }
        }
        if (cost < bestCost) { bestCost = cost; best = courts.map((c) => [...c]); if (cost === 0) break; }
      }
      return best || [];
    };

    const matches = []; let round = 0;
    for (let slot = 0; slot < n; slot++) {
      if (weekly) { const av = availAt(slot); AVG_REMAIN = av.length ? av.reduce((a, p) => a + remainOf(p, slot), 0) / av.length : 0; }
      if (GEN_HOOK && slot < GEN_HOOK.fromSlot) { const fx = GEN_HOOK.fixed.filter((m) => m.slot === slot); if (fx.length) { for (const m of fx) matches.push({ id: uid(), phase: 'rot', round, slot, court: m.court, aIds: m.aIds, bIds: m.bIds }); round++; } continue; } // 이미 시작한 시간대는 그대로
      const avail = availAt(slot);
      const used = new Set(); const courts = [];
      for (const f of forced) if (f.slot === slot) { const c = f.build(used); if (!c) throw new Error(`${f.label}을(를) 편성하지 못했습니다 (같은 시간대에 다른 필수 대진과 선수가 겹쳐 인원이 부족합니다).`); courts.push(c); c.forEach((x) => used.add(x)); }
      const rest = avail.filter((p) => !used.has(p.id));
      const k = Math.min(courtsAtSlot(s, slot) - courts.length, Math.floor(rest.length / 4));
      if (k >= 1) { let built = buildCourts(rest, k, slot); if (!built.length && menEq) { menEq = false; try { built = buildCourts(rest, k, slot); } finally { menEq = true; } } courts.push(...built); } // 남자 NTRP 동일 규칙으로 코트가 하나도 안 나오면(예: 남자 2명뿐) 그 시간대는 규칙 없이
      if (!courts.length) continue;
      { const seen = new Set(); for (const c of courts) for (const x of c) { if (x == null || seen.has(x)) throw new Error('같은 시간대에 선수가 겹쳤습니다 (내부 오류). 다시 생성하세요.'); seen.add(x); } }
      courts.forEach(([a1, a2, b1, b2], c) => {
        matches.push({ id: uid(), phase: 'rot', round, slot, court: c + 1, aIds: ['p:' + a1, 'p:' + a2], bIds: ['p:' + b1, 'p:' + b2] });
        partner[key(a1, a2)] = (partner[key(a1, a2)] || 0) + 1; partner[key(b1, b2)] = (partner[key(b1, b2)] || 0) + 1;
        for (const x of [a1, a2]) for (const y of [b1, b2]) opp[key(x, y)] = (opp[key(x, y)] || 0) + 1;
        const tp = pairType(a1, a2); if (tp === 'FF') ffDone++; const wk = fmWomenKey([a1, a2, b1, b2]); if (wk) fmWomen[wk] = (fmWomen[wk] || 0) + 1;
        for (const x of [a1, a2, b1, b2]) { played[x]++; lastPlayed[x] = slot; playedSlots[x].add(slot); if (tp === 'FM') fmCnt[x]++; else if (tp === 'MM') mmCnt[x]++; }
      });
      round++;
    }
    if (!matches.length) throw new Error('배정 가능한 경기가 없습니다. 합류 시각과 종료 시각을 확인하세요.');
    const bad = forced.filter((f) => !matches.some((m) => m.slot === f.slot)); if (bad.length) throw new Error(`${bad[0].label} 편성 실패`);
    return { groups: [], advance: 0, matches, qualifiers: 0, extraSlots: 0, unitIds: ps.map((p) => 'p:' + p.id), seed, ...(notes.length ? { notes } : {}) };
  }
  function generate(s, units) {
    const ids = units.map((u) => u.id);
    if (ids.length < 2) throw new Error(`${unitLabel()}이(가) 2개 이상 필요합니다.`);
    const matches = []; let groups = []; let advance = 0; let qualifiers = 0;
    if (s.format === 'rr') {
      groups = [ids];
      roundRobin(ids).forEach((pairs, r) => pairs.forEach(([a, b]) => matches.push({ id: uid(), phase: 'rr', group: 0, round: r, aId: a, bId: b })));
    } else if (s.format === 'groups') {
      const gc = Math.max(1, Math.min(s.groupCount, Math.floor(ids.length / 2)));
      groups = Array.from({ length: gc }, () => []);
      ids.forEach((id, i) => { const c = i % (gc * 2); groups[c < gc ? c : gc * 2 - 1 - c].push(id); });
      groups.forEach((g, gi) => roundRobin(g).forEach((pairs, r) => pairs.forEach(([a, b]) => matches.push({ id: uid(), phase: 'group', group: gi, round: r, aId: a, bId: b }))));
      advance = Math.min(s.advance, Math.min(...groups.map((g) => g.length)));
      qualifiers = gc > 1 || advance > 1 ? gc * advance : 0;
      if (qualifiers < 2) qualifiers = 0;
    } else qualifiers = ids.length;

    if (qualifiers >= 2) {
      const size = nextPow2(qualifiers); const order = seedOrder(size);
      const seedSrc = (seed) => s.format === 'groups' ? { type: 'group', g: (seed - 1) % groups.length, pos: Math.floor((seed - 1) / groups.length) } : { type: 'seed', i: seed - 1 };
      let prev = [], rIdx = 0;
      for (let rs = size; rs >= 2; rs /= 2, rIdx++) {
        const cur = [];
        for (let i = 0; i < rs / 2; i++) {
          const m = { id: uid(), phase: 'ko', koRound: rIdx, koSize: rs, koIndex: i, aId: null, bId: null };
          if (rs === size) {
            const sa = order[2 * i], sb = order[2 * i + 1];
            m.aFrom = sa <= qualifiers ? seedSrc(sa) : { type: 'bye' };
            m.bFrom = sb <= qualifiers ? seedSrc(sb) : { type: 'bye' };
            m.bye = m.aFrom.type === 'bye' || m.bFrom.type === 'bye';
          } else { m.aFrom = { type: 'winner', id: prev[2 * i].id }; m.bFrom = { type: 'winner', id: prev[2 * i + 1].id }; }
          cur.push(m);
        }
        matches.push(...cur);
        if (rs === 4 && s.thirdPlace) matches.push({ id: uid(), phase: 'ko', koRound: rIdx + 1, koSize: 2, koIndex: 0, third: true, aFrom: { type: 'loser', id: cur[0].id }, bFrom: { type: 'loser', id: cur[1].id }, aId: null, bId: null });
        prev = cur;
      }
    }
    assignSlots(s, matches);
    return { groups, advance, matches, qualifiers, extraSlots: 0, unitIds: ids };
  }
  function assignSlots(s, matches) {
    const slots = []; const ensure = (i) => { while (slots.length <= i) slots.push({ used: 0, busy: new Set() }); return slots[i]; };
    const koMax = {}; let groupMax = -1;
    const ordered = [
      ...matches.filter((m) => m.phase !== 'ko').sort((a, b) => a.round - b.round || a.group - b.group),
      ...matches.filter((m) => m.phase === 'ko' && !m.bye).sort((a, b) => a.koRound - b.koRound || a.koIndex - b.koIndex),
    ];
    for (const m of ordered) {
      let earliest = 0;
      if (m.phase === 'ko') earliest = (m.koRound === 0 ? groupMax : (koMax[m.koRound - 1] ?? groupMax)) + 1;
      const parts = [m.aId, m.bId].filter(Boolean);
      let i = earliest;
      for (;; i++) { const sl = ensure(i); if (sl.used < s.courts && parts.every((p) => !sl.busy.has(p))) break; }
      const sl = slots[i]; m.slot = i; m.court = sl.used + 1; sl.used++; parts.forEach((p) => sl.busy.add(p));
      if (m.phase !== 'ko') groupMax = Math.max(groupMax, i); else koMax[m.koRound] = Math.max(koMax[m.koRound] ?? -1, i);
    }
  }

  // ================= 결과/순위 =================
  const subCount = () => 1;
  function getResult(mid) {
    const n = subCount(); let r = state.results[mid];
    if (!r || r.length !== n) r = state.results[mid] = Array.from({ length: n }, (_, i) => r?.[i] ?? { a: '', b: '' });
    return r;
  }
  const num = (v) => (v === '' || v == null ? null : Number(v));
  function matchOutcome(m) {
    if (m.bye) return { aw: 0, bw: 0, ag: 0, bg: 0, filled: 0, winner: 'a', winnerId: m.aId, loserId: null };
    const r = getResult(m.id); let aw = 0, bw = 0, ag = 0, bg = 0, filled = 0;
    for (const sub of r) { const a = num(sub.a), b = num(sub.b); if (a == null || b == null) continue; filled++; ag += a; bg += b; if (a > b) aw++; else if (b > a) bw++; }
    const n = r.length; let winner = null;
    if (aw > n / 2) winner = 'a'; else if (bw > n / 2) winner = 'b';
    else if (filled === n) winner = aw > bw ? 'a' : bw > aw ? 'b' : ag > bg ? 'a' : bg > ag ? 'b' : null;
    return { aw, bw, ag, bg, filled, winner, winnerId: winner === 'a' ? m.aId : winner === 'b' ? m.bId : null, loserId: winner === 'a' ? m.bId : winner === 'b' ? m.aId : null };
  }
  function groupStandings(gi) {
    const sch = state.schedule; const ids = sch.groups[gi];
    const rows = Object.fromEntries(ids.map((id) => [id, { id, p: 0, w: 0, l: 0, sw: 0, sl: 0, gf: 0, ga: 0 }]));
    let complete = true;
    for (const m of sch.matches.filter((m) => (m.phase === 'group' || m.phase === 'rr') && m.group === gi)) {
      const o = matchOutcome(m); const A = rows[m.aId], B = rows[m.bId];
      if (!o.winnerId || !A || !B) { complete = false; continue; }
      A.p++; B.p++; A.sw += o.aw; A.sl += o.bw; B.sw += o.bw; B.sl += o.aw; A.gf += o.ag; A.ga += o.bg; B.gf += o.bg; B.ga += o.ag;
      if (o.winner === 'a') { A.w++; B.l++; } else { B.w++; A.l++; }
    }
    const list = Object.values(rows).sort((x, y) => y.w - x.w || (y.sw - y.sl) - (x.sw - x.sl) || (y.gf - y.ga) - (x.gf - x.ga) || y.gf - x.gf || ids.indexOf(x.id) - ids.indexOf(y.id));
    return { list, complete };
  }
  function koLabel(m) { return m.third ? '3·4위전' : `${roundName(m.koSize)}${m.koSize > 2 ? ' ' + (m.koIndex + 1) : ''}`; }
  function resolveSource(src) {
    if (!src) return { id: null, label: '' };
    if (src.type === 'bye') return { id: null, label: '부전승', bye: true };
    if (src.type === 'seed') return { id: state.schedule.unitIds[src.i] ?? null, label: `시드 ${src.i + 1}` };
    if (src.type === 'group') { const st = groupStandings(src.g); return { id: st.complete ? st.list[src.pos]?.id ?? null : null, label: `${GROUP_NAMES[src.g]}조 ${src.pos + 1}위` }; }
    const m = state.schedule.matches.find((x) => x.id === src.id); if (!m) return { id: null, label: '' };
    const o = matchOutcome(m);
    return { id: src.type === 'winner' ? o.winnerId : o.loserId, label: `${koLabel(m)} ${src.type === 'winner' ? '승자' : '패자'}` };
  }
  function resolveKO() {
    const sch = state.schedule; if (!sch) return;
    for (const m of sch.matches.filter((m) => m.phase === 'ko').sort((a, b) => a.koRound - b.koRound || a.koIndex - b.koIndex)) {
      const a = resolveSource(m.aFrom), b = resolveSource(m.bFrom);
      m.aId = m.aManual ?? a.id; m.bId = m.bManual ?? b.id; m.aLabel = a.label; m.bLabel = b.label;
      if (m.bye) { m.aId = a.bye ? m.bId : m.aId; m.bId = null; }
    }
  }
  function conflicts() {
    const bySlot = {}; const bad = new Set();
    for (const m of state.schedule.matches.filter((m) => !m.bye)) (bySlot[m.slot] ??= []).push(m);
    for (const ms of Object.values(bySlot)) {
      const seenU = {}, seenC = {};
      for (const m of ms) {
        const people = m.aPlayers ? [...m.aPlayers, ...m.bPlayers] : [...sideIds(m, 'a'), ...sideIds(m, 'b')];
        for (const u of people.filter(Boolean)) { if (seenU[u]) { bad.add(m.id); bad.add(seenU[u]); } seenU[u] = m.id; }
        if (seenC[m.court]) { bad.add(m.id); bad.add(seenC[m.court]); } seenC[m.court] = m.id;
      }
    }
    return bad;
  }

  // ================= 표시 =================
  function unitHtml(id, fallback) {
    const u = unitById(id);
    if (!u) return `<span class="tbd">${esc(fallback || '미정')}</span>`;
    const mem = unitKind() !== 'single' && u.playerIds.length ? `<div class="sub">${esc(u.playerIds.map(pname).join(' · '))}</div>` : '';
    return `<div><b>${esc(unitName(u))}</b>${mem}</div>`;
  }
  const sideIds = (m, side) => m[side + 'Ids'] ? m[side + 'Ids'].filter(Boolean) : [m[side + 'Id']].filter(Boolean);
  const sideName = (m, side) => sideIds(m, side).map((id) => unitById(id) ? unitName(unitById(id)) : '?').join(' · ');
  const pnameHtml = (id) => { const p = playerById(id); return p ? `<span class="pname ${p.gender === 'F' ? 'f' : 'm'}">${esc(p.name)}</span>` : '<i>미정</i>'; }; // 이름 색으로 남녀 구분
  function sideHtml(m, side) {
    if (m[side + 'Players']) {
      const u = unitById(m[side + 'Id']);
      return `<div><b>${u ? esc(unitName(u)) : '<span class="tbd">미정</span>'}</b><div class="sub">${m[side + 'Players'].map((id) => pnameHtml(id)).join(' · ')}</div></div>`;
    }
    if (!m[side + 'Ids']) return unitHtml(m[side + 'Id'], m[side + 'Label']);
    const ids = m[side + 'Ids'];
    return `<div>${ids.map((id) => { const u = unitById(id); if (!u) return '<span class="tbd">미정</span>'; return u.playerIds?.length === 1 ? `<b>${pnameHtml(u.playerIds[0])}</b>` : `<b>${esc(unitName(u))}</b>`; }).join(' · ')}</div>`;
  }
  function slotTime(i) {
    const s = state.settings; const [h, m] = (s.startTime || '09:00').split(':').map(Number);
    const t = h * 60 + m + i * (s.matchMinutes + s.breakMinutes);
    return `${String(Math.floor(t / 60) % 24).padStart(2, '0')}:${String(t % 60).padStart(2, '0')}`;
  }
  function phaseTag(m) {
    if (m.phase === 'rr') return state.settings.mode === 'team' ? `<span class="tag">팀전 ${m.slot + 1}R</span>` : `<span class="tag">풀리그 ${m.round + 1}R</span>`;
    if (m.phase === 'group') return `<span class="tag">${GROUP_NAMES[m.group]}조 ${m.round + 1}R</span>`;
    if (m.phase === 'extra') return `<span class="tag extra">추가 경기</span>`;
    if (m.phase === 'rot') return `<span class="tag">${m.round + 1}R</span>`;
    return `<span class="tag">${esc(koLabel(m))}</span>`;
  }
  function totalSlots() { const ms = state.schedule.matches.filter((m) => !m.bye); return (ms.length ? Math.max(...ms.map((m) => m.slot)) : -1) + 1 + (state.schedule.extraSlots || 0); }

  // ================= ⑥ 회식 장소 =================
  const VENUE_FIELDS = ['name', 'time', 'addr', 'phone', 'menu', 'note'];
  const venueOf = () => ({ ...{ name: '', time: '', addr: '', phone: '', menu: '', note: '' }, ...(state.settings.venue || {}) });
  const telHref = (p) => 'tel:' + String(p).replace(/[^0-9+]/g, '');
  function renderVenue() {
    const box = $('#venue-view'); if (!box) return;
    const v = venueOf(); const f = $('#form-venue');
    if (f) for (const k of VENUE_FIELDS) { const el = f.elements[k]; if (el) el.value = v[k]; }
    if (!v.name && !v.addr && !v.note) { box.innerHTML = `<p class="hint">${viewOnly ? '회식 장소는 아직 안내되지 않았습니다.' : '아래에서 회식 장소를 입력하세요. 입력한 내용이 대회 화면에 표시됩니다.'}</p>`; return; }
    box.innerHTML = venueCardHtml(v);
  }
  /** 회식 장소 카드 (대회 화면·보관본 공용) */
  function venueCardHtml(v) {
    const q = encodeURIComponent([v.name, v.addr].filter(Boolean).join(' '));
    const row = (label, val, extra = '') => (val ? `<div class="vrow"><span class="vk">${esc(label)}</span><span class="vv">${extra || esc(val)}</span></div>` : '');
    return `<div class="venue-card">
      <div class="venue-head"><svg class="ic"><use href="#i-cup"/></svg><b>${esc(v.name || '회식')}</b>${v.time ? `<span class="venue-time">${esc(v.time)}</span>` : ''}</div>
      ${row('주소', v.addr)}${row('전화', v.phone, `<a href="${esc(telHref(v.phone))}">${esc(v.phone)}</a>`)}${row('메뉴·회비', v.menu)}${row('안내', v.note)}
      <div class="venue-map no-print"><iframe src="https://maps.google.com/maps?q=${q}&z=16&hl=ko&output=embed" title="${esc(v.name || '회식 장소')} 지도" loading="lazy" referrerpolicy="no-referrer-when-downgrade" allowfullscreen></iframe></div>
      <div class="venue-maps no-print">
        <a class="mapbtn" target="_blank" rel="noopener noreferrer" href="https://map.naver.com/p/search/${q}"><svg class="ic"><use href="#i-pin"/></svg>네이버 지도</a>
        <a class="mapbtn" target="_blank" rel="noopener noreferrer" href="https://map.kakao.com/?q=${q}"><svg class="ic"><use href="#i-pin"/></svg>카카오맵</a>
        <a class="mapbtn" target="_blank" rel="noopener noreferrer" href="https://www.google.com/maps/search/?api=1&query=${q}"><svg class="ic"><use href="#i-pin"/></svg>구글 지도</a>
      </div>
      <p class="hint no-print">${v.addr ? '지도와 버튼은 주소 기준입니다.' : '지도와 버튼은 장소 이름 검색 결과입니다.'}</p>
    </div>`;
  }
  $('#form-venue')?.addEventListener('submit', (e) => {
    e.preventDefault(); if (viewOnly) return;
    const fd = new FormData(e.target); const v = {};
    for (const k of VENUE_FIELDS) v[k] = String(fd.get(k) || '').trim().slice(0, k === 'note' ? 200 : k === 'addr' ? 120 : 60);
    state.settings.venue = v; save(); renderTournament(); toast('회식 장소를 저장했습니다 · 게시하기를 누르면 모두에게 반영됩니다');
  });

  function renderHeader() { const admin = document.body.dataset.page === 'admin'; const live = liveTournament(); $('#hdr-title').textContent = [live ? state.settings.name : '', admin ? '관리자' : ''].filter(Boolean).join(' · '); document.title = admin ? '테니스윗 관리자' : '테니스윗'; }
  function render() {
    hydrateSettings();
    renderHeader();
    $$('.inp-minff').forEach((el) => { el.value = state.settings.minWomenDoubles ?? 1; });
    const ap = $('#chk-autopub'); if (ap) ap.checked = localStorage.getItem('tennisweet.autopub') === '1';
    renderPlayers(); renderUnits();
    if (state.schedule) resolveKO();
    renderSchedule(); renderStandings(); renderBracket(); renderVenue(); renderWeeklyView(); renderTournament();
  }
  /** 대회 당일에만: 지금 시각이 이 시간대 안이면 'live', 지났으면 'past', 아니면 '' */
  function slotStatus(i) {
    const s = state.settings; if (!s.date) return '';
    const now = new Date(); const ymd = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`;
    if (ymd !== s.date) return '';
    const cur = now.getHours() * 60 + now.getMinutes(); const t0 = slotStartMin(s, i), t1 = t0 + s.matchMinutes;
    return cur >= t0 && cur < t1 ? 'live' : cur >= t1 ? 'past' : '';
  }
  function matchPeople(m) { return m.aPlayers ? [...m.aPlayers, ...m.bPlayers] : [...sideIds(m, 'a'), ...sideIds(m, 'b')].flatMap((id) => unitById(id)?.playerIds || []); }
  const modeLabel = () => ({ team: '팀전', rotation: '개인전', individual: '고정조 대회' }[state.settings.mode] || '');
  function renderSchedule() {
    const s = state.settings; const view = $('#schedule-view'); const sch = state.schedule;
    $('#mode-badge').textContent = modeLabel(); $('#mode-badge2').textContent = modeLabel();
    $('#print-title').textContent = s.name || '테니스윗 분기 대회';
    const edit = state.editMode && !viewOnly;
    $('#chk-edit').checked = edit; $('#chk-edit').disabled = viewOnly || !sch;
    for (const id of ['#btn-add-match', '#btn-add-slot', '#btn-compact']) $(id).hidden = !edit;
    if (!sch) { view.innerHTML = '<p class="hint">아직 일정표가 없습니다. 팀 구성 탭에서 생성하세요.</p>'; $('#print-meta').textContent = ''; $('#sel-me').innerHTML = ''; return; }
    const ms = sch.matches.filter((m) => !m.bye).sort((a, b) => a.slot - b.slot || a.court - b.court);
    const nSlots = totalSlots(); const bad = conflicts(); const n = subCount();
    $('#print-meta').textContent = `${s.date || ''}  ·  ${s.mode === 'team' ? '팀전' : s.mode === 'rotation' ? '개인전' : '고정조 대회'} ${s.mode === 'individual' && s.discipline === 'singles' ? '단식' : '복식'}  ·  코트 ${s.courts}면  ·  ${slotTime(0)}~${slotTime(nSlots)} (경기 ${ms.length})`;
    // 선수 필터 (모바일에서 내 경기만 보기)
    const sel = $('#sel-me'); const cur = state.meFilter || '';
    const inSched = new Set(ms.flatMap(matchPeople));
    sel.innerHTML = `<option value="">전체 경기</option>${state.players.filter((p) => inSched.has(p.id)).sort((a, b) => a.name.localeCompare(b.name, 'ko')).map((p) => `<option value="${esc(p.id)}" ${p.id === cur ? 'selected' : ''}>${esc(p.name)} 경기만</option>`).join('')}`;
    const unitOpts = (selId) => `<option value="">(미정)</option>${sch.unitIds.map((id) => `<option value="${esc(id)}" ${id === selId ? 'selected' : ''}>${esc(unitName(unitById(id) || { playerIds: [] }))}</option>`).join('')}`;
    const slotOpts = (selI) => Array.from({ length: nSlots }, (_, i) => `<option value="${i}" ${i === selI ? 'selected' : ''}>${slotTime(i)}</option>`).join('');
    const courtOpts = (selC) => Array.from({ length: s.courts }, (_, i) => `<option value="${i + 1}" ${i + 1 === selC ? 'selected' : ''}>${i + 1}코트</option>`).join('');
    const cell = (m, side) => {
      if (!edit) return sideHtml(m, side);
      if (m[side + 'Ids']) return m[side + 'Ids'].map((id, i) => `<select class="ed" data-mid="${esc(m.id)}" data-f="${side}${i}">${unitOpts(id)}</select>`).join('');
      if (m[side + 'Players']) {
        const team = unitById(m[side + 'Id']); const pool = team ? team.playerIds : state.players.map((p) => p.id);
        // 나머지 3명이 정해져 있으면 남복·여복·혼복 종류가 유지되는 선수만 선택지에 표시
        const okFor = (i, cand) => { const t = { aPlayers: [...m.aPlayers], bPlayers: [...m.bPlayers] }; t[side + 'Players'][i] = cand; const mt = matchType(t); return !mt || !mt.mismatch; };
        const popts = (selP, i) => `<option value="">(미정)</option>${pool.filter((id) => id === selP || okFor(i, id)).map((id) => `<option value="${esc(id)}" ${id === selP ? 'selected' : ''}>${esc(pname(id))}</option>`).join('')}`;
        return `<select class="ed" data-mid="${esc(m.id)}" data-f="${side}">${unitOpts(m[side + 'Id'])}</select>` + m[side + 'Players'].map((id, i) => `<select class="ed" data-mid="${esc(m.id)}" data-f="p${side}${i}">${popts(id, i)}</select>`).join('');
      }
      return `<select class="ed" data-mid="${esc(m.id)}" data-f="${side}">${unitOpts(m[side + 'Id'])}</select>${m.phase === 'ko' && m[side + 'Manual'] ? '<div class="sub">수동 지정</div>' : ''}`;
    };
    let html = '<div class="legend"><span class="tag type fm">혼복</span><span class="tag type mm">남복</span><span class="tag type ff">여복</span><span class="sub">카드 왼쪽 띠 색도 같은 뜻</span></div>';
    for (let slot = 0; slot < nSlots; slot++) {
      let rows = ms.filter((m) => m.slot === slot);
      if (cur) rows = rows.filter((m) => matchPeople(m).includes(cur));
      if (!rows.length && !(edit && !cur)) continue;
      const st8 = slotStatus(slot);
      html += `<div class="slot ${st8}"><div class="slot-title"><span class="t">${slotTime(slot)}</span><span class="to">~ ${slotTime(slot + 1)}</span>${rows.length ? '' : ' <span class="sub">(비어 있음)</span>'}${st8 === 'live' ? '<span class="live">진행 중</span>' : ''}</div><div class="cards match-cards">`;
      for (const m of rows) {
        const o = matchOutcome(m); const r = getResult(m.id); const canInput = sideIds(m, 'a').length && sideIds(m, 'b').length && !viewOnly;
        const scores = r.map((sub, i) => `<div class="score">${n > 1 ? `<span class="sub">${i + 1}</span>` : ''}
          <input type="number" min="0" max="${s.maxGames || 6}" inputmode="numeric" data-mid="${esc(m.id)}" data-i="${i}" data-side="a" value="${esc(sub.a)}" aria-label="${esc(sideName(m, 'a') || 'A')} 게임 수" ${canInput ? '' : 'disabled'}><span class="colon">:</span>
          <input type="number" min="0" max="${s.maxGames || 6}" inputmode="numeric" data-mid="${esc(m.id)}" data-i="${i}" data-side="b" value="${esc(sub.b)}" aria-label="${esc(sideName(m, 'b') || 'B')} 게임 수" ${canInput ? '' : 'disabled'}></div>`).join('');
        const res = o.winner ? `<div class="done">${esc(sideName(m, o.winner))} 승${n > 1 ? ` (${o.aw}:${o.bw})` : ''}</div>` : '';
        const clearBtn = !viewOnly && r.some((x) => x.a !== '' || x.b !== '') ? `<button class="small clear-score" data-clear="${esc(m.id)}" title="이 경기 점수 지우기">지우기</button>` : '';
        const mt = m.aPlayers ? matchType(m) : (m.aIds && m.bIds && [...m.aIds, ...m.bIds].every(Boolean) ? matchType({ aPlayers: m.aIds.map((id) => unitById(id)?.playerIds[0]), bPlayers: m.bIds.map((id) => unitById(id)?.playerIds[0]) }) : null);
        const typeTag = mt ? `<span class="tag ${mt.mismatch ? 'bad' : 'type ' + mt.code}">${esc(mt.label)}</span>` : '';
        const warn = (bad.has(m.id) ? '<span class="warn" title="같은 시간대에 참가자 또는 코트가 겹칩니다">⚠ 겹침</span>' : '') + (mt?.mismatch ? '<span class="warn" title="남복·여복·혼복은 양쪽 조 종류가 같아야 합니다">⚠ 종류 불일치</span>' : '') + (!viewOnly && isRot() && fmMenBad(m) ? '<span class="warn" title="혼복은 양쪽 남자 NTRP 가 같아야 합니다 (특별 규칙)">⚠ 남자 NTRP</span>' : '') + (!viewOnly && isRot() && avoidedPartner(m) ? `<span class="warn" title="같은 조 금지 (특별 규칙)">⚠ 금지 조합 ${esc(avoidedPartner(m))}</span>` : '');
        const mine = ''; // '내 경기' 필터는 목록 자체를 걸러서 보여주므로 별도 강조 불필요
        html += `<div class="mcard ${mt && !mt.mismatch ? 't-' + mt.code : ''} ${o.winner ? 'decided' : ''} ${bad.has(m.id) || mt?.mismatch ? 'conflict' : ''} ${mine}" data-card="${esc(m.id)}">
          <div class="mhead">${edit ? `<select class="ed" data-mid="${esc(m.id)}" data-f="slot">${slotOpts(m.slot)}</select><select class="ed" data-mid="${esc(m.id)}" data-f="court">${courtOpts(m.court)}</select>` : `<b class="court">${m.court}<small>코트</small></b>`} ${phaseTag(m)}${typeTag} ${warn}${edit ? `<button class="small x" data-del-match="${esc(m.id)}">삭제</button>` : ''}</div>
          <div class="mbody"><div class="side side-a ${o.winner === 'a' ? 'w' : ''}">${cell(m, 'a')}</div><div class="vs" aria-hidden="true"></div><div class="side side-b ${o.winner === 'b' ? 'w' : ''}">${cell(m, 'b')}</div></div>
          <div class="mfoot">${scores}<span class="res">${res}</span>${clearBtn}</div></div>`;
      }
      html += '</div></div>';
    }
    view.innerHTML = html || '<p class="hint">표시할 경기가 없습니다.</p>';
    renderGamesSummary(ms);
  }
  /** 일정표 아래: 선수별 경기 수 · 남복/여복/혼복 횟수 · 연속 휴식 표 (골고루 참여 확인용) */
  function renderGamesSummary(ms) {
    const box = $('#games-summary'); const games = {};
    ms.forEach((m) => matchPeople(m).filter(Boolean).forEach((id) => (games[id] = (games[id] || 0) + 1)));
    const ps = activePlayers();
    if (!ps.length || !ms.length) { box.innerHTML = ''; return; }
    const counts = ps.map((p) => games[p.id] || 0); const min = Math.min(...counts), max = Math.max(...counts);
    const teamOf = {}; if (state.settings.mode === 'team') state.units.forEach((u) => u.playerIds.forEach((id) => (teamOf[id] = unitName(u))));
    // 종류별 횟수
    const tc = {}; ms.forEach((m) => {
      const mt = m.aPlayers ? matchType(m) : (m.aIds && m.bIds && [...m.aIds, ...m.bIds].every(Boolean) ? matchType({ aPlayers: m.aIds.map((id) => unitById(id)?.playerIds[0]), bPlayers: m.bIds.map((id) => unitById(id)?.playerIds[0]) }) : null);
      if (!mt || mt.mismatch) return;
      matchPeople(m).filter(Boolean).forEach((id) => { (tc[id] ??= { 남복: 0, 여복: 0, 혼복: 0 })[mt.label]++; });
    });
    // 2회 연속 휴식 (참석 가능한 시간대 기준)
    const slotsOf = {}; ms.forEach((m) => matchPeople(m).filter(Boolean).forEach((id) => (slotsOf[id] ??= new Set()).add(m.slot)));
    const nSlotsAll = totalSlots(); const dblRest = {}, triple = {};
    const quad = {};
    for (const p of ps) { let run = 0, playRun = 0; for (let i = 0; i < nSlotsAll; i++) { if (!playerAvailable(p, state.settings, i)) { run = 0; playRun = 0; continue; } if (slotsOf[p.id]?.has(i)) { run = 0; playRun++; if (playRun >= 3) triple[p.id] = (triple[p.id] || 0) + 1; if (playRun >= 4) quad[p.id] = (quad[p.id] || 0) + 1; } else { playRun = 0; run++; if (run >= 2) dblRest[p.id] = (dblRest[p.id] || 0) + 1; } } }
    // 파트너·상대 중복 검사
    const pc = {}, oc = {}; const k2 = (a, b) => (a < b ? a + '|' + b : b + '|' + a);
    ms.forEach((m) => { const A = m.aPlayers || (m.aIds || []).map((id) => unitById(id)?.playerIds[0]), B = m.bPlayers || (m.bIds || []).map((id) => unitById(id)?.playerIds[0]); if (!A || !B || A.some((x) => !x) || B.some((x) => !x)) return;
      if (A.length === 2) pc[k2(A[0], A[1])] = (pc[k2(A[0], A[1])] || 0) + 1; if (B.length === 2) pc[k2(B[0], B[1])] = (pc[k2(B[0], B[1])] || 0) + 1;
      for (const x of A) for (const y of B) oc[k2(x, y)] = (oc[k2(x, y)] || 0) + 1; });
    const repP = Object.entries(pc).filter(([, v]) => v > 1).map(([k]) => k.split('|').map(pname).join('·'));
    const repOPairs = Object.entries(oc).filter(([, v]) => v > 1).map(([k, v]) => ({ ids: k.split('|'), v }));
    const repO = repOPairs.map(({ ids, v }) => ids.map(pname).join(' vs ') + (v > 2 ? ` ×${v}` : ''));
    const womenOnly = repOPairs.length > 0 && repOPairs.every(({ ids }) => ids.every((id) => gOf(id) === 'F'));
    const nWomen = ps.filter((p) => p.gender === 'F').length;
    const sorted = [...ps].sort((a, b) => (games[b.id] || 0) - (games[a.id] || 0) || (teamOf[a.id] || '').localeCompare(teamOf[b.id] || '') || a.name.localeCompare(b.name));
    const team = state.settings.mode === 'team';
    const cell = (v, cls) => `<td class="num ${cls || ''}">${v || '-'}</td>`;
    box.innerHTML = `<h3>인당 경기 수 <span class="sub">(최소 ${min} · 최대 ${max} · 총 ${ms.length}경기${state.schedule?.seed != null ? ` · 생성 #${state.schedule.seed}` : ''})</span></h3>
      <div class="table-wrap"><table class="stand summary"><thead><tr><th>선수</th>${team ? '<th>팀</th>' : ''}<th>합류</th><th class="num">경기</th><th class="num">남복</th><th class="num">여복</th><th class="num">혼복</th><th>비고</th></tr></thead><tbody>
      ${sorted.map((p) => { const g = games[p.id] || 0; const t = tc[p.id] || {}; return `<tr class="${g === max && max !== min ? 'hi' : ''} ${g === min && max !== min ? 'lo' : ''}">
        <td><b class="pname ${p.gender === 'F' ? 'f' : 'm'}">${esc(p.name)}</b></td>${team ? `<td class="sub">${esc(teamOf[p.id] || '')}</td>` : ''}<td class="sub">${esc(p.from || '')}${p.until ? '~' + esc(p.until) : ''}</td>
        <td class="num"><b>${g}</b></td>${cell(t.남복)}${cell(t.여복)}${cell(t.혼복)}<td class="sub">${[dblRest[p.id] ? '⚠ 2회 연속 휴식' : '', quad[p.id] ? '⚠ 4경기 연속' : triple[p.id] ? '3경기 연속' : ''].filter(Boolean).join(' · ')}</td></tr>`; }).join('')}</tbody></table></div>
      ${Object.keys(triple).length ? `<p class="hint">연속 출전 ${Object.keys(triple).length}명: 코트 ${state.settings.courts}면에 참석 ${ps.length}명이면 시간대마다 ${Math.max(0, ps.length - state.settings.courts * 4)}명만 쉬므로, 경기 수를 고르게 맞추려면 연속 출전은 불가피합니다.</p>` : ''}
      ${max - min > 1 ? '<p class="hint">경기 수 차이가 2 이상입니다. 합류 시각 차이 때문이면 정상이며, 그렇지 않으면 현장 편집으로 조정하세요.</p>' : ''}
      ${Object.keys(dblRest).length ? '<p class="hint">⚠ 표시: 참석 가능한 시간대에 2회 연속 쉬는 구간이 있습니다. 인원·성별 구성상 불가피한 경우(예: 19시대 코트 1면)가 아니면 다시 생성하거나 현장 편집으로 조정하세요.</p>' : ''}
      ${!viewOnly && isRot() && specialStatus(ms).length ? `<p class="hint">특별 규칙: ${specialStatus(ms).join(' · ')}</p>` : ''}
      <p class="hint">${repP.length ? `⚠ 같은 파트너 2회: ${esc(repP.join(', '))}` : '✓ 같은 파트너 반복 없음'} · ${repO.length ? `⚠ 같은 상대 2회 이상: ${esc(repO.join(', '))}` : '✓ 같은 상대 반복 없음'}${womenOnly ? ` <span class="sub">(여성 ${nWomen}명이 혼복·여복으로만 만나는 구성상 여성끼리 중복은 불가피)</span>` : ''}</p>`;
  }
  $('#sel-me').addEventListener('change', (e) => { state.meFilter = e.target.value; renderSchedule(); });
  setInterval(() => { if (state.schedule && !document.hidden && slotStatus(0) !== '' || (state.schedule && [...Array(totalSlots()).keys()].some((i) => slotStatus(i)))) renderSchedule(); }, 60000); // 당일 '진행 중' 표시 갱신
  /** 점수 입력 후 해당 카드만 갱신 (전체 재렌더 X → 다음 칸 포커스 유지) */
  function refreshCard(m) {
    const card = $(`#schedule-view .mcard[data-card="${CSS.escape(m.id)}"]`); if (!card) return;
    const o = matchOutcome(m); const n = subCount();
    card.classList.toggle('decided', !!o.winner);
    card.querySelector('.side-a')?.classList.toggle('w', o.winner === 'a');
    card.querySelector('.side-b')?.classList.toggle('w', o.winner === 'b');
    const res = card.querySelector('.res'); if (res) res.innerHTML = o.winner ? `<div class="done">${esc(sideName(m, o.winner))} 승${n > 1 ? ` (${o.aw}:${o.bw})` : ''}</div>` : '';
    const r = getResult(m.id); const has = r.some((x) => x.a !== '' || x.b !== ''); let cb = card.querySelector('.clear-score');
    if (has && !cb && !viewOnly) { cb = document.createElement('button'); cb.className = 'small clear-score'; cb.dataset.clear = m.id; cb.title = '이 경기 점수 지우기'; cb.textContent = '지우기'; card.querySelector('.mfoot').appendChild(cb); }
    if (!has && cb) cb.remove();
    renderStandings(); renderGamesSummary(state.schedule.matches.filter((x) => !x.bye));
  }
  const clampScore = (el) => { const mx = state.settings.maxGames || 6; if (el.value !== '' && Number(el.value) > mx) el.value = String(mx); if (el.value !== '' && Number(el.value) < 0) el.value = '0'; return el.value; };
  $('#schedule-view').addEventListener('input', (e) => { // 타이핑 즉시 저장 (포커스 이동 전에 게시해도 반영)
    const el = e.target; if (!el.dataset?.side) return;
    const m = state.schedule?.matches.find((x) => x.id === el.dataset.mid); if (!m) return;
    getResult(m.id)[+el.dataset.i][el.dataset.side] = clampScore(el); save();
  });
  $('#schedule-view').addEventListener('change', (e) => {
    const el = e.target; const m = state.schedule?.matches.find((x) => x.id === el.dataset.mid); if (!m) return;
    if (el.dataset.side) { getResult(m.id)[+el.dataset.i][el.dataset.side] = clampScore(el); save(); refreshCard(m); scheduleAutoPublish(); return; }
    const f = el.dataset.f;
    if (f === 'slot') m.slot = +el.value; else if (f === 'court') m.court = +el.value;
    else if (/^[ab]\d$/.test(f)) { m[f[0] + 'Ids'][+f[1]] = el.value || null; }
    else if (/^p[ab]\d$/.test(f)) {
      const arr = m[f[1] + 'Players']; const prev = arr[+f[2]]; arr[+f[2]] = el.value || null;
      const mt = matchType(m);
      if (mt?.mismatch) { arr[+f[2]] = prev; alert('경기 종류(남복·여복·혼복)는 양쪽 조가 반드시 같아야 합니다.\n' + mt.label + ' 조합은 편성할 수 없습니다.'); render(); return; }
    }
    else if (f === 'a' || f === 'b') { const v = el.value || null; if (m.phase === 'ko') m[f + 'Manual'] = v; else { m[f + 'Id'] = v; if (m[f + 'Players']) m[f + 'Players'] = [null, null]; } }
    commit();
  });
  $('#schedule-view').addEventListener('click', (e) => {
    const clr = e.target.closest('button[data-clear]');
    if (clr) {
      const m = state.schedule?.matches.find((x) => x.id === clr.dataset.clear); if (!m) return;
      getResult(m.id).forEach((x) => { x.a = ''; x.b = ''; });
      $$(`#schedule-view .mcard[data-card="${CSS.escape(m.id)}"] .score input`).forEach((inp) => (inp.value = ''));
      save(); refreshCard(m); scheduleAutoPublish(); return;
    }
    const del = e.target.closest('button[data-del-match]'); if (!del) return;
    if (!confirm('이 경기를 삭제할까요?')) return;
    state.schedule.matches = state.schedule.matches.filter((m) => m.id !== del.dataset.delMatch); delete state.results[del.dataset.delMatch]; commit();
  });
  $('#chk-edit').addEventListener('change', (e) => { state.editMode = e.target.checked; commit(); });
  $('#btn-clear-results')?.addEventListener('click', () => {
    if (!state.schedule) return;
    const n = Object.values(state.results).flat().filter((x) => x.a !== '' || x.b !== '').length;
    if (!n) { toast('지울 기록이 없습니다'); return; }
    if (!confirm(`입력된 점수 ${n}건을 모두 지웁니다. 일정은 그대로 남습니다. 계속할까요?`)) return;
    state.results = {}; commit(); toast('기록을 모두 지웠습니다 · 게시하기를 눌러야 반영됩니다');
  });
  $('#btn-add-match').addEventListener('click', () => { state.schedule.matches.push(isRot() ? { id: uid(), phase: 'extra', slot: totalSlots() - 1, court: 1, aIds: [null, null], bIds: [null, null] } : state.settings.mode === 'team' ? { id: uid(), phase: 'rr', group: 0, round: 0, slot: totalSlots() - 1, court: 1, aId: null, bId: null, aPlayers: [null, null], bPlayers: [null, null] } : { id: uid(), phase: 'extra', slot: totalSlots() - 1, court: 1, aId: null, bId: null }); commit(); });
  $('#btn-add-slot').addEventListener('click', () => { state.schedule.extraSlots = (state.schedule.extraSlots || 0) + 1; commit(); });
  $('#btn-compact').addEventListener('click', () => {
    const ms = state.schedule.matches.filter((m) => !m.bye); const used = [...new Set(ms.map((m) => m.slot))].sort((a, b) => a - b);
    ms.forEach((m) => (m.slot = used.indexOf(m.slot))); state.schedule.extraSlots = 0; commit();
  });

  /** 공정 순위: 승률 → 경기당 평균 득실 → 승수 → 득게임 (경기 수가 달라도 비교 가능) */
  const winRate = (r) => (r.p ? r.w / r.p : 0), avgDiff = (r) => (r.p ? (r.gf - r.ga) / r.p : 0);
  const fairCmp = (x, y) => winRate(y) - winRate(x) || avgDiff(y) - avgDiff(x) || y.w - x.w || y.gf - x.gf || y.p - x.p;
  const pct = (r) => (r.p ? Math.round(winRate(r) * 100) + '%' : '-'), avgStr = (r) => (r.p ? (avgDiff(r) >= 0 ? '+' : '') + avgDiff(r).toFixed(1) : '-');
  function rotationStandings() {
    const rows = Object.fromEntries(state.schedule.unitIds.map((id) => [id, { id, p: 0, w: 0, l: 0, d: 0, gf: 0, ga: 0 }]));
    for (const m of state.schedule.matches) {
      if (!m.aIds) continue; const o = matchOutcome(m); if (!o.filled) continue;
      const A = sideIds(m, 'a').map((id) => rows[id]).filter(Boolean), B = sideIds(m, 'b').map((id) => rows[id]).filter(Boolean);
      A.forEach((r) => { r.p++; r.gf += o.ag; r.ga += o.bg; if (o.winner === 'a') r.w++; else if (o.winner === 'b') r.l++; else r.d++; });
      B.forEach((r) => { r.p++; r.gf += o.bg; r.ga += o.ag; if (o.winner === 'b') r.w++; else if (o.winner === 'a') r.l++; else r.d++; });
    }
    return Object.values(rows).sort(fairCmp);
  }
  /** 방문자용 순위: 3위까지만 (상세 순위는 관리자 화면) */
  function podiumHtml(list, title, nameOf = (id) => unitName(unitById(id) || { playerIds: [] })) {
    const played = list.filter((r) => r.p > 0);
    if (!played.length) return `<h3>${esc(title)}</h3><p class="hint">아직 입력된 경기 결과가 없습니다. 결과가 게시되면 상위 3명이 표시됩니다.</p>`;
    const top = list.slice(0, 3); const medal = ['🥇', '🥈', '🥉'];
    return `<h3>${esc(title)} <span class="sub">(승률 → 경기당 평균 득실 → 승수)</span></h3>
      <ol class="podium">${top.map((r, i) => `<li class="p${i + 1}"><span class="medal">${medal[i]}</span><span class="pname">${esc(nameOf(r.id))}</span><span class="pstat">${r.w}승 ${r.l}패${r.d ? ` ${r.d}무` : ''} · 승률 ${pct(r)} · 평균 득실 ${avgStr(r)}</span></li>`).join('')}</ol>
      <p class="hint">경기 수·승패 상세는 관리자에게 문의하세요.</p>`;
  }
  function renderStandings() {
    const view = $('#standings-view'); const sch = state.schedule;
    if (sch && isRot() && viewOnly) { view.innerHTML = podiumHtml(rotationStandings(), '개인 순위'); return; }
    if (sch && isRot()) {
      const list = rotationStandings(); const games = {}; sch.matches.forEach((m) => [...sideIds(m, 'a'), ...sideIds(m, 'b')].forEach((id) => (games[id] = (games[id] || 0) + 1)));
      view.innerHTML = '<div class="table-wrap">' + `<h3>개인 순위 <span class="sub">(승률 → 경기당 평균 득실 → 승수 → 득게임)</span></h3><table class="stand"><thead><tr><th class="num">순위</th><th>선수</th><th class="num">경기</th><th class="num">승</th><th class="num">패</th><th class="num">무</th><th class="num">승률</th><th class="num">평균 득실</th><th class="num">득게임</th><th class="num">실게임</th></tr></thead><tbody>
        ${list.map((r, i) => `<tr class="${i === 0 && r.p ? 'rank1' : ''}"><td class="num">${i + 1}</td><td>${unitHtml(r.id)}</td><td class="num">${r.p}<span class="sub">/${games[r.id] || 0}</span></td><td class="num">${r.w}</td><td class="num">${r.l}</td><td class="num">${r.d}</td><td class="num"><b>${pct(r)}</b></td><td class="num">${avgStr(r)}</td><td class="num">${r.gf}</td><td class="num">${r.ga}</td></tr>`).join('')}</tbody></table>` + '</div>';
      return;
    }
    if (!sch || state.settings.format === 'ko') { view.innerHTML = sch ? '<p class="hint">토너먼트 방식은 순위표가 없습니다.</p>' : '<p class="hint">일정표를 먼저 생성하세요.</p>'; return; }
    const team = false;
    const indiv = state.settings.mode === 'team' ? (() => {
      const rows = {}; state.players.forEach((p) => { rows[p.id] = { id: p.id, p: 0, w: 0, l: 0, d: 0, gf: 0, ga: 0 }; });
      const teamOf = {}; state.units.forEach((u) => u.playerIds.forEach((id) => (teamOf[id] = unitName(u))));
      for (const m of sch.matches) { if (!m.aPlayers) continue; const o = matchOutcome(m); if (!o.filled) continue;
        m.aPlayers.filter((id) => rows[id]).forEach((id) => { const r = rows[id]; r.p++; r.gf += o.ag; r.ga += o.bg; if (o.winner === 'a') r.w++; else if (o.winner === 'b') r.l++; else r.d++; });
        m.bPlayers.filter((id) => rows[id]).forEach((id) => { const r = rows[id]; r.p++; r.gf += o.bg; r.ga += o.ag; if (o.winner === 'b') r.w++; else if (o.winner === 'a') r.l++; else r.d++; }); }
      const games = {}; sch.matches.forEach((m) => [...(m.aPlayers || []), ...(m.bPlayers || [])].forEach((id) => (games[id] = (games[id] || 0) + 1)));
      const list = Object.values(rows).filter((r) => games[r.id]).sort(fairCmp);
      if (viewOnly) return podiumHtml(list, '개인 기록 상위 3명', (id) => pname(id));
      return `<h3>개인 기록 <span class="sub">(승률 → 경기당 평균 득실 → 승수)</span></h3><table class="stand"><thead><tr><th class="num">순위</th><th>선수</th><th>팀</th><th class="num">경기</th><th class="num">승</th><th class="num">패</th><th class="num">승률</th><th class="num">평균 득실</th></tr></thead><tbody>
        ${list.map((r, i) => `<tr><td class="num">${i + 1}</td><td>${esc(pname(r.id))}</td><td class="sub">${esc(teamOf[r.id] || '')}</td><td class="num">${r.p}<span class="sub">/${games[r.id]}</span></td><td class="num">${r.w}</td><td class="num">${r.l}</td><td class="num"><b>${pct(r)}</b></td><td class="num">${avgStr(r)}</td></tr>`).join('')}</tbody></table>`;
    })() : '';
    view.innerHTML = '<div class="table-wrap">' + sch.groups.map((g, gi) => {
      const st = groupStandings(gi);
      return `<h3>${sch.groups.length > 1 ? GROUP_NAMES[gi] + '조' : state.settings.mode === 'team' ? '팀 순위 <span class="sub">(복식 승수 → 득실차)</span>' : '풀리그'} ${st.complete ? '<span class="tag">완료</span>' : ''}</h3>
      <table class="stand"><thead><tr><th class="num">순위</th><th>${esc(unitLabel())}</th><th class="num">경기</th><th class="num">승</th><th class="num">패</th>
      ${team ? '<th class="num">세부승</th><th class="num">세부패</th>' : ''}<th class="num">득게임</th><th class="num">실게임</th><th class="num">득실차</th></tr></thead><tbody>
      ${st.list.map((r, i) => `<tr class="${sch.qualifiers && i < sch.advance ? 'rank1' : ''}"><td class="num">${i + 1}</td><td>${unitHtml(r.id)}</td>
        <td class="num">${r.p}</td><td class="num">${r.w}</td><td class="num">${r.l}</td>${team ? `<td class="num">${r.sw}</td><td class="num">${r.sl}</td>` : ''}
        <td class="num">${r.gf}</td><td class="num">${r.ga}</td><td class="num">${r.gf - r.ga}</td></tr>`).join('')}
      </tbody></table>`;
    }).join('') + indiv + '</div>' + (sch.qualifiers ? `<p class="hint">각 조 상위 ${sch.advance}${unitKind() === 'single' ? '명' : '개'}가 본선에 진출합니다. 조 경기가 모두 끝나면 본선 대진이 자동으로 채워집니다.</p>` : '');
  }
  function renderBracket() {
    const view = $('#bracket-view'); const sch = state.schedule;
    const kos = sch?.matches.filter((m) => m.phase === 'ko') || [];
    $('#bracket-title').style.display = kos.length ? '' : 'none';
    if (!kos.length) { view.innerHTML = ''; return; }
    const rounds = {}; kos.filter((m) => !m.third).forEach((m) => (rounds[m.koRound] ??= []).push(m));
    const third = kos.find((m) => m.third);
    const nm = (id, lbl) => unitById(id) ? esc(unitName(unitById(id))) : `<span class="tbd">${esc(lbl || '미정')}</span>`;
    const card = (m) => {
      const o = matchOutcome(m); const r = getResult(m.id);
      const sc = (side) => m.bye ? '' : r.map((s) => s[side] === '' ? '-' : esc(s[side])).join(' ');
      return `<div class="match"><div class="lbl">${esc(koLabel(m))}${m.bye ? ' · 부전승' : m.slot != null ? ` · ${slotTime(m.slot)} ${m.court}코트` : ''}</div>
        <div class="${o.winner === 'a' ? 'w' : ''}"><span>${nm(m.aId, m.aLabel)}</span><span>${sc('a')}</span></div>
        <div class="${o.winner === 'b' ? 'w' : ''}"><span>${m.bye ? '<span class="tbd">부전승</span>' : nm(m.bId, m.bLabel)}</span><span>${sc('b')}</span></div></div>`;
    };
    const keys = Object.keys(rounds).map(Number).sort((a, b) => a - b);
    let html = '<div class="bracket">' + keys.map((r) => `<div class="round"><h4>${esc(roundName(rounds[r][0].koSize))}</h4>${rounds[r].map(card).join('')}</div>`).join('');
    const champ = matchOutcome(rounds[keys[keys.length - 1]][0]).winnerId;
    html += `<div class="round"><h4>우승</h4><div class="match"><div class="${champ ? 'w' : ''}"><span>${champ ? '🏆 ' + nm(champ) : '<span class="tbd">미정</span>'}</span></div></div>
      ${third ? `<h4>3·4위전</h4>${card(third)}` : ''}</div></div>`;
    view.innerHTML = html;
  }

  // ================= 상단 액션 =================
  $('#btn-share').addEventListener('click', makeShareLink);
  $('#btn-export').addEventListener('click', () => {
    if (!assertTypesOk()) return;
    const out = { ...state, editMode: false, meFilter: undefined, savedAt: undefined, basePublishedAt: undefined, ghTokenEnc: undefined, publishedAt: new Date().toISOString() };
    state.publishedAt = out.publishedAt; save(); // 이 파일을 게시하면 작업본과 같은 게시본으로 인식
    const blob = new Blob([JSON.stringify(out, null, 2)], { type: 'application/json' });
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
    a.download = 'tournament.json'; a.click();
    toast('tournament.json 저장됨 · 저장소 data/ 에 넣고 push 하면 게시됩니다 (보통은 🚀 게시하기로 충분)', 6000);
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  });
  $('#btn-import').addEventListener('click', () => $('#file-import').click());
  $('#file-import').addEventListener('change', async (e) => {
    const f = e.target.files[0]; if (!f) return;
    try {
      const data = JSON.parse(await f.text());
      if (!data.settings || !Array.isArray(data.players)) throw new Error('형식이 올바르지 않습니다.');
      state = normalize(data); await decryptAll(); commit();
    } catch (err) { alert('가져오기 실패: ' + err.message); }
    e.target.value = '';
  });
  $('#btn-print').addEventListener('click', () => window.print());
  // ---- 이미지 저장 (모바일: 인쇄 대신) ----
  function loadScript(src) { return new Promise((res, rej) => { if (document.querySelector(`script[src="${src}"]`)) return res(); const sc = document.createElement('script'); sc.src = src; sc.onload = res; sc.onerror = () => rej(new Error('스크립트 로드 실패')); document.head.appendChild(sc); }); }
  let lastImageBlob = null;
  async function saveImage() {
    const btn = $('#btn-image'); const label = btn.innerHTML; btn.disabled = true; btn.textContent = '만드는 중…';
    try {
      await loadScript('https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js');
      const target = $('.tab.active') || $('main');
      const name = (state.settings.name || '테니스윗') + ' · ' + ($('.tabs button.active')?.textContent.trim() || '');
      // 캡처용 헤더를 임시로 붙임
      const head = document.createElement('div'); head.className = 'capture-head'; head.style.cssText = 'padding:10px 14px;font-weight:800;font-size:18px;color:#07452a;'; head.textContent = name + (state.publishedAt ? `  (${new Date(state.publishedAt).toLocaleString('ko-KR')} 게시)` : '');
      target.prepend(head); document.body.classList.add('capturing');
      const canvas = await window.html2canvas(target, { scale: Math.min(2, window.devicePixelRatio || 1) * 1.5, backgroundColor: '#ffffff', useCORS: true, logging: false, windowWidth: Math.max(720, target.scrollWidth) });
      document.body.classList.remove('capturing'); head.remove();
      const blob = await new Promise((r) => canvas.toBlob(r, 'image/png')); lastImageBlob = blob;
      const url = URL.createObjectURL(blob);
      const file = new File([blob], 'tennisweet.png', { type: 'image/png' });
      const canShare = !!(navigator.canShare && navigator.canShare({ files: [file] }));
      const img = $('#image-out'); img.src = url; $('#image-download').href = url; $('#image-download').download = `${(state.settings.name || 'tennisweet').replace(/\s+/g, '_')}.png`;
      $('#image-share').hidden = !canShare; $('#image-modal').hidden = false;
      if (canShare) { $('#image-share').onclick = async () => { try { await navigator.share({ files: [file], title: name }); } catch {} }; }
    } catch (e) { alert('이미지를 만들지 못했습니다: ' + e.message); document.body.classList.remove('capturing'); $('.capture-head')?.remove(); }
    finally { btn.disabled = false; btn.innerHTML = label; }
  }
  $('#btn-image')?.addEventListener('click', saveImage);
  $('#image-close')?.addEventListener('click', () => { $('#image-modal').hidden = true; });
  $('#image-modal')?.addEventListener('click', (e) => { if (e.target.id === 'image-modal') $('#image-modal').hidden = true; });
  $('#btn-reset').addEventListener('click', () => {
    if (!confirm('모든 설정·참가자·결과를 지웁니다. 계속할까요? (먼저 내보내기를 권장)')) return;
    state = emptyState(); save(); forgetToken(); render(); showTab('players');
  });

  // ================= 게시본 (저장소 data/tournament.json) =================
  const EDITOR_FLAG = 'tennisweet.editor';
  async function loadPublished() {
    if (WK_MOCK) { const m = wkMock.get('data/tournament.json'); if (m) return m; } // 로컬: 모의 게시본이 있으면 그것을
    try { const res = await fetch('data/tournament.json?_=' + Date.now(), { cache: 'no-store' }); if (!res.ok) return null; return await res.json(); } catch { return null; } // CDN 캐시 우회
  }
  function toast(msg, ms = 3500) { const t = $('#toast'); if (!t) return; t.textContent = msg; t.hidden = false; clearTimeout(toast._t); toast._t = setTimeout(() => (t.hidden = true), ms); }

  // ================= 게시하기 (GitHub Contents API 로 data/tournament.json 커밋) =================
  const GH = { owner: 'koozinsong', repo: 'tennisweet', path: 'data/tournament.json', branches: ['main', 'gh-pages'] }; // main = 원본, gh-pages = 서빙 중인 사본(즉시 반영용)
  const TOKEN_KEY = 'tennisweet.ghtokenEnc';
  async function loadToken() { const enc = localStorage.getItem(TOKEN_KEY); if (!enc || !adminKey) return null; try { return await decStr(enc); } catch { return null; } }
  async function saveToken(tok) { localStorage.setItem(TOKEN_KEY, await encStr(tok.trim())); }
  function forgetToken() { localStorage.removeItem(TOKEN_KEY); }
  /** 게시본에 암호화되어 실린 토큰(ghTokenEnc)을 이 기기에 가져옴 — 관리자 비밀번호만 있으면 다른 기기에서도 바로 게시 가능 */
  async function syncTokenFromPublished(pub) {
    if (!adminKey || !pub?.ghTokenEnc || localStorage.getItem(TOKEN_KEY)) return false;
    try { const tok = await decStr(pub.ghTokenEnc); if (/^(github_pat_|ghp_)/.test(tok)) { await saveToken(tok); return true; } } catch {}
    return false;
  }
  function askToken(err) {
    return new Promise((resolve) => {
      const modal = $('#token-modal'), form = $('#token-form'), inp = $('#token-input'), errEl = $('#token-err');
      const opener = document.activeElement;
      errEl.textContent = err || ''; inp.value = ''; modal.hidden = false; inp.focus();
      const onKey = (e) => { if (e.key === 'Escape') done(null); };
      document.addEventListener('keydown', onKey);
      const done = (v) => { modal.hidden = true; form.onsubmit = null; $('#token-cancel').onclick = null; $('#token-forget').onclick = null; document.removeEventListener('keydown', onKey); opener?.focus?.(); resolve(v); };
      form.onsubmit = (e) => { e.preventDefault(); const v = inp.value.trim(); if (!/^(github_pat_|ghp_)/.test(v)) { errEl.textContent = '토큰 형식이 아닙니다 (github_pat_… 또는 ghp_…).'; return; } done(v); };
      $('#token-cancel').onclick = () => done(null);
      $('#token-forget').onclick = () => { forgetToken(); errEl.textContent = '저장된 토큰을 삭제했습니다.'; };
    });
  }
  const ghHeaders = (tok) => ({ Authorization: 'Bearer ' + tok, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' });
  const b64utf8 = (str) => b64(new TextEncoder().encode(str));
  /** 한 브랜치에 파일 커밋 (있으면 sha 포함 갱신, 없으면 생성). 409/422 충돌 시 sha 재조회 후 1회 재시도 */
  /** opts.base = 이 작업본이 기준으로 삼은 게시본의 publishedAt. 원본의 publishedAt 이 그보다 새로우면(다른 기기 게시) CONFLICT — opts.overwrite 면 무시 */
  async function ghPutFile(tok, branch, content, message, opts = {}) {
    const url = `https://api.github.com/repos/${GH.owner}/${GH.repo}/contents/${opts.path || GH.path}`;
    const utf8 = (b64s) => new TextDecoder().decode(unb64(b64s.replace(/\n/g, '')));
    for (let attempt = 0; attempt < 2; attempt++) {
      const cur = await fetch(`${url}?ref=${branch}&_=${Date.now()}`, { headers: ghHeaders(tok), cache: 'no-store' });
      if (cur.status === 401) throw Object.assign(new Error('AUTH'), { status: 401 });
      if (cur.status === 403) { const b = await cur.json().catch(() => ({})); if (/rate limit|abuse|secondary/i.test(b.message || '')) throw new Error(`GitHub 요청 제한 (잠시 후 다시 시도): ${b.message}`); throw Object.assign(new Error('AUTH'), { status: 403 }); }
      if (cur.status !== 200 && cur.status !== 404) throw new Error(`${branch} 조회 실패 (${cur.status})`);
      const curBody = cur.status === 200 ? await cur.json() : null; const sha = curBody?.sha;
      if (opts.expectSha !== undefined && (sha || null) !== (opts.expectSha || null)) throw Object.assign(new Error('STALE'), { sha: sha || null }); // 읽었을 때와 파일이 달라짐 → 호출자가 다시 읽어 적용
      if (opts.base !== undefined && !opts.overwrite && curBody?.content) { // 충돌 검사 (원본 기준)
        let remotePub = null; try { remotePub = JSON.parse(utf8(curBody.content)).publishedAt || null; } catch {}
        if (remotePub && remotePub !== opts.base && (!opts.base || Date.parse(remotePub) > Date.parse(opts.base))) throw Object.assign(new Error('CONFLICT'), { remote: remotePub });
      }
      const res = await fetch(url, { method: 'PUT', headers: { ...ghHeaders(tok), 'Content-Type': 'application/json' }, body: JSON.stringify({ message, content: b64utf8(content), branch, ...(sha ? { sha } : {}) }) });
      if (res.ok) return await res.json();
      const body = await res.json().catch(() => ({}));
      if (res.status === 401) throw Object.assign(new Error('AUTH'), { status: 401 });
      if (res.status === 403 && !/rate limit|abuse|secondary|protected|ruleset/i.test(body.message || '')) throw Object.assign(new Error('AUTH'), { status: 403 }); // 권한 문제만 토큰 문제로
      if (res.status === 404) throw Object.assign(new Error('NOPERM'), { status: 404 }); // 읽기는 되는데 쓰기 404 = 토큰에 이 저장소 쓰기 권한 없음
      if ((res.status === 409 || res.status === 422) && attempt === 0) continue; // 동시 변경 → 재시도
      throw new Error(`${branch} 커밋 실패 (${res.status}) ${body.message || ''}`);
    }
  }
  let publishing = false;
  const bannerAdmin = (extra) => { const el = $('#view-banner-text'); if (el) el.textContent = `✏️ 관리자 모드 (v ${String(window.TENNISWEET_VERSION || '').slice(0, 7)}) · ${extra}`; };
  async function publish(retry = 0, overwrite = false) {
    if (publishing) return; publishing = true; // 중복 클릭 즉시 차단
    const btn = $('#btn-publish'); const label = btn.innerHTML; btn.disabled = true; btn.textContent = '게시 중…';
    let again = false;
    try {
      if (!assertTypesOk()) return;
      if (!state.schedule && !confirm('아직 일정표가 없습니다. 선수·설정만 게시할까요?')) return;
      if (WK_MOCK) { // 로컬 테스트: GitHub 대신 브라우저 모의 저장소에 게시 → 같은 브라우저의 방문자 화면(localhost)에 반영
        const publishedAt = new Date().toISOString(); const out = { ...state, editMode: false, meFilter: undefined, savedAt: undefined, basePublishedAt: undefined, publishedAt };
        wkMock.set('data/tournament.json', JSON.parse(JSON.stringify(out))); state.publishedAt = publishedAt; state.basePublishedAt = publishedAt; save();
        toast('로컬 모의 게시 완료 · 이 브라우저의 방문자 화면(localhost:8090)에 반영됩니다. 실제 저장소에는 올라가지 않습니다', 6000); bannerAdmin(`로컬 모의 게시 ${new Date(publishedAt).toLocaleTimeString('ko-KR')} (GitHub 미반영)`); return;
      }
      let tok = await loadToken();
      if (!tok) { tok = await askToken(); if (!tok) { toast('게시를 취소했습니다 (토큰 없음)'); return; } await saveToken(tok); }
      const publishedAt = new Date().toISOString();
      const out = { ...state, editMode: false, meFilter: undefined, savedAt: undefined, basePublishedAt: undefined, publishedAt, ghTokenEnc: await encStr(tok) }; // 토큰은 관리자 키로 암호화해 동봉 (다른 기기는 비밀번호만으로 게시 가능)
      const content = JSON.stringify(out, null, 2) + '\n';
      const msg = `게시: ${state.settings.name || '대회'} · ${new Date(publishedAt).toLocaleString('ko-KR')}`;
      const results = []; let mainOk = false;
      for (const br of GH.branches) {
        try { await ghPutFile(tok, br, content, msg, br === 'main' ? { base: state.basePublishedAt || null, overwrite } : {}); results.push(`${br} ✓`); if (br === 'main') mainOk = true; }
        catch (e) {
          if (br === 'main') throw e; // 원본 실패 = 게시 실패
          results.push(`${br} ✗ ${e.message === 'AUTH' || e.message === 'NOPERM' ? '권한 없음' : e.message}`); // 서빙 사본 실패는 Actions 배포(1~2분)로 대체됨
        }
      }
      if (mainOk) { state.publishedAt = publishedAt; state.basePublishedAt = publishedAt; save(); } // 작업본 = 게시본 (새 게시본 확인창 방지)
      toast(`게시 완료 · ${results.join(' · ')}`, 5000);
      bannerAdmin(`방금 게시함 ${new Date(publishedAt).toLocaleTimeString('ko-KR')} · 방문자 화면은 1분 안에 자동 갱신`);
    } catch (e) {
      if (e.message === 'CONFLICT') { // 원본(main)에 내 기준보다 새로운 게시본이 있음 = 다른 기기에서 게시함
        const when = e.remote ? new Date(e.remote).toLocaleString('ko-KR') : '알 수 없음';
        if (confirm(`저장소에 더 새로운 게시본(${when})이 있습니다. 다른 기기에서 게시한 내용을 지금 작업본으로 덮어쓸까요?\n(취소 후 '게시본 불러오기'로 최신을 받아 다시 편집할 수 있습니다)`)) { again = true; overwrite = true; } else toast('게시를 취소했습니다');
      } else if (e.message === 'AUTH' || e.message === 'NOPERM') {
        forgetToken();
        const t2 = await askToken(e.message === 'AUTH' ? '토큰이 거부되었습니다 (만료·오타). 새 토큰을 넣어 주세요.' : '이 토큰으로는 저장소에 쓸 수 없습니다 (Repository access 에 koozinsong/tennisweet, Contents: Read and write 필요). 새 토큰을 넣어 주세요.');
        if (t2 && retry < 2) { await saveToken(t2); again = true; } else toast('게시를 취소했습니다');
      } else alert('게시 실패: ' + e.message + '\n(내보내기 → data/tournament.json 교체 → push 로도 게시할 수 있습니다)');
    } finally { publishing = false; btn.disabled = false; btn.innerHTML = label; }
    if (again) return publish(retry + 1, overwrite);
  }
  $('#btn-publish').addEventListener('contextmenu', (e) => { e.preventDefault(); if (confirm('저장된 GitHub 토큰을 삭제할까요? 다음 게시 때 다시 묻습니다.')) { forgetToken(); toast('토큰을 삭제했습니다'); } }); // 우클릭/길게 누르기 = 토큰 삭제
  $('#btn-publish').addEventListener('click', () => publish());
  // 자동 게시: 스코어 입력 후 3초 지나면 게시 (기기별 설정, localStorage)
  const AUTOPUB_KEY = 'tennisweet.autopub';
  const autoPubOn = () => localStorage.getItem(AUTOPUB_KEY) === '1';
  let autoPubTimer = null;
  function scheduleAutoPublish() { if (!autoPubOn() || viewOnly) return; clearTimeout(autoPubTimer); autoPubTimer = setTimeout(() => { if (!publishing) publish(); }, 3000); }
  $('#chk-autopub')?.addEventListener('change', (e) => { localStorage.setItem(AUTOPUB_KEY, e.target.checked ? '1' : '0'); toast(e.target.checked ? '자동 게시 켜짐 · 스코어 입력 3초 뒤 게시됩니다' : '자동 게시 꺼짐'); });
  const ID_RE = /^[A-Za-z0-9_:.-]{1,40}$/;
  /** 외부에서 온 데이터(공유 링크·가져오기·게시본)의 id 검증: 화면 속성에 들어가므로 형식이 다르면 거부 */
  function assertIds(data) {
    const bad = (v) => v != null && !(typeof v === 'string' && ID_RE.test(v));
    for (const p of data.players || []) { if (bad(p.id)) throw new Error('선수 id 형식 오류'); if (p.pref != null && !['', 'p', 's', 'e'].includes(p.pref)) p.pref = ''; }
    for (const u of data.units || []) { if (bad(u.id)) throw new Error('팀 id 형식 오류'); for (const x of u.playerIds || []) if (bad(x)) throw new Error('팀원 id 형식 오류'); }
    for (const m of data.schedule?.matches || []) {
      for (const v of [m.id, m.aId, m.bId, m.aManual, m.bManual, ...(m.aIds || []), ...(m.bIds || []), ...(m.aPlayers || []), ...(m.bPlayers || [])]) if (bad(v)) throw new Error('경기 id 형식 오류');
      for (const src of [m.aFrom, m.bFrom]) if (src && bad(src.id)) throw new Error('경기 참조 id 형식 오류');
    }
    for (const k of Object.keys(data.results || {})) if (bad(k)) throw new Error('결과 id 형식 오류');
    // 화면에 그대로 들어가는 숫자 필드·스코어는 형식을 강제 (문자열 주입 차단)
    const num = (v, d = 0) => (Number.isFinite(Number(v)) ? Math.max(0, Math.floor(Number(v))) : d);
    for (const m of data.schedule?.matches || []) { for (const k of ['slot', 'court', 'round', 'group', 'koRound', 'koSize', 'koIndex']) if (m[k] != null) m[k] = num(m[k]); if (m.phase != null && !/^[a-z]{1,10}$/.test(String(m.phase))) m.phase = 'extra'; }
    for (const arr of Object.values(data.results || {})) if (Array.isArray(arr)) for (const r of arr) { for (const k of ['a', 'b']) r[k] = /^\d{1,3}$/.test(String(r?.[k] ?? '')) ? String(r[k]) : ''; }
    { const v = data.settings?.venue; const LIM = { name: 60, time: 40, addr: 120, phone: 30, menu: 60, note: 200 }; const out = {}; for (const k of Object.keys(LIM)) out[k] = typeof v?.[k] === 'string' ? v[k].trim().slice(0, LIM[k]) : ''; if (data.settings) data.settings.venue = out; }
    if (data.schedule) { if (data.schedule.notes != null) { data.schedule.notes = Array.isArray(data.schedule.notes) ? data.schedule.notes.filter((x) => typeof x === 'string').map((x) => x.slice(0, 200)).slice(0, 10) : undefined; if (!data.schedule.notes?.length) delete data.schedule.notes; } data.schedule.extraSlots = num(data.schedule.extraSlots); data.schedule.advance = num(data.schedule.advance); if (data.schedule.seed != null) data.schedule.seed = num(data.schedule.seed); }
    return data;
  }
  const normalize = (data) => ({ ...emptyState(), ...assertIds(data), settings: { ...DEFAULT_SETTINGS, ...(data.settings || {}) }, editMode: false });
  /** 게시본을 작업본으로 삼을 때: 기준 버전(basePublishedAt)을 그 게시본의 publishedAt 으로 */
  const fromPublished = (pub) => { const st = normalize(pub); st.basePublishedAt = pub.publishedAt || null; return st; };
  function enterViewOnly(text) {
    viewOnly = true; document.body.classList.add('view-only');
    try { $('#form-settings').inert = true; } catch {}
    $('#view-banner').hidden = false; $('#view-banner-text').textContent = text;
  }
  function adminLogin() { location.href = 'admin.html?t=' + Date.now(); } // 관리자 페이지로 이동 (캐시된 옛 페이지 방지)
  $('#btn-editor').addEventListener('click', adminLogin);
  $('#btn-leave-editor').addEventListener('click', () => { sessionStorage.removeItem(PW_KEY); location.href = './'; }); // 토큰은 암호화된 채 브라우저에 남김 (초기화·게시 버튼 우클릭으로 삭제)
  $('#btn-load-published').addEventListener('click', async () => {
    const pub = await loadPublished(); if (!pub) { alert('게시본(data/tournament.json)을 찾을 수 없습니다.'); return; }
    if (!confirm('게시본을 불러와 현재 작업본을 덮어씁니다. 계속할까요?')) return;
    state = fromPublished(pub); await decryptAll(); await syncTokenFromPublished(pub); commit();
  });

  // ================= ⑦ 정기 모임 (주간 모임: 관리자가 날짜 생성 → 멤버가 참석 체크 → 누구나 대진 생성 → 완료 체크) =================
  // 데이터는 별도 저장소(tennisweet-data)의 정적 파일. 읽기 = GitHub Pages, 멤버 쓰기 = Apps Script 프록시(토큰은 프록시에만), 관리자 쓰기(날짜 생성) = 관리자 토큰
  const DATA_BASE = 'https://koozinsong.github.io/tennisweet-data/';
  const GH_DATA = { repo: 'tennisweet-data', branch: 'main' };
  const IS_LOCAL = /^(localhost|127\.0\.0\.1)$/.test(location.hostname);
  const WK_MOCK = IS_LOCAL && !/[?&]store=live/.test(location.search); // 로컬 개발: 브라우저 저장소로 흉내 (운영 데이터를 건드리지 않음)
  const PROXY_RE = /^https:\/\/script\.google\.com\/macros\/s\/[A-Za-z0-9_-]+\/exec$/;
  const TIME_RE = /^\d{2}:\d{2}$/, SESSION_RE = /^\d{4}-\d{2}-\d{2}[a-z]?$/, MID_RE = /^s\d{1,2}c\d{1,2}$/;
  const fnv1a = (str) => { let h = 0x811c9dc5; for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; } return h >>> 0; };
  const guestId = (name) => 'g:' + fnv1a(String(name).normalize('NFC').replace(/\s+/g, '')).toString(36); // 같은 이름 게스트는 다음 주에도 같은 id (이력이 이어짐)
  /** 세션 문서에 작업 1건 적용 — 프록시(tools/gas-proxy/Code.gs)의 applyWeeklyOp 와 같은 로직. 둘을 함께 고칠 것 */
  function applyWeeklyOp(doc, op) {
    const okId = (v) => typeof v === 'string' && ID_RE.test(v);
    if (op.op === 'set') {
      const m = /^(attendance|done)\.([A-Za-z0-9_:.-]{1,40})$/.exec(String(op.path || '')); if (!m) return { code: 'INVALID' };
      const coll = m[1], key = m[2]; doc[coll] = doc[coll] || {};
      if (op.value == null) delete doc[coll][key];
      else if (coll === 'attendance') {
        const v = op.value; if (!v || typeof v.n !== 'string' || !v.n.trim() || !['M', 'F'].includes(v.g) || !TIME_RE.test(v.from) || !TIME_RE.test(v.until) || v.from >= v.until) return { code: 'INVALID' };
        if (!doc.attendance[key] && Object.keys(doc.attendance).length >= 80) return { code: 'FULL' }; // 파일 무한 팽창 방지
        doc.attendance[key] = { n: v.n.trim().slice(0, 20), g: v.g, from: v.from, until: v.until, ...(v.guest ? { guest: true } : {}) };
      } else { if (op.value !== true || !doc.schedule || !(doc.schedule.matches || []).some((x) => x.id === key)) return { code: 'INVALID' }; doc.done[key] = true; }
    } else if (op.op === 'generate') {
      if ((op.base | 0) !== (doc.rev | 0)) return { code: 'STALE' };
      const v = op.value;
      if (v == null) { doc.schedule = null; doc.done = {}; }
      else {
        if (!v || !Array.isArray(v.matches) || v.matches.length > 64) return { code: 'INVALID' };
        for (const x of v.matches) if (!x || !MID_RE.test(String(x.id)) || !Number.isInteger(x.slot) || !Number.isInteger(x.court) || ![x.aIds, x.bIds].every((a) => Array.isArray(a) && a.length === 2 && a.every(okId))) return { code: 'INVALID' };
        doc.schedule = { seed: v.seed | 0, gen: v.gen | 0, fromSlot: v.fromSlot | 0, inputHash: String(v.inputHash || '').slice(0, 16), at: String(v.at || '').slice(0, 30), by: String(v.by || '').slice(0, 20), matches: v.matches.map((x) => ({ id: x.id, slot: x.slot, court: x.court, aIds: x.aIds, bIds: x.bIds })) };
        const fs = v.fromSlot | 0; const keep = new Set(fs > 0 ? v.matches.filter((x) => (x.slot | 0) < fs).map((x) => x.id) : []); // 전체 재편성(다시 섞기)은 완료 표시를 모두 비우고, 남은 시간대만 다시 짠 경우는 그대로 둔 시간대의 완료만 남긴다 (경기 id 가 s{slot}c{court} 로 재사용되므로)
        doc.done = doc.done || {}; for (const k of Object.keys(doc.done)) if (!keep.has(k)) delete doc.done[k];
      }
    } else if (op.op === 'edit') { // 조 조정: 지정한 경기(최대 4개)의 양쪽 조를 통째로 교체. 같은 시간대 중복 출전 금지, 완료 표시는 그대로
      if ((op.base | 0) !== (doc.rev | 0)) return { code: 'STALE' };
      const ms = doc.schedule && Array.isArray(doc.schedule.matches) ? doc.schedule.matches : null; if (!ms) return { code: 'INVALID' };
      const list = Array.isArray(op.value) ? op.value : [op.value]; if (!list.length || list.length > 4) return { code: 'INVALID' };
      if (op.prev != null) { // 조 조정은 '내가 본 팀'이 그대로일 때만 적용 (base 는 폴링·앞 응답으로 이미 최신일 수 있어 그것만으로는 타인의 변경을 못 잡는다)
        if (typeof op.prev !== 'object' || Array.isArray(op.prev)) return { code: 'INVALID' };
        for (const e of list) { const pv = e && op.prev[e.id]; const m = e && ms.find((x) => x.id === e.id); if (!m || !Array.isArray(pv) || pv.length !== 2 || !pv.every((a) => Array.isArray(a) && a.length === 2 && a.every(okId))) return { code: 'INVALID' }; if (m.aIds.join() !== pv[0].join() || m.bIds.join() !== pv[1].join()) return { code: 'STALE' }; }
      }
      const next = ms.map((m) => ({ id: m.id, slot: m.slot, court: m.court, aIds: m.aIds.slice(), bIds: m.bIds.slice() }));
      for (const e of list) { const m = e && next.find((x) => x.id === e.id); if (!m || ![e.aIds, e.bIds].every((a) => Array.isArray(a) && a.length === 2 && a.every(okId))) return { code: 'INVALID' }; if (new Set([...e.aIds, ...e.bIds]).size !== 4) return { code: 'INVALID' }; m.aIds = [e.aIds[0], e.aIds[1]]; m.bIds = [e.bIds[0], e.bIds[1]]; }
      for (const e of list) { const m = next.find((x) => x.id === e.id); const seen = new Set(); for (const x of next) { if (x.slot !== m.slot) continue; for (const id of [...x.aIds, ...x.bIds]) { if (seen.has(id)) return { code: 'INVALID' }; seen.add(id); } } }
      doc.schedule.matches = next;
    } else return { code: 'INVALID' };
    doc.rev = (doc.rev | 0) + 1; doc.updatedAt = new Date().toISOString();
    return { ok: true };
  }
  /** 외부에서 온 세션 문서 검증·정리 (화면 속성에 들어가므로 형식을 강제) */
  function assertWeekly(doc) {
    if (!doc || typeof doc !== 'object' || !SESSION_RE.test(String(doc.id || '')) || !/^\d{4}-\d{2}-\d{2}$/.test(String(doc.date || ''))) throw new Error('세션 형식 오류');
    const att = {}; for (const [k, v] of Object.entries(doc.attendance || {})) { if (!ID_RE.test(k) || !v || typeof v.n !== 'string' || !['M', 'F'].includes(v.g) || !TIME_RE.test(v.from || '') || !TIME_RE.test(v.until || '')) continue; att[k] = { n: v.n.slice(0, 20), g: v.g, from: v.from, until: v.until, ...(v.guest ? { guest: true } : {}) }; }
    doc.attendance = att;
    if (doc.schedule && typeof doc.schedule === 'object') {
      const ms = (Array.isArray(doc.schedule.matches) ? doc.schedule.matches : []).filter((m) => m && MID_RE.test(String(m.id)) && Number.isInteger(m.slot) && Number.isInteger(m.court) && [m.aIds, m.bIds].every((a) => Array.isArray(a) && a.length === 2 && a.every((x) => typeof x === 'string' && ID_RE.test(x)))).slice(0, 64).map((m) => ({ id: m.id, slot: m.slot, court: m.court, aIds: m.aIds, bIds: m.bIds }));
      doc.schedule = { seed: doc.schedule.seed | 0, gen: doc.schedule.gen | 0, fromSlot: doc.schedule.fromSlot | 0, inputHash: String(doc.schedule.inputHash || '').slice(0, 16), at: String(doc.schedule.at || '').slice(0, 30), by: String(doc.schedule.by || '').slice(0, 20), matches: ms };
    } else doc.schedule = null;
    const dn = {}; for (const k of Object.keys(doc.done || {})) if (MID_RE.test(k) && doc.done[k] === true) dn[k] = true; doc.done = dn;
    doc.rev = doc.rev | 0; doc.status = doc.status === 'closed' ? 'closed' : 'open';
    const st = { ...(doc.settings || {}) }; for (const k of ['courts', 'matchMinutes', 'breakMinutes', 'minWomenDoubles']) st[k] = Math.max(0, parseInt(st[k], 10) || 0); st.courts = Math.max(1, st.courts); st.matchMinutes = Math.max(5, st.matchMinutes || 30);
    if (!TIME_RE.test(st.startTime || '')) st.startTime = '18:00'; if (!TIME_RE.test(st.endTime || '')) st.endTime = '22:00';
    if (st.courtsByHour && typeof st.courtsByHour === 'object') { const cb = {}; for (const [h, v] of Object.entries(st.courtsByHour)) if (/^\d{1,2}$/.test(h) && Number.isInteger(v) && v >= 0 && v <= 8) cb[h] = v; st.courtsByHour = Object.keys(cb).length ? cb : undefined; } else delete st.courtsByHour;
    doc.settings = st;
    return doc;
  }
  // ---- 저장소 접근: 로컬은 모의(localStorage), 운영은 Pages 정적 파일 + 프록시 ----
  const wkMock = {
    key: 'tennisweet.weekly.mock',
    all() { try { return JSON.parse(localStorage.getItem(this.key) || '{}'); } catch { return {}; } },
    get(path) { const v = this.all()[path]; return v ? JSON.parse(JSON.stringify(v)) : null; },
    set(path, v) { const a = this.all(); if (v == null) delete a[path]; else a[path] = v; localStorage.setItem(this.key, JSON.stringify(a)); },
  };
  // 저장 위치: 지금은 코드 저장소의 data/weekly/… (관리자 토큰으로 main·gh-pages 에 커밋). 프록시를 붙이면 별도 저장소(DATA_BASE)로 옮긴다
  const WK_PATH = (path) => 'data/' + path;
  const wkFresh = {}; // 관리자가 방금 쓴 파일: Pages 반영(약 30초~1분)까지는 읽기보다 이 값을 우선
  const newer = (a, b) => { if (!a) return false; if (!b) return true; if (a.rev != null || b.rev != null) return (a.rev | 0) > (b.rev | 0); return String(a.updatedAt || '') > String(b.updatedAt || ''); };
  async function dataRead(path) {
    if (WK_MOCK) return wkMock.get(path);
    let got = null; try { const r = await fetch(WK_PATH(path) + '?_=' + Date.now(), { cache: 'no-store' }); if (r.ok) got = await r.json(); } catch {}
    const f = wkFresh[path]; if (f && Date.now() - f.t < 5 * 60000 && newer(f.v, got)) return JSON.parse(JSON.stringify(f.v));
    return got;
  }
  /** 관리자 토큰으로 정기 모임 파일 갱신: mutate(json|null) → 새 json (null 이면 중단) */
  async function dataAdminUpdate(path, mutate, msg) {
    if (WK_MOCK) { const next = mutate(wkMock.get(path)); if (next == null) return false; wkMock.set(path, next); return true; }
    let written = null; const ok = await repoAdminUpdate(WK_PATH(path), (cur) => { const next = mutate(cur); if (next != null) written = next; return next; }, msg);
    if (ok && written) wkFresh[path] = { v: JSON.parse(JSON.stringify(written)), t: Date.now() };
    return ok;
  }
  const wkCanWrite = () => WK_MOCK || !!adminKey || !!W.index?.proxy; // 저장 수단: 로컬 모의 / 관리자 토큰 / 프록시
  const wkClosed = (doc) => doc?.status === 'closed' || (/^\d{4}-\d{2}-\d{2}$/.test(doc?.date || '') && Date.parse(doc.date + 'T00:00:00+09:00') + 86400000 <= Date.now()); // 모임 다음날 0시(KST)부터 읽기 전용
  /** 멤버 쓰기: 프록시에 작업 1건 전송 (로컬은 모의 저장소에 직접 적용) */
  async function proxySend(op) {
    if (WK_MOCK) {
      const path = `weekly/sessions/${op.session}.json`; const doc = wkMock.get(path);
      if (!doc) return { ok: false, code: 'NOSESSION' }; if (wkClosed(doc)) return { ok: false, code: 'CLOSED', rev: doc.rev, doc };
      const r = applyWeeklyOp(doc, op); if (!r.ok) return { ok: false, code: r.code, rev: doc.rev, doc };
      wkMock.set(path, doc); await new Promise((res) => setTimeout(res, 200)); return { ok: true, rev: doc.rev, doc };
    }
    const url = W.index?.proxy;
    if (url) { // 프록시가 있으면 관리자도 프록시로 (프록시 캐시가 최신을 유지하도록). 프록시 장애 시 관리자는 자기 토큰으로
      try { const r = await fetch(url, { method: 'POST', body: JSON.stringify(op), redirect: 'follow' }); const j = await r.json(); if (!(adminKey && ['NETWORK', 'GITHUB', 'BUSY'].includes(j?.code))) return j; } // Content-Type 미지정(text/plain) → preflight 없음
      catch (e) { if (!adminKey) return { ok: false, code: 'NETWORK', detail: e.message }; }
    }
    if (adminKey) return adminApplyOp(op); // 관리자: 자기 토큰으로 직접 저장
    return { ok: false, code: 'NOPROXY' };
  }
  /** 관리자가 세션 파일을 직접 만들거나 지운 뒤 프록시 캐시를 맞춘다 */
  async function wkProxyRefresh(id) { const url = !WK_MOCK && W.index?.proxy; if (!url) return; try { await fetch(url, { method: 'POST', body: JSON.stringify({ v: 1, club: 'tennisweet', session: id, op: 'refresh' }), redirect: 'follow' }); } catch {} }
  /** 관리자 토큰으로 세션 파일에 작업 적용 (프록시와 같은 규칙: 마감 검사 → applyWeeklyOp → 커밋, 동시 변경은 다시 읽어 재시도) */
  async function adminApplyOp(op) {
    let fail = null, result = null;
    const ok = await repoAdminUpdate(WK_PATH(`weekly/sessions/${op.session}.json`), (cur) => {
      if (!cur) { fail = { ok: false, code: 'NOSESSION' }; return null; }
      let doc; try { doc = assertWeekly(cur); } catch { fail = { ok: false, code: 'INVALID' }; return null; }
      if (wkClosed(doc)) { fail = { ok: false, code: 'CLOSED', rev: doc.rev, doc }; return null; }
      const r = applyWeeklyOp(doc, op); if (!r.ok) { fail = { ok: false, code: r.code, rev: doc.rev, doc }; return null; }
      result = doc; return doc;
    }, wkCommitMsg(op), { quiet: true });
    if (fail) return fail; if (!ok || !result) return { ok: false, code: 'GITHUB' };
    wkFresh[`weekly/sessions/${op.session}.json`] = { v: JSON.parse(JSON.stringify(result)), t: Date.now() };
    await wkProxyRefresh(op.session); // 프록시 캐시(6시간)에 관리자 저장분을 반영 (멤버 화면이 묵지 않도록)
    return { ok: true, rev: result.rev, doc: result };
  }
  const wkCommitMsg = (op) => { const who = op.by ? ` by ${String(op.by).slice(0, 20)}` : ''; if (op.op === 'edit') return `정기 모임 ${op.session} 조 조정 ${(Array.isArray(op.value) ? op.value : [op.value]).map((e) => e && e.id).join(',')}${who}`; return op.op === 'set' ? `정기 모임 ${op.session} ${op.path}${op.value == null ? ' 삭제' : ''}${who}` : `정기 모임 ${op.session} 대진 ${op.value ? '#' + (op.value.seed | 0) : '삭제'}${who}`; };
  // ---- 상태 ----
  const W = { index: null, indexErr: '', id: null, doc: null, docErr: '', me: localStorage.getItem('tennisweet.me') || '', edit: null, filter: null, adjust: null, pick: null, busy: false, pending: [], failed: [], srvRev: -1, lastMsg: '', cache: {}, hist: null, histFor: null };
  const wkUnsent = () => [...W.pending, ...W.failed].filter((op) => op.session === W.id); // 아직 서버가 확인하지 않은 이 모임의 변경 (순서대로)
  /** 서버 문서를 받아들이되, 아직 확인되지 않은 내 변경은 그 위에 다시 얹는다 (화면이 되돌아가지 않도록) */
  function wkAdopt(raw, rev) { let d; try { d = assertWeekly(raw); } catch { return false; } if (d.id !== W.id) return false; const r = rev != null ? rev | 0 : d.rev | 0; W.srvRev = W.doc ? Math.max(W.srvRev, r) : r; for (const op of wkUnsent()) { const c = JSON.parse(JSON.stringify(d)); const r = applyWeeklyOp(c, op.op === 'generate' || op.op === 'edit' ? { ...op, base: c.rev } : op); if (r.ok) d = c; else if (op.op === 'edit') { W.failed = W.failed.filter((x) => x !== op); W.pending = W.pending.filter((x) => x !== op); } } W.doc = d; return true; } // 서버 문서와 어긋난 조 조정은 버린다 // 지금 보고 있는 모임의 문서만 채택 (다른 모임 응답·전환 경합 방지)
  const ymdOf = (d = new Date()) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
  const fmtDate = (ymd) => { const d = new Date(ymd + 'T00:00:00'); return isNaN(d) ? ymd : `${d.getMonth() + 1}/${d.getDate()}(${'일월화수목금토'[d.getDay()]})`; };
  const isToday = (ymd) => ymd === ymdOf();
  const hhmm = (min) => `${String(Math.floor(min / 60)).padStart(2, '0')}:${String(min % 60).padStart(2, '0')}`;
  const wkSessions = () => [...(W.index?.sessions || [])].sort((a, b) => (a.date < b.date ? -1 : a.date > b.date ? 1 : 0)); // 날짜순 (지난 모임 → 다가오는 모임)
  function wkDefaultId() { const today = ymdOf(); const list = wkSessions(); const up = list.filter((s) => s.date >= today); return up.length ? up[0].id : list[list.length - 1]?.id || null; } // 오늘 이후 중 가장 가까운 날, 없으면 가장 최근
  const wkSettings = (doc) => ({ ...DEFAULT_SETTINGS, ...(doc?.settings || {}), fmMenEqual: true, mustFace: '', sameNtrpGame: '', avoidPairs: '', date: doc?.date || '' });
  function wkHours(s) { const a = Math.ceil(toMin(s.startTime) / 60), b = Math.floor(toMin(s.endTime) / 60); const out = []; for (let h = a; h < b; h++) out.push(h); return out; }
  /** 코트 수 표시: 시간대별로 다르면 "18~20시 2면 · 20~22시 3면" */
  function wkCourtsLabel(s) {
    const cb = s.courtsByHour; if (!cb || typeof cb !== 'object') return `코트 ${s.courts}면`;
    const hours = wkHours(s); const parts = []; let i = 0;
    while (i < hours.length) { const v = cb[String(hours[i])] ?? s.courts; let j = i; while (j + 1 < hours.length && (cb[String(hours[j + 1])] ?? s.courts) === v) j++; parts.push(`${hours[i]}~${hours[j] + 1}시 ${v}면`); i = j + 1; }
    return parts.length === 1 ? `코트 ${parts[0].replace(/^\S+ /, '')}` : '코트 ' + parts.join(' · ');
  }
  const wkAttendees = (doc) => Object.entries(doc?.attendance || {}).map(([id, a]) => ({ id, name: a.n, gender: a.g, from: a.from, until: a.until, guest: !!a.guest, active: true })).sort((x, y) => (x.id < y.id ? -1 : 1));
  const wkName = (doc, id) => doc?.attendance?.[id]?.n || playerById(id)?.name || id;
  function wkStatus(msg, bad) { const el = $('#wk-status'); if (!el) return; el.textContent = msg || ''; el.classList.toggle('bad', !!bad); const rb = $('#wk-retry'); if (rb) rb.hidden = !W.failed.length; }
  function wkCoverMeta() { const s = wkSessions().find((x) => x.id === W.id); if (!s) return '예정된 모임 없음'; const st = W.doc ? wkSettings(W.doc) : null; const n = W.doc ? Object.keys(W.doc.attendance).length : null; return `${fmtDate(s.date)}${st ? ` ${st.startTime.slice(0, 2)}~${st.endTime.slice(0, 2)}시` : ''}${n != null ? ` · 참석 ${n}명` : ''}${W.doc?.schedule ? ' · 대진 있음' : ''}`; }
  function wkUpdateCover() { const el = $('#cover-weekly'); if (el) el.textContent = wkCoverMeta(); }
  // ---- 읽기 ----
  async function weeklyRefresh() {
    const idx = await dataRead('weekly/index.json');
    if (idx && typeof idx === 'object') {
      const lv = {}; if (idx.levels && typeof idx.levels === 'object') for (const [k, v] of Object.entries(idx.levels)) if (ID_RE.test(k) && Number.isFinite(Number(v))) lv[k] = Number(v);
      W.index = { v: 1, levels: lv, levelsAt: String(idx.levelsAt || '').slice(0, 30), proxy: PROXY_RE.test(String(idx.proxy || '')) ? String(idx.proxy) : '', sessions: (Array.isArray(idx.sessions) ? idx.sessions : []).filter((s) => s && SESSION_RE.test(String(s.id || '')) && /^\d{4}-\d{2}-\d{2}$/.test(String(s.date || ''))).map((s) => ({ id: String(s.id), date: String(s.date), courts: s.courts | 0, matchMinutes: s.matchMinutes | 0, courtsLabel: String(s.courtsLabel || '').slice(0, 60) })) }; W.indexErr = '';
    } else { W.index = { v: 1, proxy: '', sessions: [] }; W.indexErr = WK_MOCK ? '' : (document.body.classList.contains('editor') ? '아직 모임 목록 파일이 없습니다. 위에서 첫 모임을 만들면 생깁니다 (데이터 저장소 tennisweet-data 와 GitHub Pages 가 준비되어 있어야 합니다 — README 참고).' : '아직 만들어진 정기 모임이 없습니다.'); }
    if (!W.id || !wkSessions().some((s) => s.id === W.id)) { W.id = wkDefaultId(); W.doc = null; W.edit = null; W.filter = null; W.adjust = null; W.pick = null; W.srvRev = -1; }
    renderWeeklyView();
    if (W.id) await wkLoadDoc(W.id); else wkUpdateCover();
  }
  /** 세션 읽기: 프록시가 있으면 프록시 캐시(저장 직후 최신), 없거나 실패하면 Pages 정적 파일 */
  async function wkReadSession(id) {
    const url = !WK_MOCK && W.index?.proxy;
    if (url) { try { const r = await fetch(`${url}?session=${encodeURIComponent(id)}&_=${Date.now()}`, { redirect: 'follow' }); const j = await r.json(); if (j && j.ok && j.doc) return j.doc; if (j && j.code === 'NOSESSION') return null; } catch {} }
    return dataRead(`weekly/sessions/${id}.json`);
  }
  async function wkLoadDoc(id, { quiet = false } = {}) {
    const raw = await wkReadSession(id); if (W.id !== id) return;
    if (!raw) { if (!quiet) { W.doc = null; W.docErr = '이 날짜의 파일을 찾지 못했습니다.'; renderWeeklyView(); } return; }
    let d; try { d = assertWeekly(raw); } catch { if (!quiet) { W.doc = null; W.docErr = '이 날짜의 파일 형식이 올바르지 않습니다.'; renderWeeklyView(); } return; }
    if (!W.doc || (d.rev | 0) > W.srvRev) { const had = !!W.doc; wkAdopt(d, d.rev); W.docErr = ''; renderWeeklyView(); wkUpdateCover(); if (quiet && had) toast('정기 모임 내용이 갱신되었습니다'); }
  }
  function wkSelect(id) { if (W.id === id) return; W.id = id; W.doc = null; W.docErr = ''; W.edit = null; W.filter = null; W.adjust = null; W.pick = null; W.srvRev = -1; renderWeeklyView(); wkLoadDoc(id); }
  setInterval(() => { if (!document.hidden && $('#tab-weekly')?.classList.contains('active') && W.id && !W.edit && !W.busy && !W.pending.length) wkLoadDoc(W.id, { quiet: true }); }, 20000); // 탭이 보일 때만 20초마다 (전송 중에는 건너뜀)
  document.addEventListener('visibilitychange', () => { if (!document.hidden && $('#tab-weekly')?.classList.contains('active') && W.id && !W.edit) wkLoadDoc(W.id, { quiet: true }); });
  // ---- 쓰기 (낙관적 반영 → 순서대로 전송) ----
  let wkQueue = Promise.resolve();
  const editKey = (op) => (Array.isArray(op.value) ? op.value : [op.value]).map((e) => e && e.id).sort().join(',');
  const wkSameTarget = (nw, old) => old.session === nw.session && (nw.op === 'set' ? old.op === 'set' && old.path === nw.path : nw.op === 'edit' ? old.op === 'edit' && editKey(old) === editKey(nw) : old.op === 'generate'); // 같은 대상(참석 한 사람·완료 한 경기·대진)의 옛 변경은 새 변경이 대체
  function wkSend(op) {
    const full = { v: 1, club: 'tennisweet', session: W.id, by: W.me || '', ...op };
    W.failed = W.failed.filter((x) => !wkSameTarget(full, x)); // 옛 실패분이 나중에 다시 얹히거나 재전송돼 최신 편집을 되돌리지 않도록
    W.pending.push(full); // 서버가 확인할 때까지 보관 (뒤 요청이 성공해도 앞 실패분이 사라지지 않도록)
    if (W.doc) { const d = JSON.parse(JSON.stringify(W.doc)); const r = applyWeeklyOp(d, full); if (r.ok) { W.doc = d; renderWeeklyView(); } }
    const p = wkQueue.then(() => wkSendNow(full)); wkQueue = p.catch(() => {}); return p;
  }
  async function wkSendNow(op) {
    W.busy = true; wkStatus('저장 중…');
    if ((op.op === 'generate' || op.op === 'edit') && W.failed.some((x) => x !== op && x.session === op.session)) { W.busy = false; W.pending = W.pending.filter((x) => x !== op); W.failed.push(op); wkStatus(`저장하지 못한 변경 ${W.failed.length}건 · 다시 시도를 누르세요`, true); renderWeeklyView(); return false; } // 앞선 실패분이 있으면 순서를 지켜 함께 재시도
    if ((op.op === 'generate' || op.op === 'edit') && op.session === W.id && W.srvRev >= 0) op.base = W.srvRev; // 앞선 변경이 실패해 큐에서 빠졌어도 서버 기준 rev 로 보낸다
    let res = await proxySend(op);
    for (let k = 0; k < 2 && res.code === 'STALE' && op.op === 'edit' && op.prev && res.doc; k++) { // 그사이 다른 변경(완료 표시 등)이 있어도 내가 고친 경기가 그대로면 최신 rev 로 다시 보낸다
      const cur = res.doc.schedule && res.doc.schedule.matches || []; const same = Object.entries(op.prev).every(([id, [a, b]]) => { const m = cur.find((x) => x.id === id); return m && m.aIds.join() === a.join() && m.bIds.join() === b.join(); });
      if (!same) break; op.base = res.doc.rev | 0; res = await proxySend(op);
    }
    W.busy = false;
    W.pending = W.pending.filter((x) => x !== op);
    const mine = op.session === W.id; // 다른 모임의 응답 문서는 화면에 채택하지 않는다
    if (res.ok) { if (res.doc && mine) wkAdopt(res.doc, res.rev); W.lastMsg = '저장됨 · ' + new Date().toLocaleTimeString('ko-KR', { hour: '2-digit', minute: '2-digit' }); renderWeeklyView(); wkUpdateCover(); return true; }
    const msg = { STALE: '다른 분이 방금 바꿨습니다 · 최신 내용으로 갱신했습니다', CLOSED: '지난 모임은 수정할 수 없습니다', NOSESSION: '관리자가 아직 이 날짜를 만들지 않았습니다', INVALID: '저장할 수 없는 값입니다 (저장 서버가 옛 버전이면 조 조정을 아직 못 받습니다)', FULL: '참석 인원이 너무 많아 더 넣을 수 없습니다', BUSY: '지금 저장이 몰려 있습니다 · 잠시 후 다시 시도하세요', NOPROXY: '지금은 관리자만 저장할 수 있습니다', NETWORK: '연결에 실패했습니다 · 다시 시도하세요', GITHUB: '저장하지 못했습니다 · 잠시 후 다시 시도하세요' }[res.code] || ('저장 실패: ' + (res.code || '?'));
    const retryable = ['NETWORK', 'BUSY', 'GITHUB', 'NOPROXY'].includes(res.code);
    if (retryable && !W.pending.some((x) => wkSameTarget(x, op))) W.failed.push(op); // 재시도 대기 (같은 대상의 더 새로운 변경이 이미 큐에 있으면 옛 실패분은 버린다 — 새 변경이 그 내용을 포함)
    if (mine) { if (res.doc) wkAdopt(res.doc, res.rev); else if (!retryable) await wkLoadDoc(W.id, { quiet: true }); } // 거부된 변경은 서버 문서로 되돌린다 (현재 모임일 때만)
    const n = W.failed.length; wkStatus(n > 1 ? `${msg} (미저장 ${n}건)` : msg, true); toast(msg); renderWeeklyView(); return false;
  }
  // ---- 화면 ----
  function renderWeeklyView() {
    const box = $('#wk-view'); if (!box) return;
    const editor = document.body.classList.contains('editor'); const list = wkSessions(); const doc = W.doc;
    const ls = $('#wk-levels-status'); if (ls) { const n = Object.keys(W.index?.levels || {}).length; ls.textContent = !W.index ? '' : n ? `${n}명 반영${W.index.levelsAt ? ' · ' + new Date(W.index.levelsAt).toLocaleString('ko-KR', { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : ''}` : '아직 반영 안 됨 — 대진에 NTRP 가 고려되지 않습니다'; }
    const al = $('#wk-admin-list'); if (al) { al.innerHTML = list.length ? `<div class="wk-admin-rows">${list.map((s) => `<div class="wk-admin-row"><b>${esc(fmtDate(s.date))}</b><span class="sub">${esc(s.date)} · ${esc(s.courtsLabel || `코트 ${s.courts}면`)} · ${s.matchMinutes}분${W.id === s.id && W.doc ? ` · 참석 ${Object.keys(W.doc.attendance).length}명${W.doc.schedule ? ' · 대진 있음' : ''}` : ''}</span><button class="small wk-del" data-wk-del="${esc(s.id)}">🗑 삭제</button></div>`).join('')}</div>` : '<p class="hint">만든 모임이 없습니다.</p>'; const pi = $('#wk-form-proxy [name=proxy]'); if (pi && document.activeElement !== pi) pi.value = W.index?.proxy || ''; }
    if (!W.index) { box.innerHTML = '<p class="hint">불러오는 중…</p>'; return; }
    if (W.indexErr && !list.length) { box.innerHTML = `<p class="hint">${esc(W.indexErr)}</p>`; return; }
    if (!list.length) { box.innerHTML = `<p class="hint">아직 만들어진 모임 날짜가 없습니다.${editor ? ' 위에서 날짜를 만드세요.' : ' 관리자가 날짜를 만들면 여기서 참석을 체크할 수 있습니다.'}</p>`; return; }
    let html = `<div class="chips wk-sessions">${list.slice(-10).map((s) => `<button class="chip ${s.id === W.id ? 'on' : ''}" data-wk-session="${esc(s.id)}">${esc(fmtDate(s.date))}</button>`).join('')}</div>`;
    if (!doc) { box.innerHTML = html + `<p class="hint">${esc(W.docErr || '불러오는 중…')}</p>`; return; }
    const s = wkSettings(doc); const closed = wkClosed(doc) || !wkCanWrite(); const att = wkAttendees(doc); const hours = wkHours(s); // 저장 수단이 없는 방문자는 보기 전용
    const cnt = (h) => att.filter((p) => toMin(p.from) <= h * 60 && toMin(p.until) >= (h + 1) * 60).length;
    html += `<div class="wk-head"><span class="wk-date">${esc(fmtDate(doc.date))}</span><span class="sub">${esc(s.startTime)}~${esc(s.endTime)} · ${esc(wkCourtsLabel(s))} · ${s.matchMinutes}분 경기</span>${closed ? '<span class="tag">지난 모임</span>' : isToday(doc.date) ? '<span class="tag type fm">오늘</span>' : ''}</div>`;
    const members = [...state.players].sort((a, b) => a.name.localeCompare(b.name, 'ko'));
    const chip = (id, name, a, guest) => `<button class="chip wk-chip ${a ? 'on ' + (a.g === 'F' ? 'f' : 'm') : ''} ${guest ? 'guest' : ''} ${W.edit?.id === id ? 'sel' : ''} ${W.me === id ? 'me' : ''}" data-wk-chip="${esc(id)}" ${closed ? 'disabled' : ''}>${guest ? '<span class="gmark">G</span>' : ''}${esc(name)}${a ? `<small>${esc(a.from.slice(0, 2))}~${esc(a.until.slice(0, 2))}</small>` : ''}</button>`;
    const guests = att.filter((p) => p.guest);
    html += `<h3>참석 ${att.length}명 <span class="sub">(남 ${att.filter((p) => p.gender !== 'F').length} · 여 ${att.filter((p) => p.gender === 'F').length})${att.length ? ' · ' + hours.map((h) => `${h}시 ${cnt(h)}`).join(' · ') : ''}</span></h3>
      <p class="hint">${wkClosed(doc) ? '지난 모임의 참석 기록입니다.' : closed ? '참석·대진은 관리자가 입력합니다. 참석 여부는 관리자에게 알려 주세요.' : '이름을 누르고 도착·퇴장 시각을 고르면 참석이 저장됩니다. 클럽 명단에 없는 분은 [+ 게스트]로 추가하세요.'}</p>
      <div class="chips wk-chips">${members.map((p) => chip(p.id, p.name, doc.attendance[p.id], false)).join('')}${guests.map((p) => chip(p.id, p.name, doc.attendance[p.id], true)).join('')}${closed ? '' : `<button class="chip wk-chip add ${W.edit?.guest && !W.edit.id ? 'sel' : ''}" id="wk-guest-add">+ 게스트</button>`}</div>`;
    if (W.edit && !closed) html += wkPanelHtml(s);
    html += `<div class="wk-status-row"><span id="wk-status" class="sub"></span><button id="wk-retry" class="small" hidden>다시 시도</button></div>`;
    html += wkScheduleHtml(doc, s, closed);
    box.innerHTML = html;
    wkStatus(W.busy ? '저장 중…' : W.failed.length ? `저장하지 못한 변경 ${W.failed.length}건 · 다시 시도를 누르세요` : W.lastMsg || '', !!W.failed.length);
    const ni = $('#wk-guest-name'); if (ni && W.edit?.guest && !W.edit.id && !W.edit.name) ni.focus();
  }
  function wkPanelHtml(s) {
    const e = W.edit; const hours = wkHours(s); const H = (h) => String(h).padStart(2, '0') + ':00';
    const hb = (kind, list) => list.map((h) => `<button class="hbtn ${e[kind] === H(h) ? 'sel' : ''}" data-wk-hour="${H(h)}" data-wk-kind="${kind}">${h}</button>`).join('');
    const isNew = e.guest && !e.id;
    return `<div class="wk-panel">
      <div class="wk-panel-head">${e.guest ? `<input id="wk-guest-name" placeholder="게스트 이름" maxlength="20" autocomplete="off" value="${esc(e.name || '')}" ${isNew ? '' : 'disabled'}><span class="wk-gender"><button class="hbtn ${e.gender === 'M' ? 'sel' : ''}" data-wk-gender="M">남</button><button class="hbtn ${e.gender === 'F' ? 'sel' : ''}" data-wk-gender="F">여</button></span>` : `<b>${esc(e.name)}</b>`}${e.attending ? '<span class="tag">참석 중</span>' : ''}</div>
      <div class="wk-hours"><span class="lbl">도착</span>${hb('from', hours)}</div>
      <div class="wk-hours"><span class="lbl">퇴장</span>${hb('until', hours.map((h) => h + 1))}</div>
      <div class="row"><button id="wk-save" class="primary">${esc(e.from.slice(0, 2))}~${esc(e.until.slice(0, 2))}시 참석${e.attending ? '으로 변경' : ''}</button>${e.attending ? `<button id="wk-absent" class="danger-text">${e.guest ? '게스트 삭제' : '불참'}</button>` : ''}<button id="wk-close">닫기</button></div>
    </div>`;
  }
  function wkOpen(id) {
    const doc = W.doc; if (!doc) return; const s = wkSettings(doc); const a = doc.attendance[id]; const p = playerById(id); if (!a && !p) return;
    W.edit = { id, guest: a ? !!a.guest : false, name: a?.n || p?.name || '', gender: a?.g || (p?.gender === 'F' ? 'F' : 'M'), from: a?.from || s.startTime, until: a?.until || s.endTime, attending: !!a };
    renderWeeklyView(); $('.wk-panel')?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }
  async function wkSaveEdit() {
    const e = W.edit; if (!e) return; let id = e.id; const name = (e.name || '').trim();
    if (e.guest) {
      if (!name) { toast('게스트 이름을 입력하세요'); $('#wk-guest-name')?.focus(); return; }
      if (!['M', 'F'].includes(e.gender)) { toast('게스트의 남/여를 골라 주세요'); return; }
      if (!id) { if (state.players.some((p) => p.name === name)) { toast(`${name} 님은 클럽 명단에 있습니다 · 명단에서 이름을 눌러 주세요`); return; } id = guestId(name); }
    }
    if (toMin(e.from) >= toMin(e.until)) { toast('퇴장 시각이 도착보다 뒤여야 합니다'); return; }
    W.edit = null;
    const ok = await wkSend({ op: 'set', path: 'attendance.' + id, value: { n: name, g: e.gender === 'F' ? 'F' : 'M', from: e.from, until: e.until, ...(e.guest ? { guest: true } : {}) } });
    if (ok && !e.guest && !W.me) { W.me = id; localStorage.setItem('tennisweet.me', id); renderWeeklyView(); }
  }
  $('#tab-weekly')?.addEventListener('click', async (e) => {
    const t = e.target;
    const ses = t.closest('[data-wk-session]'); if (ses) { wkSelect(ses.dataset.wkSession); return; }
    const chip = t.closest('[data-wk-chip]'); if (chip && !chip.disabled) { wkOpen(chip.dataset.wkChip); return; }
    if (t.closest('#wk-guest-add')) { const s = wkSettings(W.doc); W.edit = { id: null, guest: true, name: '', gender: '', from: s.startTime, until: s.endTime, attending: false }; renderWeeklyView(); return; }
    const hb = t.closest('[data-wk-hour]'); if (hb && W.edit) { const k = hb.dataset.wkKind, v = hb.dataset.wkHour; W.edit[k] = v; if (k === 'from' && W.edit.until <= v) W.edit.until = hhmm(toMin(v) + 60); if (k === 'until' && W.edit.from >= v) W.edit.from = hhmm(toMin(v) - 60); renderWeeklyView(); return; }
    const gb = t.closest('[data-wk-gender]'); if (gb && W.edit) { W.edit.gender = gb.dataset.wkGender; renderWeeklyView(); return; }
    if (t.closest('#wk-close')) { W.edit = null; renderWeeklyView(); return; }
    if (t.closest('#wk-save')) { await wkSaveEdit(); return; }
    if (t.closest('#wk-absent') && W.edit) { const { id, name, guest } = W.edit; W.edit = null; if (confirm(guest ? `게스트 ${name} 님을 이 모임에서 삭제할까요?` : `${name} 님을 불참으로 바꿀까요?`)) await wkSend({ op: 'set', path: 'attendance.' + id, value: null }); else renderWeeklyView(); return; }
    if (t.closest('#wk-retry') && W.failed.length) { const ops = W.failed; W.failed = []; W.pending.push(...ops); for (const op of ops) wkQueue = wkQueue.then(() => wkSendNow(op)).catch(() => {}); return; } // 실패분을 순서대로 다시 전송
    const del = t.closest('[data-wk-del]'); if (del) { await wkDeleteSession(del.dataset.wkDel); return; }
    await wkScheduleClick(t);
  });
  $('#tab-weekly')?.addEventListener('input', (e) => { if (e.target.id === 'wk-guest-name' && W.edit) W.edit.name = e.target.value; });
  $('#tab-weekly')?.addEventListener('change', (e) => { if (e.target.id === 'wk-me') { W.me = e.target.value || ''; if (W.me) localStorage.setItem('tennisweet.me', W.me); else localStorage.removeItem('tennisweet.me'); renderWeeklyView(); } });
  $('#tab-weekly')?.addEventListener('keydown', (e) => { if (e.target.id === 'wk-guest-name' && e.key === 'Enter') { e.preventDefault(); $('#wk-save')?.click(); } });
  // ---- 대진 생성: 기존 개인전 생성기를 참석자·세션 설정으로 잠시 바꿔 호출 (NTRP = 레벨로 균형만, 특별 규칙·개인 선호 없음). 이력·고정 경기는 GEN_HOOK 으로 주입 ----
  function wkFromSlot(doc, s) { if (!isToday(doc.date)) return 0; const now = new Date(); const cur = now.getHours() * 60 + now.getMinutes(); const n = maxSlots(s); for (let i = 0; i < n; i++) if (slotStartMin(s, i) > cur) return i; return n; } // 아직 시작하지 않은 첫 시간대
  const wkInputHash = (doc) => fnv1a(wkAttendees(doc).map((p) => `${p.id}:${p.from}-${p.until}`).join(',')).toString(36);
  function generateWeeklySchedule(doc, hist, fromSlot, gen) {
    const ps = wkAttendees(doc); const s = wkSettings(doc);
    const fixed = fromSlot > 0 ? (doc.schedule?.matches || []).filter((m) => m.slot < fromSlot) : [];
    const inputHash = wkInputHash(doc); const seed = fnv1a(`${doc.id}|${inputHash}|${gen}|${fromSlot}`) % 1000000; // 같은 참석 상태면 어느 기기에서 눌러도 같은 판
    const saved = { players: state.players, settings: state.settings, nt: new Map(ntrp) };
    state.players = ps; state.settings = s; ntrp.clear();
    ps.forEach((p) => ntrp.set(p.id, String(wkLevelOf(p)))); // 레벨(관리자가 갱신: NTRP, 여성 −0.5)로 균형. 게스트·미입력은 3.5 로 간주
    { const menLv = ps.filter((p) => p.gender !== 'F').map((p) => wkLevelOf(p)); s.sameNtrpGame = menLv.length >= 4 ? String(Math.max(...menLv)) : ''; } // 상위 남복 1경기: 참석 남자 최고 레벨 4명 (모자라면 다음 등급 포함 상위 4명) — 대회의 '동일 NTRP 남복' 장치 재사용
    GEN_HOOK = { fromSlot, fixed, hist: hist || null, mixOk: true };
    try {
      const sch = generateRotation(s, seed);
      const matches = sch.matches.map((m) => ({ id: `s${m.slot}c${m.court}`, slot: m.slot, court: m.court, aIds: m.aIds, bIds: m.bIds })).sort((a, b) => a.slot - b.slot || a.court - b.court);
      return { seed, gen, fromSlot, inputHash, at: new Date().toISOString(), by: W.me || '', matches };
    } finally { GEN_HOOK = null; state.players = saved.players; state.settings = saved.settings; ntrp.clear(); saved.nt.forEach((v, k) => ntrp.set(k, v)); }
  }
  /** 최근 6회 모임의 파트너·상대·혼복 여성 상대 횟수 (완료 체크된 경기만, 없으면 편성 전체를 절반 가중) — 골고루 섞기용 */
  async function wkHistory(curId) {
    if (W.histFor === curId && W.hist) return W.hist;
    const cur = wkSessions().find((x) => x.id === curId); const past = cur ? wkSessions().filter((x) => x.id !== curId && x.date < cur.date).reverse().slice(0, 6) : []; // 가까운 과거부터 6회
    const H = { partner: {}, opp: {}, fmWomen: {}, sessions: 0 }; const key = (a, b) => (a < b ? a + '|' + b : b + '|' + a); const add = (o, k, v) => (o[k] = (o[k] || 0) + v);
    for (let k = 0; k < past.length; k++) {
      let d = W.cache[past[k].id]; if (!d) { d = await dataRead(`weekly/sessions/${past[k].id}.json`); if (d) { try { d = assertWeekly(d); } catch { d = null; } } if (d) W.cache[past[k].id] = d; }
      if (!d?.schedule?.matches?.length) continue; H.sessions++;
      const ms = d.schedule.matches; const dn = ms.filter((m) => d.done[m.id]); const use = dn.length ? dn : ms; const w = Math.pow(0.8, k) * (dn.length ? 1 : 0.5);
      for (const m of use) { const A = m.aIds.map((x) => x.slice(2)), B = m.bIds.map((x) => x.slice(2)); add(H.partner, key(A[0], A[1]), w); add(H.partner, key(B[0], B[1]), w); for (const x of A) for (const y of B) add(H.opp, key(x, y), w); const g = (x) => d.attendance[x]?.g; const wa = A.filter((x) => g(x) === 'F'), wb = B.filter((x) => g(x) === 'F'); if (wa.length === 1 && wb.length === 1) add(H.fmWomen, key(wa[0], wb[0]), w); }
    }
    W.hist = H; W.histFor = curId; return H;
  }
  async function wkGenerate(mode) {
    const doc = W.doc; if (!doc || wkClosed(doc) || !wkCanWrite()) return; const s = wkSettings(doc); const att = wkAttendees(doc);
    if (att.length < 4) { toast('4명 이상 참석해야 대진을 만들 수 있습니다'); return; }
    if (W.failed.some((op) => op.session === doc.id)) { toast('저장하지 못한 변경이 있습니다 · 먼저 "다시 시도"로 보낸 뒤 대진을 만드세요'); return; }
    const hasDone = Object.keys(doc.done).length > 0; let fromSlot = 0, gen = 1;
    if (mode === 'left') { fromSlot = wkFromSlot(doc, s); gen = doc.schedule?.gen || 1; if (fromSlot === 0 && hasDone && !confirm('아직 시작 전이라 전체를 다시 만듭니다. 완료 표시가 지워질 수 있습니다. 계속할까요?')) return; }
    else if (mode === 'reshuffle') { if (!confirm(hasDone ? '완료 표시된 경기가 있습니다. 전체를 새로 섞으면 완료 표시도 지워집니다. 계속할까요?' : '대진을 새로 섞을까요? 다른 분들 화면도 함께 바뀝니다.')) return; gen = (doc.schedule?.gen || 0) + 1; }
    $$('#wk-gen, #wk-regen-left, #wk-reshuffle').forEach((b) => { b.disabled = true; }); wkStatus('대진 만드는 중…');
    try {
      const hist = await wkHistory(doc.id); await new Promise((r) => setTimeout(r, 30));
      const sch = generateWeeklySchedule(doc, hist, fromSlot, gen);
      await wkSend({ op: 'generate', base: doc.rev, value: sch });
    } catch (err) { alert('대진을 만들지 못했습니다: ' + err.message); renderWeeklyView(); }
  }
  const wkSlotStatus = (t0, t1) => { const now = new Date(); const cur = now.getHours() * 60 + now.getMinutes(); return cur >= t0 && cur < t1 ? 'live' : cur >= t1 ? 'past' : ''; };
  function wkCardHtml(m, doc, done, closed, s) {
    const adj = !closed && wkCanWrite() && W.adjust === m.id; const pk = adj && W.pick && W.pick.mid === m.id ? W.pick : null; // 카드별 조정 모드 (W.adjust = 경기 id)
    const nm = (x, side, idx) => { const a = doc.attendance[x.slice(2)]; const inner = `<span class="${a ? (a.guest ? 'gname ' : 'pname ') + (a.g === 'F' ? 'f' : 'm') : ''}">${esc(wkName(doc, x.slice(2)))}</span>`; return adj ? `<button type="button" class="nm-btn ${pk && pk.side === side && pk.idx === idx ? 'sel' : ''}" data-wk-pick="${esc(m.id)}|${side}|${idx}">${inner}</button>` : inner; }; const g = (x) => (doc.attendance[x.slice(2)]?.g === 'F' ? 'F' : 'M');
    const ta = [g(m.aIds[0]), g(m.aIds[1])].sort().join(''), tb = [g(m.bIds[0]), g(m.bIds[1])].sort().join('');
    const code = ta === tb ? ta.toLowerCase() : 'mix'; const label = ta === tb ? TYPE_LABEL[ta] : '잡복';
    const gone = [...m.aIds, ...m.bIds].some((x) => !doc.attendance[x.slice(2)]); // 불참으로 바뀐 사람이 포함된 경기
    let picker = '';
    if (pk && s) { // 후보: 이 시간대에 참석 중인 사람 (이 경기의 다른 3명 제외). 같은 시간대 다른 코트에 있으면 맞교환
      const cur = m[pk.side + 'Ids'][pk.idx]; const inSlot = {}; // 같은 시간대에 편성된 사람만: 같은 코트의 나머지 3명(짝 바꾸기) + 다른 코트(맞교환). 쉬는 사람은 넣지 않는다
      for (const x of (doc.schedule?.matches || [])) if (x.slot === m.slot) for (const id of [...x.aIds, ...x.bIds]) if (id !== cur && !(x.id === m.id && m[pk.side + 'Ids'].includes(id))) inSlot[id] = x.court; // 같은 편 파트너와의 교환은 조가 안 바뀌므로 제외
      const cands = Object.keys(inSlot).map((id) => ({ id, a: doc.attendance[id.slice(2)], court: inSlot[id] })).sort((x, y) => (x.court === m.court ? 0 : 1) - (y.court === m.court ? 0 : 1) || x.court - y.court);
      picker = `<div class="wk-picker"><div class="sub">${esc(wkName(doc, cur.slice(2)))} ↔ 자리 바꿀 사람</div><div class="chips">${cands.map((c) => `<button type="button" class="chip ${c.a?.g === 'F' ? 'f' : 'm'} ${c.a?.guest ? 'guest' : ''}" data-wk-swap="${esc(c.id.slice(2))}">${c.a?.guest ? '<span class="gmark">G</span>' : ''}${esc(wkName(doc, c.id.slice(2)))}<small>${c.court === m.court ? '같은 코트' : c.court + '코트'}</small></button>`).join('')}<button type="button" class="chip" data-wk-pick-close="1">닫기</button></div></div>`;
    }
    return `<div class="mcard wk ${code ? 't-' + code : ''} ${done ? 'decided' : ''} ${gone ? 'conflict' : ''} ${adj ? 'adjusting' : ''} ${pk ? 'picking' : ''}" data-wk-done="${esc(m.id)}" role="button" tabindex="0" title="${closed ? '' : adj ? '이름을 누르면 바꿀 사람을 고릅니다' : done ? '완료 표시 취소' : '경기가 끝나면 눌러 완료 표시 (흐리게)'}">
      <div class="mhead"><b class="court">${m.court}<small>코트</small></b><span class="tag type ${code}">${esc(label)}</span>${gone ? '<span class="warn">⚠ 불참자 포함</span>' : ''}${done ? '<span class="tag wk-done">✓ 완료</span>' : ''}${!closed && wkCanWrite() ? `<button type="button" class="adj-btn ${adj ? 'on' : ''}" data-wk-adjust="${esc(m.id)}" title="${adj ? '조 조정 끝내기' : '이 경기 조 조정'}"><svg class="ic"><use href="#i-edit"/></svg>${adj ? '끝' : '조정'}</button>` : ''}</div>
      ${adj ? '<div class="sub adj-hint">이름을 누르고 자리를 바꿀 사람을 고르세요 (같은 코트 상대편 = 조 변경, 다른 코트 = 코트 맞교환)</div>' : ''}
      <div class="mbody"><div class="side"><div><b>${nm(m.aIds[0], 'a', 0)}</b> · <b>${nm(m.aIds[1], 'a', 1)}</b></div></div><div class="vs" aria-hidden="true"></div><div class="side"><div><b>${nm(m.bIds[0], 'b', 0)}</b> · <b>${nm(m.bIds[1], 'b', 1)}</b></div></div></div>${picker}</div>`;
  }
  function wkScheduleHtml(doc, s, closed) {
    let html = ''; const att = wkAttendees(doc); const sch = doc.schedule; const today = isToday(doc.date);
    if (sch || !closed) html += `<div class="wk-title"><svg class="genie" aria-hidden="true"><use href="#i-genie"/></svg><div><h3>대진표</h3><span class="sub">${sch ? '카드를 누르면 완료 표시, ✎ 조정으로 자리 바꾸기' : '참석이 모이면 지니가 골고루 섞어 드립니다'}</span></div></div>`;
    if (!closed) {
      const stale = sch && sch.inputHash !== wkInputHash(doc); const fromSlot = wkFromSlot(doc, s); const left = fromSlot < maxSlots(s);
      if (!sch) html += `<div class="row wk-gen"><button id="wk-gen" class="primary big" ${att.length < 4 ? 'disabled' : ''}><svg class="ic"><use href="#i-ball"/></svg>대진 생성</button><span class="hint">${att.length < 4 ? '4명 이상 참석하면 만들 수 있습니다.' : '참석한 사람으로 시간대별 대진을 만듭니다. 누가 눌러도 같은 판이 나오고, 모두의 화면에 뜹니다.'}</span></div>`;
      else html += `<div class="row wk-gen"><span class="sub">대진 #${sch.seed}${sch.gen > 1 ? ` (${sch.gen}번째)` : ''}${sch.by ? ' · ' + esc(wkName(doc, sch.by)) : ''}${sch.at ? ' · ' + new Date(sch.at).toLocaleString('ko-KR', { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : ''}</span>${stale ? '<span class="warn">참석이 바뀌었습니다</span>' : ''}${stale && left ? `<button id="wk-regen-left" class="primary">${fromSlot > 0 ? '남은 시간대 다시 짜기' : '대진 다시 만들기'}</button>` : ''}<button id="wk-reshuffle" class="small">다시 섞기</button></div>`;
    }
    if (sch) {
      const ms = [...sch.matches].sort((a, b) => a.slot - b.slot || a.court - b.court); const rc = wkRuleCheck(doc, s, ms);
      const filter = W.filter || 'all'; // 완료한 경기도 자리에 흐리게 남긴다 ('남은 대진' 은 선택)
      const isLeft = (m) => !doc.done[m.id]; // 예정 시각과 무관하게 완료 표시한 경기만 '남은 대진'에서 뺀다
      const leftN = ms.filter(isLeft).length;
      const meId = W.me && doc.attendance[W.me] ? W.me : ''; const isMine = (m) => !!meId && [...m.aIds, ...m.bIds].includes('p:' + meId); const mineN = ms.filter(isMine).length;
      const meSel = `<select id="wk-me" class="me" aria-label="내 이름"><option value="">이름 선택…</option>${[...att].sort((a, b) => a.name.localeCompare(b.name, 'ko')).map((p) => `<option value="${esc(p.id)}" ${p.id === meId ? 'selected' : ''}>${esc(p.name)}</option>`).join('')}</select>`;
      html += `<div class="row wk-filter"><button class="chip ${filter === 'all' ? 'on' : ''}" data-wk-filter="all">전체 ${ms.length}</button><button class="chip ${filter === 'me' ? 'on' : ''}" data-wk-filter="me">내 경기${meId ? ' ' + mineN : ''}</button>${filter === 'me' ? meSel : ''}<button class="chip ${filter === 'left' ? 'on' : ''}" data-wk-filter="left">남은 대진 ${leftN}</button>${closed ? '' : '<span class="hint">경기가 끝나면 카드를 눌러 완료 표시(흐리게). 다시 누르면 되살아납니다.</span>'}</div>`;
      html += '<div class="legend"><span class="tag type fm">혼복</span><span class="tag type mm">남복</span><span class="tag type ff">여복</span></div>';
      const nSlots = ms.length ? Math.max(...ms.map((m) => m.slot)) + 1 : 0; let shown = 0;
      for (let slot = 0; slot < nSlots; slot++) {
        let rows = ms.filter((m) => m.slot === slot); if (filter === 'left') rows = rows.filter(isLeft); if (filter === 'me') rows = rows.filter(isMine); if (!rows.length) continue; shown += rows.length;
        const t0 = slotStartMin(s, slot), t1 = t0 + s.matchMinutes; const st8 = today ? wkSlotStatus(t0, t1) : '';
        html += `<div class="slot ${st8}"><div class="slot-title"><span class="t">${hhmm(t0)}</span><span class="to">~ ${hhmm(t1)}</span>${st8 === 'live' ? '<span class="live">진행 중</span>' : ''}</div><div class="cards match-cards">${rows.map((m) => wkCardHtml(m, doc, !!doc.done[m.id], closed, s)).join('')}</div></div>`;
      }
      if (!shown) html += `<p class="hint">${filter === 'me' ? (meId ? '내 경기가 없습니다.' : '위에서 이름을 고르면 내 경기만 보입니다.') : filter === 'left' ? '남은 대진이 없습니다. 모두 완료했습니다 🎾' : '경기가 없습니다.'}</p>`;
      html += wkSummaryHtml(doc, s, ms);
      if (document.body.classList.contains('editor')) html += `<p class="hint wk-rules">${rc.issues.length ? `<b>⚠ 룰 체크 ${rc.issues.length}건</b><br>${rc.issues.map(esc).join('<br>')}${closed ? '' : '<br>✎ 조정으로 자리를 바꾸거나 다시 섞기로 해결할 수 있습니다.'}` : '✓ 룰 체크 통과 — 잡복 원칙(여자 쪽 합이 1.5 이상 부족 금지) · 시간대 중복 · 경기 수 차이 1 이내 (잡복 0.5 부족·파트너≠최고 남자·혼복 남자 급·연속 휴식은 참고 줄)'}${rc.notes.length ? `<br><span class="sub">참고: ${rc.notes.map(esc).join(' / ')}</span>` : ''}</p>`; // 관리자 화면에만 (멤버 화면에 위반 표시는 두지 않음)
    } else if (closed) html += `<p class="hint">${wkClosed(doc) ? '이 모임에는 대진이 없었습니다.' : '대진은 관리자가 만들면 여기에 표시됩니다.'}</p>`;
    return html;
  }
  /** 정기 모임 룰 체크 — 생성·조 조정 뒤 판이 규칙을 지키는지: 잡복 원칙(여자−0.5+파트너 ≥ 상대 남자 합), 혼복 남자 NTRP, 같은 시간대 중복, 경기 수 차이 */
  function wkRuleCheck(doc, s, ms) {
    const att = doc.attendance || {}; const L = W.index?.levels || {}; const lv = (id) => { const a = att[id]; if (!a) return 0; return Number.isFinite(L[id]) ? L[id] : WK_GUEST_NTRP - (a.g === 'F' ? 0.5 : 0); };
    const g = (id) => (att[id]?.g === 'F' ? 'F' : 'M'); const nm = (id) => wkName(doc, id); const bad = {}, soft = {}; const issues = [], notes = []; // bad[mid] = 위반, soft[mid] = 참고
    const flag = (m, why) => { (bad[m.id] ??= []).push(why); }; const note = (m, why) => { (soft[m.id] ??= []).push(why); };
    for (const m of ms) {
      const A = m.aIds.map((x) => x.slice(2)), B = m.bIds.map((x) => x.slice(2));
      if ([...A, ...B].some((id) => !att[id])) { flag(m, '불참자 포함'); continue; }
      const wa = A.filter((id) => g(id) === 'F').length, wb = B.filter((id) => g(id) === 'F').length; const sa = A.reduce((a, id) => a + lv(id), 0), sb = B.reduce((a, id) => a + lv(id), 0);
      if (wa + wb === 1) { const wSide = wa ? sa : sb, mSide = wa ? sb : sa; if (mSide - wSide >= 1.5) flag(m, `잡복 원칙: 여자 쪽 ${wSide} < 남자 쪽 ${mSide}`); else if (mSide > wSide) note(m, `잡복: 여자 쪽 ${wSide} < 남자 쪽 ${mSide} (${mSide - wSide} 부족, 파트너 다양성 위해 허용)`); const side = wa ? A : B, other = wa ? B : A; const mate = side.find((id) => g(id) !== 'F'); if (mate && other.some((id) => lv(id) > lv(mate))) note(m, `잡복: 여자 파트너(${nm(mate)} ${lv(mate)})가 최고 남자가 아님`); }
      else if (wa === 1 && wb === 1) { const w1 = A.find((id) => g(id) === 'F'), m1 = A.find((id) => g(id) !== 'F'), w2 = B.find((id) => g(id) === 'F'), m2 = B.find((id) => g(id) !== 'F'); if (fmMixBad(lv(w1), lv(m1), lv(w2), lv(m2))) note(m, `혼복 남자 NTRP 다름 (${lv(m1)} vs ${lv(m2)})`); } // 남자가 둘뿐인 시간대 등 불가피한 경우가 있어 참고로만
      else if (wa !== wb) flag(m, '양쪽 조 구성이 다름');
    }
    const seen = {}; for (const m of ms) for (const x of [...m.aIds, ...m.bIds]) { const k = m.slot + '|' + x; if (seen[k]) { flag(m, `${nm(x.slice(2))} 같은 시간대 중복`); } seen[k] = true; }
    const games = {}; for (const m of ms) for (const x of [...m.aIds, ...m.bIds]) games[x.slice(2)] = (games[x.slice(2)] || 0) + 1;
    const n = maxSlots(s); const avail = (id) => { const a = att[id]; let c = 0; for (let i = 0; i < n; i++) { const t0 = slotStartMin(s, i); if (toMin(a.from) <= t0 && toMin(a.until) >= t0 + s.matchMinutes) c++; } return c; };
    const ids = Object.keys(att); const maxG = ids.length ? Math.max(...ids.map((id) => games[id] || 0)) : 0;
    const short = ids.filter((id) => (games[id] || 0) < avail(id) && (games[id] || 0) < maxG - 1).map((id) => `${nm(id)} ${games[id] || 0}`);
    if (short.length) issues.push(`경기 수 2 이상 부족: ${short.join(', ')} (최다 ${maxG})`);
    { const playedAt = {}; for (const m of ms) for (const x of [...m.aIds, ...m.bIds]) (playedAt[x.slice(2)] ??= new Set()).add(m.slot); const dbl = []; for (const id of ids) { const a = att[id]; const set = playedAt[id] || new Set(); for (let sl = 1; sl < n; sl++) { const av = (i) => { const t0 = slotStartMin(s, i); return toMin(a.from) <= t0 && toMin(a.until) >= t0 + s.matchMinutes; }; if (av(sl - 1) && av(sl) && !set.has(sl - 1) && !set.has(sl)) { dbl.push(`${nm(id)} ${hhmm(slotStartMin(s, sl - 1))}~`); break; } } } if (dbl.length) notes.push(`연속 2회 휴식: ${dbl.join(', ')} (경기 수 균등을 위해 허용)`); }
    for (const m of ms) if (bad[m.id]) issues.push(`${hhmm(slotStartMin(s, m.slot))} ${m.court}코트 — ${bad[m.id].join(' · ')}`);
    for (const m of ms) if (soft[m.id]) notes.push(`${hhmm(slotStartMin(s, m.slot))} ${m.court}코트 — ${soft[m.id].join(' · ')}`);
    { const men = ids.filter((id) => g(id) !== 'F').sort((a, b) => lv(b) - lv(a)); if (men.length >= 4) { const th = lv(men[3]); const top = ms.find((m) => { const all = [...m.aIds, ...m.bIds].map((x) => x.slice(2)); return all.every((id) => att[id] && g(id) !== 'F' && lv(id) >= th); }); notes.push(top ? `상위 남복 있음: ${hhmm(slotStartMin(s, top.slot))} ${top.court}코트` : '상위 남복 없음 (다시 섞기로 만들 수 있음)'); } }
    return { bad, issues, notes };
  }
  /** 인당 경기 수 요약 (접기) */
  function wkSummaryHtml(doc, s, ms) {
    const att = wkAttendees(doc); if (!att.length || !ms.length) return '';
    const games = {}, tc = {}; const g = (id) => (doc.attendance[id]?.g === 'F' ? 'F' : 'M');
    const typeOf = (m) => { const A = m.aIds.map((x) => x.slice(2)), B = m.bIds.map((x) => x.slice(2)); const ta = [g(A[0]), g(A[1])].sort().join(''), tb = [g(B[0]), g(B[1])].sort().join(''); return ta === tb ? ta : 'MIX'; };
    for (const m of ms) { const A = m.aIds.map((x) => x.slice(2)), B = m.bIds.map((x) => x.slice(2)); const t = typeOf(m); for (const x of [...A, ...B]) { games[x] = (games[x] || 0) + 1; (tc[x] ??= { FF: 0, FM: 0, MM: 0, MIX: 0 })[t]++; } }
    const rows = [...att].sort((a, b) => (games[b.id] || 0) - (games[a.id] || 0) || a.name.localeCompare(b.name, 'ko'));
    const cnts = rows.map((p) => games[p.id] || 0); const mn = Math.min(...cnts), mx = Math.max(...cnts);
    const tot = { FM: 0, MM: 0, FF: 0, MIX: 0 }; for (const m of ms) tot[typeOf(m)]++;
    return `<div class="wk-summary"><h3>인당 경기 수 <span class="sub">(최소 ${mn} · 최대 ${mx} · 총 ${ms.length}경기 = 혼복 ${tot.FM} · 남복 ${tot.MM} · 여복 ${tot.FF}${tot.MIX ? ` · 잡복 ${tot.MIX}` : ''})</span></h3><div class="table-wrap"><table class="stand summary"><thead><tr><th>이름</th><th>시간</th><th class="num">경기</th><th class="num">혼복</th><th class="num">남복</th><th class="num">여복</th>${tot.MIX ? '<th class="num">잡복</th>' : ''}</tr></thead><tbody>${rows.map((p) => { const t = tc[p.id] || {}; const gN = games[p.id] || 0; return `<tr class="${gN === mx && mx !== mn ? 'hi' : ''} ${gN === mn && mx !== mn ? 'lo' : ''}"><td><b class="${p.guest ? 'gname' : 'pname'} ${p.gender === 'F' ? 'f' : 'm'}">${esc(p.name)}</b></td><td class="sub">${esc(p.from.slice(0, 2))}~${esc(p.until.slice(0, 2))}</td><td class="num"><b>${gN}</b></td><td class="num">${t.FM || '-'}</td><td class="num">${t.MM || '-'}</td><td class="num">${t.FF || '-'}</td>${tot.MIX ? `<td class="num">${t.MIX || '-'}</td>` : ''}</tr>`; }).join('')}</tbody></table></div></div>`;
  }
  async function wkScheduleClick(t) {
    if (t.closest('#wk-gen')) { await wkGenerate('full'); return; }
    if (t.closest('#wk-regen-left')) { await wkGenerate('left'); return; }
    if (t.closest('#wk-reshuffle')) { await wkGenerate('reshuffle'); return; }
    const fb = t.closest('[data-wk-filter]'); if (fb) { W.filter = fb.dataset.wkFilter; renderWeeklyView(); return; }
    const ab = t.closest('[data-wk-adjust]'); if (ab) { const mid = ab.dataset.wkAdjust; W.adjust = W.adjust === mid ? null : mid; W.pick = null; renderWeeklyView(); return; }
    if (t.closest('[data-wk-pick-close]')) { W.pick = null; renderWeeklyView(); return; }
    const pb = t.closest('[data-wk-pick]'); if (pb) { const [mid, side, idx] = pb.dataset.wkPick.split('|'); W.pick = W.pick && W.pick.mid === mid && W.pick.side === side && +W.pick.idx === +idx ? null : { mid, side, idx: +idx }; renderWeeklyView(); if (W.pick) $('.wk-picker')?.scrollIntoView({ block: 'nearest', behavior: 'smooth' }); return; }
    const sw = t.closest('[data-wk-swap]'); if (sw && W.pick && W.doc && !wkClosed(W.doc) && wkCanWrite()) { await wkSwap(sw.dataset.wkSwap); return; }
    const card = t.closest('[data-wk-done]'); if (card && W.adjust === card.dataset.wkDone) return; // 조정 중인 카드는 탭해도 완료 표시로 바뀌지 않게
    if (card && W.doc && !wkClosed(W.doc) && wkCanWrite()) { const mid = card.dataset.wkDone; const done = !!W.doc.done[mid]; await wkSend({ op: 'set', path: 'done.' + mid, value: done ? null : true }); } // 다시 누르면 완료 취소
  }
  /** 조 조정: 고른 자리(W.pick)의 사람을 pid 로 바꾼다. pid 가 같은 시간대 다른 코트에 있으면 맞교환, 쉬는 사람이면 교체 */
  async function wkSwap(pid) {
    const doc = W.doc, pk = W.pick; if (!doc?.schedule || !pk) return;
    if (W.failed.some((op) => op.session === doc.id)) { W.pick = null; renderWeeklyView(); toast('저장하지 못한 변경이 있습니다 · 먼저 "다시 시도"로 보낸 뒤 조를 조정하세요'); return; }
    const ms = doc.schedule.matches; const m = ms.find((x) => x.id === pk.mid); if (!m) return;
    const cur = m[pk.side + 'Ids'][pk.idx]; const nid = 'p:' + pid; if (cur === nid) { W.pick = null; renderWeeklyView(); return; }
    const copy = (x) => ({ id: x.id, aIds: x.aIds.slice(), bIds: x.bIds.slice() });
    const e1 = copy(m); const value = [e1]; const prev = { [m.id]: [m.aIds.slice(), m.bIds.slice()] };
    const here = [...m.aIds, ...m.bIds].includes(nid); const other = here ? null : ms.find((x) => x.slot === m.slot && x.id !== m.id && [...x.aIds, ...x.bIds].includes(nid));
    if (!here && !other) { toast('이 시간대에 편성된 사람끼리만 자리를 바꿀 수 있습니다'); return; }
    e1[pk.side + 'Ids'][pk.idx] = nid;
    if (here) { for (const side of ['a', 'b']) e1[side + 'Ids'] = e1[side + 'Ids'].map((x, i) => (x === nid && !(side === pk.side && i === pk.idx) ? cur : x)); } // 같은 코트: 두 자리를 맞바꿔 조 구성 변경
    else { const e2 = copy(other); for (const side of ['a', 'b']) { const i = e2[side + 'Ids'].indexOf(nid); if (i >= 0) e2[side + 'Ids'][i] = cur; } value.push(e2); prev[other.id] = [other.aIds.slice(), other.bIds.slice()]; }
    W.pick = null; W.adjust = null; // 한 번 바꾸면 조정 모드 종료
    await wkSend({ op: 'edit', base: doc.rev, value, prev });
  }
  /** 관리자: 모임 삭제 (목록에서 빼고 세션 파일도 지움) */
  async function wkDeleteSession(id) {
    if (!SESSION_RE.test(id)) return;
    const d = W.id === id ? W.doc : (W.cache[id] || null); const n = d ? Object.keys(d.attendance || {}).length : null;
    if (!confirm(`${fmtDate(id)} 모임을 삭제할까요?${n ? `\n참석 ${n}명의 체크와 대진이 함께 지워집니다.` : ''}`)) return;
    const ok = await dataAdminUpdate('weekly/index.json', (cur) => { const idx = cur && typeof cur === 'object' ? cur : { v: 1, sessions: [] }; idx.sessions = (idx.sessions || []).filter((x) => x.id !== id); idx.updatedAt = new Date().toISOString(); return idx; }, `정기 모임 ${id} 삭제`);
    if (!ok) return;
    await dataAdminDelete(`weekly/sessions/${id}.json`, `정기 모임 ${id} 파일 삭제`); delete wkFresh[`weekly/sessions/${id}.json`]; await wkProxyRefresh(id);
    delete W.cache[id]; if (W.id === id) { W.id = null; W.doc = null; W.srvRev = -1; } toast(`${fmtDate(id)} 모임을 삭제했습니다`); await weeklyRefresh();
  }
  /** 관리자 토큰으로 정기 모임 파일 삭제 (main·gh-pages, 없으면 무시) */
  async function dataAdminDelete(path, msg) {
    if (WK_MOCK) { wkMock.set(path, null); return true; }
    const tok = await loadToken(); if (!tok) return false; let ok = true;
    for (const br of GH.branches) {
      try {
        const url = `https://api.github.com/repos/${GH.owner}/${GH.repo}/contents/${WK_PATH(path)}`;
        const cur = await fetch(`${url}?ref=${br}&_=${Date.now()}`, { headers: ghHeaders(tok), cache: 'no-store' }); if (cur.status === 404) continue; if (!cur.ok) { ok = false; continue; }
        const { sha } = await cur.json();
        const res = await fetch(url, { method: 'DELETE', headers: { ...ghHeaders(tok), 'Content-Type': 'application/json' }, body: JSON.stringify({ message: msg, sha, branch: br }) }); if (!res.ok && br === 'main') ok = false;
      } catch { ok = false; }
    }
    if (!ok) toast('파일 삭제는 실패했지만 목록에서는 뺐습니다'); return ok;
  }
  // ---- 관리자: 날짜 만들기 · 프록시 주소 ----
  $('#wk-form-session')?.addEventListener('submit', async (e) => {
    e.preventDefault(); const f = e.target; const fd = new FormData(f); const date = String(fd.get('date') || ''); if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return;
    const st = { startTime: String(fd.get('startTime') || '18:00'), endTime: String(fd.get('endTime') || '22:00'), matchMinutes: Math.max(5, parseInt(fd.get('matchMinutes'), 10) || 30), breakMinutes: 0, courts: 2, minWomenDoubles: Math.max(0, parseInt(fd.get('minWomenDoubles'), 10) || 0) };
    if (!TIME_RE.test(st.startTime) || !TIME_RE.test(st.endTime) || toMin(st.startTime) >= toMin(st.endTime)) { alert('시작·종료 시각을 확인하세요.'); return; }
    { const cb = {}; let mx = 0; for (const h of wkHours(st)) { const v = Math.max(0, Math.min(8, parseInt(fd.get('c_' + h), 10) || 0)); cb[String(h)] = v; mx = Math.max(mx, v); } if (!mx) { alert('코트 수를 입력하세요.'); return; } st.courts = mx; if (new Set(Object.values(cb)).size > 1) st.courtsByHour = cb; } // 시간대마다 코트 수가 다르면 저장
    const id = date; const btn = f.querySelector('button[type=submit]'); const label = btn.innerHTML; btn.disabled = true; btn.textContent = '만드는 중… (5초 정도)';
    try {
      if (wkSessions().some((x) => x.id === id)) { alert('이미 있는 날짜입니다.'); return; }
      const [ok1, ok2] = await Promise.all([ // 세션 파일과 목록을 동시에 (각각 원본·사본 동시 커밋)
        dataAdminUpdate(`weekly/sessions/${id}.json`, (cur) => cur || { v: 1, id, date, status: 'open', rev: 0, settings: st, attendance: {}, schedule: null, done: {}, createdAt: new Date().toISOString() }, `정기 모임 ${date} 생성`),
        dataAdminUpdate('weekly/index.json', (cur) => { const idx = cur && typeof cur === 'object' ? cur : { v: 1, sessions: [] }; idx.v = 1; idx.sessions = (idx.sessions || []).filter((x) => x.id !== id); idx.sessions.push({ id, date, courts: st.courts, matchMinutes: st.matchMinutes, startTime: st.startTime, endTime: st.endTime, courtsLabel: wkCourtsLabel(st) }); idx.sessions.sort((a, b) => (a.date < b.date ? 1 : -1)); idx.updatedAt = new Date().toISOString(); return idx; }, `정기 모임 ${date} 목록 추가`),
      ]);
      if (ok1 && ok2) { toast(`${fmtDate(date)} 모임을 만들었습니다 · 아래 목록에 추가됨`, 5000); W.id = id; W.doc = null; W.srvRev = -1; W.adjust = null; W.pick = null; if (adminKey || WK_MOCK) await wkSaveLevels({ quiet: true }); await weeklyRefresh(); await wkProxyRefresh(id); $('#wk-admin-list')?.scrollIntoView({ block: 'nearest', behavior: 'smooth' }); }
    } finally { btn.disabled = false; btn.innerHTML = label; }
  });
  /** 레벨 산출: NTRP(관리자 키로 복호화된 값), 여성은 −0.5 보정. 누구나 대진을 만들 수 있으려면 이 값이 공개 파일(index.json)에 있어야 한다 — 화면에는 표시하지 않는다 */
  const WK_GUEST_NTRP = 3.5; // 레벨을 모르는 참석자(게스트·NTRP 미입력)는 3.5 로 간주 (여성은 −0.5 → 3.0)
  const wkLevelOf = (p) => { const v = W.index?.levels?.[p.id]; return Number.isFinite(v) ? v : WK_GUEST_NTRP - (p.gender === 'F' ? 0.5 : 0); };
  function wkLevelsFromPlayers() {
    const out = {};
    for (const p of state.players) { const v = parseFloat(ntrp.get(p.id)); if (!Number.isFinite(v) || v <= 0) continue; out[p.id] = Math.round((v - (p.gender === 'F' ? 0.5 : 0)) * 100) / 100; }
    return out;
  }
  async function wkSaveLevels({ quiet = false } = {}) {
    if (!adminKey && !WK_MOCK) { if (!quiet) toast('관리자 로그인 상태에서만 갱신할 수 있습니다'); return false; }
    const levels = wkLevelsFromPlayers(); const n = Object.keys(levels).length;
    if (!n) { if (!quiet) toast('NTRP 가 입력된 선수가 없습니다'); return false; }
    const ok = await dataAdminUpdate('weekly/index.json', (cur) => { const idx = cur && typeof cur === 'object' ? cur : { v: 1, sessions: [] }; idx.levels = levels; idx.levelsAt = new Date().toISOString(); idx.updatedAt = idx.levelsAt; return idx; }, `정기 모임 레벨 갱신 (${n}명)`);
    if (ok) { if (!quiet) toast(`레벨을 갱신했습니다 · ${n}명`); await weeklyRefresh(); }
    return ok;
  }
  $('#wk-levels')?.addEventListener('click', () => wkSaveLevels());
  $('#wk-form-proxy')?.addEventListener('submit', async (e) => {
    e.preventDefault(); const url = String(new FormData(e.target).get('proxy') || '').trim();
    if (url && !PROXY_RE.test(url)) { alert('Apps Script 웹앱 주소 형식이 아닙니다 (https://script.google.com/macros/s/…/exec).'); return; }
    const st = $('#wk-proxy-status'); if (st) st.textContent = '저장 중…';
    if (await dataAdminUpdate('weekly/index.json', (cur) => { const idx = cur && typeof cur === 'object' ? cur : { v: 1, sessions: [] }; idx.proxy = url; idx.updatedAt = new Date().toISOString(); return idx; }, '정기 모임 저장 서버 주소 설정')) { toast(url ? '저장 서버 주소를 저장했습니다' : '저장 서버 주소를 지웠습니다'); if (st) st.textContent = (url ? '✓ 저장됨 ' : '✓ 지움 ') + new Date().toLocaleTimeString('ko-KR', { hour: '2-digit', minute: '2-digit' }); await weeklyRefresh(); } else if (st) st.textContent = '저장 실패';
  });
  $('#wk-ping')?.addEventListener('click', async () => {
    const url = String($('#wk-form-proxy [name=proxy]')?.value || '').trim(); if (WK_MOCK) { toast('로컬 모의 저장소에서는 확인할 수 없습니다'); return; } if (!PROXY_RE.test(url)) { toast('주소를 먼저 입력하세요'); return; }
    const st = $('#wk-proxy-status'); if (st) st.textContent = '확인 중…';
    try { const r = await fetch(url, { method: 'POST', body: JSON.stringify({ v: 1, club: 'tennisweet', session: '2000-01-01', op: 'ping' }), redirect: 'follow' }); const j = await r.json(); const msg = j.ok ? `✓ 연결됨 · 서버 시각 ${new Date(j.t).toLocaleTimeString('ko-KR')}` : '응답은 왔지만 형식이 다릅니다'; toast(msg); if (st) st.textContent = msg; } catch (e) { toast('연결 실패: ' + e.message); if (st) st.textContent = '✗ 연결 실패: ' + e.message; }
  });
  /** 정기 모임 생성 폼: 시작~종료 사이 매 시각의 코트 수 입력칸 (기본은 이전 값 또는 2) */
  function wkRenderCourtInputs() {
    const f = $('#wk-form-session'); const box = $('#wk-court-hours'); if (!f || !box) return;
    const st = { startTime: f.startTime.value || '18:00', endTime: f.endTime.value || '22:00' }; if (!TIME_RE.test(st.startTime) || !TIME_RE.test(st.endTime)) return;
    const prev = {}; box.querySelectorAll('input').forEach((i) => (prev[i.name] = i.value));
    box.innerHTML = wkHours(st).map((h) => `<label class="inline wk-ch">${h}시 <input name="c_${h}" type="number" min="0" max="8" value="${esc(prev['c_' + h] ?? '2')}" style="width:52px"></label>`).join('');
  }
  $('#wk-form-session')?.addEventListener('change', (e) => { if (e.target.name === 'startTime' || e.target.name === 'endTime') wkRenderCourtInputs(); });
  function weeklyBoot() { const f = $('#wk-form-session [name=date]'); if (f && !f.value) { const d = new Date(); d.setDate(d.getDate() + ((6 - d.getDay() + 7) % 7 || 7)); f.value = ymdOf(d); } wkRenderCourtInputs(); weeklyRefresh(); } // 기본값: 다음 토요일

  // ================= ⑧ 대회 페이지 (이번 대회 + 지난 대회 보관 — 대진과 참가자만, 점수·순위·NTRP 는 저장하지 않음) =================
  const ARCH_RE = /^[A-Za-z0-9_-]{1,30}$/;
  const T = { index: null, indexErr: '', doc: null };
  async function archRead(path) { // 코드 저장소 data/archive/… (정적 파일). 로컬은 모의 저장소에 있으면 그것을, 없으면 실제 파일
    if (WK_MOCK) { const m = wkMock.get('data/' + path); if (m) return m; }
    try { const r = await fetch('data/' + path + '?_=' + Date.now(), { cache: 'no-store' }); if (!r.ok) return null; return await r.json(); } catch { return null; }
  }
  async function ghGetJson(tok, path, branch) {
    const r = await fetch(`https://api.github.com/repos/${GH.owner}/${GH.repo}/contents/${path}?ref=${branch}&_=${Date.now()}`, { headers: ghHeaders(tok), cache: 'no-store' });
    if (r.status === 404) return null; if (r.status === 401 || r.status === 403) throw Object.assign(new Error('AUTH'), { status: r.status }); if (!r.ok) throw new Error(`조회 실패 (${r.status})`);
    const b = await r.json(); let json = null; try { json = JSON.parse(new TextDecoder().decode(unb64(String(b.content || '').replace(/\n/g, '')))); } catch {} return { sha: b.sha || null, json };
  }
  /** 관리자 토큰으로 코드 저장소 data/… 파일 갱신: main 원본 + gh-pages 서빙 사본 (게시하기와 같은 방식). mutate(json|null) → 새 json, null 이면 중단 */
  async function repoAdminUpdate(path, mutate, msg, { quiet = false } = {}) {
    if (WK_MOCK) { const next = mutate(wkMock.get(path)); if (next == null) return false; wkMock.set(path, next); return true; }
    let tok = await loadToken(); if (!tok) { tok = await askToken(); if (!tok) return false; await saveToken(tok); }
    for (let retry = 0; retry < 4; retry++) {
      try {
        const got = await ghGetJson(tok, path, 'main'); const cur = got ? got.json : null; const next = mutate(cur); if (next == null) return false;
        const content = JSON.stringify(next, null, 1) + '\n';
        try { await ghPutFile(tok, 'main', content, msg, { path, expectSha: got ? got.sha : null }); } // 원본 먼저, 읽은 sha 기준(CAS)
        catch (e) { if (e.message === 'STALE' && retry < 3) continue; throw e; } // 그사이 다른 저장(멤버·프록시) → 다시 읽어 그 위에 적용
        const fails = []; for (const br of GH.branches.slice(1)) { try { await ghPutFile(tok, br, content, msg, { path }); } catch { fails.push(br); } } // 서빙 사본은 원본에 확정된 내용만
        if (fails.length) toast(`${fails.join(', ')} 사본 쓰기 실패 · 방문자 화면에는 다음 저장 때 반영됩니다`);
        return true;
      } catch (e) {
        if (e.message === 'STALE') { if (!quiet) toast('다른 저장이 몰려 있습니다 · 잠시 후 다시 시도하세요'); return false; } // CAS 4회 소진
        if ((e.message === 'AUTH' || e.message === 'NOPERM') && retry === 0) { forgetToken(); const t2 = await askToken(e.message === 'AUTH' ? '토큰이 거부되었습니다 (만료·오타). 새 토큰을 넣어 주세요.' : '이 토큰으로는 저장소에 쓸 수 없습니다. 새 토큰을 넣어 주세요.'); if (!t2) return false; await saveToken(t2); tok = t2; continue; }
        alert('저장 실패: ' + e.message); return false;
      }
    }
    return false;
  }
  /** 보관본 만들기: 화이트리스트로만 구성 (results·ntrpEnc·특별 규칙·토큰이 들어갈 길이 없음) */
  function buildArchive(id) {
    const s = state.settings, sch = state.schedule; if (!sch) return null;
    const ms = sch.matches.filter((m) => !m.bye).map((m) => { const o = { id: m.id, phase: m.phase, slot: m.slot, court: m.court }; for (const k of ['round', 'group', 'koRound', 'koSize', 'koIndex', 'third', 'aId', 'bId', 'aIds', 'bIds', 'aPlayers', 'bPlayers', 'aLabel', 'bLabel']) if (m[k] != null) o[k] = m[k]; return o; });
    const used = new Set(); ms.forEach((m) => matchPeople(m).filter(Boolean).forEach((x) => used.add(x))); state.units.forEach((u) => u.playerIds.forEach((x) => used.add(x)));
    return { v: 1, id, name: s.name || '', date: s.date || '', archivedAt: new Date().toISOString(),
      settings: { mode: s.mode, discipline: s.discipline, courts: s.courts, startTime: s.startTime, endTime: s.endTime || '', matchMinutes: s.matchMinutes, breakMinutes: s.breakMinutes, venue: venueOf() },
      players: state.players.filter((p) => used.has(p.id)).map((p) => ({ id: p.id, name: p.name, gender: p.gender || '' })),
      units: state.units.filter((u) => u.playerIds.length).map((u) => ({ id: u.id, name: u.name || '', playerIds: [...u.playerIds] })),
      schedule: { matches: ms, unitIds: [...(sch.unitIds || [])], groups: sch.groups || [], extraSlots: sch.extraSlots || 0 },
      results: Object.fromEntries(Object.entries(state.results || {}).filter(([mid, arr]) => ms.some((m) => m.id === mid) && Array.isArray(arr) && arr.some((r) => r && (r.a !== '' || r.b !== ''))).map(([mid, arr]) => [mid, arr.map((r) => ({ a: String(r?.a ?? ''), b: String(r?.b ?? '') }))])) };
  }
  /** 외부에서 온 보관본 검증: id 형식·금지 키 제거 (이중 방어) */
  function assertArchive(doc) {
    if (!doc || typeof doc !== 'object' || !ARCH_RE.test(String(doc.id || ''))) throw new Error('보관본 형식 오류');
    for (const k of ['ntrpEnc', 'ghTokenEnc', 'mustFace', 'sameNtrpGame', 'avoidPairs', 'notes']) delete doc[k];
    doc.players = (Array.isArray(doc.players) ? doc.players : []).filter((p) => p && ID_RE.test(String(p.id))).map((p) => ({ id: p.id, name: String(p.name || '').slice(0, 30), gender: p.gender === 'F' ? 'F' : p.gender === 'M' ? 'M' : '' }));
    doc.units = (Array.isArray(doc.units) ? doc.units : []).filter((u) => u && ID_RE.test(String(u.id))).map((u) => ({ id: u.id, name: String(u.name || '').slice(0, 30), playerIds: (Array.isArray(u.playerIds) ? u.playerIds : []).filter((x) => typeof x === 'string' && ID_RE.test(x)) }));
    doc.schedule = { matches: Array.isArray(doc.schedule?.matches) ? doc.schedule.matches : [] }; doc.results = doc.results && typeof doc.results === 'object' ? doc.results : {}; assertIds({ schedule: doc.schedule, results: doc.results });
    doc.settings = { ...(doc.settings || {}) }; for (const k of ['courts', 'matchMinutes', 'breakMinutes']) doc.settings[k] = Math.max(0, parseInt(doc.settings[k], 10) || 0); for (const k of ['startTime', 'endTime']) if (!TIME_RE.test(doc.settings[k] || '')) doc.settings[k] = k === 'startTime' ? '09:00' : '';
    { const v = doc.settings.venue; const LIM = { name: 60, time: 40, addr: 120, phone: 30, menu: 60, note: 200 }; const out = {}; for (const k of Object.keys(LIM)) out[k] = typeof v?.[k] === 'string' ? v[k].trim().slice(0, LIM[k]) : ''; doc.settings.venue = out; }
    doc.name = String(doc.name || '').slice(0, 60); doc.date = /^\d{4}-\d{2}-\d{2}$/.test(String(doc.date || '')) ? doc.date : '';
    return doc;
  }
  const MODE_KO = { team: '팀전', rotation: '개인전', individual: '고정조 대회' };
  function archiveHtml(doc) {
    const P = {}; doc.players.forEach((p) => (P[p.id] = p)); const U = {}; doc.units.forEach((u) => (U[u.id] = u));
    const pn = (id) => esc(P[id]?.name || '?'); const g = (id) => (P[id]?.gender === 'F' ? 'F' : 'M');
    const un = (id) => { const u = U[id]; return u ? `<b>${esc(u.name || u.playerIds.map((x) => P[x]?.name || '?').join('·'))}</b>` : '<span class="tbd">미정</span>'; };
    const people = (m, sd) => m[sd + 'Players'] ? m[sd + 'Players'].filter(Boolean) : (m[sd + 'Ids'] || [m[sd + 'Id']]).filter(Boolean).flatMap((id) => U[id]?.playerIds || []);
    const side = (m, sd) => m[sd + 'Players'] ? `<div>${un(m[sd + 'Id'])}<div class="sub">${m[sd + 'Players'].map((id) => (id ? pn(id) : '<i>미정</i>')).join(' · ')}</div></div>` : m[sd + 'Ids'] ? `<div>${m[sd + 'Ids'].map(un).join(' · ')}</div>` : `<div>${m[sd + 'Id'] ? un(m[sd + 'Id']) : `<span class="tbd">${esc(m[sd + 'Label'] || '미정')}</span>`}</div>`;
    const s = doc.settings; const slotT = (i) => hhmm(toMin(s.startTime || '09:00') + i * ((s.matchMinutes || 30) + (s.breakMinutes || 0)));
    const R = doc.results || {}; const scoreOf = (m) => { const arr = R[m.id]; if (!Array.isArray(arr)) return null; const r = arr.find((x) => x && (x.a !== '' || x.b !== '')); if (!r) return null; const a = Number(r.a), b = Number(r.b); return { a: r.a, b: r.b, w: r.a !== '' && r.b !== '' ? (a > b ? 'a' : b > a ? 'b' : '') : '' }; };
    const nameOf = (m, sd) => m[sd + 'Players'] ? (U[m[sd + 'Id']] ? (U[m[sd + 'Id']].name || '') : '') || m[sd + 'Players'].map((id) => P[id]?.name || '?').join('·') : m[sd + 'Ids'] ? m[sd + 'Ids'].map((id) => U[id]?.name || U[id]?.playerIds.map((x) => P[x]?.name || '?').join('·') || '?').join(' · ') : U[m[sd + 'Id']] ? (U[m[sd + 'Id']].name || U[m[sd + 'Id']].playerIds.map((x) => P[x]?.name || '?').join('·')) : '';
    const ms = [...doc.schedule.matches].filter((m) => !m.bye && scoreOf(m)).sort((a, b) => (a.slot ?? 0) - (b.slot ?? 0) || (a.court ?? 0) - (b.court ?? 0)); // 점수가 기록된 경기만
    let html = `<div class="row"><button id="arch-back">← 지난 대회 목록</button></div><div class="tour-card"><div class="tour-head"><b>${esc(doc.name || doc.id)}</b><span class="sub">${esc(doc.date)}${doc.date ? ' · ' : ''}${MODE_KO[s.mode] || ''} · 코트 ${s.courts || '?'}면 · 기록 ${ms.length}경기${s.venue.name ? ` · 회식 ${esc(s.venue.name)}` : ''}</span></div>
      <div class="chips">${doc.players.map((p) => `<span class="chip ${p.gender === 'F' ? 'f' : ''}">${esc(p.name)}</span>`).join('') || '<span class="tbd">참가자 정보 없음</span>'}</div></div>`;
    const nSlots = ms.length ? Math.max(...ms.map((m) => m.slot ?? 0)) + 1 : 0;
    for (let slot = 0; slot < nSlots; slot++) {
      const rows = ms.filter((m) => (m.slot ?? 0) === slot); if (!rows.length) continue;
      html += `<div class="slot"><div class="slot-title"><span class="t">${slotT(slot)}</span><span class="to">~ ${slotT(slot + 1)}</span></div><div class="cards match-cards">${rows.map((m) => {
        const A = people(m, 'a'), B = people(m, 'b'); const ta = A.length === 2 ? A.map(g).sort().join('') : '', tb = B.length === 2 ? B.map(g).sort().join('') : ''; const code = ta && ta === tb ? ta.toLowerCase() : '';
        const ph = m.phase === 'ko' ? `<span class="tag">${esc(m.third ? '3·4위전' : m.koSize === 2 ? '결승' : m.koSize === 4 ? '준결승' : `${m.koSize}강`)}</span>` : m.phase === 'group' ? `<span class="tag">${GROUP_NAMES[m.group] || ''}조</span>` : '';
        const sc = scoreOf(m); const foot = sc ? `<div class="mfoot"><span class="score-text"><b>${esc(sc.a || '-')}</b><span class="colon">:</span><b>${esc(sc.b || '-')}</b></span>${sc.w ? `<span class="done">${esc(nameOf(m, sc.w))} 승</span>` : ''}</div>` : '';
        return `<div class="mcard ${code ? 't-' + code : ''} ${sc?.w ? 'decided' : ''}"><div class="mhead"><b class="court">${m.court ?? ''}<small>코트</small></b>${ph}${code ? `<span class="tag type ${code}">${TYPE_LABEL[ta]}</span>` : ''}</div><div class="mbody"><div class="side ${sc?.w === 'a' ? 'w' : ''}">${side(m, 'a')}</div><div class="vs" aria-hidden="true"></div><div class="side ${sc?.w === 'b' ? 'w' : ''}">${side(m, 'b')}</div></div>${foot}</div>`; }).join('')}</div></div>`;
    }
    if (!ms.length) html += '<p class="hint">점수가 기록된 경기가 없습니다.</p>';
    else html += archivePodium(doc, ms, P, U, scoreOf);
    const v = s.venue || {}; if (v.name || v.addr || v.note) html += `<h3>회식 장소</h3>${venueCardHtml(v)}`;
    return html;
  }
  /** 보관본 순위 상위 3 (승률 → 경기당 평균 득실 → 승수 → 득게임): 개인전은 선수, 팀전은 개인 기록, 고정조는 조 */
  function archivePodium(doc, ms, P, U, scoreOf) {
    const mode = doc.settings.mode; const rows = {}; const row = (id) => (rows[id] ??= { id, p: 0, w: 0, l: 0, d: 0, gf: 0, ga: 0 });
    for (const m of ms) {
      const sc = scoreOf(m); if (!sc || sc.a === '' || sc.b === '') continue; const a = Number(sc.a), b = Number(sc.b); if (!Number.isFinite(a) || !Number.isFinite(b)) continue;
      const A = mode === 'team' ? (m.aPlayers || []).filter(Boolean) : (m.aIds || [m.aId]).filter(Boolean), B = mode === 'team' ? (m.bPlayers || []).filter(Boolean) : (m.bIds || [m.bId]).filter(Boolean);
      A.forEach((id) => { const r = row(id); r.p++; r.gf += a; r.ga += b; if (a > b) r.w++; else if (b > a) r.l++; else r.d++; });
      B.forEach((id) => { const r = row(id); r.p++; r.gf += b; r.ga += a; if (b > a) r.w++; else if (a > b) r.l++; else r.d++; });
    }
    const list = Object.values(rows).filter((r) => r.p > 0).sort(fairCmp).slice(0, 3); if (!list.length) return '';
    const nameOf = (id) => mode === 'team' ? (P[id]?.name || '?') : U[id] ? (U[id].name || U[id].playerIds.map((x) => P[x]?.name || '?').join('·')) : '?';
    const medal = ['🥇', '🥈', '🥉'];
    return `<h3>${mode === 'team' ? '개인 기록 상위 3' : '순위 상위 3'} <span class="sub">(승률 → 경기당 평균 득실 → 승수)</span></h3>
      <ol class="podium">${list.map((r, i) => `<li class="p${i + 1}"><span class="medal">${medal[i]}</span><span class="pname">${esc(nameOf(r.id))}</span><span class="pstat">${r.w}승 ${r.l}패${r.d ? ` ${r.d}무` : ''} · 승률 ${pct(r)} · 평균 득실 ${avgStr(r)}</span></li>`).join('')}</ol>`;
  }
  function renderTournament() {
    const box = $('#tour-view'); if (!box) return; const s = state.settings, sch = state.schedule; const editor = document.body.classList.contains('editor');
    const n = sch ? sch.matches.filter((m) => !m.bye).length : 0; const live = liveTournament();
    let html = '';
    if (editor) {
      html += `<h3>대회 생성</h3><div class="tour-card"><form id="tour-form-new" class="row" autocomplete="off"><label class="inline" style="flex:1 1 260px">대회명 <input name="name" maxlength="60" required placeholder="예: 2026년 4분기 테니스윗 대회"></label><label class="inline">날짜 <input name="date" type="date" style="width:auto"></label><button type="submit" class="primary">🆕 대회 만들기</button></form>
        <p class="hint">만든 뒤 <b>대회 설정</b>(방식·코트·시간) → <b>선수</b> 탭에서 참가 체크 → 생성 → 게시 순서입니다. 진행 중인 대회가 있으면 먼저 지난 대회로 보관하세요.</p></div>`;
      if (live) html += `<h3>진행 중인 대회</h3><div class="tour-card"><div class="tour-head"><b>${esc(s.name || '(대회명 없음)')}</b><span class="sub">${esc(s.date || '날짜 없음')} · ${modeLabel()}${n ? ` · ${n}경기` : ' · 일정표 없음'}${state.publishedAt ? ` · ${new Date(state.publishedAt).toLocaleDateString('ko-KR')} 게시` : ''}</span></div>
        <div class="row"><button data-go-tab="setup"><svg class="ic"><use href="#i-settings"/></svg>대회 설정</button><button data-go-tab="players"><svg class="ic"><use href="#i-users"/></svg>참가 선수</button><button data-go-tab="schedule"><svg class="ic"><use href="#i-court"/></svg>일정표</button><button data-go-tab="standings"><svg class="ic"><use href="#i-trophy"/></svg>순위</button><button data-go-tab="venue"><svg class="ic"><use href="#i-cup"/></svg>회식 장소</button>${sch ? '<button id="tour-archive" title="대진·참가자·경기 기록을 지난 대회 목록에 보관 (순위표 제외)">📦 지난 대회로 보관</button>' : ''}</div></div>`;
    }
    html += '<h3>지난 대회</h3>';
    if (T.doc) html += (T.doc.id === LIVE_ID ? `<div class="row"><button data-go-tab="schedule" class="primary"><svg class="ic"><use href="#i-court"/></svg>경기 일정표 (전체)</button><button data-go-tab="standings"><svg class="ic"><use href="#i-trophy"/></svg>순위</button></div>` : '') + archiveHtml(T.doc);
    else {
      const items = [];
      if (live) items.push(`<button class="card tour-item live" data-arch="${LIVE_ID}"><b>${esc(s.name || '이번 대회')} <span class="tag type fm">진행 중</span></b><span class="sub">${esc(s.date || '')}${s.date ? ' · ' : ''}${modeLabel()} · ${n}경기 · 누르면 경기 기록, 전체 일정은 첫 화면의 경기 일정표</span></button>`);
      if (!T.index) items.push(`<p class="hint">${esc(T.indexErr || '불러오는 중…')}</p>`);
      else items.push(...T.index.events.map((ev) => `<button class="card tour-item" data-arch="${esc(ev.id)}"><b>${esc(ev.name || ev.id)}</b><span class="sub">${esc(ev.date)}${ev.date ? ' · ' : ''}${esc(ev.mode)}${ev.players ? ` · ${ev.players}명` : ''}${ev.matches ? ` · ${ev.matches}경기` : ''}</span></button>`));
      html += items.length ? `<div class="cards">${items.join('')}</div>` : '<p class="hint">보관된 대회가 아직 없습니다.</p>';
    }
    box.innerHTML = html;
    const f = $('#tour-form-new [name=date]'); if (f && !f.value) f.value = ymdOf();
  }
  /** 새 대회 만들기: 이름·날짜를 넣고 작업본의 일정·점수·팀·특별 규칙·회식을 비우고 참가 체크 해제 (명단·NTRP 유지, 게시본은 게시 전까지 그대로) */
  function newTournament(name, date) {
    if (state.schedule && liveTournament() && !confirm(`진행 중인 대회 '${state.settings.name || ''}' 의 일정표·점수가 이 브라우저 작업본에서 지워집니다 (게시본은 게시하기 전까지 그대로).\n아직 보관하지 않았다면 취소하고 먼저 "지난 대회로 보관"을 하세요. 계속할까요?`)) return;
    state.schedule = null; state.results = {}; state.units = []; state.editMode = false; state.meFilter = undefined;
    state.settings = { ...state.settings, name, date, mustFace: '', sameNtrpGame: '', avoidPairs: '', venue: { name: '', time: '', addr: '', phone: '', menu: '', note: '' } };
    state.players.forEach((p) => { p.active = false; p.from = ''; p.until = ''; });
    save(); showTab('setup'); toast(`'${name}' 대회를 만들었습니다 · 방식·코트·시간을 정한 뒤 선수 탭에서 참가를 체크하세요`, 6000);
  }
  const LIVE_ID = 'live';
  /** 새 대회 시작: 작업본의 일정·점수·팀·특별 규칙·회식을 비우고 참가 체크를 해제 (명단·NTRP 유지, 게시본은 게시 전까지 그대로) */
  function newTournament() {
    if (!confirm('새 대회를 시작합니다.\n이 브라우저 작업본의 일정표·점수·팀 구성·회식 안내가 비워지고 참가 체크가 모두 해제됩니다 (선수 명단과 NTRP 는 유지, 게시본은 게시하기 전까지 그대로).\n먼저 "지난 대회로 보관"을 했는지 확인하세요. 계속할까요?')) return;
    state.schedule = null; state.results = {}; state.units = []; state.editMode = false; state.meFilter = undefined;
    state.settings = { ...state.settings, name: '', date: '', mustFace: '', sameNtrpGame: '', avoidPairs: '', venue: { name: '', time: '', addr: '', phone: '', menu: '', note: '' } };
    state.players.forEach((p) => { p.active = false; p.from = ''; p.until = ''; });
    save(); showTab('setup'); toast('대회 설정(이름·날짜·방식)을 입력한 뒤 선수 탭에서 참가를 체크하고 생성하세요', 6000);
  }
  async function tournamentRefresh() {
    const idx = await archRead('archive/index.json');
    if (idx && typeof idx === 'object') T.index = { v: 1, events: (Array.isArray(idx.events) ? idx.events : []).filter((e) => e && ARCH_RE.test(String(e.id || ''))).map((e) => ({ id: String(e.id), name: String(e.name || '').slice(0, 60), date: /^\d{4}-\d{2}-\d{2}$/.test(String(e.date || '')) ? e.date : '', mode: String(e.mode || '').slice(0, 10), players: e.players | 0, matches: e.matches | 0 })).sort((a, b) => (a.date < b.date ? 1 : -1)) };
    else { T.index = { v: 1, events: [] }; T.indexErr = ''; }
    renderTournament(); renderHeader(); if (!$('#cover')?.hidden) updateCover();
  }
  async function openArchive(id) {
    if (id === LIVE_ID) { const d = buildArchive(LIVE_ID); if (!d) return; try { T.doc = assertArchive(d); } catch { return; } renderTournament(); window.scrollTo(0, 0); return; } // 진행 중인 대회: 게시본 그대로
    if (!ARCH_RE.test(id)) return; const raw = await archRead(`archive/${id}.json`); if (!raw) { toast('보관본을 찾지 못했습니다'); return; }
    try { T.doc = assertArchive(raw); } catch (e) { toast('보관본을 읽을 수 없습니다: ' + e.message); return; }
    renderTournament(); window.scrollTo(0, 0);
  }
  async function archiveCurrent() {
    if (!state.schedule) { alert('보관할 일정표가 없습니다.'); return; }
    const s = state.settings; const def = s.date ? `${s.date.slice(0, 4)}-q${Math.ceil((parseInt(s.date.slice(5, 7), 10) || 1) / 3)}` : '';
    const id = prompt('보관 이름 (영문·숫자·하이픈, 예: 2026-q3)\n대진·참가자·경기 기록이 저장됩니다. 순위표와 NTRP 는 저장되지 않습니다.', def); if (id == null) return;
    if (!ARCH_RE.test(id.trim())) { alert('영문·숫자·하이픈만, 30자 이내로 입력하세요.'); return; }
    const doc = buildArchive(id.trim()); if (!doc) return;
    const btn = $('#tour-archive'); if (btn) { btn.disabled = true; btn.textContent = '보관 중…'; }
    try {
      let stop = false;
      const ok1 = await repoAdminUpdate(`data/archive/${doc.id}.json`, (cur) => { if (cur && !confirm(`이미 '${doc.id}' 보관본이 있습니다. 덮어쓸까요?`)) { stop = true; return null; } return doc; }, `대회 보관: ${doc.name || doc.id}`);
      if (stop || !ok1) return;
      const ok2 = await repoAdminUpdate('data/archive/index.json', (cur) => { const idx = cur && typeof cur === 'object' ? cur : { v: 1, events: [] }; idx.v = 1; idx.events = (idx.events || []).filter((x) => x && x.id !== doc.id); idx.events.unshift({ id: doc.id, name: doc.name, date: doc.date, mode: MODE_KO[doc.settings.mode] || '', players: doc.players.length, matches: doc.schedule.matches.length }); idx.events.sort((a, b) => ((a.date || '') < (b.date || '') ? 1 : -1)); idx.updatedAt = new Date().toISOString(); return idx; }, `대회 보관 목록: ${doc.id}`);
      if (ok2) { toast(`'${doc.name || doc.id}' 을(를) 지난 대회로 보관했습니다`, 5000); T.doc = null; await tournamentRefresh(); }
    } finally { if (btn) { btn.disabled = false; btn.textContent = '📦 지난 대회로 보관'; } }
  }
  $('#tab-tournament')?.addEventListener('submit', (e) => {
    if (e.target.id !== 'tour-form-new') return; e.preventDefault(); const fd = new FormData(e.target);
    const name = String(fd.get('name') || '').trim().slice(0, 60); const date = String(fd.get('date') || ''); if (!name) return;
    newTournament(name, /^\d{4}-\d{2}-\d{2}$/.test(date) ? date : '');
  });
  $('#tab-tournament')?.addEventListener('click', async (e) => {
    const go = e.target.closest('[data-go-tab]'); if (go) { showTab(go.dataset.goTab); history.replaceState(null, '', '#' + go.dataset.goTab); return; }
    if (e.target.closest('#tour-archive')) { await archiveCurrent(); return; }
    if (e.target.closest('#arch-back')) { T.doc = null; renderTournament(); return; }
    const it = e.target.closest('[data-arch]'); if (it) await openArchive(it.dataset.arch);
  });

  window.tennisweet = { weekly: { W, applyOp: applyWeeklyOp, refresh: weeklyRefresh, mock: wkMock, send: wkSend, generate: generateWeeklySchedule, history: wkHistory }, archive: { T, build: buildArchive, refresh: tournamentRefresh }, _genOnce: (seed) => generateRotationOnce(state.settings, seed), _score: scheduleScore, syncTokenFromPublished, hasToken: () => !!localStorage.getItem(TOKEN_KEY), getState: () => JSON.parse(JSON.stringify(state)), setState: async (d) => { state = normalize(d); await decryptAll(); commit(); }, isAdmin: () => !!adminKey };

  // ================= 시작 =================
  (async () => {
    $$('.tab').forEach((t) => t.classList.remove('active')); // 초기 활성 탭은 모드 결정 후 지정
    if (await tryLoadShared()) { enterViewOnly(`공유 링크 보기 (읽기 전용) · ${sharedAt ? new Date(sharedAt).toLocaleString('ko-KR') : ''} 기준`); render(); showTab('schedule'); return; }
    const published = await loadPublished();
    const pw = sessionStorage.getItem(PW_KEY);
    const isAdminPage = document.body.dataset.page === 'admin';
    const editor = isAdminPage && pw && (await verifierHex(pw)) === ADMIN_HASH;
    if (isAdminPage && !editor) { location.replace('admin.html?t=' + Date.now()); return; }
    if (!editor) { // 일반 페이지는 항상 보기 전용
      if (published) state = normalize(published);
      enterViewOnly(published ? `게시본 보기 (읽기 전용)${published.publishedAt ? ' · ' + new Date(published.publishedAt).toLocaleString('ko-KR') + ' 게시' : ''}` : '게시본(data/tournament.json)이 아직 없습니다. 관리자 페이지에서 만들어 게시하세요.');
      render();
      const want = (location.hash || '').replace('#', '');
      if (['weekly', 'tournament', 'schedule', 'standings', 'players', 'units', 'setup', 'venue'].includes(want)) showTab(want); else { showTab('weekly'); showCover(true); } // 첫 화면 = 포스터 커버
      weeklyBoot(); tournamentRefresh();
      // 방문자: 게시본이 바뀌면 자동 갱신 (현장에서 관리자가 게시하면 곧 반영)
      let lastPub = published?.publishedAt || null;
      setInterval(async () => {
        if (document.hidden) return;
        const p = await loadPublished(); if (!p || !p.publishedAt || (lastPub && Date.parse(p.publishedAt) <= Date.parse(lastPub))) return; // 더 새로운 게시본만 (CDN 지연으로 옛 사본이 오면 무시)
        const mf = state.meFilter; lastPub = p.publishedAt; state = normalize(p);
        if (mf && (state.schedule?.matches || []).some((m) => matchPeople(m).includes(mf))) state.meFilter = mf; // 방문자의 '내 경기' 필터 유지
        render();
        $('#view-banner-text').textContent = `게시본 보기 (읽기 전용) · ${new Date(p.publishedAt).toLocaleString('ko-KR')} 게시`;
        toast('일정이 갱신되었습니다');
      }, 45000);
      return;
    }
    document.body.classList.add('editor');
    let saved = storage.load();
    // 게시본이 작업본보다 새로우면(다른 기기·Claude 에서 게시) 작업본을 게시본으로 교체할지 확인
    // 작업본의 기준 버전(basePublishedAt)과 서버 게시본이 다르면 = 다른 기기에서 게시됨
    if (saved && published?.publishedAt && saved.basePublishedAt !== published.publishedAt) {
      if (confirm(`저장소의 게시본(${new Date(published.publishedAt).toLocaleString('ko-KR')})이 이 브라우저의 작업본보다 새롭습니다.\n게시본을 불러올까요? (취소하면 기존 작업본을 계속 편집)`)) saved = null;
    }
    state = saved ? normalize(saved) : published ? fromPublished(published) : emptyState();
    if (!saved) save(); // 게시본을 작업본으로 복사
    $('#view-banner').hidden = false; $('#view-banner').classList.add('editor-banner');
    bannerAdmin(`이 브라우저의 작업본을 편집 중${published?.publishedAt ? ` · 현재 게시본 ${new Date(published.publishedAt).toLocaleString('ko-KR')}` : ''} · 바꾼 내용은 🚀 게시하기를 눌러야 모두에게 반영됩니다`);
    adminKey = await deriveKey(pw); await decryptAll();
    if (await syncTokenFromPublished(published)) toast('게시 토큰을 게시본에서 가져왔습니다 · 바로 게시할 수 있습니다');
    render(); { const want = (location.hash || '').replace('#', ''); if (['weekly', 'tournament', 'schedule', 'standings', 'players', 'units', 'setup', 'venue'].includes(want)) showTab(want); else { showTab('weekly'); showCover(true); } } weeklyBoot(); tournamentRefresh();
  })();
})();
