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
    courts: 2, startTime: '09:00', endTime: '', matchMinutes: 30, breakMinutes: 0, minWomenDoubles: 1,
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
  const ADMIN_HASH = 'fd8dd30608d332345643934a07ca0c380c73b85ebac5fb641a90f50ed0fcd81a'; // sha256(ADMIN_SALT + 비밀번호)
  const PW_KEY = 'tennisweet.pw';
  let adminKey = null; const ntrp = new Map(); // playerId -> NTRP 평문 (메모리에만)
  const b64 = (u8) => btoa(String.fromCharCode(...u8)); const unb64 = (str) => Uint8Array.from(atob(str), (c) => c.charCodeAt(0));
  async function sha256hex(str) { const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str)); return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join(''); }
  async function deriveKey(pw) {
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: new TextEncoder().encode(ADMIN_SALT), iterations: 120000, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  async function encStr(str) { const iv = crypto.getRandomValues(new Uint8Array(12)); const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, adminKey, new TextEncoder().encode(str)); return b64(iv) + '.' + b64(new Uint8Array(ct)); }
  async function decStr(packed) { const [iv, ct] = packed.split('.'); return new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(iv) }, adminKey, unb64(ct))); }
  async function unlockAdmin(pw) {
    if (!pw || (await sha256hex(ADMIN_SALT + pw)) !== ADMIN_HASH) return false;
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
    if (!('CompressionStream' in window)) return 'p' + btoa(String.fromCharCode(...bytes));
    const cs = new CompressionStream('deflate-raw');
    const buf = await new Response(new Blob([bytes]).stream().pipeThrough(cs)).arrayBuffer();
    return 'z' + btoa(String.fromCharCode(...new Uint8Array(buf)));
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
    const snap = { ...state, editMode: false, sharedAt: new Date().toISOString() };
    const enc = await compress(JSON.stringify(snap));
    const url = `${location.origin}${location.pathname}#s=${encodeURIComponent(enc)}`;
    try { await navigator.clipboard.writeText(url); alert(`공유 링크가 복사되었습니다 (${Math.round(url.length / 1024)}KB).\n카톡 등으로 전달하면 누구나 일정·결과를 읽기 전용으로 볼 수 있습니다.\n결과가 바뀌면 다시 공유하세요.`); }
    catch { prompt('아래 링크를 복사하세요', url); }
  }
  async function tryLoadShared() {
    const m = location.hash.match(/^#s=(.+)$/); if (!m) return false;
    try {
      const data = JSON.parse(await decompress(decodeURIComponent(m[1])));
      state = { ...emptyState(), ...data, editMode: false }; viewOnly = true; sharedAt = data.sharedAt;
      return true;
    } catch (e) { alert('공유 링크를 읽을 수 없습니다: ' + e.message); return false; }
  }

  // ================= 탭 =================
  $$('.tabs button').forEach((b) => b.addEventListener('click', () => showTab(b.dataset.tab)));
  function showTab(name) {
    $$('.tabs button').forEach((b) => b.classList.toggle('active', b.dataset.tab === name));
    $$('.tab').forEach((t) => t.classList.toggle('active', t.id === 'tab-' + name));
    render();
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
    $('#players-title').textContent = `선수 명단 (${state.players.length}명, 참가 ${act}명)`;
    if (viewOnly) {
      $('#tbl-players tbody').innerHTML = state.players.map((p, i) => `<tr class="${p.active ? '' : 'inactive'}">
        <td>${i + 1}</td><td>${p.active ? '✅' : '—'}</td><td><b>${esc(p.name)}</b></td><td>${p.gender === 'M' ? '남' : p.gender === 'F' ? '여' : ''}</td>
        <td class="only-editor"></td><td>${esc(p.from || '')}</td><td>${esc(p.until || '')}</td><td class="only-editor"></td><td class="sub">${esc(p.note || '')}</td><td></td></tr>`).join('');
      return;
    }
    $('#tbl-players tbody').innerHTML = state.players.map((p, i) => `<tr class="${p.active ? '' : 'inactive'}">
      <td>${i + 1}</td><td><input type="checkbox" data-pid="${p.id}" ${p.active ? 'checked' : ''}></td>
      <td><input class="cell" data-pid="${p.id}" data-field="name" value="${esc(p.name)}"></td>
      <td><select class="cell" data-pid="${p.id}" data-field="gender"><option value="">-</option><option value="M" ${p.gender === 'M' ? 'selected' : ''}>남</option><option value="F" ${p.gender === 'F' ? 'selected' : ''}>여</option></select></td>
      <td class="only-editor">${adminKey ? `<input class="cell" type="number" step="0.5" min="1" max="7" data-pid="${p.id}" data-field="ntrp" value="${esc(ntrp.get(p.id) || '')}">` : '<span class="tbd">🔒</span>'}</td>
      <td><input class="cell" type="time" data-pid="${p.id}" data-field="from" value="${esc(p.from || '')}"></td>
      <td><input class="cell" type="time" data-pid="${p.id}" data-field="until" value="${esc(p.until || '')}"></td>
      <td class="only-editor"><input class="cell" data-pid="${p.id}" data-field="tag" value="${esc(p.tag || '')}" placeholder="예: A" style="max-width:70px"></td>
      <td><input class="cell" data-pid="${p.id}" data-field="note" value="${esc(p.note)}"></td>
      <td><button class="small" data-del="${p.id}">삭제</button></td></tr>`).join('');
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
    s.thirdPlace = fd.get('thirdPlace') === 'on';
    for (const k of ['minWomenDoubles', 'teamCount', 'groupCount', 'advance', 'courts', 'matchMinutes', 'breakMinutes']) s[k] = Math.max(0, parseInt(s[k], 10) || 0);
    s.courts = Math.max(1, s.courts); s.teamCount = Math.max(2, s.teamCount || 2); s.groupCount = Math.max(1, s.groupCount); s.advance = Math.max(1, s.advance); s.matchMinutes = Math.max(5, s.matchMinutes);
    return s;
  }
  function updateSettingsVisibility() {
    const fd = new FormData(formSettings); const mode = fd.get('mode'), format = fd.get('format');
    const rot = mode === 'rotation' || mode === 'team'; // 팀전·로테이션은 시간대 기반 복식 배정 (조/토너먼트 없음)
    $('#lbl-disc').style.display = rot ? 'none' : '';
    $('#lbl-teamcount').style.display = mode === 'team' ? '' : 'none';
    $('#fs-format').style.display = rot ? 'none' : '';
    $('#lbl-groups').style.display = !rot && format === 'groups' ? '' : 'none';
    $('#lbl-advance').style.display = !rot && format === 'groups' ? '' : 'none';
    $('#lbl-third').style.display = rot || format === 'rr' ? 'none' : '';
  }
  formSettings.addEventListener('change', updateSettingsVisibility);
  formSettings.addEventListener('submit', (e) => {
    e.preventDefault(); const ns = readSettings();
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
      view.innerHTML = `<p class="hint">개인전은 팀 구성이 없습니다. ① 선수 탭의 참가 선수 ${ps.length}명이 매 경기 파트너·상대를 바꿔 가며 개인 순위로 경쟁합니다.</p>`;
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
    const opt = (sel) => `<option value="">+ 선수 추가</option>${free.map((p) => `<option value="${p.id}">${esc(p.name)}${adminKey && ntrp.get(p.id) ? ` (${esc(ntrp.get(p.id))})` : ''}</option>`).join('')}`;
    const pchip = (u, pid) => { const p = playerById(pid); return `<span class="chip">${esc(p?.name ?? '?')}${adminKey && ntrp.get(p.id) ? `<small> ${esc(ntrp.get(p.id))}</small>` : ''}${p?.from ? `<small> ${esc(p.from)}~</small>` : ''}${viewOnly ? '' : `<button class="x" data-rm="${u.id}:${pid}" title="빼기">×</button>`}</span>`; };
    const dis = viewOnly ? 'disabled' : '';
    view.innerHTML = `<div class="cards">${state.units.map((u, i) => `<div class="card">
        <div class="card-head">${kind === 'team' ? `<input class="unit-name" data-uid="${u.id}" value="${esc(u.name)}" placeholder="팀명" ${dis}>` : `<b>${i + 1}. ${esc(unitName(u))}</b>`}
          ${viewOnly ? '' : `<button class="small" data-del-unit="${u.id}">삭제</button>`}</div>
        <div class="chips">${u.playerIds.map((pid) => pchip(u, pid)).join('') || '<span class="tbd">선수 없음</span>'}</div>
        ${!viewOnly && (kind === 'team' || u.playerIds.length < (kind === 'pair' ? 2 : 1)) && free.length ? `<select class="add-player" data-uid="${u.id}">${opt()}</select>` : ''}
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
    if (state.schedule && Object.keys(state.results).length && !confirm(`입력된 결과와 현장 수정 내용이 모두 지워집니다. ${label} 일정을 다시 생성할까요?`)) return;
    if (mode && mode !== state.settings.mode) { state.settings.mode = mode; state.units = []; }
    if (mode === 'team' && !state.settings.endTime) { alert('팀전은 종료 시각이 필요합니다 (② 대회 설정).'); return; }
    try {
      seedRng(newSeed());
      if (state.settings.mode === 'team') autoBuild(state.settings.teamCount || 2);
      else if (isRot()) ensureRotationUnits();
      else if (!state.units.length) autoBuild();
      state.schedule = isRot() ? generateRotation(state.settings) : state.settings.mode === 'team' ? generateTeam(state.settings, state.units.filter((u) => u.playerIds.length)) : generate(state.settings, state.units.filter((u) => u.playerIds.length));
      state.results = {};
    } catch (err) { alert(err.message); return; }
    save(); showTab('schedule');
  }
  $$('.btn-regen').forEach((b) => b.addEventListener('click', () => regenerateAll(b.dataset.mode)));
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
  /** 경기 종류 (양쪽 조가 모두 정해졌을 때). mismatch=true 면 규칙 위반 */
  function matchType(m) {
    const a = m.aPlayers, b = m.bPlayers; if (!a || !b || a.some((x) => !x) || b.some((x) => !x)) return null;
    const ta = pairType(a[0], a[1]), tb = pairType(b[0], b[1]);
    return { label: ta === tb ? TYPE_LABEL[ta] : `${TYPE_LABEL[ta]} vs ${TYPE_LABEL[tb]}`, mismatch: ta !== tb };
  }
  const toMin = (t) => { if (!t) return null; const [h, m] = t.split(':').map(Number); return h * 60 + m; };
  const slotStartMin = (s, i) => toMin(s.startTime || '09:00') + i * (s.matchMinutes + s.breakMinutes);
  function maxSlots(s) { const end = toMin(s.endTime); if (end == null) return Infinity; const start = toMin(s.startTime || '09:00'); return Math.max(0, Math.floor((end - start + s.breakMinutes) / (s.matchMinutes + s.breakMinutes))); }
  function playerAvailable(p, s, slot) {
    const t0 = slotStartMin(s, slot), t1 = t0 + s.matchMinutes;
    const from = toMin(p.from), until = toMin(p.until);
    return (from == null || from <= t0) && (until == null || until >= t1);
  }
  /** 팀전: 시간대마다 코트별로 팀 대 팀 복식 1경기. 대전 횟수 적은 팀끼리, 경기 수 적은 선수부터, 파트너 중복 최소 */
  function generateTeam(s, teams, seed = newSeed()) {
    seedRng(seed);
    if (teams.length < 2) throw new Error('팀이 2개 이상 필요합니다.');
    const n = maxSlots(s); if (!isFinite(n)) throw new Error('팀전은 종료 시각이 필요합니다 (② 대회 설정).');
    if (n < 1) throw new Error('시작~종료 사이에 경기 시간이 없습니다.');
    const played = {}, lastPlayed = {}, partner = {}, meet = {}, fmCnt = {}, mmCnt = {};
    const key = (a, b) => (a < b ? a + '|' + b : b + '|' + a);
    teams.forEach((t) => t.playerIds.forEach((id) => { played[id] = 0; lastPlayed[id] = -1; fmCnt[id] = 0; mmCnt[id] = 0; }));
    let ffDone = 0; const minFF = s.minWomenDoubles || 0;
    const matches = [];
    for (let slot = 0; slot < n; slot++) {
      const usedP = new Set(); const usedT = {};
      const availOf = (t) => t.playerIds.filter((id) => !usedP.has(id) && playerById(id) && playerAvailable(playerById(id), s, slot));
      for (let c = 1; c <= s.courts; c++) {
        // 각 팀의 후보 조(경기 수 적은 선수 우선, 파트너 중복 벌점) → 남복/여복/혼복 종류가 같은 조합만 허용
        const restedLast = (id) => slot > 0 && lastPlayed[id] < slot - 1 && playerAvailable(playerById(id), s, slot - 1); // 직전 시간대 휴식 → 최우선
        const candPairs = (t) => {
          const cand = availOf(t).sort((a, b) => (restedLast(b) ? 1 : 0) - (restedLast(a) ? 1 : 0) || played[a] - played[b] || lastPlayed[a] - lastPlayed[b] || rng() - 0.5).slice(0, 8);
          const out = [];
          for (let i = 0; i < cand.length; i++) for (let j = i + 1; j < cand.length; j++)
          {
            const tp = pairType(cand[i], cand[j]);
            // 남복·혼복 골고루: 이 종류를 이미 많이 한 남성이면 벌점, 적게 했으면 가점
            const mix = [cand[i], cand[j]].filter((id) => gOf(id) === 'M').reduce((c, id) => c + (tp === 'FM' ? fmCnt[id] - mmCnt[id] : tp === 'MM' ? mmCnt[id] - fmCnt[id] : 0), 0) * 4;
            out.push({ p: [cand[i], cand[j]], type: tp, cost: (played[cand[i]] + played[cand[j]]) * 5 + (partner[key(cand[i], cand[j])] || 0) * 6 + mix - (restedLast(cand[i]) ? 40 : 0) - (restedLast(cand[j]) ? 40 : 0) });
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
            const cost = teamCost + x.cost + y.cost + rng() - (x.type === 'FF' && ffDone < minFF ? 500 : 0); // 여복 부족하면 여복 우선
            if (cost < bestCost) { bestCost = cost; best = [A, B, x.p, y.p]; }
          }
        }
        if (!best) break;
        const [A, B, pa, pb] = best;
        matches.push({ id: uid(), phase: 'rr', group: 0, round: slot, slot, court: c, aId: A.id, bId: B.id, aPlayers: pa, bPlayers: pb });
        meet[key(A.id, B.id)] = (meet[key(A.id, B.id)] || 0) + 1; usedT[A.id] = (usedT[A.id] || 0) + 1; usedT[B.id] = (usedT[B.id] || 0) + 1;
        [pa, pb].forEach(([x, y]) => { partner[key(x, y)] = (partner[key(x, y)] || 0) + 1; });
        const tpm = pairType(pa[0], pa[1]); if (tpm === 'FF') ffDone++;
        [...pa, ...pb].forEach((id) => { usedP.add(id); played[id]++; lastPlayed[id] = slot; if (tpm === 'FM') fmCnt[id]++; else if (tpm === 'MM') mmCnt[id]++; });
      }
    }
    if (!matches.length) throw new Error('배정 가능한 경기가 없습니다. 각 팀에 같은 시각 참석 가능 선수가 2명 이상이고, 남복·여복·혼복 중 맞출 수 있는 조합이 있는지 확인하세요.');
    return { groups: [teams.map((t) => t.id)], advance: 0, matches, qualifiers: 0, extraSlots: 0, unitIds: teams.map((t) => t.id), seed };
  }
  /** 복식 로테이션: 슬롯마다 가용 선수 중 경기 수 적은 순으로 코트×4 명 선발, 파트너·상대 중복 최소 조합 */
  function generateRotation(s, seed = newSeed()) {
    seedRng(seed);
    const ps = activePlayers(); if (ps.length < 4) throw new Error('개인전은 참가 선수 4명 이상이 필요합니다.');
    const n = maxSlots(s); if (!isFinite(n)) throw new Error('개인전은 종료 시각이 필요합니다 (② 대회 설정).');
    if (n < 1) throw new Error('시작~종료 사이에 경기 시간이 없습니다.');
    const played = {}, lastPlayed = {}, partner = {}, opp = {}, fmCnt = {}, mmCnt = {};
    const key = (a, b) => (a < b ? a + '|' + b : b + '|' + a);
    ps.forEach((p) => { played[p.id] = 0; lastPlayed[p.id] = -1; fmCnt[p.id] = 0; mmCnt[p.id] = 0; });
    let ffDone = 0; const minFF = s.minWomenDoubles || 0; // 여복 최소 경기 수
    const matches = []; let round = 0;
    for (let slot = 0; slot < n; slot++) {
      const avail = ps.filter((p) => playerAvailable(p, s, slot));
      const k = Math.min(s.courts, Math.floor(avail.length / 4)); if (k < 1) continue;
      // 1) 선발: 가용 인원의 성별 비율에 맞춰 여성 수(짝수)를 정하고, 성별별로 [직전 휴식자 → 경기 수 적은 순 → 오래 쉰 순]
      const restedLast = (p) => slot > 0 && lastPlayed[p.id] < slot - 1 && playerAvailable(p, s, slot - 1);
      const isF = (p) => p.gender === 'F';
      const rank = (arr) => shuffle([...arr]).sort((a, b) => (restedLast(b) ? 1 : 0) - (restedLast(a) ? 1 : 0) || played[a.id] - played[b.id] || lastPlayed[a.id] - lastPlayed[b.id]);
      const Wav = rank(avail.filter(isF)), Mav = rank(avail.filter((p) => !isF(p)));
      // 여성 수(짝수) 분할: 가능한 분할 중 선발자 우선순위 점수 합이 가장 좋은 것 (직전 휴식자 우선, 경기 수 적은 순, 오래 쉰 순)
      const score = (p) => (restedLast(p) ? -1000 : 0) + played[p.id] * 100 - (slot - lastPlayed[p.id]);
      // 여복 최소 경기: 남은 시간대 중 여성 4명이 모이는 슬롯 수가 부족분 이하이면 강제, 아니면 가점만 (연속 편성·편중 방지)
      const ffNeed = minFF - ffDone;
      const ffSlotsLeft = ffNeed > 0 ? Array.from({ length: n - slot }, (_, i) => slot + i).filter((sl) => ps.filter((p) => p.gender === 'F' && playerAvailable(p, s, sl)).length >= 4).length : 0;
      const ffPossible = ffNeed > 0 && Wav.length >= 4;
      const ffForce = ffPossible && ffSlotsLeft <= ffNeed;
      let kSel = k, wT = -1, wantFF = false;
      for (; kSel >= 1; kSel--) {
        const need = kSel * 4; let best = Infinity, bestDist = Infinity;
        const ideal = need * Wav.length / avail.length; // 동률이면 성별 비율에 가까운 분할
        for (let t = ffForce ? 4 : 0; t <= Wav.length; t += 2) {
          if (need - t < 0 || need - t > Mav.length) continue;
          const base = Wav.slice(0, t).reduce((a, p) => a + score(p), 0) + Mav.slice(0, need - t).reduce((a, p) => a + score(p), 0);
          const dist = Math.abs(t - ideal);
          for (const asFF of (ffPossible && t >= 4 ? [false, true] : [false])) {
            const sum = base - (asFF ? (ffForce ? 1e9 : 150) : 0);
            if (sum < best || (sum === best && dist < bestDist)) { best = sum; bestDist = dist; wT = t; wantFF = asFF; }
          }
        }
        if (wT >= 0) break;
      }
      if (kSel < 1 || wT < 0) continue;
      const W = Wav.slice(0, wT).map((p) => p.id), M = Mav.slice(0, kSel * 4 - wT).map((p) => p.id);
      const kk = Math.floor((W.length + M.length) / 4); if (kk < 1) continue;
      // 2) 구성: 여성 2명씩 혼복 코트(양쪽 1명씩), 코트가 모자라면 여성 4명 여복 코트, 나머지는 남복 코트. 여러 번 섞어 파트너·상대 중복 최소 조합 선택
      let best = null, bestCost = Infinity;
      for (let t = 0; t < 300; t++) {
        // 남성은 혼복을 덜 한 사람이 뒤(=먼저 뽑히는 쪽)에 오도록 정렬 → 혼복 코트에 우선 배치, 남복은 그 반대 (골고루)
        const w = shuffle([...W]), m = shuffle([...M]).sort((a, b) => (fmCnt[b] - mmCnt[b]) - (fmCnt[a] - mmCnt[a]) + (rng() - 0.5) * 0.5); const courts = [];
        let ff = wantFF ? 1 : 0; while (w.length - ff * 4 > 2 * (kk - ff)) ff++; // 혼복 코트로 다 못 담으면 여복 코트 수 증가
        for (let c = 0; c < ff; c++) courts.push([w.pop(), w.pop(), w.pop(), w.pop()]);
        while (w.length >= 2) courts.push([w.pop(), m.pop(), w.pop(), m.pop()]);
        while (courts.length < kk && m.length >= 4) courts.push([m.pop(), m.pop(), m.pop(), m.pop()]);
        if (courts.some((c) => c.some((x) => x == null))) continue;
        let cost = 0;
        for (const [a1, a2, b1, b2] of courts) {
          cost += 3 * ((partner[key(a1, a2)] || 0) + (partner[key(b1, b2)] || 0));
          for (const x of [a1, a2]) for (const y of [b1, b2]) cost += opp[key(x, y)] || 0;
        }
        if (cost < bestCost) { bestCost = cost; best = courts; if (cost === 0) break; }
      }
      if (!best) continue;
      best.forEach(([a1, a2, b1, b2], c) => {
        matches.push({ id: uid(), phase: 'rot', round, slot, court: c + 1, aIds: ['p:' + a1, 'p:' + a2], bIds: ['p:' + b1, 'p:' + b2] });
        partner[key(a1, a2)] = (partner[key(a1, a2)] || 0) + 1; partner[key(b1, b2)] = (partner[key(b1, b2)] || 0) + 1;
        for (const x of [a1, a2]) for (const y of [b1, b2]) opp[key(x, y)] = (opp[key(x, y)] || 0) + 1;
        const tp = pairType(a1, a2); if (tp === 'FF') ffDone++;
        for (const x of [a1, a2, b1, b2]) { played[x]++; lastPlayed[x] = slot; if (tp === 'FM') fmCnt[x]++; else if (tp === 'MM') mmCnt[x]++; }
      });
      round++;
    }
    if (!matches.length) throw new Error('배정 가능한 경기가 없습니다. 합류 시각과 종료 시각을 확인하세요.');
    return { groups: [], advance: 0, matches, qualifiers: 0, extraSlots: 0, unitIds: ps.map((p) => 'p:' + p.id), seed };
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
  function sideHtml(m, side) {
    if (m[side + 'Players']) {
      const u = unitById(m[side + 'Id']);
      return `<div><b>${u ? esc(unitName(u)) : '<span class="tbd">미정</span>'}</b><div class="sub">${m[side + 'Players'].map((id) => playerById(id) ? esc(pname(id)) : '<i>미정</i>').join(' · ')}</div></div>`;
    }
    if (!m[side + 'Ids']) return unitHtml(m[side + 'Id'], m[side + 'Label']);
    const ids = m[side + 'Ids'];
    return `<div>${ids.map((id) => unitById(id) ? `<b>${esc(unitName(unitById(id)))}</b>` : '<span class="tbd">미정</span>').join(' · ')}</div>`;
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

  function render() {
    hydrateSettings();
    $('#hdr-title').textContent = (state.settings.name || '분기 대회 일정표') + (document.body.dataset.page === 'admin' ? ' · 관리자' : '');
    $$('.inp-minff').forEach((el) => { el.value = state.settings.minWomenDoubles ?? 1; });
    renderPlayers(); renderUnits();
    if (state.schedule) resolveKO();
    renderSchedule(); renderStandings(); renderBracket();
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
    if (!sch) { view.innerHTML = '<p class="hint">아직 일정표가 없습니다. ③ 팀 구성 탭에서 생성하세요.</p>'; $('#print-meta').textContent = ''; $('#sel-me').innerHTML = ''; return; }
    const ms = sch.matches.filter((m) => !m.bye).sort((a, b) => a.slot - b.slot || a.court - b.court);
    const nSlots = totalSlots(); const bad = conflicts(); const n = subCount();
    $('#print-meta').textContent = `${s.date || ''}  ·  ${s.mode === 'team' ? '팀전' : s.mode === 'rotation' ? '개인전' : '고정조 대회'} ${s.mode === 'individual' && s.discipline === 'singles' ? '단식' : '복식'}  ·  코트 ${s.courts}면  ·  ${slotTime(0)}~${slotTime(nSlots)} (경기 ${ms.length})`;
    // 선수 필터 (모바일에서 내 경기만 보기)
    const sel = $('#sel-me'); const cur = state.meFilter || '';
    const inSched = new Set(ms.flatMap(matchPeople));
    sel.innerHTML = `<option value="">전체 경기</option>${state.players.filter((p) => inSched.has(p.id)).map((p) => `<option value="${p.id}" ${p.id === cur ? 'selected' : ''}>${esc(p.name)} 경기만</option>`).join('')}`;
    const unitOpts = (selId) => `<option value="">(미정)</option>${sch.unitIds.map((id) => `<option value="${id}" ${id === selId ? 'selected' : ''}>${esc(unitName(unitById(id) || { playerIds: [] }))}</option>`).join('')}`;
    const slotOpts = (selI) => Array.from({ length: nSlots }, (_, i) => `<option value="${i}" ${i === selI ? 'selected' : ''}>${slotTime(i)}</option>`).join('');
    const courtOpts = (selC) => Array.from({ length: s.courts }, (_, i) => `<option value="${i + 1}" ${i + 1 === selC ? 'selected' : ''}>${i + 1}코트</option>`).join('');
    const cell = (m, side) => {
      if (!edit) return sideHtml(m, side);
      if (m[side + 'Ids']) return m[side + 'Ids'].map((id, i) => `<select class="ed" data-mid="${m.id}" data-f="${side}${i}">${unitOpts(id)}</select>`).join('');
      if (m[side + 'Players']) {
        const team = unitById(m[side + 'Id']); const pool = team ? team.playerIds : state.players.map((p) => p.id);
        // 나머지 3명이 정해져 있으면 남복·여복·혼복 종류가 유지되는 선수만 선택지에 표시
        const okFor = (i, cand) => { const t = { aPlayers: [...m.aPlayers], bPlayers: [...m.bPlayers] }; t[side + 'Players'][i] = cand; const mt = matchType(t); return !mt || !mt.mismatch; };
        const popts = (selP, i) => `<option value="">(미정)</option>${pool.filter((id) => id === selP || okFor(i, id)).map((id) => `<option value="${id}" ${id === selP ? 'selected' : ''}>${esc(pname(id))}</option>`).join('')}`;
        return `<select class="ed" data-mid="${m.id}" data-f="${side}">${unitOpts(m[side + 'Id'])}</select>` + m[side + 'Players'].map((id, i) => `<select class="ed" data-mid="${m.id}" data-f="p${side}${i}">${popts(id, i)}</select>`).join('');
      }
      return `<select class="ed" data-mid="${m.id}" data-f="${side}">${unitOpts(m[side + 'Id'])}</select>${m.phase === 'ko' && m[side + 'Manual'] ? '<div class="sub">수동 지정</div>' : ''}`;
    };
    let html = '';
    for (let slot = 0; slot < nSlots; slot++) {
      let rows = ms.filter((m) => m.slot === slot);
      if (cur) rows = rows.filter((m) => matchPeople(m).includes(cur));
      if (!rows.length && !(edit && !cur)) continue;
      html += `<div class="slot"><div class="slot-title">${slotTime(slot)} <span class="sub">~ ${slotTime(slot + 1)}</span>${rows.length ? '' : ' <span class="sub">(비어 있음)</span>'}</div><div class="cards match-cards">`;
      for (const m of rows) {
        const o = matchOutcome(m); const r = getResult(m.id); const canInput = sideIds(m, 'a').length && sideIds(m, 'b').length && !viewOnly;
        const scores = r.map((sub, i) => `<div class="score">${n > 1 ? `<span class="sub">${i + 1}</span>` : ''}
          <input type="number" min="0" inputmode="numeric" data-mid="${m.id}" data-i="${i}" data-side="a" value="${esc(sub.a)}" ${canInput ? '' : 'disabled'}><span class="colon">:</span>
          <input type="number" min="0" inputmode="numeric" data-mid="${m.id}" data-i="${i}" data-side="b" value="${esc(sub.b)}" ${canInput ? '' : 'disabled'}></div>`).join('');
        const res = o.winner ? `<div class="done">${esc(sideName(m, o.winner))} 승${n > 1 ? ` (${o.aw}:${o.bw})` : ''}</div>` : '';
        const mt = m.aPlayers ? matchType(m) : (m.aIds && m.bIds && [...m.aIds, ...m.bIds].every(Boolean) ? matchType({ aPlayers: m.aIds.map((id) => unitById(id)?.playerIds[0]), bPlayers: m.bIds.map((id) => unitById(id)?.playerIds[0]) }) : null);
        const typeTag = mt ? `<span class="tag ${mt.mismatch ? 'bad' : 'type'}">${esc(mt.label)}</span>` : '';
        const warn = (bad.has(m.id) ? '<span class="warn" title="같은 시간대에 참가자 또는 코트가 겹칩니다">⚠ 겹침</span>' : '') + (mt?.mismatch ? '<span class="warn" title="남복·여복·혼복은 양쪽 조 종류가 같아야 합니다">⚠ 종류 불일치</span>' : '');
        const mine = cur && matchPeople(m).includes(cur) ? 'mine' : '';
        html += `<div class="mcard ${o.winner ? 'decided' : ''} ${bad.has(m.id) || mt?.mismatch ? 'conflict' : ''} ${mine}">
          <div class="mhead">${edit ? `<select class="ed" data-mid="${m.id}" data-f="slot">${slotOpts(m.slot)}</select><select class="ed" data-mid="${m.id}" data-f="court">${courtOpts(m.court)}</select>` : `<b>${m.court}코트</b>`} ${phaseTag(m)}${typeTag} ${warn}${edit ? `<button class="small x" data-del-match="${m.id}">삭제</button>` : ''}</div>
          <div class="mbody"><div class="side ${o.winner === 'a' ? 'w' : ''}">${cell(m, 'a')}</div><div class="vs">vs</div><div class="side ${o.winner === 'b' ? 'w' : ''}">${cell(m, 'b')}</div></div>
          <div class="mfoot">${scores}${res}</div></div>`;
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
    const nSlotsAll = totalSlots(); const dblRest = {};
    for (const p of ps) { let run = 0; for (let i = 0; i < nSlotsAll; i++) { if (!playerAvailable(p, state.settings, i)) { run = 0; continue; } if (slotsOf[p.id]?.has(i)) run = 0; else { run++; if (run >= 2) dblRest[p.id] = (dblRest[p.id] || 0) + 1; } } }
    const sorted = [...ps].sort((a, b) => (games[b.id] || 0) - (games[a.id] || 0) || (teamOf[a.id] || '').localeCompare(teamOf[b.id] || '') || a.name.localeCompare(b.name));
    const team = state.settings.mode === 'team';
    const cell = (v, cls) => `<td class="num ${cls || ''}">${v || '-'}</td>`;
    box.innerHTML = `<h3>인당 경기 수 <span class="sub">(최소 ${min} · 최대 ${max} · 총 ${ms.length}경기${state.schedule?.seed != null ? ` · 생성 #${state.schedule.seed}` : ''})</span></h3>
      <div class="table-wrap"><table class="stand summary"><thead><tr><th>선수</th>${team ? '<th>팀</th>' : ''}<th>합류</th><th class="num">경기</th><th class="num">남복</th><th class="num">여복</th><th class="num">혼복</th><th>비고</th></tr></thead><tbody>
      ${sorted.map((p) => { const g = games[p.id] || 0; const t = tc[p.id] || {}; return `<tr class="${g === max && max !== min ? 'hi' : ''} ${g === min && max !== min ? 'lo' : ''}">
        <td><b>${esc(p.name)}</b>${p.gender === 'F' ? ' <span class="sub">여</span>' : ''}</td>${team ? `<td class="sub">${esc(teamOf[p.id] || '')}</td>` : ''}<td class="sub">${esc(p.from || '')}${p.until ? '~' + esc(p.until) : ''}</td>
        <td class="num"><b>${g}</b></td>${cell(t.남복)}${cell(t.여복)}${cell(t.혼복)}<td class="sub">${dblRest[p.id] ? '⚠ 2회 연속 휴식' : ''}</td></tr>`; }).join('')}</tbody></table></div>
      ${max - min > 1 ? '<p class="hint">경기 수 차이가 2 이상입니다. 합류 시각 차이 때문이면 정상이며, 그렇지 않으면 현장 편집으로 조정하세요.</p>' : ''}
      ${Object.keys(dblRest).length ? '<p class="hint">⚠ 표시: 참석 가능한 시간대에 2회 연속 쉬는 구간이 있습니다. 인원·성별 구성상 불가피한 경우(예: 19시대 코트 1면)가 아니면 다시 생성하거나 현장 편집으로 조정하세요.</p>' : ''}`;
  }
  $('#sel-me').addEventListener('change', (e) => { state.meFilter = e.target.value; renderSchedule(); });
  $('#schedule-view').addEventListener('change', (e) => {
    const el = e.target; const m = state.schedule?.matches.find((x) => x.id === el.dataset.mid); if (!m) return;
    if (el.dataset.side) { getResult(m.id)[+el.dataset.i][el.dataset.side] = el.value; commit(); return; }
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
    const del = e.target.closest('button[data-del-match]'); if (!del) return;
    if (!confirm('이 경기를 삭제할까요?')) return;
    state.schedule.matches = state.schedule.matches.filter((m) => m.id !== del.dataset.delMatch); delete state.results[del.dataset.delMatch]; commit();
  });
  $('#chk-edit').addEventListener('change', (e) => { state.editMode = e.target.checked; commit(); });
  $('#btn-add-match').addEventListener('click', () => { state.schedule.matches.push(isRot() ? { id: uid(), phase: 'extra', slot: totalSlots() - 1, court: 1, aIds: [null, null], bIds: [null, null] } : state.settings.mode === 'team' ? { id: uid(), phase: 'rr', group: 0, round: 0, slot: totalSlots() - 1, court: 1, aId: null, bId: null, aPlayers: [null, null], bPlayers: [null, null] } : { id: uid(), phase: 'extra', slot: totalSlots() - 1, court: 1, aId: null, bId: null }); commit(); });
  $('#btn-add-slot').addEventListener('click', () => { state.schedule.extraSlots = (state.schedule.extraSlots || 0) + 1; commit(); });
  $('#btn-compact').addEventListener('click', () => {
    const ms = state.schedule.matches.filter((m) => !m.bye); const used = [...new Set(ms.map((m) => m.slot))].sort((a, b) => a - b);
    ms.forEach((m) => (m.slot = used.indexOf(m.slot))); state.schedule.extraSlots = 0; commit();
  });

  function rotationStandings() {
    const rows = Object.fromEntries(state.schedule.unitIds.map((id) => [id, { id, p: 0, w: 0, l: 0, d: 0, gf: 0, ga: 0 }]));
    for (const m of state.schedule.matches) {
      if (!m.aIds) continue; const o = matchOutcome(m); if (!o.filled) continue;
      const A = sideIds(m, 'a').map((id) => rows[id]).filter(Boolean), B = sideIds(m, 'b').map((id) => rows[id]).filter(Boolean);
      A.forEach((r) => { r.p++; r.gf += o.ag; r.ga += o.bg; if (o.winner === 'a') r.w++; else if (o.winner === 'b') r.l++; else r.d++; });
      B.forEach((r) => { r.p++; r.gf += o.bg; r.ga += o.ag; if (o.winner === 'b') r.w++; else if (o.winner === 'a') r.l++; else r.d++; });
    }
    return Object.values(rows).sort((x, y) => y.w - x.w || (y.gf - y.ga) - (x.gf - x.ga) || y.gf - x.gf || x.p - y.p);
  }
  function renderStandings() {
    const view = $('#standings-view'); const sch = state.schedule;
    if (sch && isRot()) {
      const list = rotationStandings(); const games = {}; sch.matches.forEach((m) => [...sideIds(m, 'a'), ...sideIds(m, 'b')].forEach((id) => (games[id] = (games[id] || 0) + 1)));
      view.innerHTML = `<h3>개인 순위 <span class="sub">(승 → 득실차 → 득게임)</span></h3><table class="stand"><thead><tr><th class="num">순위</th><th>선수</th><th class="num">배정</th><th class="num">경기</th><th class="num">승</th><th class="num">패</th><th class="num">무</th><th class="num">득게임</th><th class="num">실게임</th><th class="num">득실차</th></tr></thead><tbody>
        ${list.map((r, i) => `<tr class="${i === 0 && r.p ? 'rank1' : ''}"><td class="num">${i + 1}</td><td>${unitHtml(r.id)}</td><td class="num">${games[r.id] || 0}</td><td class="num">${r.p}</td><td class="num">${r.w}</td><td class="num">${r.l}</td><td class="num">${r.d}</td><td class="num">${r.gf}</td><td class="num">${r.ga}</td><td class="num">${r.gf - r.ga}</td></tr>`).join('')}</tbody></table>`;
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
      const list = Object.values(rows).filter((r) => games[r.id]).sort((x, y) => y.w - x.w || (y.gf - y.ga) - (x.gf - x.ga) || y.gf - x.gf);
      return `<h3>개인 기록</h3><table class="stand"><thead><tr><th class="num">순위</th><th>선수</th><th>팀</th><th class="num">배정</th><th class="num">경기</th><th class="num">승</th><th class="num">패</th><th class="num">득실차</th></tr></thead><tbody>
        ${list.map((r, i) => `<tr><td class="num">${i + 1}</td><td>${esc(pname(r.id))}</td><td class="sub">${esc(teamOf[r.id] || '')}</td><td class="num">${games[r.id]}</td><td class="num">${r.p}</td><td class="num">${r.w}</td><td class="num">${r.l}</td><td class="num">${r.gf - r.ga}</td></tr>`).join('')}</tbody></table>`;
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
      const sc = (side) => m.bye ? '' : r.map((s) => s[side] === '' ? '-' : s[side]).join(' ');
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
    const out = { ...state, editMode: false, publishedAt: new Date().toISOString() };
    const blob = new Blob([JSON.stringify(out, null, 2)], { type: 'application/json' });
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
    a.download = 'tournament.json'; a.click();
    alert('tournament.json 을 저장소의 data/ 폴더에 넣고 push 하면 게시됩니다.');
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  });
  $('#btn-import').addEventListener('click', () => $('#file-import').click());
  $('#file-import').addEventListener('change', async (e) => {
    const f = e.target.files[0]; if (!f) return;
    try {
      const data = JSON.parse(await f.text());
      if (!data.settings || !Array.isArray(data.players)) throw new Error('형식이 올바르지 않습니다.');
      state = { ...emptyState(), ...data, settings: { ...DEFAULT_SETTINGS, ...data.settings } }; await decryptAll(); commit();
    } catch (err) { alert('가져오기 실패: ' + err.message); }
    e.target.value = '';
  });
  $('#btn-print').addEventListener('click', () => window.print());
  $('#btn-reset').addEventListener('click', () => {
    if (!confirm('모든 설정·참가자·결과를 지웁니다. 계속할까요? (먼저 내보내기를 권장)')) return;
    state = emptyState(); save(); render(); showTab('players');
  });

  // ================= 게시본 (저장소 data/tournament.json) =================
  const EDITOR_FLAG = 'tennisweet.editor';
  async function loadPublished() {
    try { const res = await fetch('data/tournament.json', { cache: 'no-store' }); if (!res.ok) return null; return await res.json(); } catch { return null; }
  }
  const normalize = (data) => ({ ...emptyState(), ...data, settings: { ...DEFAULT_SETTINGS, ...(data.settings || {}) }, editMode: false });
  function enterViewOnly(text) {
    viewOnly = true; document.body.classList.add('view-only');
    $('#view-banner').hidden = false; $('#view-banner-text').textContent = text;
  }
  function adminLogin() { location.href = 'admin.html?t=' + Date.now(); } // 관리자 페이지로 이동 (캐시된 옛 페이지 방지)
  $('#btn-editor').addEventListener('click', adminLogin);
  $('#btn-leave-editor').addEventListener('click', () => { sessionStorage.removeItem(PW_KEY); location.href = './'; });
  $('#btn-load-published').addEventListener('click', async () => {
    const pub = await loadPublished(); if (!pub) { alert('게시본(data/tournament.json)을 찾을 수 없습니다.'); return; }
    if (!confirm('게시본을 불러와 현재 작업본을 덮어씁니다. 계속할까요?')) return;
    state = normalize(pub); await decryptAll(); commit();
  });

  window.tennisweet = { getState: () => JSON.parse(JSON.stringify(state)), setState: async (d) => { state = normalize(d); await decryptAll(); commit(); }, isAdmin: () => !!adminKey };

  // ================= 시작 =================
  (async () => {
    $$('.tab').forEach((t) => t.classList.remove('active')); // 초기 활성 탭은 모드 결정 후 지정
    if (await tryLoadShared()) { enterViewOnly(`공유 링크 보기 (읽기 전용) · ${sharedAt ? new Date(sharedAt).toLocaleString('ko-KR') : ''} 기준`); render(); showTab('schedule'); return; }
    const published = await loadPublished();
    const pw = sessionStorage.getItem(PW_KEY);
    const isAdminPage = document.body.dataset.page === 'admin';
    const editor = isAdminPage && pw && (await sha256hex(ADMIN_SALT + pw)) === ADMIN_HASH;
    if (isAdminPage && !editor) { location.replace('admin.html?t=' + Date.now()); return; }
    if (!editor) { // 일반 페이지는 항상 보기 전용
      if (published) state = normalize(published);
      enterViewOnly(published ? `게시본 보기 (읽기 전용)${published.publishedAt ? ' · ' + new Date(published.publishedAt).toLocaleString('ko-KR') + ' 게시' : ''}` : '게시본(data/tournament.json)이 아직 없습니다. 관리자 페이지에서 만들어 게시하세요.');
      render(); showTab(state.schedule ? 'schedule' : 'players'); return;
    }
    document.body.classList.add('editor');
    let saved = storage.load();
    // 게시본이 작업본보다 새로우면(다른 기기·Claude 에서 게시) 작업본을 게시본으로 교체할지 확인
    if (saved && published && published.publishedAt && (!saved.savedAt || published.publishedAt > saved.savedAt)) {
      if (confirm(`저장소의 게시본(${new Date(published.publishedAt).toLocaleString('ko-KR')})이 이 브라우저의 작업본보다 새롭습니다.\n게시본을 불러올까요? (취소하면 기존 작업본을 계속 편집)`)) saved = null;
    }
    state = saved ? normalize(saved) : published ? normalize(published) : emptyState();
    if (!saved) save(); // 게시본을 작업본으로 복사
    $('#view-banner').hidden = false; $('#view-banner').classList.add('editor-banner');
    $('#view-banner-text').textContent = `✏️ 관리자 모드 (v ${String(window.TENNISWEET_VERSION || '').slice(0, 7)}) · 이 브라우저의 작업본을 편집 중${published?.publishedAt ? ` · 현재 게시본 ${new Date(published.publishedAt).toLocaleString('ko-KR')}` : ''} · 게시하려면 내보내기 → data/tournament.json 교체 → push`;
    adminKey = await deriveKey(pw); await decryptAll();
    render(); showTab('players');
  })();
})();
