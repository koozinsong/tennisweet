// 정기 모임 대진 생성기 headless 검증: app.js 전체를 DOM 스텁 위에 로드하고 generateWeeklySchedule / wkRuleCheck 를 꺼내 돌린다
// 사용: node tools/wk_harness.js live [날짜…]     실제 data/weekly 세션으로 생성해 보고 불변식·인당 경기 수를 출력
//       node tools/wk_harness.js early             일찍 온 사람 시나리오 (여 3·남 1 등)
//       node tools/wk_harness.js fuzz [횟수]        무작위 구성으로 불변식 검사 (중복·빈 코트·도착 직후 휴식·2경기 차이·게스트)
const fs = require('fs'); const vm = require('vm'); const path = require('path');
const ROOT = path.join(__dirname, '..');
let src = fs.readFileSync(path.join(ROOT, 'app.js'), 'utf8');
{ const lines = src.split('\n'); let ln = -1; for (let i = lines.length - 1; i >= 0; i--) if (lines[i] === '  (async () => {') { ln = i; break; }
  if (ln < 0) throw new Error('init IIFE not found');
  lines.splice(ln, 0, '  globalThis.__T = { generateWeeklySchedule, wkRuleCheck, wkSettings, wkAttendees, W };');
  lines.splice(ln + 1, 1, '  (async () => { return; '); src = lines.join('\n'); } // 초기화(네트워크·렌더)는 실행하지 않는다
const el = () => new Proxy({ classList: { contains: () => false, toggle() {}, add() {}, remove() {} }, style: {}, dataset: {}, value: '', textContent: '', innerHTML: '', hidden: false, addEventListener() {}, removeEventListener() {}, setAttribute() {}, getAttribute: () => null, querySelector: () => null, querySelectorAll: () => [], closest: () => null, focus() {}, click() {}, appendChild() {}, remove() {} }, { get: (t, k) => (k in t ? t[k] : (typeof k === 'string' && /^[a-z]/.test(k) ? () => undefined : undefined)) });
const store = () => { const m = new Map(); return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k), clear: () => m.clear() }; };
const doc = { body: el(), documentElement: el(), querySelector: () => el(), querySelectorAll: () => [], getElementById: () => el(), createElement: () => el(), addEventListener() {}, removeEventListener() {}, activeElement: null, hidden: false };
const ctx = { console, setTimeout, clearTimeout, setInterval: () => 0, clearInterval() {}, Date, Math, JSON, Map, Set, Promise, Proxy, Reflect, Number, String, Array, Object, TextEncoder, TextDecoder, btoa, atob, URL, URLSearchParams, crypto: globalThis.crypto || require('crypto').webcrypto, document: doc, localStorage: store(), sessionStorage: store(), location: { origin: 'http://localhost', pathname: '/', hash: '', search: '', href: 'http://localhost/', hostname: 'localhost', reload() {} }, navigator: { userAgent: 'node', clipboard: {} }, history: { replaceState() {} }, alert() {}, confirm: () => true, prompt: () => null, fetch: () => Promise.reject(new Error('no fetch')), requestAnimationFrame: (f) => setTimeout(f, 0), matchMedia: () => ({ matches: false, addEventListener() {} }), performance, structuredClone, CSS: { escape: (s) => s } };
ctx.window = ctx; ctx.globalThis = ctx; ctx.self = ctx;
vm.createContext(ctx); vm.runInContext(src, ctx, { filename: 'app.js' });
const T = ctx.__T; if (!T) throw new Error('export failed');

const toMin = (t) => { const [h, m] = t.split(':').map(Number); return h * 60 + m; };
const T0 = (s, i) => toMin(s.startTime) + i * (s.matchMinutes + (s.breakMinutes || 0));
const nSlots = (s) => Math.floor((toMin(s.endTime) - toMin(s.startTime) + (s.breakMinutes || 0)) / (s.matchMinutes + (s.breakMinutes || 0)));
const courtsAt = (s, i) => { const cb = s.courtsByHour; if (cb) { const v = cb[String(Math.floor(T0(s, i) / 60))]; if (Number.isInteger(v)) return v; } return s.courts; };
const avail = (a, s, i) => toMin(a.from) <= T0(s, i) && toMin(a.until) >= T0(s, i) + s.matchMinutes;
const hhmm = (min) => `${String(Math.floor(min / 60)).padStart(2, '0')}:${String(min % 60).padStart(2, '0')}`;
/** 그 시간대에 채울 수 있는 코트 수: 여자 0~4명 코트가 모두 가능(여 3·남 1 포함)하므로 인원만 맞으면 된다 */
const feasCap = (n, courts) => Math.min(courts, Math.floor(n / 4));
function analyze(d, sch) {
  const s = d.settings; const n = nSlots(s); const att = d.attendance; const ids = Object.keys(att); const nm = (x) => att[x.slice(2)]?.n || x;
  const by = {}; for (const m of sch.matches) (by[m.slot] ??= []).push(m);
  const games = {}; ids.forEach((k) => { games[k] = 0; }); const played = new Set(); const out = { dup: [], lateRest: [], empty: [], bad: [], lines: [] };
  for (let i = 0; i < n; i++) {
    const ms = (by[i] || []).sort((a, b) => a.court - b.court); const seen = new Set(); const playing = new Set();
    for (const m of ms) { for (const x of [...m.aIds, ...m.bIds]) { if (seen.has(x)) out.dup.push(`${hhmm(T0(s, i))} ${nm(x)}`); seen.add(x); playing.add(x.slice(2)); if (!att[x.slice(2)] || !avail(att[x.slice(2)], s, i)) out.bad.push(`${hhmm(T0(s, i))} ${nm(x)} 참석 시간 밖`); }
      const g = (x) => att[x.slice(2)]?.g; const wa = m.aIds.filter((x) => g(x) === 'F').length, wb = m.bIds.filter((x) => g(x) === 'F').length; if (Math.abs(wa - wb) > 1) out.bad.push(`${hhmm(T0(s, i))} c${m.court} 여${wa} vs 여${wb}`); }
    const av = ids.filter((k) => avail(att[k], s, i)); const cap = feasCap(av.length, courtsAt(s, i)); if (ms.length < cap) out.empty.push(`${hhmm(T0(s, i))} ${ms.length}/${cap}면 (참석 ${av.length})`);
    const first = av.filter((k) => { for (let j = 0; j < i; j++) if (avail(att[k], s, j)) return false; return true; });
    const resting = first.filter((k) => !playing.has(k)); const early = [...playing].filter((k) => played.has(k));
    if (resting.length && early.length) { const zero = av.filter((k) => !played.has(k)); out.lateRest.push(`${hhmm(T0(s, i))} 쉼 ${resting.map((k) => att[k].n)} / 이미 뛴 ${early.map((k) => att[k].n)}${zero.length <= 4 * ms.length ? '' : ' [자리 부족 — 불가피]'}`); }
    for (const k of playing) { games[k]++; played.add(k); }
    const tag = (m) => { const g = (x) => (att[x.slice(2)]?.g === 'F' ? 'F' : 'M'); const a = m.aIds.map(g).sort().join(''), b = m.bIds.map(g).sort().join(''); return a === b ? { FF: '여복', FM: '혼복', MM: '남복' }[a] : '잡복'; };
    for (const m of ms) out.lines.push(`${hhmm(T0(s, i))} c${m.court} ${tag(m)}  ${m.aIds.map(nm).join('+')} vs ${m.bIds.map(nm).join('+')}`);
  }
  const on = []; for (let i = 0; i < n; i++) on[i] = Math.min(courtsAt(s, i), Math.floor(ids.filter((k) => avail(att[k], s, i)).length / 4)) >= 1; // 코트가 서는 시간대 (4명 이상)
  const slotsOf = (k) => { let c = 0; for (let i = 0; i < n; i++) if (on[i] && avail(att[k], s, i)) c++; return c; };
  const maxG = Math.max(0, ...Object.values(games)); const open = ids.filter((k) => games[k] < slotsOf(k));
  out.gap2 = open.filter((k) => games[k] <= maxG - 2).map((k) => `${att[k].n} ${games[k]}/${maxG}`);
  out.guestBehind = ids.filter((k) => att[k].guest && games[k] < slotsOf(k) && ids.some((q) => !att[q].guest && games[q] > games[k])).map((k) => `${att[k].n} ${games[k]}`);
  out.table = ids.map((k) => ({ n: att[k].n, when: `${att[k].from.slice(0, 5)}~${att[k].until.slice(0, 5)}`, slots: slotsOf(k), games: games[k] })).sort((a, b) => (a.when < b.when ? -1 : a.when > b.when ? 1 : 0));
  return out;
}
function report(name, d, levels, gens = [1]) {
  T.W.index = { levels: levels || {} }; T.W.id = d.id; console.log(`\n##### ${name}`); let allOk = true;
  for (const g of gens) {
    let sch; const t0 = Date.now(); try { sch = T.generateWeeklySchedule(d, null, 0, g); } catch (e) { console.log(`gen${g} ERROR ${e.message}`); allOk = false; continue; }
    const a = analyze(d, sch); const rc = T.wkRuleCheck(d, T.wkSettings(d), sch.matches); const bad = a.dup.length || a.bad.length || a.empty.length || a.gap2.length || a.guestBehind.length || a.lateRest.some((x) => !/불가피/.test(x)); if (bad) allOk = false;
    console.log(`gen${g} ${bad ? '✗' : '✓'} (${Date.now() - t0}ms) 경기 ${sch.matches.length} | 중복 ${JSON.stringify(a.dup)} 구성오류 ${JSON.stringify(a.bad)} 빈코트 ${JSON.stringify(a.empty)} 도착휴식 ${JSON.stringify(a.lateRest)} 2경기차 ${JSON.stringify(a.gap2)} 게스트 ${JSON.stringify(a.guestBehind)}`);
    console.log('   룰 체크:', rc.issues.length ? rc.issues.join(' | ') : '통과');
    console.log('   인당(이름 시간 경기/있는 시간대):', a.table.map((r) => `${r.n} ${r.when} ${r.games}/${r.slots}`).join(' · '));
    if (process.env.LINES || bad) console.log('   ' + a.lines.join('\n   '));
  }
  return allOk;
}
const P = (n, g, from, until, lv, guest) => ({ n, g, from, until, lv, guest });
function mkDoc(people, settings) { const att = {}, levels = {}; people.forEach((p, i) => { const k = 'p' + i; att[k] = { n: p.n, g: p.g, from: p.from, until: p.until, ...(p.guest ? { guest: true } : {}) }; if (p.lv != null) levels[k] = p.lv; }); return { doc: { v: 1, id: '2026-10-01', date: '2026-10-01', status: 'open', rev: 1, settings: { startTime: '19:00', endTime: '22:00', matchMinutes: 30, breakMinutes: 0, courts: 2, minWomenDoubles: 1, ...settings }, attendance: att, schedule: null, done: {} }, levels }; }
const mode = process.argv[2] || 'live';
if (mode === 'live') {
  const idx = JSON.parse(fs.readFileSync(path.join(ROOT, 'data/weekly/index.json'), 'utf8')); const want = process.argv.slice(3); const ids = want.length ? want : idx.sessions.map((s) => s.id);
  for (const id of ids) { const d = JSON.parse(fs.readFileSync(path.join(ROOT, `data/weekly/sessions/${id}.json`), 'utf8')); d.schedule = null; d.done = {}; d.results = {}; report(`live ${id} (${d.settings.startTime}~${d.settings.endTime}, 참석 ${Object.keys(d.attendance).length})`, d, idx.levels, [1, 2, 3]); }
} else if (mode === 'early') {
  const F = (n, a, b, lv = 3) => P(n, 'F', a, b, lv), M = (n, a, b, lv = 3.5) => P(n, 'M', a, b, lv); const run = (name, people, st) => { const { doc: d, levels } = mkDoc(people, st); return report(name, d, levels, [1, 2]); };
  run('여 3 + 남 1 이 1시간 먼저 (1면 → 3면)', [F('w1', '19:00', '20:30', 3.5), F('w2', '19:00', '20:30', 3.5), F('w3', '19:00', '21:00', 2.5), M('m1', '19:00', '21:00', 3), ...[1, 2, 3, 4, 5, 6, 7, 8].map((i) => M('n' + i, '20:00', '22:00', [3, 3.5, 4][i % 3])), F('nw', '20:00', '22:00', 3)], { startTime: '18:00', courts: 3, courtsByHour: { 18: 1, 19: 1, 20: 3, 21: 3 } });
  run('여 1 + 남 3 이 먼저', [F('w1', '19:00', '22:00'), M('m1', '19:00', '22:00'), M('m2', '19:00', '22:00', 3), M('m3', '19:00', '21:00', 4), ...[1, 2, 3, 4, 5, 6].map((i) => M('n' + i, '20:00', '22:00'))], { courts: 2 });
  run('여 7 + 남 1 (2면)', [...[1, 2, 3, 4, 5, 6, 7].map((i) => F('w' + i, '19:00', '21:00', [2.5, 3, 3.5][i % 3])), M('m1', '19:00', '21:00')], { endTime: '21:00', courts: 2 });
  run('여 8 먼저 + 남 1 나중 (3면)', [...[1, 2, 3, 4, 5, 6, 7, 8].map((i) => F('w' + i, '19:00', '21:00')), M('m1', '20:00', '21:00')], { endTime: '21:00', courts: 3 });
  run('남 4 먼저 + 여 3 나중', [...[1, 2, 3, 4].map((i) => M('m' + i, '19:00', '21:00')), F('a1', '20:00', '21:00'), F('a2', '20:00', '21:00'), F('a3', '20:00', '21:00')], { endTime: '21:00', matchMinutes: 60, courts: 3 });
} else if (mode === 'fuzz') {
  const N = +process.argv[3] || 40; let a = 7; const rnd = () => { a = (a + 0x6D2B79F5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; const pick = (arr) => arr[Math.floor(rnd() * arr.length)];
  const tally = { runs: 0, dup: 0, bad: 0, empty: 0, lateRest: 0, gap2: 0, guest: 0, error: 0 }; const samples = []; const log = console.log;
  for (let r = 0; r < N; r++) {
    const mm = pick([30, 60]); const courts = pick([1, 2, 3]); const n = 5 + Math.floor(rnd() * 14); const times = mm === 60 ? ['19:00', '20:00', '21:00'] : ['19:00', '19:30', '20:00', '20:30', '21:00']; const people = [];
    for (let i = 0; i < n; i++) { const g = rnd() < 0.4 ? 'F' : 'M'; const from = pick(times.slice(0, -1)); const until = rnd() < 0.7 ? '22:00' : pick(times.filter((t) => t > from).concat(['22:00'])); people.push(P((g === 'F' ? 'w' : 'm') + i, g, from, until, pick(g === 'F' ? [2.5, 3, 3.5] : [3, 3.5, 4]), rnd() < 0.1)); }
    const { doc: d, levels } = mkDoc(people, { matchMinutes: mm, courts, minWomenDoubles: pick([0, 1]) }); T.W.index = { levels }; T.W.id = d.id; tally.runs++;
    let sch; try { sch = T.generateWeeklySchedule(d, null, 0, 1); } catch (e) { if (!/배정 가능한 경기가 없습니다/.test(e.message)) { tally.error++; samples.push([r, 'ERR', e.message]); } continue; }
    const x = analyze(d, sch); if (x.dup.length) { tally.dup++; samples.push([r, 'dup', x.dup]); } if (x.bad.length) { tally.bad++; samples.push([r, 'bad', x.bad]); } if (x.empty.length) { tally.empty++; samples.push([r, 'empty', x.empty, people.map((p) => `${p.g}${p.from}-${p.until}`).join(' ')]); }
    if (x.lateRest.some((l) => !/불가피/.test(l))) { tally.lateRest++; samples.push([r, 'lateRest', x.lateRest]); } if (x.gap2.length) { tally.gap2++; samples.push([r, 'gap2', x.gap2, people.map((p) => `${p.g}${p.from}-${p.until}`).join(' '), `courts ${courts} mm ${mm}`]); } if (x.guestBehind.length) { tally.guest++; samples.push([r, 'guest', x.guestBehind]); }
  }
  log('\n##### FUZZ', JSON.stringify(tally)); for (const s of samples.slice(0, 14)) log('  ', JSON.stringify(s).slice(0, 600));
}
