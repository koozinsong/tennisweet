// 정기 모임 대진 생성기 headless 검증: app.js 전체를 DOM 스텁 위에 로드하고 generateWeeklySchedule / wkRuleCheck 를 꺼내 돌린다
// 사용: node tools/wk_harness.js live [날짜…]     실제 data/weekly 세션으로 생성해 보고 불변식·인당 경기 수를 출력
//       node tools/wk_harness.js early             일찍 온 사람 시나리오 (여 3·남 1 등)
//       node tools/wk_harness.js fuzz [횟수]        무작위 구성으로 불변식 검사 (중복·빈 코트·도착 직후 휴식·2경기 차이·게스트)
//       node tools/wk_harness.js json <날짜> [gen] [by]  그 세션 대진을 앱과 같은 seed 로 생성해 JSON 출력 (파일 저장은 하지 않음)
const fs = require('fs'); const vm = require('vm'); const path = require('path');
const ROOT = path.join(__dirname, '..');
let src = fs.readFileSync(process.env.APP || path.join(ROOT, 'app.js'), 'utf8'); // APP=다른 app.js 경로 (이전 판과 비교할 때)
{ const lines = src.split('\n'); let ln = -1; for (let i = lines.length - 1; i >= 0; i--) if (lines[i] === '  (async () => {') { ln = i; break; }
  if (ln < 0) throw new Error('init IIFE not found');
  lines.splice(ln, 0, '  globalThis.__T = { generateWeeklySchedule, wkRuleCheck, wkSettings, wkAttendees, expectedGames: typeof expectedGames === \'function\' ? expectedGames : null, W };');
  lines.splice(ln + 1, 1, '  (async () => { return; '); src = lines.join('\n'); } // 초기화(네트워크·렌더)는 실행하지 않는다
const el = () => new Proxy({ classList: { contains: () => false, toggle() {}, add() {}, remove() {} }, style: {}, dataset: {}, value: '', textContent: '', innerHTML: '', hidden: false, addEventListener() {}, removeEventListener() {}, setAttribute() {}, getAttribute: () => null, querySelector: () => null, querySelectorAll: () => [], closest: () => null, focus() {}, click() {}, appendChild() {}, remove() {} }, { get: (t, k) => (k in t ? t[k] : (typeof k === 'string' && /^[a-z]/.test(k) ? () => undefined : undefined)) });
const store = () => { const m = new Map(); return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k), clear: () => m.clear() }; };
const doc = { body: el(), documentElement: el(), querySelector: () => el(), querySelectorAll: () => [], getElementById: () => el(), createElement: () => el(), addEventListener() {}, removeEventListener() {}, activeElement: null, hidden: false };
const ctx = { console, setTimeout, clearTimeout, setInterval: () => 0, clearInterval() {}, Date, Math, JSON, Map, Set, Promise, Proxy, Reflect, Number, String, Array, Object, TextEncoder, TextDecoder, btoa, atob, URL, URLSearchParams, crypto: globalThis.crypto || require('crypto').webcrypto, document: doc, localStorage: store(), sessionStorage: store(), location: { origin: 'http://localhost', pathname: '/', hash: '', search: '', href: 'http://localhost/', hostname: 'localhost', reload() {} }, navigator: { userAgent: 'node', clipboard: {} }, history: { replaceState() {} }, alert() {}, confirm: () => true, prompt: () => null, fetch: () => Promise.reject(new Error('no fetch')), requestAnimationFrame: (f) => setTimeout(f, 0), matchMedia: () => ({ matches: false, addEventListener() {} }), performance, structuredClone, CSS: { escape: (s) => s } };
ctx.window = ctx; ctx.globalThis = ctx; ctx.self = ctx;
vm.createContext(ctx); vm.runInContext(src, ctx, { filename: 'app.js' });
const T = ctx.__T; if (!T) throw new Error('export failed');
if (!T.expectedGames) T.expectedGames = function expectedGames(people, n, av, seatsAt, guestSeatsAt) { // app.js 의 같은 이름 함수 사본 (APP= 로 이전 판을 돌릴 때)
  const E = {}, Eq = {}, pre = {}; for (const p of people) { E[p.id] = 0; Eq[p.id] = 0; pre[p.id] = []; }
  for (let sl = 0; sl < n; sl++) { for (const p of people) pre[p.id][sl] = E[p.id]; const here = people.filter((p) => av(p.id, sl)); const seats = Math.max(0, seatsAt(sl) | 0); if (here.length < 4 || seats <= 0) continue;
    const gs = here.filter((p) => p.guest), ms = here.filter((p) => !p.guest); const gSeats = Math.min(seats, guestSeatsAt ? Math.max(0, guestSeatsAt(sl) | 0) : gs.length);
    const mShare = ms.length ? Math.min(1, Math.max(0, seats - gSeats) / ms.length) : 0, gShare = gs.length ? Math.min(1, gSeats / gs.length) : 0, eq = Math.min(1, seats / here.length); for (const p of here) { E[p.id] += p.guest ? gShare : mShare; Eq[p.id] += eq; } }
  return { E, Eq, upTo: (id, slot) => (pre[id] && pre[id][slot] != null ? pre[id][slot] : E[id] || 0) }; };

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
  const minFF = new Set(sch.matches.filter((m) => [...m.aIds, ...m.bIds].every((x) => att[x.slice(2)]?.g === 'F')).sort((a, b) => a.slot - b.slot || a.court - b.court).slice(0, s.minWomenDoubles | 0).map((m) => m.id)); // 최소 여복에 해당하는 코트만 도착 우선의 예외
  const games = {}; ids.forEach((k) => { games[k] = 0; }); const played = new Set(); const out = { dup: [], lateRest: [], empty: [], bad: [], lines: [] };
  for (let i = 0; i < n; i++) {
    const ms = (by[i] || []).sort((a, b) => a.court - b.court); const seen = new Set(); const playing = new Set();
    for (const m of ms) { for (const x of [...m.aIds, ...m.bIds]) { if (seen.has(x)) out.dup.push(`${hhmm(T0(s, i))} ${nm(x)}`); seen.add(x); playing.add(x.slice(2)); if (!att[x.slice(2)] || !avail(att[x.slice(2)], s, i)) out.bad.push(`${hhmm(T0(s, i))} ${nm(x)} 참석 시간 밖`); }
      const g = (x) => att[x.slice(2)]?.g; const wa = m.aIds.filter((x) => g(x) === 'F').length, wb = m.bIds.filter((x) => g(x) === 'F').length; if (Math.abs(wa - wb) > 1) out.bad.push(`${hhmm(T0(s, i))} c${m.court} 여${wa} vs 여${wb}`); }
    const av = ids.filter((k) => avail(att[k], s, i)); const cap = feasCap(av.length, courtsAt(s, i)); if (ms.length < cap) out.empty.push(`${hhmm(T0(s, i))} ${ms.length}/${cap}면 (참석 ${av.length})`);
    const first = av.filter((k) => { for (let j = 0; j < i; j++) if (avail(att[k], s, j)) return false; return true; });
    const ffIds = new Set(ms.filter((m) => minFF.has(m.id)).flatMap((m) => [...m.aIds, ...m.bIds].map((x) => x.slice(2)))); // 여복 코트 (여복 우선: 이 코트 때문에 막 도착한 남자가 쉬는 것은 허용)
    const early0 = [...playing].filter((k) => played.has(k) && !att[k].guest); const resting = first.filter((k) => !playing.has(k)).filter((k) => early0.some((q) => !(att[k].g !== 'F' && ffIds.has(q)))); const early = early0;
    if (resting.length && early.length) { const zero = av.filter((k) => !played.has(k)); out.lateRest.push(`${hhmm(T0(s, i))} 쉼 ${resting.map((k) => att[k].n)} / 이미 뛴 ${early.map((k) => att[k].n)}${zero.length <= 4 * ms.length ? '' : ' [자리 부족 — 불가피]'}`); }
    for (const k of playing) { games[k]++; played.add(k); }
    const tag = (m) => { const g = (x) => (att[x.slice(2)]?.g === 'F' ? 'F' : 'M'); const a = m.aIds.map(g).sort().join(''), b = m.bIds.map(g).sort().join(''); return a === b ? { FF: '여복', FM: '혼복', MM: '남복' }[a] : '잡복'; };
    for (const m of ms) { const lv = (x) => { const v = T.W.index?.levels?.[x.slice(2)]; return Number.isFinite(v) ? v : (att[x.slice(2)]?.g === 'F' ? 3 : 3.5); }; const sa = m.aIds.reduce((a, x) => a + lv(x), 0), sb = m.bIds.reduce((a, x) => a + lv(x), 0); const dd = Math.abs(sa - sb); out.diffSum = (out.diffSum || 0) + dd; if (dd >= 1 && tag(m) !== '혼복') (out.big ??= []).push(`${hhmm(T0(s, i))} c${m.court} ${tag(m)} ${sa} vs ${sb}`); out.lines.push(`${hhmm(T0(s, i))} c${m.court} ${tag(m)}  ${m.aIds.map(nm).join('+')}(${sa}) vs ${m.bIds.map(nm).join('+')}(${sb})${dd >= 1 ? '  ◀ 차이 ' + dd : ''}`); }
  }
  const on = []; for (let i = 0; i < n; i++) on[i] = Math.min(courtsAt(s, i), Math.floor(ids.filter((k) => avail(att[k], s, i)).length / 4)) >= 1; // 코트가 서는 시간대 (4명 이상)
  const slotsOf = (k) => { let c = 0; for (let i = 0; i < n; i++) if (on[i] && avail(att[k], s, i)) c++; return c; };
  out.ff = sch.matches.filter((m) => [...m.aIds, ...m.bIds].every((x) => att[x.slice(2)]?.g === 'F')).length; out.ffPossible = (() => { for (let i = 0; i < n; i++) if (courtsAt(s, i) >= 1 && ids.filter((k) => att[k].g === 'F' && avail(att[k], s, i)).length >= 4) return true; return false; })();
  const maxG = Math.max(0, ...Object.values(games)); const mem = ids.filter((k) => !att[k].guest); const maxM = Math.max(0, ...mem.map((k) => games[k])); const open = mem.filter((k) => games[k] < slotsOf(k));
  const X = (() => { const seatsAt = [], gSeatsAt = []; for (const m of sch.matches) { const all = [...m.aIds, ...m.bIds].map((x) => x.slice(2)); seatsAt[m.slot] = (seatsAt[m.slot] || 0) + all.length; gSeatsAt[m.slot] = (gSeatsAt[m.slot] || 0) + all.filter((x) => att[x]?.guest).length; } return T.expectedGames(ids.map((k) => ({ id: k, guest: !!att[k].guest, yield: !!att[k].y })), n, (k, i) => avail(att[k], s, i), (i) => seatsAt[i] || 0, (i) => gSeatsAt[i] || 0); })(); // 기대 경기 수 (룰 체크와 같은 계산)
  const fl = (x) => Math.floor(x + 1e-6), ce = (x) => Math.ceil(x - 1e-6); const tops = ids.filter((k) => games[k] === maxG).map((k) => X.Eq[k] || 0); const topEq = tops.length ? Math.min(...tops) : 0; const hardOf = (k) => Math.max(Math.min(slotsOf(k), maxG - 2 - Math.max(0, fl(topEq - (X.Eq[k] || 0)))), maxG >= 2 ? 1 : 0); const floorOf = (k, E = X.E) => Math.max(fl(E[k] || 0), hardOf(k)); out.E = X.E; // 룰 체크(wkRuleCheck)와 같은 하한
  let memSeats = 0, memCap = 0; for (let i = 0; i < n; i++) { const seatsI = sch.matches.filter((m) => m.slot === i).reduce((a, m) => a + m.aIds.length + m.bIds.length, 0); memCap += Math.min(seatsI, mem.filter((k) => avail(att[k], s, i)).length); } for (const m of sch.matches) memSeats += [...m.aIds, ...m.bIds].filter((x) => !att[x.slice(2)]?.guest).length; const needFloor = mem.reduce((a, k) => a + (slotsOf(k) >= 1 ? Math.min(slotsOf(k), floorOf(k)) : 0), 0), hardNeed = mem.reduce((a, k) => a + (slotsOf(k) >= 1 ? Math.min(slotsOf(k), hardOf(k)) : 0), 0); const slack = Math.max(0, needFloor - Math.max(memSeats, Math.min(memCap, hardNeed))); const shortIds = mem.filter((k) => games[k] < slotsOf(k) && games[k] < floorOf(k)); const unavoidable = shortIds.length <= slack && shortIds.every((k) => games[k] >= floorOf(k) - 1); out.shortNote = unavoidable && shortIds.length ? shortIds.map((k) => `${att[k].n} ${games[k]} (기대 ${(X.E[k] || 0).toFixed(1)}, 자리 수상 불가피)`) : []; // 하한의 합 > 회원 자리면 1경기 부족은 불가피 (룰 체크와 같은 기준)
  out.gap2 = mem.filter((k) => (!unavoidable && games[k] < slotsOf(k) && games[k] < floorOf(k)) || games[k] > ce(X.E[k] || 0)).map((k) => `${att[k].n} ${games[k]} (기대 ${(X.E[k] || 0).toFixed(1)})`); // 기대의 내림보다 적게(하한 포함) 또는 올림보다 많이 뛴 회원
  { const playAt = {}; for (const m of sch.matches) for (const x of [...m.aIds, ...m.bIds]) (playAt[x.slice(2)] ??= new Set()).add(m.slot); const dev = (k) => games[k] - (X.E[k] || 0); const firstOf = (k) => { for (let i = 0; i < n; i++) if (avail(att[k], s, i)) return i; return -1; };
    const canSwap = (i, j) => { if (att[i].g !== att[j].g) return false; for (let sl = 0; sl < n; sl++) if (playAt[i]?.has(sl) && sl !== firstOf(i) && avail(att[j], s, sl) && !playAt[j]?.has(sl)) return true; return false; };
    for (const i of mem) for (const j of mem) if (i !== j && games[i] - games[j] >= 2 && dev(i) - dev(j) > 1 + 1e-6 && canSwap(i, j)) out.gap2.push(`${att[i].n} ${games[i]} > ${att[j].n} ${games[j]} (기대 ${(X.E[i] || 0).toFixed(1)}/${(X.E[j] || 0).toFixed(1)})`); } // 룰 체크의 '경기 수 불균형'과 같은 기준
  const Xp = (() => { const seatsAt = []; for (const m of sch.matches) seatsAt[m.slot] = (seatsAt[m.slot] || 0) + m.aIds.length + m.bIds.length; return T.expectedGames(ids.map((k) => ({ id: k, guest: !!att[k].guest, yield: !!att[k].y })), n, (k, i) => avail(att[k], s, i), (i) => seatsAt[i] || 0, null); })(); const canGive = mem.some((k) => games[k] >= 2 && games[k] - 1 >= floorOf(k, Xp.E)); /* 룰 체크(wkRuleCheck)와 같은 기준: 게스트가 먼저 앉은 기대 기준으로 하한을 지키면서 자리를 내줄 수 있는 회원 */ out.guestBehind = ids.filter((k) => { if (!att[k].guest) return false; const tg = Math.min(slotsOf(k), maxG); return games[k] < tg && (canGive || games[k] < tg - 1); }).map((k) => `${att[k].n} ${games[k]}/${Math.min(slotsOf(k), maxG)}`); // 게스트 최대 경기 보장 — 회원이 자리를 내주면 최다보다 3경기 이상 뒤지게 되는 경우(게스트가 자리보다 많음)의 1경기 부족은 불가피
  out.table = ids.map((k) => ({ n: att[k].n + (att[k].guest ? '(G)' : ''), when: `${att[k].from.slice(0, 5)}~${att[k].until.slice(0, 5)}`, slots: slotsOf(k), games: games[k], e: X.E[k] || 0 })).sort((a, b) => (a.when < b.when ? -1 : a.when > b.when ? 1 : 0));
  return out;
}
const att_y = (d, r) => Object.values(d.attendance).some((a) => a.n === r.n.replace(/\(G\)$/, '') && a.y);
function report(name, d, levels, gens = [1]) {
  T.W.index = { levels: levels || {} }; T.W.id = d.id; console.log(`\n##### ${name}`); let allOk = true;
  for (const g of gens) {
    let sch; const t0 = Date.now(); try { sch = T.generateWeeklySchedule(d, null, 0, g); } catch (e) { console.log(`gen${g} ERROR ${e.message}`); allOk = false; continue; }
    const a = analyze(d, sch); const rc = T.wkRuleCheck(d, T.wkSettings(d), sch.matches); const ffMiss = (d.settings.minWomenDoubles | 0) >= 1 && a.ffPossible && a.ff < 1; const bad = a.dup.length || a.bad.length || a.empty.length || a.gap2.length || a.guestBehind.length || a.lateRest.some((x) => !/불가피/.test(x)); if (bad) allOk = false; // 여복 미달(ffMiss)은 경기 수 균등이 더 먼저라 생길 수 있어 참고로만 표시
    console.log(`gen${g} ${bad ? '✗' : '✓'} (${Date.now() - t0}ms) 경기 ${sch.matches.length} | 중복 ${JSON.stringify(a.dup)} 구성오류 ${JSON.stringify(a.bad)} 빈코트 ${JSON.stringify(a.empty)} 도착휴식 ${JSON.stringify(a.lateRest)} 불균형 ${JSON.stringify(a.gap2)} 게스트 ${JSON.stringify(a.guestBehind)} 여복 ${a.ff}${ffMiss ? ' (가능한데 없음 — 경기 수 균등 우선)' : ''}`);
    console.log('   룰 체크:', rc.issues.length ? rc.issues.join(' | ') : '통과', '|', (rc.notes.find((x) => /상위 남복/.test(x)) || '').slice(0, 24), '| 팀 합 차이 합계', a.diffSum || 0, '| 1.0 이상(혼복 제외):', JSON.stringify(a.big || []));
    console.log('   인당(이름 시간 경기/있는 시간대 (기대)):', a.table.map((r) => `${r.n}${att_y(d, r) ? '(양보)' : ''} ${r.when} ${r.games}/${r.slots} (${r.e.toFixed(1)})`).join(' · '));
    if (process.env.LINES || bad) console.log('   ' + a.lines.join('\n   '));
  }
  return allOk;
}
const P = (n, g, from, until, lv, guest, y) => ({ n, g, from, until, lv, guest, y });
function mkDoc(people, settings) { const att = {}, levels = {}; people.forEach((p, i) => { const k = 'p' + i; att[k] = { n: p.n, g: p.g, from: p.from, until: p.until, ...(p.guest ? { guest: true } : {}), ...(p.y ? { y: true } : {}) }; if (p.lv != null) levels[k] = p.lv; }); return { doc: { v: 1, id: '2026-10-01', date: '2026-10-01', status: 'open', rev: 1, settings: { startTime: '19:00', endTime: '22:00', matchMinutes: 30, breakMinutes: 0, courts: 2, minWomenDoubles: 1, ...settings }, attendance: att, schedule: null, done: {} }, levels }; }
if (require.main !== module) { module.exports = { T, analyze, report, mkDoc, P, nSlots, courtsAt, avail, hhmm, T0 }; return; } // 다른 스크립트에서 require 하면 로더·분석만 제공 (모드 실행 안 함)
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
  run('상위 남자 1명이 훨씬 높음 (상위 남복 유지 확인)', [M('top', '19:00', '21:00', 5), M('a1', '19:00', '21:00', 3.5), M('a2', '19:00', '21:00', 3.5), M('a3', '19:00', '21:00', 3.5), ...[1, 2, 3, 4].map((i) => M('b' + i, '19:00', '21:00', 3))], { endTime: '21:00', matchMinutes: 60, courts: 2 });
  run('남 4 먼저 + 여 3 나중', [...[1, 2, 3, 4].map((i) => M('m' + i, '19:00', '21:00')), F('a1', '20:00', '21:00'), F('a2', '20:00', '21:00'), F('a3', '20:00', '21:00')], { endTime: '21:00', matchMinutes: 60, courts: 3 });
} else if (mode === 'guest') { // 게스트 최대 경기 보장 시나리오
  const F = (n, a, b, lv = 3, gst) => P(n, 'F', a, b, lv, gst), M = (n, a, b, lv = 3.5, gst) => P(n, 'M', a, b, lv, gst); const run = (name, people, st) => { const { doc: d, levels } = mkDoc(people, st); return report(name, d, levels, [1, 2]); };
  run('게스트 6 + 회원 11 (오늘과 같은 꼴)', [F('w1', '19:00', '20:30', 3.5), F('w2', '19:00', '20:30', 3.5), F('w3', '19:00', '21:00', 2.5), M('m1', '19:00', '21:00', 3), F('w4', '20:00', '22:00', 3), ...[1, 2, 3, 4, 5, 6].map((i) => M('회' + i, '20:00', '22:00', [3, 3.5, 4][i % 3])), ...[1, 2, 3, 4, 5, 6].map((i) => M('G' + i, '20:00', '22:00', null, true))], { startTime: '18:00', courts: 3, courtsByHour: { 18: 1, 19: 1, 20: 3, 21: 3 } });
  run('게스트가 자리보다 많음 (게스트 10 + 회원 6, 2면)', [...[1, 2, 3, 4, 5, 6].map((i) => M('회' + i, '19:00', '22:00', 3.5)), ...[1, 2, 3, 4, 5, 6, 7, 8, 9, 10].map((i) => M('G' + i, '19:00', '22:00', null, true))], { courts: 2 });
  run('게스트가 늦게 오고 일찍 감 + 여자 게스트', [...[1, 2, 3, 4].map((i) => F('w' + i, '19:00', '22:00', 3)), ...[1, 2, 3, 4, 5, 6].map((i) => M('회' + i, '19:00', '22:00', 3.5)), M('G늦', '20:30', '22:00', null, true), M('G일찍', '19:00', '20:00', null, true), F('G여', '19:30', '21:30', null, true)], { courts: 2 });
  run('여복 마지막 기회에 게스트 남자가 자리를 다 씀 (여복 생략)', [F('w1', '19:00', '20:00'), F('w2', '19:00', '20:00'), F('w3', '19:00', '20:00'), F('w4', '19:00', '20:00'), ...[1, 2, 3, 4, 5, 6, 7, 8].map((i) => M('G' + i, '19:00', '20:00', null, true))], { endTime: '20:00', matchMinutes: 60, courts: 2 });
  const Gs = (k, a = '19:00', b = '22:00') => Array.from({ length: k }, (_, i) => M('G' + (i + 1), a, b, null, true)), Ms = (k, a = '19:00', b = '22:00') => Array.from({ length: k }, (_, i) => M('회' + (i + 1), a, b, 3.5));
  // 10/2 검토에서 나온 구성 — 게스트만으로 자리가 차는 날에도 회원이 0경기로 남지 않아야 한다 (누군가 2경기를 뛰는 동안)
  run('1면 3타임(60분) 게스트 6 + 회원 2', [...Gs(6), ...Ms(2)], { matchMinutes: 60, courts: 1 });
  run('1면 4타임 게스트 8 + 회원 1', [...Gs(8, '20:00'), ...Ms(1, '20:00')], { startTime: '20:00', courts: 1 });
  run('2면 2타임(60분) 게스트 8 + 회원 4', [...Gs(8, '19:00', '21:00'), ...Ms(4, '19:00', '21:00')], { endTime: '21:00', matchMinutes: 60, courts: 2 });
  run('1면 18~22시 게스트 2 + 회원 10 — 게스트가 회원보다 3경기 이상 앞서면 안 됨', [...Gs(2, '18:00'), ...Ms(10, '18:00')], { startTime: '18:00', courts: 1 });
  run('10/8 꼴 + 양보 1명: 일찍 온 4명(1면) + 20시 10명(3면), 한 명 양보 → 그 사람이 가장 적게', [F('w1', '19:00', '22:00', 3), F('w2', '19:00', '22:00', 3), M('e1', '19:00', '22:00', 3.5), M('e2', '19:00', '22:00', 4), ...[1, 2, 3, 4, 5, 6, 7, 8].map((i) => M('n' + i, '20:00', '22:00', [3, 3.5, 4][i % 3])), F('nw', '20:00', '22:00', 3), P('양보', 'M', '20:00', '22:00', 3.5, false, true)], { startTime: '18:00', courts: 3, courtsByHour: { 18: 1, 19: 1, 20: 3, 21: 3 } });
  run('17명 3면 게스트 6 — 도착 직후 휴식이 없어야 함', [M('G0', '19:00', '22:00', null, true), F('w1', '19:00', '22:00', 3.5), F('G2', '19:00', '19:30', null, true), M('m3', '19:30', '22:00', 4), M('m4', '19:30', '20:00', 3), F('w5', '20:30', '21:00', 3.5), F('w6', '19:30', '22:00', 3.5), M('G7', '20:30', '22:00', null, true), M('m8', '19:00', '19:30', 3.5), F('w9', '19:00', '20:30', 3), M('G10', '19:00', '20:00', null, true), M('m11', '19:00', '22:00', 4), M('G12', '19:00', '22:00', null, true), M('m13', '19:00', '22:00', 3.5), M('G14', '19:00', '20:30', null, true), M('m15', '21:00', '22:00', 3.5), M('m16', '19:00', '19:30', 3)], { courts: 3, minWomenDoubles: 1 });
} else if (mode === 'late') { // 참고용: 막판에 여럿이 도착 (1면) — 모두 한 번은 뛰어야 한다 (회원끼리 2경기 차이는 자리 수상 피할 수 없어 ✗ 로 나올 수 있음, 0경기가 없는지만 본다)
  const F = (n, a, b, lv = 3, gst) => P(n, 'F', a, b, lv, gst), M = (n, a, b, lv = 3.5, gst) => P(n, 'M', a, b, lv, gst); const run = (name, people, st) => { const { doc: d, levels } = mkDoc(people, st); return report(name, d, levels, [1, 2]); };
  const late6 = [1, 2, 3, 4, 5, 6].map((i) => M('m' + i, '21:00', '22:00', 3.5));
  run('1면 18~22시: 회원 2 + 게스트 2 종일, 회원 6 이 21시 도착', [M('a1', '18:00', '22:00'), M('a2', '18:00', '22:00'), M('E1', '18:00', '22:00', null, true), M('E2', '18:00', '22:00', null, true), ...late6], { startTime: '18:00', courts: 1 });
  run('1면 18~22시: 게스트 4 종일, 회원 6 이 21시 도착', [...[1, 2, 3, 4].map((i) => M('E' + i, '18:00', '22:00', null, true)), ...late6], { startTime: '18:00', courts: 1 });
} else if (mode === 'json') { // node tools/wk_harness.js json <날짜> [gen] [by] → 그 세션을 앱과 같은 seed 로 생성해 schedule 객체를 JSON 으로 출력 (파일은 건드리지 않음 — 관리자가 직접 저장할 때 씀)
  const id = process.argv[3]; const gen = +process.argv[4] || 1; const by = process.argv[5] || 'tool';
  const idx = JSON.parse(fs.readFileSync(path.join(ROOT, 'data/weekly/index.json'), 'utf8')); const d = JSON.parse(fs.readFileSync(path.join(ROOT, `data/weekly/sessions/${id}.json`), 'utf8'));
  T.W.index = { levels: idx.levels || {} }; T.W.id = d.id; T.W.me = by; const sch = T.generateWeeklySchedule(d, null, 0, gen); const a = analyze(d, sch);
  process.stderr.write(`${id} gen${gen} seed ${sch.seed} 경기 ${sch.matches.length} | 불균형 ${JSON.stringify(a.gap2)} 도착휴식 ${JSON.stringify(a.lateRest)} 게스트 ${JSON.stringify(a.guestBehind)}\n   인당: ${a.table.map((r) => `${r.n} ${r.games}/${r.slots} (${r.e.toFixed(1)})`).join(' · ')}\n   ${a.lines.join('\n   ')}\n`);
  process.stdout.write(JSON.stringify(sch));
} else if (mode === 'fuzz') {
  const N = +process.argv[3] || 40; let a = 7; const rnd = () => { a = (a + 0x6D2B79F5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; const pick = (arr) => arr[Math.floor(rnd() * arr.length)];
  const tally = { runs: 0, dup: 0, bad: 0, empty: 0, lateRest: 0, gap2: 0, guest: 0, error: 0, bigDiffMatches: 0, matches: 0, ms: 0 }; const samples = []; const log = console.log;
  for (let r = 0; r < N; r++) {
    const mm = pick([30, 60]); const courts = pick([1, 2, 3]); const n = 5 + Math.floor(rnd() * 14); const times = mm === 60 ? ['19:00', '20:00', '21:00'] : ['19:00', '19:30', '20:00', '20:30', '21:00']; const people = [];
    for (let i = 0; i < n; i++) { const g = rnd() < 0.4 ? 'F' : 'M'; const from = pick(times.slice(0, -1)); const until = rnd() < 0.7 ? '22:00' : pick(times.filter((t) => t > from).concat(['22:00'])); people.push(P((g === 'F' ? 'w' : 'm') + i, g, from, until, pick(g === 'F' ? [2.5, 3, 3.5] : [3, 3.5, 4]), rnd() < 0.1)); }
    const { doc: d, levels } = mkDoc(people, { matchMinutes: mm, courts, minWomenDoubles: pick([0, 1]) }); if (process.env.ONLY && +process.env.ONLY !== r) continue; /* ONLY=번호 → 그 무작위 구성 하나만 다시 돌려 자세히 봄 */ T.W.index = { levels }; T.W.id = d.id; tally.runs++;
    let sch; const tt = Date.now(); try { sch = T.generateWeeklySchedule(d, null, 0, 1); const el = Date.now() - tt; tally.ms += el; if (process.env.TRACE) process.stderr.write(`#${r} ${n}명(게스트 ${people.filter((p) => p.guest).length}) ${courts}면 ${mm}분 ${el}ms\n`); if (el > (tally.maxMs || 0)) { tally.maxMs = el; tally.slowest = `#${r} ${n}명 ${courts}면 ${mm}분`; } } catch (e) { if (!/배정 가능한 경기가 없습니다/.test(e.message)) { tally.error++; samples.push([r, 'ERR', e.message]); } continue; }
    const x = analyze(d, sch); if (process.env.ONLY) { log(people.map((p) => `${p.n}${p.guest ? '(G)' : ''} ${p.g} ${p.from}-${p.until}`).join(' · ')); log('   ' + x.lines.join('\n   ')); log('   인당: ' + x.per); } tally.bigDiffMatches += (x.big || []).length; tally.matches += sch.matches.length; if (x.dup.length) { tally.dup++; samples.push([r, 'dup', x.dup]); } if (x.bad.length) { tally.bad++; samples.push([r, 'bad', x.bad]); } if (x.empty.length) { tally.empty++; samples.push([r, 'empty', x.empty, people.map((p) => `${p.g}${p.from}-${p.until}`).join(' ')]); }
    if (x.lateRest.some((l) => !/불가피/.test(l))) { tally.lateRest++; samples.push([r, 'lateRest', x.lateRest]); } if (x.gap2.length) { tally.gap2++; samples.push([r, 'gap2', x.gap2, people.map((p) => `${p.g}${p.from}-${p.until}`).join(' '), `courts ${courts} mm ${mm}`]); } if (x.guestBehind.length) { tally.guest++; samples.push([r, 'guest', x.guestBehind]); } if ((d.settings.minWomenDoubles | 0) >= 1 && x.ffPossible && x.ff < 1) { tally.ffMiss = (tally.ffMiss || 0) + 1; samples.push([r, 'ffMiss', people.map((p) => `${p.g}${p.from}-${p.until}`).join(' '), `courts ${courts} mm ${mm}`]); }
  }
  log('\n##### FUZZ', JSON.stringify(tally)); for (const s of samples.slice(0, 14)) log('  ', JSON.stringify(s).slice(0, 600));
}
