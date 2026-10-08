// 로컬 검증: GAS 전역을 흉내 내어 Code.gs 의 doPost 를 실행 (node tools/gas-proxy/test_local.js)
const fs = require('fs'); const vm = require('vm');
const store = { 'data/weekly/sessions/2026-09-20.json': { v: 1, id: '2026-09-20', date: '2099-01-01', status: 'open', rev: 0, settings: { startTime: '18:00', endTime: '22:00', matchMinutes: 30, breakMinutes: 0, courts: 2, minWomenDoubles: 1 }, attendance: {}, schedule: null, done: {} } };
const shas = {}; let putCalls = 0, conflictOnce = false;
const gas = {
  PropertiesService: { getScriptProperties: () => ({ getProperty: (k) => ({ GH_TOKEN: 'tok' }[k] || null) }) },
  LockService: { getScriptLock: () => ({ tryLock: () => true, releaseLock: () => {} }) },
  ContentService: { createTextOutput: (s) => ({ setMimeType: () => ({ text: s }) }), MimeType: { JSON: 'json' } },
  Utilities: { computeDigest: (alg, s) => [...require('crypto').createHash('sha256').update(String(s), 'utf8').digest()].map((b) => (b > 127 ? b - 256 : b)), DigestAlgorithm: { SHA_256: 'sha256' }, base64Decode: (s) => Buffer.from(s, 'base64'), base64Encode: (s) => Buffer.from(s, 'utf8').toString('base64'), newBlob: (buf) => ({ getDataAsString: () => buf.toString('utf8') }), Charset: { UTF_8: 'utf8' } },
  UrlFetchApp: { fetch: (url, opt = {}) => {
    const m = url.match(/contents\/(.+?)(\?|$)/); const path = m[1]; const br = (url.match(/ref=([^&]+)/) || [])[1] || (opt.payload && JSON.parse(opt.payload).branch); const key = br + ':' + path; const isMain = br === 'main';
    if (!opt.method) { const doc = isMain ? store[path] : store['gh:' + path]; if (!doc) return { getResponseCode: () => 404, getContentText: () => '' }; const content = Buffer.from(JSON.stringify(doc)).toString('base64'); shas[key] = shas[key] || 'sha1'; return { getResponseCode: () => 200, getContentText: () => JSON.stringify({ sha: shas[key], content }) }; }
    if (isMain) putCalls++; const body = JSON.parse(opt.payload); if ((shas[key] || null) !== (body.sha || null)) return { getResponseCode: () => 409, getContentText: () => '{}' }; if (isMain && conflictOnce) { conflictOnce = false; shas[key] += 'x'; return { getResponseCode: () => 409, getContentText: () => '{}' }; }
    const doc = JSON.parse(Buffer.from(body.content, 'base64').toString('utf8')); if (isMain) store[path] = doc; else store['gh:' + path] = doc; shas[key] = (shas[key] || 'sha1') + 'x'; return { getResponseCode: () => 200, getContentText: () => '{}' }; } },
  CacheService: { getScriptCache: () => ({ get: (k) => (globalThis.__cache = globalThis.__cache || {})[k] || null, put: (k, v) => { (globalThis.__cache = globalThis.__cache || {})[k] = v; }, remove: (k) => { delete (globalThis.__cache = globalThis.__cache || {})[k]; } }) },
  Date,
};
const TEST_KEY = 'ab'.repeat(32); // 테스트용 열쇠 — 실제 열쇠(비밀번호에서 파생)는 저장소 어디에도 없다. Code.gs 의 WK_KEY_SHA 를 이 열쇠의 해시로 바꿔 실행한다
const gsSrc = fs.readFileSync(__dirname + '/Code.gs', 'utf8').replace(/const WK_KEY_SHA = '[0-9a-f]{64}'/, "const WK_KEY_SHA = '" + require('crypto').createHash('sha256').update(TEST_KEY).digest('hex') + "'");
const ctx = vm.createContext(gas); vm.runInContext(gsSrc + '\nglobalThis.__doPost = doPost; globalThis.__doGet = doGet;', ctx);
const call = (body) => JSON.parse(ctx.__doPost({ postData: { contents: JSON.stringify(body) } }).text);
const base = { v: 1, club: 'tennisweet', session: '2026-09-20' };
const AUTH = TEST_KEY; const OLD_VERIFIER = '3b4facb575a1dc30b189b7c01b746e68e952b3a94a4b9776a6f261aba87e2bac'; // 옛 방식의 공개 검증값 — 이제 인증으로 통하지 않아야 한다
const results = [];
{ const p = call({ ...base, op: 'ping' }); results.push(['ping', p.ok === true && p.v === 6]); }
results.push(['bad club', call({ ...base, club: 'x', op: 'set' }).code === 'INVALID']);
results.push(['no session', call({ ...base, session: '2026-01-01', op: 'set', path: 'attendance.a', value: { n: 'x', g: 'M', from: '18:00', until: '22:00' } }).code === 'NOSESSION']);
let r = call({ ...base, op: 'set', path: 'attendance.h0teikh', value: { n: '송국진', g: 'M', from: '19:00', until: '22:00' }, by: 'h0teikh' }); results.push(['attend ok', r.ok && r.rev === 1 && r.doc.attendance.h0teikh.n === '송국진']);
r = call({ ...base, op: 'set', path: 'attendance.g:abc', value: { n: '홍길동', g: 'F', from: '18:00', until: '22:00', guest: true } }); results.push(['guest ok', r.ok && r.doc.attendance['g:abc'].guest === true && r.rev === 2]);
r = call({ ...base, op: 'set', path: 'attendance.yy1', value: { n: '양보자', g: 'M', from: '18:00', until: '22:00', y: true } }); results.push(['yield stored', r.ok && r.doc.attendance.yy1.y === true]); r = call({ ...base, op: 'set', path: 'attendance.yy1', value: { n: '양보자', g: 'M', from: '18:00', until: '22:00' } }); results.push(['yield cleared when omitted', r.ok && r.doc.attendance.yy1.y === undefined]);
r = call({ ...base, op: 'set', path: 'attendance.h0teikh', value: { n: '송국진', g: 'M', from: '22:00', until: '19:00' } }); results.push(['bad time invalid', r.code === 'INVALID']);
r = call({ ...base, op: 'set', path: 'done.s0c1', value: true }); results.push(['done before schedule invalid', r.code === 'INVALID']);
r = call({ ...base, op: 'generate', key: AUTH, base: 1, value: { seed: 1, gen: 1, fromSlot: 0, inputHash: 'x', matches: [{ id: 's0c1', slot: 0, court: 1, aIds: ['p:h0teikh', 'p:g:abc'], bIds: ['p:a', 'p:b'] }] } }); results.push(['generate stale', r.code === 'STALE' && r.rev === 4]);
r = call({ ...base, op: 'generate', key: AUTH, base: 4, value: { seed: 1, gen: 1, fromSlot: 0, inputHash: 'x', matches: [{ id: 's0c1', slot: 0, court: 1, aIds: ['p:h0teikh', 'p:g:abc'], bIds: ['p:a', 'p:b'] }] } }); results.push(['generate ok', r.ok && r.rev === 5 && r.doc.schedule.matches.length === 1]);
r = call({ ...base, op: 'generate', base: 2, value: { seed: 1, gen: 1, fromSlot: 0, inputHash: 'x', matches: [{ id: 's0c1', slot: 0, court: 1, aIds: ['p:h0teikh', 'p:g:abc'], bIds: ['p:a', 'p:b'] }] } }); results.push(['generate without auth → AUTH', r.code === 'AUTH']);
r = call({ ...base, op: 'edit', key: 'wrong', base: 2, value: [{ id: 's0c1', aIds: ['p:h0teikh', 'p:a'], bIds: ['p:g:abc', 'p:b'] }] }); results.push(['edit wrong auth → AUTH', r.code === 'AUTH']);
r = call({ ...base, op: 'generate', auth: OLD_VERIFIER, key: OLD_VERIFIER, base: 2, value: null }); results.push(['public verifier no longer authenticates (pass-the-hash closed)', r.code === 'AUTH']);
r = call({ ...base, op: 'set', path: 'done.s0c1', value: true }); results.push(['done ok', r.ok && r.doc.done.s0c1 === true]);
r = call({ ...base, op: 'set', path: 'done.s0c1', value: null }); results.push(['undone ok', r.ok && !r.doc.done.s0c1]);
r = call({ ...base, op: 'set', path: 'results.s0c1', value: { a: 6, b: 4 } }); results.push(['score ok + auto done', r.ok && r.doc.results.s0c1.a === 6 && r.doc.results.s0c1.b === 4 && r.doc.done.s0c1 === true]);
r = call({ ...base, op: 'set', path: 'results.s0c1', value: { a: '6', b: 4 } }); results.push(['score string invalid', r.code === 'INVALID']);
r = call({ ...base, op: 'set', path: 'results.s0c1', value: { a: 7, b: 4 } }); results.push(['score >6 invalid', r.code === 'INVALID']);
r = call({ ...base, op: 'set', path: 'results.s0c1', value: { a: 6, b: 6 } }); results.push(['score 6:6 ok', r.ok && r.doc.results.s0c1.a === 6]);
r = call({ ...base, op: 'set', path: 'results.s9c9', value: { a: 6, b: 4 } }); results.push(['score unknown match invalid', r.code === 'INVALID']);
r = call({ ...base, op: 'set', path: 'results.s0c1', value: null }); results.push(['score cleared (done stays)', r.ok && !r.doc.results.s0c1 && r.doc.done.s0c1 === true]);
r = call({ ...base, op: 'set', path: 'done.s0c1', value: null }); results.push(['undone again', r.ok && !r.doc.done.s0c1]);
r = call({ ...base, op: 'set', path: 'courtNames', value: ['5', '7'] }); results.push(['court names ok', r.ok && JSON.stringify(r.doc.settings.courtNames) === '["5","7"]']);
r = call({ ...base, op: 'set', path: 'courtNames', value: 'x' }); results.push(['court names non-array invalid', r.code === 'INVALID']);
r = call({ ...base, op: 'set', path: 'courtNames', value: ['', ''] }); results.push(['court names all blank → removed', r.ok && !r.doc.settings.courtNames]);
r = call({ ...base, op: 'set', path: 'courtNames', value: [' 12345678901 ', '', 'B'] }); results.push(['court names clipped/kept middle blank', r.ok && JSON.stringify(r.doc.settings.courtNames) === '["12345678","","B"]']); r = call({ ...base, op: 'set', path: 'courtNames', value: null }); results.push(['court names null removes', r.ok && !r.doc.settings.courtNames]);
r = call({ ...base, op: 'set', path: 'courtNames', value: { '19': ['5'], '20': ['5', ' 7 ', '9'], '08': ['A'], 'x': ['q'], '24': ['z'], '21': [] } }); results.push(['court names by hour ok (cleaned keys/values)', r.ok && JSON.stringify(r.doc.settings.courtNamesByHour) === '{"8":["A"],"19":["5"],"20":["5","7","9"]}' && !r.doc.settings.courtNames]);
r = call({ ...base, op: 'set', path: 'courtNames', value: ['1', '2'] }); results.push(['court names array replaces by-hour', r.ok && !r.doc.settings.courtNamesByHour && r.doc.settings.courtNames.join() === '1,2']);
r = call({ ...base, op: 'set', path: 'courtNames', value: { '20': ['7'] } }); r = call({ ...base, op: 'set', path: 'courtNames', value: null }); results.push(['court names null removes both', r.ok && !r.doc.settings.courtNamesByHour && !r.doc.settings.courtNames]);
r = call({ ...base, op: 'set', path: 'evil.x', value: 1 }); results.push(['bad path invalid', r.code === 'INVALID']);
r = call({ ...base, op: 'set', path: 'attendance.h0teikh', value: { n: '<b>x</b>'.repeat(10), g: 'M', from: '18:00', until: '22:00' } }); results.push(['name clipped 20', r.ok && r.doc.attendance.h0teikh.n.length === 20]);
conflictOnce = true; const before = putCalls; r = call({ ...base, op: 'set', path: 'done.s0c1', value: true }); results.push(['409 retry', r.ok && putCalls - before === 2]);
results.push(['gh-pages copy in sync', JSON.stringify(store['gh:data/weekly/sessions/2026-09-20.json']) === JSON.stringify(store['data/weekly/sessions/2026-09-20.json'])]);
store['data/weekly/sessions/2026-09-20.json'].date = '2020-01-01'; r = call({ ...base, op: 'set', path: 'done.s0c1', value: null }); results.push(['closed', r.code === 'CLOSED']);
r = call({ ...base, op: 'set', path: 'attendance.h0teikh', value: { n: 'x', g: 'M', from: '18:00', until: '22:00' } }); results.push(['closed blocks attend', r.code === 'CLOSED']);
{ const d2 = new Date(Date.now() - 2 * 86400000).toISOString().slice(0, 10); store['data/weekly/sessions/2026-09-20.json'].date = d2; // 이틀 전 모임: 완료 표시만 열려 있다 (7일 유예)
  r = call({ ...base, op: 'set', path: 'done.s0c1', value: true }); results.push(['grace: done ok 2 days later', r.ok && r.doc.done.s0c1 === true]);
  r = call({ ...base, op: 'set', path: 'done.s0c1', value: null }); results.push(['grace: undone ok', r.ok && !r.doc.done.s0c1]);
  r = call({ ...base, op: 'set', path: 'results.s0c1', value: { a: 2, b: 6 } }); results.push(['grace: score ok 2 days later', r.ok && r.doc.results.s0c1.b === 6 && r.doc.done.s0c1 === true]); r = call({ ...base, op: 'set', path: 'results.s0c1', value: null }); r = call({ ...base, op: 'set', path: 'done.s0c1', value: null });
  r = call({ ...base, op: 'set', path: 'attendance.h0teikh', value: { n: 'x', g: 'M', from: '18:00', until: '22:00' } }); results.push(['grace: attend still closed', r.code === 'CLOSED']);
  r = call({ ...base, op: 'generate', key: AUTH, base: r.rev, value: null }); results.push(['grace: generate still closed', r.code === 'CLOSED']);
  const d9 = new Date(Date.now() - 9 * 86400000).toISOString().slice(0, 10); store['data/weekly/sessions/2026-09-20.json'].date = d9; r = call({ ...base, op: 'set', path: 'done.s0c1', value: true }); results.push(['grace over: done closed 9 days later', r.code === 'CLOSED']);
  store['data/weekly/sessions/2026-09-20.json'].date = '2020-01-01'; }
{ const g = JSON.parse(ctx.__doGet({ parameter: { session: '2026-09-20' } }).text); results.push(['doGet cached doc', g.ok && g.doc && g.rev === store['data/weekly/sessions/2026-09-20.json'].rev]); const g2 = JSON.parse(ctx.__doGet({ parameter: {} }).text); results.push(['doGet ping', g2.ok && !g2.doc]); const g3 = JSON.parse(ctx.__doGet({ parameter: { session: '2030-01-01' } }).text); results.push(['doGet missing', g3.code === 'NOSESSION']); const rf = call({ ...base, op: 'refresh' }); results.push(['refresh', rf.ok && rf.doc]); const rf2 = call({ ...base, session: '2030-01-01', op: 'refresh' }); results.push(['refresh missing', rf2.code === 'NOSESSION']); }
// ---- 완료 표시 정리: 전체 재편성(다시 섞기)은 모두 비우고, 부분 재편성은 그대로 둔 시간대만 유지 ----
{ const d = store['data/weekly/sessions/2026-09-20.json']; d.date = '2099-01-01'; // 다시 열기
  const two = [{ id: 's0c1', slot: 0, court: 1, aIds: ['p:a', 'p:b'], bIds: ['p:c', 'p:d'] }, { id: 's1c1', slot: 1, court: 1, aIds: ['p:a', 'p:c'], bIds: ['p:b', 'p:d'] }];
  let g = call({ ...base, op: 'generate', key: AUTH, base: d.rev, value: { seed: 5, gen: 1, fromSlot: 0, inputHash: 'x', matches: two } }); results.push(['generate two', g.ok]);
  g = call({ ...base, op: 'set', path: 'done.s0c1', value: true }); g = call({ ...base, op: 'set', path: 'done.s1c1', value: true }); results.push(['two done', g.ok && g.doc.done.s0c1 && g.doc.done.s1c1]);
  g = call({ ...base, op: 'generate', key: AUTH, base: g.rev, value: { seed: 6, gen: 2, fromSlot: 1, inputHash: 'x', matches: two } }); results.push(['partial regen keeps slot<1 done only', g.ok && g.doc.done.s0c1 === true && !g.doc.done.s1c1]);
  g = call({ ...base, op: 'generate', key: AUTH, base: g.rev, value: { seed: 7, gen: 3, fromSlot: 0, inputHash: 'x', matches: two } }); results.push(['reshuffle clears all done', g.ok && Object.keys(g.doc.done).length === 0]);
  // ---- 참석 상한 80 ----
  let last = null; for (let i = 0; i < 80; i++) last = call({ ...base, op: 'set', path: 'attendance.z' + i, value: { n: 'p' + i, g: 'M', from: '18:00', until: '22:00' } });
  const full = call({ ...base, op: 'set', path: 'attendance.zz', value: { n: 'x', g: 'M', from: '18:00', until: '22:00' } }); results.push(['attendance cap 80 → FULL', full.code === 'FULL']);
  const upd = call({ ...base, op: 'set', path: 'attendance.z1', value: { n: 'p1b', g: 'M', from: '19:00', until: '22:00' } }); results.push(['cap allows updating existing', upd.ok]);
  const rm = call({ ...base, op: 'set', path: 'attendance.z1', value: null }); results.push(['cap allows delete', rm.ok]);
}
// ---- 조 조정(edit): 교체·맞교환·중복 금지·STALE·완료 유지 ----
{ const d = store['data/weekly/sessions/2026-09-20.json']; d.date = '2099-01-01';
  const two = [{ id: 's0c1', slot: 0, court: 1, aIds: ['p:a', 'p:b'], bIds: ['p:c', 'p:d'] }, { id: 's0c2', slot: 0, court: 2, aIds: ['p:e', 'p:f'], bIds: ['p:g', 'p:h'] }, { id: 's1c1', slot: 1, court: 1, aIds: ['p:a', 'p:c'], bIds: ['p:b', 'p:d'] }];
  let g = call({ ...base, op: 'generate', key: AUTH, base: d.rev, value: { seed: 9, gen: 1, fromSlot: 0, inputHash: 'x', matches: two } }); results.push(['edit: generate 3', g.ok]);
  g = call({ ...base, op: 'set', path: 'done.s1c1', value: true }); results.push(['edit: done s1c1', g.ok]);
  const rev = g.rev;
  g = call({ ...base, op: 'edit', key: AUTH, base: rev - 1, value: [{ id: 's0c1', aIds: ['p:a', 'p:z'], bIds: ['p:c', 'p:d'] }] }); results.push(['edit stale', g.code === 'STALE']);
  g = call({ ...base, op: 'edit', key: AUTH, base: rev, value: [{ id: 's0c1', aIds: ['p:a', 'p:z'], bIds: ['p:c', 'p:d'] }] }); results.push(['edit replace with resting player', g.ok && g.doc.schedule.matches[0].aIds[1] === 'p:z' && g.doc.done.s1c1 === true]);
  g = call({ ...base, op: 'edit', key: AUTH, base: g.rev, value: [{ id: 's0c1', aIds: ['p:a', 'p:e'], bIds: ['p:c', 'p:d'] }] }); results.push(['edit dup in slot rejected', g.code === 'INVALID']);
  g = call({ ...base, op: 'edit', key: AUTH, base: g.rev, value: [{ id: 's0c1', aIds: ['p:a', 'p:e'], bIds: ['p:c', 'p:d'] }, { id: 's0c2', aIds: ['p:z', 'p:f'], bIds: ['p:g', 'p:h'] }] }); results.push(['edit swap across courts', g.ok && g.doc.schedule.matches[0].aIds[1] === 'p:e' && g.doc.schedule.matches[1].aIds[0] === 'p:z']);
  g = call({ ...base, op: 'edit', key: AUTH, base: g.rev, value: [{ id: 's0c1', aIds: ['p:a', 'p:a'], bIds: ['p:c', 'p:d'] }] }); results.push(['edit same player twice rejected', g.code === 'INVALID']);
  g = call({ ...base, op: 'edit', key: AUTH, base: g.rev, value: [{ id: 'nope', aIds: ['p:a', 'p:b'], bIds: ['p:c', 'p:d'] }] }); results.push(['edit unknown match rejected', g.code === 'INVALID']);
  g = call({ ...base, op: 'edit', key: AUTH, base: g.rev, prev: { s0c1: [['p:zz', 'p:zz'], ['p:c', 'p:d']] }, value: [{ id: 's0c1', aIds: ['p:a', 'p:b'], bIds: ['p:c', 'p:d'] }] }); results.push(['edit prev mismatch → STALE', g.code === 'STALE']);
  { const cur = store['data/weekly/sessions/2026-09-20.json'].schedule.matches.find((x) => x.id === 's0c1'); g = call({ ...base, op: 'edit', key: AUTH, base: g.rev, prev: { s0c1: [cur.aIds.slice(), cur.bIds.slice()] }, value: [{ id: 's0c1', aIds: ['p:a', 'p:b'], bIds: ['p:c', 'p:d'] }] }); results.push(['edit prev match ok', g.ok]); }
  g = call({ ...base, op: 'edit', key: AUTH, base: g.rev, prev: 'bad', value: [{ id: 's0c1', aIds: ['p:a', 'p:b'], bIds: ['p:c', 'p:d'] }] }); results.push(['edit prev malformed → INVALID', g.code === 'INVALID']);
  g = call({ ...base, op: 'generate', key: AUTH, base: g.rev, value: null }); g = call({ ...base, op: 'edit', key: AUTH, base: g.rev, value: [{ id: 's0c1', aIds: ['p:a', 'p:b'], bIds: ['p:c', 'p:d'] }] }); results.push(['edit without schedule rejected', g.code === 'INVALID']);
}
// ---- 사본 일치: app.js 의 applyWeeklyOp 와 Code.gs 의 applyWeeklyOp 가 같은 입력에 같은 결과 ----
{ const app = fs.readFileSync(__dirname + '/../../app.js', 'utf8');
  const fn = app.slice(app.indexOf('  function applyWeeklyOp(doc, op) {'), app.indexOf('  /** 외부에서 온 세션 문서 검증'));
  const consts = [app.match(/const ID_RE = [^\n]+;/)[0], app.match(/const TIME_RE = [^\n]+;/)[0], app.match(/const WK_SCORE_MAX = [^\n]+;/)[0], app.match(/const wkCleanCourtNames = [^\n]+;/)[0], app.match(/const wkCleanCourtNamesByHour = [^\n]+;/)[0]].join('\n');
  const appCtx = vm.createContext({ Date }); vm.runInContext(consts + '\n' + fn + '\nglobalThis.__apply = applyWeeklyOp;', appCtx);
  const gsCtx = vm.createContext({ ...gas }); vm.runInContext(fs.readFileSync(__dirname + '/Code.gs', 'utf8') + '\nglobalThis.__apply = applyWeeklyOp;', gsCtx);
  const seq = [
    { op: 'set', path: 'attendance.a', value: { n: 'A', g: 'M', from: '18:00', until: '22:00' } }, { op: 'set', path: 'attendance.b', value: { n: 'B', g: 'F', from: '18:00', until: '20:00', guest: true } },
    { op: 'set', path: 'attendance.b', value: { n: 'B', g: 'F', from: '99:00', until: '20:00' } }, { op: 'set', path: 'bogus.x', value: 1 },
    { op: 'generate', key: AUTH, base: 9, value: null }, { op: 'generate', key: AUTH, base: 2, value: { seed: 1, gen: 1, fromSlot: 0, inputHash: 'h', matches: [{ id: 's0c1', slot: 0, court: 1, aIds: ['p:a', 'p:b'], bIds: ['p:c', 'p:d'] }, { id: 's1c1', slot: 1, court: 1, aIds: ['p:a', 'p:c'], bIds: ['p:b', 'p:d'] }] } },
    { op: 'set', path: 'done.s0c1', value: true }, { op: 'set', path: 'done.s1c1', value: true }, { op: 'set', path: 'done.s9c9', value: true },
    { op: 'generate', key: AUTH, base: 5, value: { seed: 2, gen: 2, fromSlot: 1, inputHash: 'h', matches: [{ id: 's0c1', slot: 0, court: 1, aIds: ['p:a', 'p:b'], bIds: ['p:c', 'p:d'] }, { id: 's1c1', slot: 1, court: 1, aIds: ['p:a', 'p:d'], bIds: ['p:b', 'p:c'] }] } },
    { op: 'generate', key: AUTH, base: 6, value: { seed: 3, gen: 3, fromSlot: 0, inputHash: 'h', matches: [{ id: 's0c1', slot: 0, court: 1, aIds: ['p:a', 'p:b'], bIds: ['p:c', 'p:d'] }] } },
    { op: 'edit', key: AUTH, base: 7, prev: { s0c1: [['p:a', 'p:b'], ['p:c', 'p:d']] }, value: [{ id: 's0c1', aIds: ['p:a', 'p:x'], bIds: ['p:c', 'p:d'] }] }, { op: 'edit', key: AUTH, base: 8, prev: { s0c1: [['p:a', 'p:b'], ['p:c', 'p:d']] }, value: [{ id: 's0c1', aIds: ['p:a', 'p:y'], bIds: ['p:c', 'p:d'] }] }, { op: 'edit', key: AUTH, base: 8, value: [{ id: 's0c1', aIds: ['p:a', 'p:x'], bIds: ['p:c', 'p:x'] }] }, { op: 'edit', key: AUTH, base: 99, value: [{ id: 's0c1', aIds: ['p:a', 'p:b'], bIds: ['p:c', 'p:d'] }] },
    { op: 'generate', key: AUTH, base: 8, value: null },
    { op: 'generate', key: AUTH, base: (d) => d.rev, value: { seed: 4, gen: 4, fromSlot: 0, inputHash: 'h', matches: [{ id: 's0c1', slot: 0, court: 1, aIds: ['p:a', 'p:b'], bIds: ['p:c', 'p:d'] }, { id: 's1c1', slot: 1, court: 1, aIds: ['p:a', 'p:c'], bIds: ['p:b', 'p:d'] }] } },
    { op: 'set', path: 'results.s0c1', value: { a: 6, b: 4 } }, { op: 'set', path: 'results.s0c1', value: { a: 6 } }, { op: 'set', path: 'results.s1c1', value: { a: 7, b: 0 } }, { op: 'set', path: 'results.s9c9', value: { a: 1, b: 2 } }, { op: 'set', path: 'results.s1c1', value: { a: 3, b: 5 } },
    { op: 'edit', key: AUTH, base: (d) => d.rev, prev: { s1c1: [['p:a', 'p:c'], ['p:b', 'p:d']] }, value: [{ id: 's1c1', aIds: ['p:a', 'p:d'], bIds: ['p:b', 'p:c'] }] }, // s1c1 점수 삭제, s0c1 유지
    { op: 'generate', key: AUTH, base: (d) => d.rev, value: { seed: 5, gen: 4, fromSlot: 1, inputHash: 'h', matches: [{ id: 's0c1', slot: 0, court: 1, aIds: ['p:a', 'p:b'], bIds: ['p:c', 'p:d'] }, { id: 's1c1', slot: 1, court: 1, aIds: ['p:a', 'p:b'], bIds: ['p:c', 'p:d'] }] } }, // 남은 시간대만: s0c1 점수 유지
    { op: 'generate', key: AUTH, base: (d) => d.rev, value: null }, // 전부 삭제 → results {}
    { op: 'set', path: 'courtNames', value: ['5', ' 7 ', ''] }, { op: 'set', path: 'courtNames', value: 3 }, { op: 'set', path: 'courtNames', value: null },
    { op: 'set', path: 'courtNames', value: { '19': ['5'], '020': ['x'], '20': ['5', '7'], 'q': ['1'] } }, { op: 'set', path: 'courtNames', value: {} }, { op: 'set', path: 'courtNames', value: ['9'] },
  ];
  const run = (ctx) => { const doc = { v: 1, id: '2026-09-20', date: '2099-01-01', status: 'open', rev: 0, attendance: {}, schedule: null, done: {} }; const codes = []; const snaps = []; for (const op of seq) { const o = typeof op.base === 'function' ? { ...op, base: op.base(doc) } : op; const r = ctx.__apply(doc, { v: 1, club: 'tennisweet', session: '2026-09-20', ...o }); codes.push(r.ok ? 'ok' : r.code); if (o.op === 'set' && /^results/.test(o.path) || o.op === 'edit' || o.op === 'generate') snaps.push(JSON.stringify(doc.results || null)); } delete doc.updatedAt; return JSON.stringify({ doc, codes, snaps }); };
  const a = run(appCtx), b = run(gsCtx); results.push(['app.js ↔ Code.gs applyWeeklyOp parity', a === b]); if (a !== b) console.log('APP', a, '\nGS ', b);
  results.push(['parity sequence exercised codes', /INVALID/.test(a) && /STALE/.test(a) && /"ok","ok"/.test(a)]);
  { const j = JSON.parse(a); const tail = j.codes.slice(-15); results.push(['parity: score seq codes', JSON.stringify(tail) === JSON.stringify(['ok', 'ok', 'INVALID', 'INVALID', 'INVALID', 'ok', 'ok', 'ok', 'ok', 'ok', 'INVALID', 'ok', 'ok', 'ok', 'ok'])]); const sn = j.snaps.slice(-4); results.push(['parity: edit clears only edited score', sn[0] === '{"s0c1":{"a":6,"b":4},"s1c1":{"a":3,"b":5}}' && sn[1] === '{"s0c1":{"a":6,"b":4}}']); results.push(['parity: partial regen keeps slot0 score, null clears', sn[2] === '{"s0c1":{"a":6,"b":4}}' && sn[3] === '{}']); }
}
// ---- 코트 예약 (op courts → data/courts.json) ----
{ const cb = { v: 1, club: 'tennisweet', op: 'courts' }; const P = 'data/courts.json'; const iso = (off) => new Date(Date.now() + off * 86400000).toISOString().slice(0, 10); const D1 = iso(0), D2 = iso(1), D5 = iso(4);
  let c = call({ ...cb, value: [{ d: D1, t: '20', c: 0, n: '정배근' }] }); results.push(['courts: no key → AUTH', c.code === 'AUTH' && !store[P]]);
  c = call({ ...cb, auth: OLD_VERIFIER, value: [{ d: D1, t: '20', c: 0, n: '정배근' }] }); results.push(['courts: public verifier → AUTH', c.code === 'AUTH' && !store[P]]);
  c = call({ ...cb, key: AUTH, value: [{ d: D1, t: '20', c: 0, n: ' 정배근 ', p: '' }, { d: D1, t: '18', c: 1, n: '김지선' }], by: 'me' }); results.push(['courts: creates file with defaults', c.ok && c.rev === 1 && JSON.stringify(store[P].res) === JSON.stringify({ [D1]: { 18: ['', '김지선', ''], 20: ['정배근', '', ''] } }) && store[P].courts.length === 3 && store[P].times.join() === '18,20']);
  results.push(['courts: gh-pages copy in sync', JSON.stringify(store['gh:' + P]) === JSON.stringify(store[P])]);
  c = call({ ...cb, key: AUTH, value: [{ d: D1, t: '20', c: 0, n: '윤성환', p: '' }] }); results.push(['courts: stale cell → STALE + doc', c.code === 'STALE' && c.doc && c.doc.res[D1]['20'][0] === '정배근' && store[P].rev === 1]);
  c = call({ ...cb, key: AUTH, value: [{ d: D1, t: '20', c: 0, n: '윤성환', p: '정배근' }, { d: D1, t: '18', c: 1, n: '', p: '김지선' }] }); results.push(['courts: replace + clear (empty row removed)', c.ok && c.rev === 2 && JSON.stringify(store[P].res) === JSON.stringify({ [D1]: { 20: ['윤성환', '', ''] } })]);
  c = call({ ...cb, key: AUTH, value: [{ d: D1, t: '20', c: 0, n: '윤성환', p: '정배근' }] }); results.push(['courts: same value despite stale p → ok', c.ok && c.rev === 3]);
  const bad = [[{ d: D1.replace(/-0?(\d+)$/, '-$1x'), t: '20', c: 0, n: 'x' }], [{ d: '2026-02-31', t: '20', c: 0, n: 'x' }], [{ d: '9999-12-31', t: '20', c: 0, n: 'x' }], [{ d: iso(-500), t: '20', c: 0, n: 'x' }], [{ d: D1, t: '19', c: 0, n: 'x' }], [{ d: D1, t: '20', c: 3, n: 'x' }], [{ d: D1, t: '20', c: 0.5, n: 'x' }], [{ d: D1, t: '20', c: 0, n: 5 }], [], 'x', Array.from({ length: 81 }, () => ({ d: D1, t: '20', c: 0, n: 'x' }))];
  results.push(['courts: invalid changes rejected (bad/impossible/far dates, time, court, size)', bad.every((v) => call({ ...cb, key: AUTH, value: v }).code === 'INVALID') && store[P].rev === 3]);
  c = call({ ...cb, key: AUTH, value: [{ d: D2, t: '20', c: 2, n: '1234567890123456' }] }); results.push(['courts: name clipped to 12', c.ok && store[P].res[D2]['20'][2] === '123456789012']);
  conflictOnce = true; const before = putCalls; c = call({ ...cb, key: AUTH, value: [{ d: D5, t: '18', c: 0, n: 'A' }] }); results.push(['courts: 409 retry', c.ok && putCalls - before === 2]);
  { const keep = store[P]; store[P] = 'garbage'; c = call({ ...cb, key: AUTH, value: [{ d: D1, t: '20', c: 0, n: 'x' }] }); results.push(['courts: broken file is not overwritten', c.code === 'GITHUB' && store[P] === 'garbage']); store[P] = keep; }
  results.push(['courts: session ops unaffected', call({ ...base, op: 'ping' }).ok === true]);
  // app.js ↔ Code.gs 동등성 (courtsClean · courtsDateOk · applyCourtsChanges)
  const app = fs.readFileSync(__dirname + '/../../app.js', 'utf8'); const fn = app.slice(app.indexOf('  function courtsClean(raw) {'), app.indexOf('  // ---- /courts shared ----'));
  const appCtx = vm.createContext({ Date }); vm.runInContext(fn + '\nglobalThis.__clean = courtsClean; globalThis.__apply = applyCourtsChanges; globalThis.__dateOk = courtsDateOk;', appCtx);
  const gsCtx = vm.createContext({ ...gas }); vm.runInContext(fs.readFileSync(__dirname + '/Code.gs', 'utf8') + '\nglobalThis.__clean = courtsClean; globalThis.__apply = applyCourtsChanges; globalThis.__dateOk = courtsDateOk;', gsCtx);
  const NOW = Date.parse('2026-10-01T00:00:00Z');
  const raws = [null, 'x', [1], { rev: '3', courts: [' A ', '', 'B', 5], times: ['18', '18', 'x', '7:30', 20], res: { '2026-10-01': { '18': ['  가 ', null, '나', '다'], '20': 'x', '21': ['z'] }, 'bad': { '18': ['q'] }, '2026-02-31': { '18': ['q'] }, '2026-10-02': { '18': ['', ''] }, '2026-10-03': null } }, { courts: [], times: [], res: [] }];
  const seq = [[{ d: '2026-10-01', t: '18', c: 0, n: '가', p: '' }], [{ d: '2026-10-01', t: '18', c: 0, n: '나', p: '' }], [{ d: '2026-10-01', t: '18', c: 0, n: '', p: '가' }], [{ d: '2026-10-09', t: '7:30', c: 1, n: 'x' }], [{ d: '2026-10-09', t: '18', c: 9, n: 'x' }], [{ d: '2028-01-01', t: '18', c: 0, n: 'x' }], [{ d: '2026-02-30', t: '18', c: 0, n: 'x' }], 'bad'];
  const run = (ctx) => JSON.stringify(raws.map((raw) => { const doc = ctx.__clean(raw); const codes = seq.map((ch) => { const r = ctx.__apply(doc, ch, NOW); return r.ok ? 'ok' : r.code; }); delete doc.updatedAt; return { doc, codes, ok: ['2026-02-28', '2026-02-29', '2024-02-29', '2026-13-01', 'x'].map((d) => ctx.__dateOk(d, null)) }; }));
  const a = run(appCtx), b = run(gsCtx); results.push(['courts: app.js ↔ Code.gs parity', a === b]); if (a !== b) console.log('APP', a, '\nGS ', b);
  results.push(['courts: parity exercised ok/STALE/INVALID', /"ok"/.test(a) && /STALE/.test(a) && /INVALID/.test(a)]);
  results.push(['courts: date check (real dates only)', JSON.stringify(JSON.parse(a)[0].ok) === '[true,false,true,false,false]']);
  const seed = JSON.parse(fs.readFileSync(__dirname + '/../../data/courts.json', 'utf8')); const cs = appCtx.__clean(seed); results.push(['courts: seed file survives clean unchanged', JSON.stringify(cs.res) === JSON.stringify(seed.res) && cs.rev === seed.rev]);
}
for (const [name, ok] of results) console.log((ok ? 'PASS' : 'FAIL') + '  ' + name);
process.exit(results.every(([, ok]) => ok) ? 0 : 1);
