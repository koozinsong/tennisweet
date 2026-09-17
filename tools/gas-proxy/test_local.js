// 로컬 검증: GAS 전역을 흉내 내어 Code.gs 의 doPost 를 실행 (node tools/gas-proxy/test_local.js)
const fs = require('fs'); const vm = require('vm');
const store = { 'data/weekly/sessions/2026-09-20.json': { v: 1, id: '2026-09-20', date: '2026-09-20', status: 'open', rev: 0, settings: { startTime: '18:00', endTime: '22:00', matchMinutes: 30, breakMinutes: 0, courts: 2, minWomenDoubles: 1 }, attendance: {}, schedule: null, done: {} } };
const shas = {}; let putCalls = 0, conflictOnce = false;
const gas = {
  PropertiesService: { getScriptProperties: () => ({ getProperty: (k) => ({ GH_TOKEN: 'tok' }[k] || null) }) },
  LockService: { getScriptLock: () => ({ tryLock: () => true, releaseLock: () => {} }) },
  ContentService: { createTextOutput: (s) => ({ setMimeType: () => ({ text: s }) }), MimeType: { JSON: 'json' } },
  Utilities: { base64Decode: (s) => Buffer.from(s, 'base64'), base64Encode: (s) => Buffer.from(s, 'utf8').toString('base64'), newBlob: (buf) => ({ getDataAsString: () => buf.toString('utf8') }), Charset: { UTF_8: 'utf8' } },
  UrlFetchApp: { fetch: (url, opt = {}) => {
    const m = url.match(/contents\/(.+?)(\?|$)/); const path = m[1]; const br = (url.match(/ref=([^&]+)/) || [])[1] || (opt.payload && JSON.parse(opt.payload).branch); const key = br + ':' + path; const isMain = br === 'main';
    if (!opt.method) { const doc = isMain ? store[path] : store['gh:' + path]; if (!doc) return { getResponseCode: () => 404, getContentText: () => '' }; const content = Buffer.from(JSON.stringify(doc)).toString('base64'); shas[key] = shas[key] || 'sha1'; return { getResponseCode: () => 200, getContentText: () => JSON.stringify({ sha: shas[key], content }) }; }
    if (isMain) putCalls++; const body = JSON.parse(opt.payload); if ((shas[key] || null) !== (body.sha || null)) return { getResponseCode: () => 409, getContentText: () => '{}' }; if (isMain && conflictOnce) { conflictOnce = false; shas[key] += 'x'; return { getResponseCode: () => 409, getContentText: () => '{}' }; }
    const doc = JSON.parse(Buffer.from(body.content, 'base64').toString('utf8')); if (isMain) store[path] = doc; else store['gh:' + path] = doc; shas[key] = (shas[key] || 'sha1') + 'x'; return { getResponseCode: () => 200, getContentText: () => '{}' }; } },
  CacheService: { getScriptCache: () => ({ get: (k) => (globalThis.__cache = globalThis.__cache || {})[k] || null, put: (k, v) => { (globalThis.__cache = globalThis.__cache || {})[k] = v; }, remove: (k) => { delete (globalThis.__cache = globalThis.__cache || {})[k]; } }) },
  Date,
};
const ctx = vm.createContext(gas); vm.runInContext(fs.readFileSync(__dirname + '/Code.gs', 'utf8') + '\nglobalThis.__doPost = doPost; globalThis.__doGet = doGet;', ctx);
const call = (body) => JSON.parse(ctx.__doPost({ postData: { contents: JSON.stringify(body) } }).text);
const base = { v: 1, club: 'tennisweet', session: '2026-09-20' };
const AUTH = '3b4facb575a1dc30b189b7c01b746e68e952b3a94a4b9776a6f261aba87e2bac'; // 대진표 비밀번호 검증값 (Code.gs WK_PW_HASH)
const results = [];
results.push(['ping', call({ ...base, op: 'ping' }).ok === true]);
results.push(['bad club', call({ ...base, club: 'x', op: 'set' }).code === 'INVALID']);
results.push(['no session', call({ ...base, session: '2026-01-01', op: 'set', path: 'attendance.a', value: { n: 'x', g: 'M', from: '18:00', until: '22:00' } }).code === 'NOSESSION']);
let r = call({ ...base, op: 'set', path: 'attendance.h0teikh', value: { n: '송국진', g: 'M', from: '19:00', until: '22:00' }, by: 'h0teikh' }); results.push(['attend ok', r.ok && r.rev === 1 && r.doc.attendance.h0teikh.n === '송국진']);
r = call({ ...base, op: 'set', path: 'attendance.g:abc', value: { n: '홍길동', g: 'F', from: '18:00', until: '22:00', guest: true } }); results.push(['guest ok', r.ok && r.doc.attendance['g:abc'].guest === true && r.rev === 2]);
r = call({ ...base, op: 'set', path: 'attendance.h0teikh', value: { n: '송국진', g: 'M', from: '22:00', until: '19:00' } }); results.push(['bad time invalid', r.code === 'INVALID']);
r = call({ ...base, op: 'set', path: 'done.s0c1', value: true }); results.push(['done before schedule invalid', r.code === 'INVALID']);
r = call({ ...base, op: 'generate', auth: AUTH, base: 1, value: { seed: 1, gen: 1, fromSlot: 0, inputHash: 'x', matches: [{ id: 's0c1', slot: 0, court: 1, aIds: ['p:h0teikh', 'p:g:abc'], bIds: ['p:a', 'p:b'] }] } }); results.push(['generate stale', r.code === 'STALE' && r.rev === 2]);
r = call({ ...base, op: 'generate', auth: AUTH, base: 2, value: { seed: 1, gen: 1, fromSlot: 0, inputHash: 'x', matches: [{ id: 's0c1', slot: 0, court: 1, aIds: ['p:h0teikh', 'p:g:abc'], bIds: ['p:a', 'p:b'] }] } }); results.push(['generate ok', r.ok && r.rev === 3 && r.doc.schedule.matches.length === 1]);
r = call({ ...base, op: 'generate', base: 2, value: { seed: 1, gen: 1, fromSlot: 0, inputHash: 'x', matches: [{ id: 's0c1', slot: 0, court: 1, aIds: ['p:h0teikh', 'p:g:abc'], bIds: ['p:a', 'p:b'] }] } }); results.push(['generate without auth → AUTH', r.code === 'AUTH']);
r = call({ ...base, op: 'edit', auth: 'wrong', base: 2, value: [{ id: 's0c1', aIds: ['p:h0teikh', 'p:a'], bIds: ['p:g:abc', 'p:b'] }] }); results.push(['edit wrong auth → AUTH', r.code === 'AUTH']);
r = call({ ...base, op: 'set', path: 'done.s0c1', value: true }); results.push(['done ok', r.ok && r.doc.done.s0c1 === true]);
r = call({ ...base, op: 'set', path: 'done.s0c1', value: null }); results.push(['undone ok', r.ok && !r.doc.done.s0c1]);
r = call({ ...base, op: 'set', path: 'evil.x', value: 1 }); results.push(['bad path invalid', r.code === 'INVALID']);
r = call({ ...base, op: 'set', path: 'attendance.h0teikh', value: { n: '<b>x</b>'.repeat(10), g: 'M', from: '18:00', until: '22:00' } }); results.push(['name clipped 20', r.ok && r.doc.attendance.h0teikh.n.length === 20]);
conflictOnce = true; const before = putCalls; r = call({ ...base, op: 'set', path: 'done.s0c1', value: true }); results.push(['409 retry', r.ok && putCalls - before === 2]);
results.push(['gh-pages copy in sync', JSON.stringify(store['gh:data/weekly/sessions/2026-09-20.json']) === JSON.stringify(store['data/weekly/sessions/2026-09-20.json'])]);
store['data/weekly/sessions/2026-09-20.json'].date = '2020-01-01'; r = call({ ...base, op: 'set', path: 'done.s0c1', value: null }); results.push(['closed', r.code === 'CLOSED']);
r = call({ ...base, op: 'set', path: 'attendance.h0teikh', value: { n: 'x', g: 'M', from: '18:00', until: '22:00' } }); results.push(['closed blocks attend', r.code === 'CLOSED']);
{ const g = JSON.parse(ctx.__doGet({ parameter: { session: '2026-09-20' } }).text); results.push(['doGet cached doc', g.ok && g.doc && g.rev === store['data/weekly/sessions/2026-09-20.json'].rev]); const g2 = JSON.parse(ctx.__doGet({ parameter: {} }).text); results.push(['doGet ping', g2.ok && !g2.doc]); const g3 = JSON.parse(ctx.__doGet({ parameter: { session: '2030-01-01' } }).text); results.push(['doGet missing', g3.code === 'NOSESSION']); const rf = call({ ...base, op: 'refresh' }); results.push(['refresh', rf.ok && rf.doc]); const rf2 = call({ ...base, session: '2030-01-01', op: 'refresh' }); results.push(['refresh missing', rf2.code === 'NOSESSION']); }
// ---- 완료 표시 정리: 전체 재편성(다시 섞기)은 모두 비우고, 부분 재편성은 그대로 둔 시간대만 유지 ----
{ const d = store['data/weekly/sessions/2026-09-20.json']; d.date = '2099-01-01'; // 다시 열기
  const two = [{ id: 's0c1', slot: 0, court: 1, aIds: ['p:a', 'p:b'], bIds: ['p:c', 'p:d'] }, { id: 's1c1', slot: 1, court: 1, aIds: ['p:a', 'p:c'], bIds: ['p:b', 'p:d'] }];
  let g = call({ ...base, op: 'generate', auth: AUTH, base: d.rev, value: { seed: 5, gen: 1, fromSlot: 0, inputHash: 'x', matches: two } }); results.push(['generate two', g.ok]);
  g = call({ ...base, op: 'set', path: 'done.s0c1', value: true }); g = call({ ...base, op: 'set', path: 'done.s1c1', value: true }); results.push(['two done', g.ok && g.doc.done.s0c1 && g.doc.done.s1c1]);
  g = call({ ...base, op: 'generate', auth: AUTH, base: g.rev, value: { seed: 6, gen: 2, fromSlot: 1, inputHash: 'x', matches: two } }); results.push(['partial regen keeps slot<1 done only', g.ok && g.doc.done.s0c1 === true && !g.doc.done.s1c1]);
  g = call({ ...base, op: 'generate', auth: AUTH, base: g.rev, value: { seed: 7, gen: 3, fromSlot: 0, inputHash: 'x', matches: two } }); results.push(['reshuffle clears all done', g.ok && Object.keys(g.doc.done).length === 0]);
  // ---- 참석 상한 80 ----
  let last = null; for (let i = 0; i < 80; i++) last = call({ ...base, op: 'set', path: 'attendance.z' + i, value: { n: 'p' + i, g: 'M', from: '18:00', until: '22:00' } });
  const full = call({ ...base, op: 'set', path: 'attendance.zz', value: { n: 'x', g: 'M', from: '18:00', until: '22:00' } }); results.push(['attendance cap 80 → FULL', full.code === 'FULL']);
  const upd = call({ ...base, op: 'set', path: 'attendance.z1', value: { n: 'p1b', g: 'M', from: '19:00', until: '22:00' } }); results.push(['cap allows updating existing', upd.ok]);
  const rm = call({ ...base, op: 'set', path: 'attendance.z1', value: null }); results.push(['cap allows delete', rm.ok]);
}
// ---- 조 조정(edit): 교체·맞교환·중복 금지·STALE·완료 유지 ----
{ const d = store['data/weekly/sessions/2026-09-20.json']; d.date = '2099-01-01';
  const two = [{ id: 's0c1', slot: 0, court: 1, aIds: ['p:a', 'p:b'], bIds: ['p:c', 'p:d'] }, { id: 's0c2', slot: 0, court: 2, aIds: ['p:e', 'p:f'], bIds: ['p:g', 'p:h'] }, { id: 's1c1', slot: 1, court: 1, aIds: ['p:a', 'p:c'], bIds: ['p:b', 'p:d'] }];
  let g = call({ ...base, op: 'generate', auth: AUTH, base: d.rev, value: { seed: 9, gen: 1, fromSlot: 0, inputHash: 'x', matches: two } }); results.push(['edit: generate 3', g.ok]);
  g = call({ ...base, op: 'set', path: 'done.s1c1', value: true }); results.push(['edit: done s1c1', g.ok]);
  const rev = g.rev;
  g = call({ ...base, op: 'edit', auth: AUTH, base: rev - 1, value: [{ id: 's0c1', aIds: ['p:a', 'p:z'], bIds: ['p:c', 'p:d'] }] }); results.push(['edit stale', g.code === 'STALE']);
  g = call({ ...base, op: 'edit', auth: AUTH, base: rev, value: [{ id: 's0c1', aIds: ['p:a', 'p:z'], bIds: ['p:c', 'p:d'] }] }); results.push(['edit replace with resting player', g.ok && g.doc.schedule.matches[0].aIds[1] === 'p:z' && g.doc.done.s1c1 === true]);
  g = call({ ...base, op: 'edit', auth: AUTH, base: g.rev, value: [{ id: 's0c1', aIds: ['p:a', 'p:e'], bIds: ['p:c', 'p:d'] }] }); results.push(['edit dup in slot rejected', g.code === 'INVALID']);
  g = call({ ...base, op: 'edit', auth: AUTH, base: g.rev, value: [{ id: 's0c1', aIds: ['p:a', 'p:e'], bIds: ['p:c', 'p:d'] }, { id: 's0c2', aIds: ['p:z', 'p:f'], bIds: ['p:g', 'p:h'] }] }); results.push(['edit swap across courts', g.ok && g.doc.schedule.matches[0].aIds[1] === 'p:e' && g.doc.schedule.matches[1].aIds[0] === 'p:z']);
  g = call({ ...base, op: 'edit', auth: AUTH, base: g.rev, value: [{ id: 's0c1', aIds: ['p:a', 'p:a'], bIds: ['p:c', 'p:d'] }] }); results.push(['edit same player twice rejected', g.code === 'INVALID']);
  g = call({ ...base, op: 'edit', auth: AUTH, base: g.rev, value: [{ id: 'nope', aIds: ['p:a', 'p:b'], bIds: ['p:c', 'p:d'] }] }); results.push(['edit unknown match rejected', g.code === 'INVALID']);
  g = call({ ...base, op: 'edit', auth: AUTH, base: g.rev, prev: { s0c1: [['p:zz', 'p:zz'], ['p:c', 'p:d']] }, value: [{ id: 's0c1', aIds: ['p:a', 'p:b'], bIds: ['p:c', 'p:d'] }] }); results.push(['edit prev mismatch → STALE', g.code === 'STALE']);
  { const cur = store['data/weekly/sessions/2026-09-20.json'].schedule.matches.find((x) => x.id === 's0c1'); g = call({ ...base, op: 'edit', auth: AUTH, base: g.rev, prev: { s0c1: [cur.aIds.slice(), cur.bIds.slice()] }, value: [{ id: 's0c1', aIds: ['p:a', 'p:b'], bIds: ['p:c', 'p:d'] }] }); results.push(['edit prev match ok', g.ok]); }
  g = call({ ...base, op: 'edit', auth: AUTH, base: g.rev, prev: 'bad', value: [{ id: 's0c1', aIds: ['p:a', 'p:b'], bIds: ['p:c', 'p:d'] }] }); results.push(['edit prev malformed → INVALID', g.code === 'INVALID']);
  g = call({ ...base, op: 'generate', auth: AUTH, base: g.rev, value: null }); g = call({ ...base, op: 'edit', auth: AUTH, base: g.rev, value: [{ id: 's0c1', aIds: ['p:a', 'p:b'], bIds: ['p:c', 'p:d'] }] }); results.push(['edit without schedule rejected', g.code === 'INVALID']);
}
// ---- 사본 일치: app.js 의 applyWeeklyOp 와 Code.gs 의 applyWeeklyOp 가 같은 입력에 같은 결과 ----
{ const app = fs.readFileSync(__dirname + '/../../app.js', 'utf8');
  const fn = app.slice(app.indexOf('  function applyWeeklyOp(doc, op) {'), app.indexOf('  /** 외부에서 온 세션 문서 검증'));
  const consts = [app.match(/const ID_RE = [^\n]+;/)[0], app.match(/const TIME_RE = [^\n]+;/)[0]].join('\n');
  const appCtx = vm.createContext({ Date }); vm.runInContext(consts + '\n' + fn + '\nglobalThis.__apply = applyWeeklyOp;', appCtx);
  const gsCtx = vm.createContext({ ...gas }); vm.runInContext(fs.readFileSync(__dirname + '/Code.gs', 'utf8') + '\nglobalThis.__apply = applyWeeklyOp;', gsCtx);
  const seq = [
    { op: 'set', path: 'attendance.a', value: { n: 'A', g: 'M', from: '18:00', until: '22:00' } }, { op: 'set', path: 'attendance.b', value: { n: 'B', g: 'F', from: '18:00', until: '20:00', guest: true } },
    { op: 'set', path: 'attendance.b', value: { n: 'B', g: 'F', from: '99:00', until: '20:00' } }, { op: 'set', path: 'bogus.x', value: 1 },
    { op: 'generate', auth: AUTH, base: 9, value: null }, { op: 'generate', auth: AUTH, base: 2, value: { seed: 1, gen: 1, fromSlot: 0, inputHash: 'h', matches: [{ id: 's0c1', slot: 0, court: 1, aIds: ['p:a', 'p:b'], bIds: ['p:c', 'p:d'] }, { id: 's1c1', slot: 1, court: 1, aIds: ['p:a', 'p:c'], bIds: ['p:b', 'p:d'] }] } },
    { op: 'set', path: 'done.s0c1', value: true }, { op: 'set', path: 'done.s1c1', value: true }, { op: 'set', path: 'done.s9c9', value: true },
    { op: 'generate', auth: AUTH, base: 5, value: { seed: 2, gen: 2, fromSlot: 1, inputHash: 'h', matches: [{ id: 's0c1', slot: 0, court: 1, aIds: ['p:a', 'p:b'], bIds: ['p:c', 'p:d'] }, { id: 's1c1', slot: 1, court: 1, aIds: ['p:a', 'p:d'], bIds: ['p:b', 'p:c'] }] } },
    { op: 'generate', auth: AUTH, base: 6, value: { seed: 3, gen: 3, fromSlot: 0, inputHash: 'h', matches: [{ id: 's0c1', slot: 0, court: 1, aIds: ['p:a', 'p:b'], bIds: ['p:c', 'p:d'] }] } },
    { op: 'edit', auth: AUTH, base: 7, prev: { s0c1: [['p:a', 'p:b'], ['p:c', 'p:d']] }, value: [{ id: 's0c1', aIds: ['p:a', 'p:x'], bIds: ['p:c', 'p:d'] }] }, { op: 'edit', auth: AUTH, base: 8, prev: { s0c1: [['p:a', 'p:b'], ['p:c', 'p:d']] }, value: [{ id: 's0c1', aIds: ['p:a', 'p:y'], bIds: ['p:c', 'p:d'] }] }, { op: 'edit', auth: AUTH, base: 8, value: [{ id: 's0c1', aIds: ['p:a', 'p:x'], bIds: ['p:c', 'p:x'] }] }, { op: 'edit', auth: AUTH, base: 99, value: [{ id: 's0c1', aIds: ['p:a', 'p:b'], bIds: ['p:c', 'p:d'] }] },
    { op: 'generate', auth: AUTH, base: 8, value: null },
  ];
  const run = (ctx) => { const doc = { v: 1, id: '2026-09-20', date: '2099-01-01', status: 'open', rev: 0, attendance: {}, schedule: null, done: {} }; const codes = []; for (const op of seq) { const r = ctx.__apply(doc, { v: 1, club: 'tennisweet', session: '2026-09-20', ...op }); codes.push(r.ok ? 'ok' : r.code); } delete doc.updatedAt; return JSON.stringify({ doc, codes }); };
  const a = run(appCtx), b = run(gsCtx); results.push(['app.js ↔ Code.gs applyWeeklyOp parity', a === b]); if (a !== b) console.log('APP', a, '\nGS ', b);
  results.push(['parity sequence exercised codes', /INVALID/.test(a) && /STALE/.test(a) && /"ok","ok"/.test(a)]);
}
for (const [name, ok] of results) console.log((ok ? 'PASS' : 'FAIL') + '  ' + name);
process.exit(results.every(([, ok]) => ok) ? 0 : 1);
