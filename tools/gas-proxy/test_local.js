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
const results = [];
results.push(['ping', call({ ...base, op: 'ping' }).ok === true]);
results.push(['bad club', call({ ...base, club: 'x', op: 'set' }).code === 'INVALID']);
results.push(['no session', call({ ...base, session: '2026-01-01', op: 'set', path: 'attendance.a', value: { n: 'x', g: 'M', from: '18:00', until: '22:00' } }).code === 'NOSESSION']);
let r = call({ ...base, op: 'set', path: 'attendance.h0teikh', value: { n: '송국진', g: 'M', from: '19:00', until: '22:00' }, by: 'h0teikh' }); results.push(['attend ok', r.ok && r.rev === 1 && r.doc.attendance.h0teikh.n === '송국진']);
r = call({ ...base, op: 'set', path: 'attendance.g:abc', value: { n: '홍길동', g: 'F', from: '18:00', until: '22:00', guest: true } }); results.push(['guest ok', r.ok && r.doc.attendance['g:abc'].guest === true && r.rev === 2]);
r = call({ ...base, op: 'set', path: 'attendance.h0teikh', value: { n: '송국진', g: 'M', from: '22:00', until: '19:00' } }); results.push(['bad time invalid', r.code === 'INVALID']);
r = call({ ...base, op: 'set', path: 'done.s0c1', value: true }); results.push(['done before schedule invalid', r.code === 'INVALID']);
r = call({ ...base, op: 'generate', base: 1, value: { seed: 1, gen: 1, fromSlot: 0, inputHash: 'x', matches: [{ id: 's0c1', slot: 0, court: 1, aIds: ['p:h0teikh', 'p:g:abc'], bIds: ['p:a', 'p:b'] }] } }); results.push(['generate stale', r.code === 'STALE' && r.rev === 2]);
r = call({ ...base, op: 'generate', base: 2, value: { seed: 1, gen: 1, fromSlot: 0, inputHash: 'x', matches: [{ id: 's0c1', slot: 0, court: 1, aIds: ['p:h0teikh', 'p:g:abc'], bIds: ['p:a', 'p:b'] }] } }); results.push(['generate ok', r.ok && r.rev === 3 && r.doc.schedule.matches.length === 1]);
r = call({ ...base, op: 'set', path: 'done.s0c1', value: true }); results.push(['done ok', r.ok && r.doc.done.s0c1 === true]);
r = call({ ...base, op: 'set', path: 'done.s0c1', value: null }); results.push(['undone ok', r.ok && !r.doc.done.s0c1]);
r = call({ ...base, op: 'set', path: 'evil.x', value: 1 }); results.push(['bad path invalid', r.code === 'INVALID']);
r = call({ ...base, op: 'set', path: 'attendance.h0teikh', value: { n: '<b>x</b>'.repeat(10), g: 'M', from: '18:00', until: '22:00' } }); results.push(['name clipped 20', r.ok && r.doc.attendance.h0teikh.n.length === 20]);
conflictOnce = true; const before = putCalls; r = call({ ...base, op: 'set', path: 'done.s0c1', value: true }); results.push(['409 retry', r.ok && putCalls - before === 2]);
results.push(['gh-pages copy in sync', JSON.stringify(store['gh:data/weekly/sessions/2026-09-20.json']) === JSON.stringify(store['data/weekly/sessions/2026-09-20.json'])]);
store['data/weekly/sessions/2026-09-20.json'].date = '2020-01-01'; r = call({ ...base, op: 'set', path: 'done.s0c1', value: null }); results.push(['closed', r.code === 'CLOSED']);
r = call({ ...base, op: 'set', path: 'attendance.h0teikh', value: { n: 'x', g: 'M', from: '18:00', until: '22:00' } }); results.push(['closed blocks attend', r.code === 'CLOSED']);
{ const g = JSON.parse(ctx.__doGet({ parameter: { session: '2026-09-20' } }).text); results.push(['doGet cached doc', g.ok && g.doc && g.rev === store['data/weekly/sessions/2026-09-20.json'].rev]); const g2 = JSON.parse(ctx.__doGet({ parameter: {} }).text); results.push(['doGet ping', g2.ok && !g2.doc]); const g3 = JSON.parse(ctx.__doGet({ parameter: { session: '2030-01-01' } }).text); results.push(['doGet missing', g3.code === 'NOSESSION']); const rf = call({ ...base, op: 'refresh' }); results.push(['refresh', rf.ok && rf.doc]); const rf2 = call({ ...base, session: '2030-01-01', op: 'refresh' }); results.push(['refresh missing', rf2.code === 'NOSESSION']); }
for (const [name, ok] of results) console.log((ok ? 'PASS' : 'FAIL') + '  ' + name);
process.exit(results.every(([, ok]) => ok) ? 0 : 1);
