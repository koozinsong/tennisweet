// 로컬 검증 (대회 op): GAS 전역을 흉내 내어 Code.gs 의 tour-create·tour-set·tour-del 을 실행하고, app.js 공용 함수와 결과가 같은지 본다 (node tools/gas-proxy/test_tour.js)
const fs = require('fs'); const vm = require('vm'); const crypto = require('crypto');
const ymd = (ms) => new Date(ms + 9 * 3600000).toISOString().slice(0, 10); // KST 날짜
const DAY = 86400000; const D_UP = ymd(Date.now() + 10 * DAY), D_PAST = ymd(Date.now() - 3 * DAY);
const IDX = 'data/weekly/index.json';
const index0 = { v: 1, sessions: [{ id: '2026-11-12', date: '2026-11-12', courts: 2, matchMinutes: 30, startTime: '20:00', endTime: '22:00', courtsLabel: '코트 2면' }], proxy: 'https://script.google.com/macros/s/X/exec', updatedAt: 'u0', levels: { a: 3.5, b: 3 }, levelsAt: 'L', past: ['2026-11-06'] };
const store = { [IDX]: JSON.parse(JSON.stringify(index0)), ['gh:' + IDX]: JSON.parse(JSON.stringify(index0)), 'data/weekly/sessions/2099-01-01.json': { v: 1, id: '2099-01-01', date: '2099-01-01', status: 'open', rev: 0, settings: { startTime: '18:00', endTime: '22:00', matchMinutes: 30, breakMinutes: 0, courts: 2, minWomenDoubles: 1 }, attendance: {}, schedule: null, done: {}, results: {} } };
const shas = {}; const puts = []; let conflictPath = null; let raw = {}; // raw[path] = 본문 그대로 (깨진 파일 흉내)
const gas = {
  PropertiesService: { getScriptProperties: () => ({ getProperty: (k) => ({ GH_TOKEN: 'tok' }[k] || null) }) },
  LockService: { getScriptLock: () => ({ tryLock: () => true, releaseLock: () => {} }) },
  ContentService: { createTextOutput: (s) => ({ setMimeType: () => ({ text: s }) }), MimeType: { JSON: 'json' } },
  Utilities: { computeDigest: (alg, s) => [...crypto.createHash('sha256').update(String(s), 'utf8').digest()].map((b) => (b > 127 ? b - 256 : b)), DigestAlgorithm: { SHA_256: 'sha256' }, base64Decode: (s) => Buffer.from(s, 'base64'), base64Encode: (s) => Buffer.from(s, 'utf8').toString('base64'), newBlob: (buf) => ({ getDataAsString: () => buf.toString('utf8') }), Charset: { UTF_8: 'utf8' } },
  UrlFetchApp: { fetch: (url, opt = {}) => {
    const path = url.match(/contents\/(.+?)(\?|$)/)[1]; const br = (url.match(/ref=([^&]+)/) || [])[1] || (opt.payload && JSON.parse(opt.payload).branch); const key = br + ':' + path; const isMain = br === 'main'; const sk = isMain ? path : 'gh:' + path;
    if (!opt.method) { if (raw[sk] == null && !store[sk]) return { getResponseCode: () => 404, getContentText: () => '' }; const text = raw[sk] != null ? raw[sk] : JSON.stringify(store[sk]); shas[key] = shas[key] || 'sha1'; return { getResponseCode: () => 200, getContentText: () => JSON.stringify({ sha: shas[key], content: Buffer.from(text).toString('base64') }) }; }
    const body = JSON.parse(opt.payload); puts.push(key); if ((shas[key] || null) !== (body.sha || null)) return { getResponseCode: () => 409, getContentText: () => '{}' };
    if (isMain && conflictPath === path) { conflictPath = null; shas[key] += 'x'; return { getResponseCode: () => 409, getContentText: () => '{}' }; } // 그사이 다른 저장이 있었던 것처럼
    store[sk] = JSON.parse(Buffer.from(body.content, 'base64').toString('utf8')); delete raw[sk]; shas[key] = (shas[key] || 'sha1') + 'x'; return { getResponseCode: () => 200, getContentText: () => '{}' }; } },
  CacheService: { getScriptCache: () => ({ get: (k) => (globalThis.__cache = globalThis.__cache || {})[k] || null, put: (k, v) => { (globalThis.__cache = globalThis.__cache || {})[k] = v; }, remove: (k) => { delete (globalThis.__cache = globalThis.__cache || {})[k]; } }) },
  Date,
};
const TEST_KEY = 'cd'.repeat(32); // 테스트용 열쇠 (실제 열쇠는 저장소에 없다)
const gsSrc = fs.readFileSync(__dirname + '/Code.gs', 'utf8').replace(/const WK_KEY_SHA = '[0-9a-f]{64}'/, "const WK_KEY_SHA = '" + crypto.createHash('sha256').update(TEST_KEY).digest('hex') + "'");
const ctx = vm.createContext(gas); vm.runInContext(gsSrc + '\nglobalThis.__doPost = doPost; globalThis.__doGet = doGet;', ctx);
const call = (body) => JSON.parse(ctx.__doPost({ postData: { contents: JSON.stringify(body) } }).text);
const get = (sid) => JSON.parse(ctx.__doGet({ parameter: { session: sid } }).text);
const C = { v: 1, club: 'tennisweet' };
const ST = { startTime: '19:00', endTime: '22:00', matchMinutes: 30, courts: 3, minWomenDoubles: 1, courtsByHour: { 19: 2, 20: 3, 21: 3 }, courtNamesByHour: { 19: ['5', '7'], 20: ['5', '7', '9'] } };
const NEW = { date: D_UP, name: '  2026년 4분기 대회  ', mode: 'rotation', venue: { name: '통속으로', time: '22:00', note: 'x'.repeat(300) }, settings: ST };
const TID = D_UP + 't', TPATH = 'data/weekly/sessions/' + TID + '.json';
const results = []; const ok = (name, cond) => { results.push([name, !!cond]); };
// ---- tour-create ----
ok('create: no key → AUTH', call({ ...C, op: 'tour-create', value: NEW }).code === 'AUTH');
ok('create: wrong key → AUTH', call({ ...C, op: 'tour-create', key: 'ab'.repeat(32), value: NEW }).code === 'AUTH');
ok('create: bad date → INVALID', call({ ...C, op: 'tour-create', key: TEST_KEY, value: { ...NEW, date: '2026-02-30' } }).code === 'INVALID');
ok('create: empty name → INVALID', call({ ...C, op: 'tour-create', key: TEST_KEY, value: { ...NEW, name: '  ' } }).code === 'INVALID');
ok('create: bad mode → INVALID', call({ ...C, op: 'tour-create', key: TEST_KEY, value: { ...NEW, mode: 'knockout' } }).code === 'INVALID');
ok('create: start ≥ end → INVALID', call({ ...C, op: 'tour-create', key: TEST_KEY, value: { ...NEW, settings: { ...ST, startTime: '22:00', endTime: '19:00' } } }).code === 'INVALID');
ok('create: teamCount 5 → INVALID', call({ ...C, op: 'tour-create', key: TEST_KEY, value: { ...NEW, mode: 'team', teamCount: 5 } }).code === 'INVALID');
ok('create: past date → CLOSED', call({ ...C, op: 'tour-create', key: TEST_KEY, value: { ...NEW, date: D_PAST } }).code === 'CLOSED');
ok('create: nothing written by rejects', !store[TPATH] && JSON.stringify(store[IDX]) === JSON.stringify(index0));
let r = call({ ...C, op: 'tour-create', key: TEST_KEY, by: 'h0teikh', value: NEW });
ok('create: ok', r.ok && r.doc.id === TID && r.doc.date === D_UP && r.doc.rev === 1 && r.doc.tour.name === '2026년 4분기 대회' && r.doc.tour.mode === 'rotation' && r.doc.tour.teams === null);
ok('create: venue trimmed to limits', r.doc.tour.venue.name === '통속으로' && r.doc.tour.venue.note.length === 200 && r.doc.tour.venue.addr === '');
ok('create: settings cleaned', JSON.stringify(r.doc.settings) === JSON.stringify({ startTime: '19:00', endTime: '22:00', matchMinutes: 30, breakMinutes: 0, courts: 3, minWomenDoubles: 1, courtsByHour: { 19: 2, 20: 3, 21: 3 }, courtNamesByHour: { 19: ['5', '7'], 20: ['5', '7', '9'] } }));
ok('create: session file main + gh', store[TPATH]?.id === TID && store['gh:' + TPATH]?.id === TID);
ok('create: index entry added', JSON.stringify(store[IDX].tours) === JSON.stringify([{ id: TID, date: D_UP, name: '2026년 4분기 대회', mode: 'rotation', teamCount: 2, startTime: '19:00', endTime: '22:00', courts: 3, archived: false }]) && r.index?.tours?.length === 1);
ok('create: index keeps sessions/proxy/levels/past', ['sessions', 'proxy', 'levels', 'levelsAt', 'past'].every((k) => JSON.stringify(store[IDX][k]) === JSON.stringify(index0[k])) && store[IDX].updatedAt !== 'u0');
ok('create: gh index copy equal', JSON.stringify(store['gh:' + IDX]) === JSON.stringify(store[IDX]));
ok('create: doGet serves it (cache)', (() => { const g = get(TID); return g.ok && g.doc.tour.name === '2026년 4분기 대회'; })());
ok('create: same date again → EXISTS', call({ ...C, op: 'tour-create', key: TEST_KEY, value: NEW }).code === 'EXISTS');
// ---- 일반 op 로 참가·대진 ----
const S = { ...C, session: TID };
for (const [id, n, g] of [['a', 'A', 'M'], ['b', 'B', 'F'], ['c', 'C', 'M'], ['d', 'D', 'F']]) call({ ...S, op: 'set', path: 'attendance.' + id, value: { n, g, from: '19:00', until: '22:00' } });
r = call({ ...S, op: 'generate', key: TEST_KEY, base: 5, value: { seed: 1, gen: 1, fromSlot: 0, inputHash: 'h~fmx', matches: [{ id: 's0c1', slot: 0, court: 1, aIds: ['p:a', 'p:b'], bIds: ['p:c', 'p:d'] }] } });
ok('attend + generate on tour', r.ok && r.doc.schedule.matches.length === 1 && Object.keys(r.doc.attendance).length === 4);
r = call({ ...S, op: 'set', path: 'results.s0c1', value: { a: 6, b: 3 } }); ok('score on tour (anyone)', r.ok && r.doc.results.s0c1.a === 6);
// ---- 대회 코트 번호는 비밀번호 ----
ok('tour courtNames: no key → AUTH', call({ ...S, op: 'set', path: 'courtNames', value: ['1', '2'] }).code === 'AUTH');
r = call({ ...S, op: 'set', path: 'courtNames', key: TEST_KEY, value: ['1', '2', '3'] }); ok('tour courtNames: key → ok', r.ok && r.doc.settings.courtNames.join() === '1,2,3' && !r.doc.settings.courtNamesByHour);
ok('weekly courtNames: still anyone', call({ ...C, session: '2099-01-01', op: 'set', path: 'courtNames', value: ['8'] }).ok === true);
// ---- tour-set ----
const rev = () => store[TPATH].rev;
ok('tour-set: no key → AUTH', call({ ...S, op: 'tour-set', base: rev(), value: { name: 'x' } }).code === 'AUTH');
ok('tour-set: stale base → STALE', call({ ...S, op: 'tour-set', key: TEST_KEY, base: rev() - 1, value: { name: 'x' } }).code === 'STALE');
ok('tour-set: on weekly session → INVALID', call({ ...C, session: '2099-01-01', op: 'tour-set', key: TEST_KEY, base: 1, value: { name: 'x' } }).code === 'INVALID');
let putsBefore = puts.length;
r = call({ ...S, op: 'tour-set', key: TEST_KEY, base: rev(), value: { name: '4분기 정기 대회', venue: { name: '새 장소', addr: '서울' } } });
ok('tour-set: name+venue ok, schedule kept', r.ok && r.doc.tour.name === '4분기 정기 대회' && r.doc.tour.venue.addr === '서울' && r.doc.schedule && r.doc.results.s0c1);
ok('tour-set: index name synced', store[IDX].tours[0].name === '4분기 정기 대회' && r.index?.tours?.[0]?.name === '4분기 정기 대회' && store['gh:' + IDX].tours[0].name === '4분기 정기 대회');
putsBefore = puts.length; r = call({ ...S, op: 'tour-set', key: TEST_KEY, base: rev(), value: { venue: { name: '새 장소 2' } } });
ok('tour-set: venue only → index not rewritten', r.ok && !puts.slice(putsBefore).some((k) => k.endsWith(IDX)) && r.index?.tours?.[0]?.name === '4분기 정기 대회');
ok('tour-set: bad teams for rotation count → INVALID', call({ ...S, op: 'tour-set', key: TEST_KEY, base: rev(), value: { teams: [['a']] } }).code === 'INVALID');
ok('tour-set: duplicate id in teams → INVALID', call({ ...S, op: 'tour-set', key: TEST_KEY, base: rev(), value: { mode: 'team', teamCount: 2, teams: [['a', 'b'], ['b', 'c']] } }).code === 'INVALID');
r = call({ ...S, op: 'tour-set', key: TEST_KEY, base: rev(), value: { mode: 'team', teamCount: 2, teamNames: ['청팀', ''] } });
ok('tour-set: mode change clears schedule/results, teams null', r.ok && r.doc.schedule === null && !Object.keys(r.doc.results).length && r.doc.tour.mode === 'team' && r.doc.tour.teams === null && r.doc.tour.teamNames.join() === '청팀,2팀' && store[IDX].tours[0].mode === 'team');
r = call({ ...S, op: 'tour-set', key: TEST_KEY, base: rev(), value: { teams: [['a', 'b'], ['c', 'd']] } }); ok('tour-set: teams ok', r.ok && JSON.stringify(r.doc.tour.teams) === '[["a","b"],["c","d"]]');
r = call({ ...S, op: 'generate', key: TEST_KEY, base: rev(), value: { seed: 2, gen: 1, fromSlot: 0, inputHash: 'h', matches: [{ id: 's0c1', slot: 0, court: 1, aIds: ['p:a', 'p:b'], bIds: ['p:c', 'p:d'] }] } }); ok('team generate', r.ok);
r = call({ ...S, op: 'tour-set', key: TEST_KEY, base: rev(), value: { teamNames: ['청팀', '백팀'] } }); ok('tour-set: team names keep teams & schedule', r.ok && r.doc.tour.teams && r.doc.schedule);
r = call({ ...S, op: 'tour-set', key: TEST_KEY, base: rev(), value: { settings: { ...ST, endTime: '21:00' } } }); ok('tour-set: time change clears schedule, keeps teams', r.ok && r.doc.schedule === null && r.doc.tour.teams && store[IDX].tours[0].endTime === '21:00');
ok('tour-set: bad settings → INVALID', call({ ...S, op: 'tour-set', key: TEST_KEY, base: rev(), value: { settings: { ...ST, courts: 9 } } }).code === 'INVALID');
r = call({ ...S, op: 'tour-set', key: TEST_KEY, base: rev(), value: { teamCount: 3 } }); ok('tour-set: team count change drops teams', r.ok && r.doc.tour.teams === null && r.doc.tour.teamNames.length === 3);
// ---- 결과 보관 ----
ok('archive: no key → AUTH', call({ ...S, op: 'tour-archive', base: rev(), value: true }).code === 'AUTH');
ok('archive: no schedule → INVALID', call({ ...S, op: 'tour-archive', key: TEST_KEY, base: rev(), value: true }).code === 'INVALID');
call({ ...S, op: 'tour-set', key: TEST_KEY, base: rev(), value: { teams: [['a', 'b'], ['c', 'd'], []] } });
r = call({ ...S, op: 'generate', key: TEST_KEY, base: rev(), value: { seed: 3, gen: 1, fromSlot: 0, inputHash: 'h', matches: [{ id: 's0c1', slot: 0, court: 1, aIds: ['p:a', 'p:b'], bIds: ['p:c', 'p:d'] }] } }); call({ ...S, op: 'set', path: 'results.s0c1', value: { a: 6, b: 2 } });
ok('archive: bad value → INVALID', call({ ...S, op: 'tour-archive', key: TEST_KEY, base: rev(), value: 'yes' }).code === 'INVALID');
r = call({ ...S, op: 'tour-archive', key: TEST_KEY, base: rev(), value: true }); ok('archive: ok → closed + index archived', r.ok && r.doc.status === 'closed' && !!r.doc.archivedAt && store[IDX].tours.find((t) => t.id === TID).archived === true && r.index?.tours?.find((t) => t.id === TID)?.archived === true);
ok('archive: score after → CLOSED', call({ ...S, op: 'set', path: 'results.s0c1', value: { a: 1, b: 6 } }).code === 'CLOSED' && store[TPATH].results.s0c1.a === 6);
ok('archive: attendance after → CLOSED', call({ ...S, op: 'set', path: 'attendance.zz', value: { n: 'Z', g: 'M', from: '19:00', until: '22:00' } }).code === 'CLOSED');
ok('archive: tour-set / generate after → CLOSED', call({ ...S, op: 'tour-set', key: TEST_KEY, base: rev(), value: { name: 'x' } }).code === 'CLOSED' && call({ ...S, op: 'generate', key: TEST_KEY, base: rev(), value: null }).code === 'CLOSED');
ok('archive: member del of archived → CLOSED', call({ ...C, op: 'tour-del', key: TEST_KEY, session: TID }).code === 'CLOSED');
r = call({ ...S, op: 'tour-archive', key: TEST_KEY, base: rev(), value: false }); ok('unarchive: ok → open + index', r.ok && r.doc.status === 'open' && !r.doc.archivedAt && store[IDX].tours.find((t) => t.id === TID).archived === false && r.doc.results.s0c1.a === 6);
ok('unarchive: scores editable again', call({ ...S, op: 'set', path: 'results.s0c1', value: { a: 5, b: 6 } }).ok === true);
// ---- 동시 저장 재시도 (목록 파일) ----
conflictPath = IDX; r = call({ ...S, op: 'tour-set', key: TEST_KEY, base: rev(), value: { name: '재시도 대회' } }); ok('index 409 → retry', r.ok && store[IDX].tours[0].name === '재시도 대회' && conflictPath === null);
// ---- tour-del ----
ok('del: no key → AUTH', call({ ...C, op: 'tour-del', session: TID }).code === 'AUTH');
ok('del: weekly id → INVALID', call({ ...C, op: 'tour-del', key: TEST_KEY, session: '2099-01-01' }).code === 'INVALID');
const revBefore = rev(); r = call({ ...C, op: 'tour-del', key: TEST_KEY, session: TID });
ok('del: removed from index, file kept but closed', r.ok && !(store[IDX].tours || []).length && store[TPATH]?.rev === revBefore + 1 && store[TPATH].deleted === true && store[TPATH].status === 'closed' && store['gh:' + TPATH].deleted === true && r.doc?.deleted === true && store[IDX].past.length === 1 && store[IDX].sessions.length === 1);
ok('deleted: attendance → CLOSED', call({ ...S, op: 'set', path: 'attendance.q1', value: { n: 'Q', g: 'M', from: '19:00', until: '22:00' } }).code === 'CLOSED');
ok('deleted: tour-set → CLOSED, not re-listed', call({ ...S, op: 'tour-set', key: TEST_KEY, base: rev(), value: { name: '되살리기' } }).code === 'CLOSED' && !(store[IDX].tours || []).length);
ok('deleted: unarchive → INVALID, not re-listed', call({ ...S, op: 'tour-archive', key: TEST_KEY, base: rev(), value: false }).code === 'INVALID' && !(store[IDX].tours || []).length && store[TPATH].status === 'closed');
ok('deleted: del again → ok (idempotent)', call({ ...C, op: 'tour-del', key: TEST_KEY, session: TID }).ok === true && store[TPATH].rev === revBefore + 1);
r = call({ ...C, op: 'tour-create', key: TEST_KEY, value: { ...NEW, name: '다시 만든 대회' } });
ok('re-create after del: fresh doc, rev continues', r.ok && r.doc.rev === revBefore + 2 && !r.doc.deleted && r.doc.status === 'open' && !Object.keys(r.doc.attendance).length && store[IDX].tours.length === 1 && r.doc.tour.name === '다시 만든 대회');
// 파일은 살아 있는데 목록에서만 빠진 경우(목록 쓰기 실패·Pages 지연): 덮어쓰지 않고 목록을 고친다
call({ ...S, op: 'set', path: 'attendance.k1', value: { n: 'K', g: 'M', from: '19:00', until: '22:00' } }); store[IDX].tours = []; const revKeep = rev();
r = call({ ...C, op: 'tour-create', key: TEST_KEY, value: { ...NEW, name: '겹친 대회' } });
ok('create over live unlisted file → EXISTS + index repaired, file kept', r.code === 'EXISTS' && r.doc.tour.name === '다시 만든 대회' && store[TPATH].rev === revKeep && store[TPATH].attendance.k1 && store[IDX].tours.length === 1 && r.index?.tours?.length === 1);
ok('create: >64 matches (09~18시 30분 4면) → INVALID', call({ ...C, op: 'tour-create', key: TEST_KEY, value: { ...NEW, date: ymd(Date.now() + 30 * DAY), settings: { startTime: '09:00', endTime: '18:00', matchMinutes: 30, courts: 4, minWomenDoubles: 1 } } }).code === 'INVALID');
r = call({ ...S, op: 'generate', key: TEST_KEY, base: rev(), value: { seed: 9, gen: 1, fromSlot: 0, inputHash: 'h', matches: [{ id: 's0c1', slot: 0, court: 1, aIds: ['p:k1', 'p:k1x'], bIds: ['p:c', 'p:d'] }] } }); r = call({ ...S, op: 'tour-set', key: TEST_KEY, base: rev(), value: { teamCount: 3 } });
ok('rotation: team count change keeps schedule', r.ok && r.doc.tour.mode === 'rotation' && !!r.doc.schedule);
// 지난 대회는 멤버가 뺄 수 없다
const OLD = D_PAST + 't'; store['data/weekly/sessions/' + OLD + '.json'] = { v: 1, id: OLD, date: D_PAST, status: 'open', rev: 3, tour: { name: '지난 대회', mode: 'rotation', teamCount: 2, teamNames: ['1팀', '2팀'], venue: {}, teams: null }, settings: ST, attendance: {}, schedule: null, done: {}, results: {} };
store[IDX].tours.push({ id: OLD, date: D_PAST, name: '지난 대회', mode: 'rotation', teamCount: 2, startTime: '19:00', endTime: '22:00', courts: 3 });
ok('del: closed tournament → CLOSED', call({ ...C, op: 'tour-del', key: TEST_KEY, session: OLD }).code === 'CLOSED' && store[IDX].tours.length === 2);
ok('tour-set: closed tournament → CLOSED', call({ ...C, session: OLD, op: 'tour-set', key: TEST_KEY, base: 3, value: { name: 'y' } }).code === 'CLOSED');
store['data/weekly/sessions/' + OLD + '.json'].schedule = { matches: [{ id: 's0c1', slot: 0, court: 1, aIds: ['p:a', 'p:b'], bIds: ['p:c', 'p:d'] }] };
r = call({ ...C, session: OLD, op: 'tour-archive', key: TEST_KEY, base: 3, value: true }); ok('archive: past tournament within 7 days → ok', r.ok && r.doc.status === 'closed');
const OLD2 = ymd(Date.now() - 9 * DAY) + 't'; store['data/weekly/sessions/' + OLD2 + '.json'] = { ...store['data/weekly/sessions/' + OLD + '.json'], id: OLD2, date: OLD2.slice(0, 10), status: 'open', rev: 1 };
ok('archive: older than 7 days → CLOSED', call({ ...C, session: OLD2, op: 'tour-archive', key: TEST_KEY, base: 1, value: true }).code === 'CLOSED');
ok('archive: weekly session → INVALID', call({ ...C, session: '2099-01-01', op: 'tour-archive', key: TEST_KEY, base: store['data/weekly/sessions/2099-01-01.json'].rev, value: true }).code === 'INVALID');
// 깨진 목록 파일은 덮어쓰지 않는다
const D2 = ymd(Date.now() + 20 * DAY); raw[IDX] = 'not json{';
r = call({ ...C, op: 'tour-create', key: TEST_KEY, value: { ...NEW, date: D2 } }); ok('broken index → GITHUB, nothing written', r.code === 'GITHUB' && !store['data/weekly/sessions/' + D2 + 't.json'] && raw[IDX] === 'not json{');
delete raw[IDX];
ok('ping v8', (() => { const p = call({ ...C, session: '2000-01-01', op: 'ping' }); return p.ok && p.v === 8; })());
// ---- 사본 일치: app.js 공용 함수(대회 정리·목록·applyWeeklyOp tour-set) 와 Code.gs ----
{ const app = fs.readFileSync(__dirname + '/../../app.js', 'utf8');
  const fn = app.slice(app.indexOf('  function applyWeeklyOp(doc, op) {'), app.indexOf('  /** 외부에서 온 세션 문서 검증'));
  const consts = [app.match(/const ID_RE = [^\n]+;/)[0], app.match(/const TIME_RE = [^\n]+;/)[0], app.match(/const WK_SCORE_MAX = [^\n]+;/)[0], app.match(/const wkCleanCourtNames = [^\n]+;/)[0], app.match(/const wkCleanCourtNamesByHour = [^\n]+;/)[0]].join('\n');
  const expose = '\nglobalThis.__t = { applyWeeklyOp, tourVenue, tourSettings, tourMeta, tourNewDoc, tourIndexEntry, tourIndexPut };';
  const appCtx = vm.createContext({ Date }); vm.runInContext(consts + '\n' + fn + expose, appCtx);
  const gsCtx = vm.createContext({ ...gas }); vm.runInContext(fs.readFileSync(__dirname + '/Code.gs', 'utf8') + expose, gsCtx);
  const run = (c) => { const t = c.__t; const out = [];
    for (const st of [ST, { ...ST, matchMinutes: 5 }, { ...ST, startTime: '24:00' }, { ...ST, courtsByHour: { 25: 1 } }, { ...ST, courtsByHour: [] }, { ...ST, courtNames: ['1', ''], courtNamesByHour: { 20: ['x'] } }, { ...ST, minWomenDoubles: -1 }, { ...ST, courts: 2.5 }, null, []]) out.push(t.tourSettings(st));
    for (const m of [{ name: ' a ', mode: 'team', teamCount: 3, teamNames: ['x', 5, ' y '], venue: { name: 1, addr: ' 주소 ' }, teams: [['a'], [], ['b', 'c']] }, { name: 'a', mode: 'team', teamCount: 2, teams: [['a'], ['a']] }, { name: 'a', mode: 'rotation' }, { name: 'a', mode: 'x' }, { name: 'a'.repeat(50), mode: 'rotation', teams: [['bad id!'], []] }]) out.push(t.tourMeta(m));
    const doc = t.tourNewDoc('2026-12-12t', '2026-12-12', t.tourMeta({ name: 'T', mode: 'rotation' }), t.tourSettings(ST), 4, 'NOW'); out.push(JSON.parse(JSON.stringify(doc)));
    let idx = { v: 1, sessions: [{ id: 'x' }], tours: [{ id: '2026-01-01t', date: '2026-01-01' }, { id: 'bad' }, null], proxy: 'p' };
    out.push(t.tourIndexPut(JSON.parse(JSON.stringify(idx)), t.tourIndexEntry(doc), null, 'N1'));
    idx = t.tourIndexPut(JSON.parse(JSON.stringify(idx)), t.tourIndexEntry(doc), null, 'N1'); out.push(t.tourIndexPut(JSON.parse(JSON.stringify(idx)), t.tourIndexEntry(doc), null, 'N2')); out.push(t.tourIndexPut(JSON.parse(JSON.stringify(idx)), null, '2026-12-12t', 'N3')); out.push(t.tourIndexPut(JSON.parse(JSON.stringify(idx)), null, 'nope', 'N4')); out.push(t.tourIndexPut(null, t.tourIndexEntry(doc), null, 'N5')); out.push(t.tourIndexPut(JSON.parse(JSON.stringify(idx)), { ...t.tourIndexEntry(doc), id: '2027-01-01t' }, null, 'N6', true)); out.push(t.tourIndexPut(JSON.parse(JSON.stringify(idx)), { ...t.tourIndexEntry(doc), name: '바뀜' }, null, 'N7', true)?.tours.find((x) => x.id === '2026-12-12t').name);
    const seq = [{ op: 'tour-set', base: 5, value: { name: 'U' } }, { op: 'tour-set', base: 6, value: { name: 'U2', mode: 'team', teamCount: 2 } }, { op: 'tour-set', base: 7, value: { teams: [['a', 'b'], ['c']] } }, { op: 'tour-set', base: 8, value: { teams: [['a'], ['a']] } }, { op: 'tour-set', base: 8, value: { settings: { ...ST, courts: 2 } } }, { op: 'tour-set', base: 9, value: [] }, { op: 'tour-set', base: 9, value: { teamCount: 4 } }, { op: 'tour-set', base: 1, value: { name: 'z' } }, { op: 'tour-set', base: 10, value: { venue: { name: '장소' }, teamNames: ['A', 'B', 'C', 'D', 'E'] } }, { op: 'tour-archive', base: 11, value: true }, { op: 'tour-archive', base: 11, value: 1 }];
    const d = JSON.parse(JSON.stringify(doc)); d.schedule = { matches: [{ id: 's0c1', slot: 0, court: 1, aIds: ['p:a', 'p:b'], bIds: ['p:c', 'p:d'] }] }; d.results = { s0c1: { a: 1, b: 2 } }; const codes = []; for (const op of seq) { if (op.op === 'tour-archive' && op.value === true) d.schedule = { matches: [{ id: 's0c1', slot: 0, court: 1, aIds: ['p:a', 'p:b'], bIds: ['p:c', 'p:d'] }] }; const r = t.applyWeeklyOp(d, { v: 1, club: 'tennisweet', session: d.id, ...op }); codes.push(r.ok ? 'ok' : r.code); } delete d.updatedAt; const arch = !!d.archivedAt; delete d.archivedAt; out.push({ d, codes, arch, entry: t.tourIndexEntry(d) });
    const w = { v: 1, id: '2026-12-12', date: '2026-12-12', status: 'open', rev: 0, settings: {}, attendance: {}, schedule: null, done: {} }; out.push(t.applyWeeklyOp(w, { op: 'tour-set', base: 0, value: { name: 'x' } }));
    return JSON.stringify(out); };
  const a = run(appCtx), b = run(gsCtx); ok('app.js ↔ Code.gs tour shared parity', a === b); if (a !== b) console.log('APP', a, '\nGS ', b);
  const j = JSON.parse(a); ok('parity: settings rejects', j.slice(1, 5).every((x) => x === null) && j[6] === null && j[7] === null && j[8] === null && j[9] === null && j[5].courtNames.join() === '1' && !j[5].courtNamesByHour);
  ok('parity: meta cleaning', j[10].name === 'a' && j[10].teamNames.join() === 'x,2팀,y' && j[10].venue.addr === '주소' && j[10].venue.name === '' && j[11] === null && j[12].teams === null && j[13] === null && j[14] === null);
  ok('parity: index put/no-op/remove', j[16].tours.length === 2 && j[16].tours[0].id === '2026-12-12t' && j[16].proxy === 'p' && j[17] === null && j[18].tours.length === 1 && j[19] === null && j[20].tours.length === 1);
  ok('parity: onlyListed', j[21] === null && j[22] === '바뀜');
  ok('parity: tour-set codes', JSON.stringify(j[23].codes) === JSON.stringify(['ok', 'ok', 'ok', 'INVALID', 'ok', 'INVALID', 'ok', 'STALE', 'ok', 'ok', 'INVALID']) && j[23].d.status === 'closed' && j[23].arch && j[23].entry.archived === true && j[23].d.tour.teamCount === 4 && j[23].d.tour.teams === null && j[23].d.tour.teamNames.join() === 'A,B,C,D' && j[23].d.tour.venue.name === '장소' && j[24].code === 'INVALID');
}
for (const [name, pass] of results) console.log((pass ? 'PASS' : 'FAIL') + '  ' + name);
process.exit(results.every(([, pass]) => pass) ? 0 : 1);
