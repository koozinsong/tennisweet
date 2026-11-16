/* 테니스윗 정기 모임 저장 프록시 — Google Apps Script 웹앱
 * 멤버 폰에는 토큰이 없다. 이 스크립트가 GitHub 저장소(koozinsong/tennisweet)의 data/weekly/sessions/<날짜>.json (대회는 <날짜>t.json), data/courts.json, data/weekly/index.json 의 대회 목록(tours)만 대신 커밋한다.
 * (게시하기와 같은 방식으로 main 원본 + gh-pages 서빙 사본 두 브랜치에 쓴다)
 *
 * 배포 (README '멤버 직접 저장' 절):
 *  1) script.google.com → 새 프로젝트 → Code.gs 내용을 이 파일로 교체
 *  2) ⚙ 프로젝트 설정 → 스크립트 속성: GH_TOKEN = koozinsong/tennisweet 저장소 Contents: Read and write 권한의 fine-grained 토큰
 *     (선택) OWNER / REPO / BRANCHES 기본값 koozinsong / tennisweet / main,gh-pages
 *  3) 배포 → 새 배포 → 유형 '웹 앱', 실행: '나', 액세스: '모든 사용자' → 웹 앱 URL(…/exec) 을 관리자 화면 정기 모임 → '저장 서버 주소'에 입력
 *  4) 코드를 고치면 배포 → 배포 관리 → 새 버전 (URL 유지)
 *
 * 읽기: GET ?session=YYYY-MM-DD → { ok, rev, doc } (캐시, Pages 지연 없음)
 * 요청: POST 본문 = JSON 문자열 (Content-Type 없이 → CORS preflight 없음)
 *   { v:1, club:'tennisweet', session:'2026-09-20', op:'set'|'generate'|'edit'|'ping', path?, value?, base?, by? }
 *   generate·edit·courts 는 key(대진표 비밀번호에서 만든 열쇠)가 필요하다 — 서버는 SHA-256(key) 만 비교
 *   courts: { op:'courts', key, value:[{ d:'YYYY-MM-DD', t:'20', c:0, n:'이름'|'', p?:'내가 본 값' }] } → data/courts.json (session 불필요, 대진표 비밀번호 필요)
 *   대회 (v8, 모두 대진표 비밀번호 필요): tour-create { op:'tour-create', key, value:{ date, name, mode:'rotation'|'team', teamCount?, teamNames?, venue?, settings } } → sessions/<날짜>t.json 생성 + index.json tours 항목 (목록에 있으면 EXISTS)
 *     tour-set { session:'<날짜>t', base, value:{ name?, mode?, teamCount?, teamNames?, venue?, teams?, settings? } } → 대회 정보 수정 (시간·코트·방식·팀 수가 바뀌면 대진·완료·점수 비움)
 *     tour-archive { session:'<날짜>t', base, value:true|false } → 결과 보관(대회를 닫음)·보관 취소, 대회 후 7일 안 (대진이 있어야 보관)
 *     tour-del { op:'tour-del', session:'<날짜>t', key } → index.json tours 에서만 뺀다 (파일 보존, 마감 지난 대회는 거절). 대회의 set courtNames 도 비밀번호 필요
 *   edit: value = [{ id, aIds:[2], bIds:[2] }, …], prev? = { id: [aIds, bIds] } (최대 4경기, 같은 시간대 중복 금지, base=rev 필수, prev 와 현재 팀이 다르면 STALE, 완료 표시 유지)
 * 응답: { ok:true, rev, doc } | { ok:false, code:'INVALID'|'NOSESSION'|'CLOSED'|'STALE'|'FULL'|'BUSY'|'GITHUB'|'AUTH'|'EXISTS', rev?, doc? } (대회 op 는 성공 시 index 도 돌려준다)
 */
const CLUB = 'tennisweet';
const WK_KEY_SHA = 'ff83ce9ab3243ef60ca56c1783ab4a0f909abae34203e9b699352e552107d9b6'; // 대진표 비밀번호 확인: 클라이언트가 보내는 열쇠 K = PBKDF2-SHA256(비밀번호, 'tennisweet-wk-key', 120000회)의 hex, 여기에는 SHA-256(K) 만 둔다. 공개된 코드(app.js·이 파일)만으로는 K 를 만들 수 없다 (옛 방식은 공개 검증값을 그대로 비교해 우회가 가능했다)
const DONE_GRACE_DAYS = 7; // 완료 표시 유예 (모임 후 7일)
const SCORE_MAX = 6; // 점수(게임 수) 상한 — app.js WK_SCORE_MAX 와 동일
const PROXY_VERSION = 8; // 앱의 '연결 확인'이 비교하는 서버 코드 버전 (app.js PROXY_VERSION_NEED): 2 = 대진표 비밀번호 검사 + 완료 표시 7일 유예, 3 = 경기 기록(results.<mid> = {a,b} 0~6, 완료 자동), 4 = 코트 번호(set courtNames), 5 = 코트 예약(op courts → data/courts.json) + 인증을 열쇠(key) 해시 비교로 변경 + 시간대별 코트 번호(set courtNames 에 { 시: [번호] }), 6 = 참석의 양보 표시(y), 7 = 게스트 NTRP(lv), 8 = 대회(tour-create·tour-set·tour-del, index.json 의 tours)
const ID_RE = /^[A-Za-z0-9_:.-]{1,40}$/, TIME_RE = /^\d{2}:\d{2}$/, SESSION_RE = /^\d{4}-\d{2}-\d{2}[a-z]?$/, MID_RE = /^s\d{1,2}c\d{1,2}$/;
function cfg() { const p = PropertiesService.getScriptProperties(); return { token: p.getProperty('GH_TOKEN'), owner: p.getProperty('OWNER') || 'koozinsong', repo: p.getProperty('REPO') || 'tennisweet', branches: (p.getProperty('BRANCHES') || 'main,gh-pages').split(',').map(function (b) { return b.trim(); }).filter(Boolean) }; }

/** GET ?session=YYYY-MM-DD → 최신 세션 문서 (쓰기 직후 캐시에 담아 두므로 Pages 반영을 기다리지 않는다). 그 외 → ping */
function doGet(e) {
  const sid = e && e.parameter && String(e.parameter.session || '');
  if (!sid) return out({ ok: true, v: 1, t: new Date().toISOString() });
  if (!SESSION_RE.test(sid)) return out({ ok: false, code: 'INVALID' });
  try {
    const cache = CacheService.getScriptCache(); const hit = cache.get('s:' + sid);
    if (hit) { const doc = JSON.parse(hit); return out({ ok: true, rev: doc.rev | 0, doc: doc, cached: true }); }
    const c = cfg(); if (!c.token) return out({ ok: false, code: 'GITHUB' });
    const cur = ghGet(c, 'data/weekly/sessions/' + sid + '.json', c.branches[0]); if (!cur || !cur.json) return out({ ok: false, code: 'NOSESSION' });
    cache.put('s:' + sid, JSON.stringify(cur.json), 21600);
    return out({ ok: true, rev: cur.json.rev | 0, doc: cur.json });
  } catch (err) { return out({ ok: false, code: 'GITHUB', detail: String(err && err.message || err) }); }
}
function doPost(e) {
  let body; try { body = JSON.parse(e.postData.contents); } catch (err) { return out({ ok: false, code: 'INVALID' }); }
  if (body && typeof body === 'object' && body.club === CLUB && body.op === 'courts') return String(e.postData.contents).length > 65536 ? out({ ok: false, code: 'INVALID' }) : courtsPost(body); // 코트 예약 현황 (data/courts.json) — 모임 날짜와 무관
  if (body && typeof body === 'object' && body.club === CLUB && (body.op === 'tour-create' || body.op === 'tour-del')) return String(e.postData.contents).length > 65536 ? out({ ok: false, code: 'INVALID' }) : tourPost(body); // 대회 만들기·목록에서 빼기 (세션 파일이 아직 없거나 목록 파일을 쓰므로 아래 일반 쓰기와 따로)
  if (!body || typeof body !== 'object' || body.club !== CLUB || !SESSION_RE.test(String(body.session || ''))) return out({ ok: false, code: 'INVALID' });
  if (String(e.postData.contents).length > 65536) return out({ ok: false, code: 'INVALID' });
  if (body.op === 'ping') return out({ ok: true, v: PROXY_VERSION, t: new Date().toISOString() });
  if ((body.op === 'generate' || body.op === 'edit' || body.op === 'tour-set' || body.op === 'tour-archive' || (body.op === 'set' && body.path === 'courtNames' && TOUR_ID_RE.test(String(body.session)))) && !authOk(body)) return out({ ok: false, code: 'AUTH' }); // 대진 생성·다시 섞기·조 조정·대회 수정(대회의 코트 번호 포함)은 대진표 비밀번호(검증값)가 있어야 한다. 참석·완료 표시는 누구나
  const c = cfg(); if (!c.token) return out({ ok: false, code: 'GITHUB', detail: 'GH_TOKEN 속성이 없습니다' });
  if (body.op === 'refresh') { // 관리자가 파일을 직접 만들거나 지우거나 직접 저장한 뒤: 캐시를 저장소 기준으로 다시 맞춘다 (쓰기와 같은 잠금 — 진행 중인 멤버 쓰기의 cache.put 을 옛 문서로 덮지 않도록)
    const rlock = LockService.getScriptLock(); if (!rlock.tryLock(20000)) return out({ ok: false, code: 'BUSY' });
    try { const cache = CacheService.getScriptCache(); const cur = ghGet(c, 'data/weekly/sessions/' + body.session + '.json', c.branches[0]); if (!cur || !cur.json) { cache.remove('s:' + body.session); return out({ ok: false, code: 'NOSESSION' }); } cache.put('s:' + body.session, JSON.stringify(cur.json), 21600); return out({ ok: true, rev: cur.json.rev | 0, doc: cur.json }); }
    catch (err) { return out({ ok: false, code: 'GITHUB', detail: String(err && err.message || err) }); }
    finally { rlock.releaseLock(); }
  }
  const lock = LockService.getScriptLock(); if (!lock.tryLock(20000)) return out({ ok: false, code: 'BUSY' });
  try {
    const path = 'data/weekly/sessions/' + body.session + '.json'; // 세션 파일만 쓸 수 있다 (경로는 서버가 정한다)
    const main = c.branches[0]; let saved = null;
    for (let attempt = 0; attempt < 3 && !saved; attempt++) {
      const cur = ghGet(c, path, main); if (!cur) return out({ ok: false, code: 'NOSESSION' });
      const doc = cur.json; if (!doc || typeof doc !== 'object') return out({ ok: false, code: 'GITHUB', detail: '세션 파일 형식 오류' });
      if (closed(doc, body)) return out({ ok: false, code: 'CLOSED', rev: doc.rev | 0, doc: doc });
      const r = applyWeeklyOp(doc, body); if (!r.ok) return out({ ok: false, code: r.code, rev: doc.rev | 0, doc: doc });
      const content = JSON.stringify(doc, null, 1) + '\n'; const code = ghPut(c, path, content, cur.sha, commitMsg(body, doc), main);
      if (code === 200 || code === 201) { saved = { doc: doc, content: content }; try { CacheService.getScriptCache().put('s:' + body.session, JSON.stringify(doc), 21600); } catch (err) {} }
      else if (code !== 409 && code !== 422) return out({ ok: false, code: 'GITHUB', detail: 'PUT ' + code });
    }
    if (!saved) return out({ ok: false, code: 'BUSY' });
    for (let i = 1; i < c.branches.length; i++) { // 서빙 사본(gh-pages): 실패해도 원본은 저장됨 (다음 배포 때 따라옴)
      try { const cur2 = ghGet(c, path, c.branches[i]); ghPut(c, path, saved.content, cur2 ? cur2.sha : null, commitMsg(body, saved.doc), c.branches[i]); } catch (err) {}
    }
    let index = null; if ((body.op === 'tour-set' || body.op === 'tour-archive') && saved.doc.tour) { try { const r = tourIndexWrite(c, function (idx) { return tourIndexPut(idx, tourIndexEntry(saved.doc), null, new Date().toISOString(), true); }, '대회 ' + saved.doc.id + ' 목록 갱신'); if (r.ok) index = r.idx; } catch (err) {} } // 이름·방식·시간·코트가 바뀌었으면 목록도 맞춘다 (같으면 쓰지 않음, 실패해도 대회 파일은 저장됨)
    return out(index ? { ok: true, rev: saved.doc.rev, doc: saved.doc, index: index } : { ok: true, rev: saved.doc.rev, doc: saved.doc });
  } catch (err) { return out({ ok: false, code: 'GITHUB', detail: String(err && err.message || err) }); }
  finally { lock.releaseLock(); }
}
/** 대회 만들기(tour-create)·목록에서 빼기(tour-del, 파일은 닫아서 남김) — 대진표 비밀번호 필요. 응답 { ok, rev?, doc?, index } | { ok:false, code:'AUTH'|'INVALID'|'EXISTS'|'CLOSED'|'BUSY'|'GITHUB', doc?, index? } */
function tourPost(body) {
  if (!authOk(body)) return out({ ok: false, code: 'AUTH' });
  const c = cfg(); if (!c.token) return out({ ok: false, code: 'GITHUB', detail: 'GH_TOKEN 속성이 없습니다' });
  const lock = LockService.getScriptLock(); if (!lock.tryLock(20000)) return out({ ok: false, code: 'BUSY' });
  try {
    const main = c.branches[0]; const who = body.by ? ' by ' + String(body.by).slice(0, 20) : ''; const now = new Date().toISOString();
    if (body.op === 'tour-del') {
      const id = String(body.session || ''); if (!TOUR_ID_RE.test(id)) return out({ ok: false, code: 'INVALID' }); const path = 'data/weekly/sessions/' + id + '.json';
      const cur = ghGet(c, path, main); if (cur && cur.json && !cur.json.deleted && closed(cur.json, null)) return out({ ok: false, code: 'CLOSED' }); // 지난 대회(기록)는 관리자만 뺄 수 있다
      const r = tourIndexWrite(c, function (idx) { return tourIndexPut(idx, null, id, now); }, '대회 ' + id + ' 목록에서 제외' + who); if (!r.ok) return out({ ok: false, code: r.code, detail: r.detail });
      let doc = null; // 파일은 남기되 닫아 둔다 (옛 링크로 참가·수정이 이어지거나 수정이 목록을 되살리지 않게). 실패해도 목록에서는 빠졌다
      for (let attempt = 0; attempt < 3 && cur && cur.json && !doc; attempt++) { const f = attempt ? ghGet(c, path, main) : cur; if (!f || !f.json || typeof f.json !== 'object') break; const d = f.json; if (d.deleted) { doc = d; break; } d.status = 'closed'; d.deleted = true; d.rev = (d.rev | 0) + 1; d.updatedAt = now; const content = JSON.stringify(d, null, 1) + '\n'; const code = ghPut(c, path, content, f.sha, '대회 ' + id + ' 닫기 (목록에서 뺌)' + who, main); if (code === 200 || code === 201) { doc = d; try { CacheService.getScriptCache().put('s:' + id, JSON.stringify(d), 21600); } catch (err) {} for (let i = 1; i < c.branches.length; i++) { try { const cur2 = ghGet(c, path, c.branches[i]); ghPut(c, path, content, cur2 ? cur2.sha : null, '대회 ' + id + ' 닫기', c.branches[i]); } catch (err) {} } } else if (code !== 409 && code !== 422) break; }
      return out(doc ? { ok: true, index: r.idx, rev: doc.rev, doc: doc } : { ok: true, index: r.idx });
    }
    const v = body.value && typeof body.value === 'object' ? body.value : {}; const date = String(v.date || '');
    if (!courtsDateOk(date, Date.now())) return out({ ok: false, code: 'INVALID' });
    if (closed({ date: date }, null)) return out({ ok: false, code: 'CLOSED' }); // 지난 날짜에는 만들 수 없다
    const meta = tourMeta({ name: v.name, mode: v.mode, teamCount: v.teamCount, teamNames: v.teamNames, venue: v.venue, teams: null }); const st = tourSettings(v.settings); if (!meta || !st) return out({ ok: false, code: 'INVALID' });
    const id = date + 't'; const path = 'data/weekly/sessions/' + id + '.json';
    const idxCur = ghGet(c, 'data/weekly/index.json', main); if (idxCur && (!idxCur.json || typeof idxCur.json !== 'object' || Array.isArray(idxCur.json))) return out({ ok: false, code: 'GITHUB', detail: 'index.json 형식 오류 — 덮어쓰지 않습니다' });
    const listed = !!(idxCur && Array.isArray(idxCur.json.tours) && idxCur.json.tours.some(function (t) { return t && t.id === id; }));
    const cur = ghGet(c, path, main); if (cur && cur.json && listed) return out({ ok: false, code: 'EXISTS', rev: cur.json.rev | 0, doc: cur.json }); // 같은 날짜 대회가 이미 있다 (목록에서 뺀 옛 파일이면 새로 만든다)
    if (cur && cur.json && cur.json.tour && !cur.json.deleted) { const rr = tourIndexWrite(c, function (idx) { return tourIndexPut(idx, tourIndexEntry(cur.json), null, now); }, '대회 ' + id + ' 목록 복구' + who); if (!rr.ok) return out({ ok: false, code: rr.code, detail: 'INDEX ' + (rr.detail || '') }); return out({ ok: false, code: 'EXISTS', rev: cur.json.rev | 0, doc: cur.json, index: rr.idx }); } // 파일은 있는데 목록에만 없다(앞선 만들기의 목록 쓰기 실패 또는 Pages 지연): 덮어쓰지 않고 목록을 고친 뒤 그 대회를 알려 준다
    const doc = tourNewDoc(id, date, meta, st, cur && cur.json ? cur.json.rev : 0, now); const content = JSON.stringify(doc, null, 1) + '\n'; const msg = '대회 ' + id + ' 만들기: ' + meta.name + who;
    const code = ghPut(c, path, content, cur ? cur.sha : null, msg, main); if (code !== 200 && code !== 201) return out({ ok: false, code: code === 409 || code === 422 ? 'BUSY' : 'GITHUB', detail: 'PUT ' + code });
    try { CacheService.getScriptCache().put('s:' + id, JSON.stringify(doc), 21600); } catch (err) {}
    for (let i = 1; i < c.branches.length; i++) { try { const cur2 = ghGet(c, path, c.branches[i]); ghPut(c, path, content, cur2 ? cur2.sha : null, msg, c.branches[i]); } catch (err) {} } // 서빙 사본(gh-pages)
    const r = tourIndexWrite(c, function (idx) { return tourIndexPut(idx, tourIndexEntry(doc), null, now); }, '대회 ' + id + ' 목록 추가' + who);
    if (!r.ok) return out({ ok: false, code: r.code, detail: 'INDEX ' + (r.detail || ''), doc: doc }); // 파일은 만들어졌지만 목록에 못 넣음 → 다시 보내면 (목록에 없으므로) 같은 파일을 새로 만들고 목록에 넣는다
    return out({ ok: true, rev: doc.rev, doc: doc, index: r.idx });
  } catch (err) { return out({ ok: false, code: 'GITHUB', detail: String(err && err.message || err) }); }
  finally { lock.releaseLock(); }
}
/** index.json 고치기: mutate(현재 목록) → 새 목록 (null 이면 바뀐 것 없음 → 쓰지 않음). 깨진 파일은 덮어쓰지 않고, 동시 저장(409/422)은 다시 읽어 3번까지. 반환 { ok, idx } | { code, detail } */
function tourIndexWrite(c, mutate, msg) {
  const path = 'data/weekly/index.json'; const main = c.branches[0];
  for (let attempt = 0; attempt < 3; attempt++) {
    const cur = ghGet(c, path, main); if (cur && (!cur.json || typeof cur.json !== 'object' || Array.isArray(cur.json))) return { code: 'GITHUB', detail: 'index.json 형식 오류 — 덮어쓰지 않습니다' };
    const idx = mutate(cur ? cur.json : null); if (!idx) return { ok: true, idx: cur ? cur.json : null };
    const content = JSON.stringify(idx, null, 1) + '\n'; const code = ghPut(c, path, content, cur ? cur.sha : null, msg, main);
    if (code === 200 || code === 201) { for (let i = 1; i < c.branches.length; i++) { try { const cur2 = ghGet(c, path, c.branches[i]); ghPut(c, path, content, cur2 ? cur2.sha : null, msg, c.branches[i]); } catch (err) {} } return { ok: true, idx: idx }; }
    if (code !== 409 && code !== 422) return { code: 'GITHUB', detail: 'PUT ' + code };
  }
  return { code: 'BUSY' };
}
/** 코트 예약 저장: { op:'courts', key, value:[{ d, t, c, n, p? }], by? } → data/courts.json 의 칸만 바꾼다 (대진표 비밀번호 필요). 응답 { ok, rev, doc } | { ok:false, code:'AUTH'|'INVALID'|'STALE'|'BUSY'|'GITHUB', doc? } */
function courtsPost(body) {
  if (!authOk(body)) return out({ ok: false, code: 'AUTH' });
  const c = cfg(); if (!c.token) return out({ ok: false, code: 'GITHUB', detail: 'GH_TOKEN 속성이 없습니다' });
  const lock = LockService.getScriptLock(); if (!lock.tryLock(20000)) return out({ ok: false, code: 'BUSY' });
  try {
    const path = 'data/courts.json'; const main = c.branches[0]; let saved = null; const n = Array.isArray(body.value) ? body.value.length : 0;
    const msg = '코트 예약 ' + n + '칸 수정' + (body.by ? ' by ' + String(body.by).slice(0, 20) : '');
    for (let attempt = 0; attempt < 3 && !saved; attempt++) {
      const cur = ghGet(c, path, main); if (cur && (!cur.json || typeof cur.json !== 'object' || Array.isArray(cur.json))) return out({ ok: false, code: 'GITHUB', detail: 'courts.json 형식 오류 — 덮어쓰지 않습니다' }); // 깨진 파일을 빈 표로 덮어쓰지 않는다
      const doc = courtsClean(cur && cur.json);
      const r = applyCourtsChanges(doc, body.value); if (!r.ok) return out({ ok: false, code: r.code, rev: doc.rev | 0, doc: doc });
      const content = JSON.stringify(doc, null, 1) + '\n'; const code = ghPut(c, path, content, cur ? cur.sha : null, msg, main);
      if (code === 200 || code === 201) saved = { doc: doc, content: content };
      else if (code !== 409 && code !== 422) return out({ ok: false, code: 'GITHUB', detail: 'PUT ' + code });
    }
    if (!saved) return out({ ok: false, code: 'BUSY' });
    for (let i = 1; i < c.branches.length; i++) { try { const cur2 = ghGet(c, path, c.branches[i]); ghPut(c, path, saved.content, cur2 ? cur2.sha : null, msg, c.branches[i]); } catch (err) {} } // 서빙 사본(gh-pages)
    return out({ ok: true, rev: saved.doc.rev, doc: saved.doc });
  } catch (err) { return out({ ok: false, code: 'GITHUB', detail: String(err && err.message || err) }); }
  finally { lock.releaseLock(); }
}
// ---- 아래 두 함수는 app.js 의 같은 이름 함수와 본문이 같다. 한쪽을 고치면 다른 쪽도 같이 고칠 것 ----
/** 코트 예약 문서 정리: { v, rev, courts:[라벨], times:['18','20'], res:{ 'YYYY-MM-DD': { '20': ['이름', '', …] } } } */
function courtsClean(raw) {
  var d = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
  var courts = (Array.isArray(d.courts) ? d.courts : []).slice(0, 8).map(function (x) { return String(x == null ? '' : x).trim().slice(0, 8); }).filter(Boolean);
  if (!courts.length) courts = ['1번', '2번', '3번'];
  var times = []; (Array.isArray(d.times) ? d.times : []).slice(0, 8).forEach(function (x) { var t = String(x == null ? '' : x).trim(); if (/^\d{1,2}(:\d{2})?$/.test(t) && times.indexOf(t) < 0) times.push(t); });
  if (!times.length) times = ['18', '20'];
  var res = {}; var src = d.res && typeof d.res === 'object' && !Array.isArray(d.res) ? d.res : {};
  Object.keys(src).filter(function (k) { return courtsDateOk(k, null); }).sort().slice(-400).forEach(function (day) { // 실제 날짜만, 최근 400일치만 (파일 크기 상한)
    var rows = src[day]; if (!rows || typeof rows !== 'object') return; var outDay = {};
    times.forEach(function (t) { var arr = rows[t]; if (!Array.isArray(arr)) return; var row = courts.map(function (_, i) { return String(arr[i] == null ? '' : arr[i]).trim().slice(0, 12); }); if (row.some(Boolean)) outDay[t] = row; });
    if (Object.keys(outDay).length) res[day] = outDay;
  });
  return { v: 1, rev: d.rev | 0, courts: courts, times: times, res: res, updatedAt: String(d.updatedAt || '').slice(0, 30) };
}
/** 실제 달력 날짜(YYYY-MM-DD)인지. now(ms)를 주면 그 앞뒤 400일 안인지도 본다 (먼 미래 날짜로 옛 예약을 밀어내지 못하게) */
function courtsDateOk(d, now) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(String(d))) return false;
  var t = Date.parse(d + 'T00:00:00Z'); if (!isFinite(t) || new Date(t).toISOString().slice(0, 10) !== d) return false;
  return now == null || Math.abs(t - now) <= 400 * 86400000;
}
/** 코트 예약 칸 변경: changes = [{ d:'YYYY-MM-DD', t:'20', c:코트 순번(0~), n:'이름'|'' , p?:'내가 본 값' }] (최대 80칸, 날짜는 오늘 앞뒤 400일). p 가 현재 값과 다르면(다른 사람이 먼저 바꿈) STALE */
function applyCourtsChanges(doc, changes, now) {
  if (!Array.isArray(changes) || !changes.length || changes.length > 80) return { code: 'INVALID' };
  var nowMs = now == null ? Date.now() : now; var next = JSON.parse(JSON.stringify(doc.res || {}));
  for (var i = 0; i < changes.length; i++) {
    var ch = changes[i];
    if (!ch || !courtsDateOk(ch.d, nowMs) || doc.times.indexOf(String(ch.t)) < 0 || !Number.isInteger(ch.c) || ch.c < 0 || ch.c >= doc.courts.length || typeof ch.n !== 'string') return { code: 'INVALID' };
    var n = ch.n.trim().slice(0, 12); var day = next[ch.d] || (next[ch.d] = {}); var row = day[String(ch.t)] || (day[String(ch.t)] = doc.courts.map(function () { return ''; }));
    var cur = row[ch.c] || '';
    if (ch.p != null && String(ch.p) !== cur && cur !== n) return { code: 'STALE' };
    row[ch.c] = n;
  }
  Object.keys(next).forEach(function (dk) { Object.keys(next[dk]).forEach(function (tk) { if (!next[dk][tk].some(Boolean)) delete next[dk][tk]; }); if (!Object.keys(next[dk]).length) delete next[dk]; });
  doc.res = next; doc.rev = (doc.rev | 0) + 1; doc.updatedAt = new Date().toISOString();
  return { ok: true };
}
// ---- /courts shared ----
/** 모임 다음날 0시(KST)부터는 수정 불가 */
function closed(doc, body) { const arch = !!body && body.op === 'tour-archive'; if (doc.status === 'closed' && !arch) return true; const t = Date.parse(String(doc.date) + 'T00:00:00+09:00'); if (!isFinite(t)) return false; const days = arch || (body && body.op === 'set' && /^(done|results)\./.test(String(body.path || ''))) ? 1 + DONE_GRACE_DAYS : 1; return t + 86400000 * days <= Date.now(); } // 참석·대진·조 조정은 다음날 0시(KST)부터, 완료 표시·점수·대회 결과 보관(과 보관 취소)은 모임 후 7일까지 (app.js wkOpAllowed 와 동일). 결과 보관으로 닫힌 대회는 보관 취소만
function commitMsg(body, doc) { const pre = (TOUR_ID_RE.test(String(doc.id)) ? '대회 ' : '정기 모임 ') + doc.id; const who = body.by ? ' by ' + String(body.by).slice(0, 20) : ''; if (body.op === 'set' && body.path === 'courtNames') return pre + ' 코트 번호' + who; if (body.op === 'tour-set') return pre + ' 대회 정보 ' + Object.keys(body.value || {}).join(',').slice(0, 60) + who; if (body.op === 'tour-archive') return pre + (body.value ? ' 결과 보관' : ' 결과 보관 취소') + who; if (body.op === 'edit') return pre + ' 조 조정 ' + (Array.isArray(body.value) ? body.value : [body.value]).map(function (e) { return e && e.id; }).join(',') + who; if (body.op === 'set') return pre + ' ' + String(body.path).slice(0, 60) + (body.value == null ? ' 삭제' : '') + who; return pre + ' 대진 ' + (body.value ? '#' + (body.value.seed | 0) : '삭제') + who; }
function sha256Hex(s) { return Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, String(s), Utilities.Charset.UTF_8).map(function (b) { return ((b + 256) % 256).toString(16).padStart(2, '0'); }).join(''); }
/** 대진표 비밀번호에서 만든 열쇠(body.key, hex 64자)의 SHA-256 이 WK_KEY_SHA 와 같은가 */
function authOk(body) { const k = String(body && body.key || ''); return /^[0-9a-f]{64}$/.test(k) && sha256Hex(k) === WK_KEY_SHA; }
function hdr(c) { return { Authorization: 'Bearer ' + c.token, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' }; }
function ghGet(c, path, branch) {
  const r = UrlFetchApp.fetch('https://api.github.com/repos/' + c.owner + '/' + c.repo + '/contents/' + path + '?ref=' + branch, { headers: hdr(c), muteHttpExceptions: true });
  if (r.getResponseCode() === 404) return null; if (r.getResponseCode() !== 200) throw new Error('GitHub GET ' + r.getResponseCode());
  const b = JSON.parse(r.getContentText()); const text = Utilities.newBlob(Utilities.base64Decode(String(b.content || '').replace(/\n/g, ''))).getDataAsString('UTF-8');
  let json = null; try { json = JSON.parse(text); } catch (err) {} return { sha: b.sha, json: json };
}
function ghPut(c, path, content, sha, message, branch) {
  const payload = { message: message, content: Utilities.base64Encode(content, Utilities.Charset.UTF_8), branch: branch }; if (sha) payload.sha = sha;
  const r = UrlFetchApp.fetch('https://api.github.com/repos/' + c.owner + '/' + c.repo + '/contents/' + path, { method: 'put', contentType: 'application/json', headers: hdr(c), payload: JSON.stringify(payload), muteHttpExceptions: true });
  return r.getResponseCode();
}
function out(o) { return ContentService.createTextOutput(JSON.stringify(o)).setMimeType(ContentService.MimeType.JSON); }

// ---- 아래 함수는 app.js 의 applyWeeklyOp 와 같은 로직. 한쪽을 고치면 다른 쪽도 같이 고칠 것 ----
/** 코트 번호 목록 정리: 문자열 배열(각 8자 이내, 최대 8개), 전부 비었으면 null — app.js wkCleanCourtNames 와 동일 */
function cleanCourtNames(v) { if (!Array.isArray(v)) return null; const out = v.slice(0, 8).map((x) => String(x == null ? '' : x).trim().slice(0, 8)); while (out.length && !out[out.length - 1]) out.pop(); return out.length ? out : null; }
/** 시간대별 코트 번호 정리: { '19': ['5'], '20': ['5','7','9'] } — app.js wkCleanCourtNamesByHour 와 동일 */
function cleanCourtNamesByHour(v) { if (!v || typeof v !== 'object' || Array.isArray(v)) return null; const out = {}; for (const h of Object.keys(v).slice(0, 24)) { if (!/^\d{1,2}$/.test(h) || +h > 23) continue; const names = cleanCourtNames(v[h]); if (names) out[String(+h)] = names; } return Object.keys(out).length ? out : null; }
// ---- 대회: 정기 모임과 같은 세션 파일에 대회 정보(doc.tour)를 더한 것. 아래 함수들은 app.js 의 같은 이름 함수와 본문이 같다. 한쪽을 고치면 다른 쪽도 같이 고칠 것 ----
const TOUR_ID_RE = /^\d{4}-\d{2}-\d{2}t$/; // 대회 id = 날짜 + 't' (같은 날 정기 모임 파일과 겹치지 않게)
const TOUR_VENUE_LIM = { name: 60, time: 40, addr: 120, phone: 30, menu: 60, note: 200 }; // 회식 장소 칸별 길이
const tourNames = cleanCourtNames, tourNamesByHour = cleanCourtNamesByHour;
/** 회식 장소 정리 */
function tourVenue(v) { const o = {}; for (const k of Object.keys(TOUR_VENUE_LIM)) o[k] = v && typeof v[k] === 'string' ? v[k].trim().slice(0, TOUR_VENUE_LIM[k]) : ''; return o; }
/** 대회 시간·코트 설정 정리 { startTime, endTime, matchMinutes 10~180, breakMinutes 0, courts 1~8, minWomenDoubles(여복 경기 수) 0~20, courtsByHour?, courtNames? | courtNamesByHour? } — 형식이 틀리면 null */
function tourSettings(st) {
  if (!st || typeof st !== 'object' || Array.isArray(st)) return null;
  const mins = (t) => { const m = /^(\d{2}):(\d{2})$/.exec(String(t || '')); return m && +m[1] <= 23 && +m[2] <= 59 ? +m[1] * 60 + +m[2] : NaN; };
  if (!(mins(st.startTime) < mins(st.endTime))) return null;
  const okInt = (v, lo, hi) => Number.isInteger(v) && v >= lo && v <= hi;
  if (!okInt(st.matchMinutes, 10, 180) || !okInt(st.courts, 1, 8) || !okInt(st.minWomenDoubles, 0, 20)) return null;
  const out = { startTime: st.startTime, endTime: st.endTime, matchMinutes: st.matchMinutes, breakMinutes: 0, courts: st.courts, minWomenDoubles: st.minWomenDoubles };
  if (st.courtsByHour != null) {
    if (typeof st.courtsByHour !== 'object' || Array.isArray(st.courtsByHour)) return null;
    const cb = {}; for (const h of Object.keys(st.courtsByHour).slice(0, 24)) { const v = st.courtsByHour[h]; if (!/^\d{1,2}$/.test(h) || +h > 23 || !okInt(v, 0, 8)) return null; cb[String(+h)] = v; }
    if (Object.keys(cb).length) out.courtsByHour = cb;
  }
  const slots = Math.floor((mins(st.endTime) - mins(st.startTime)) / st.matchMinutes); const most = Math.max(st.courts, ...Object.values(out.courtsByHour || {})); if (slots * most > 64) return null; // 대진은 64경기까지 저장된다 (시간대 수 × 가장 많은 코트 수)
  const cn = tourNames(st.courtNames), cnh = cn ? null : tourNamesByHour(st.courtNamesByHour); if (cn) out.courtNames = cn; else if (cnh) out.courtNamesByHour = cnh;
  return out;
}
/** 대회 정보 정리 { name 1~40자, mode 'rotation'(개인전)|'team'(팀전), teamCount 2~4, teamNames, venue, teams: null | [[참가자 id…] × teamCount] (한 사람은 한 팀에만) } — 틀리면 null */
function tourMeta(t) {
  if (!t || typeof t !== 'object') return null;
  const name = typeof t.name === 'string' ? t.name.trim().slice(0, 40) : ''; if (!name) return null;
  const mode = t.mode === 'team' ? 'team' : t.mode === 'rotation' ? 'rotation' : ''; if (!mode) return null;
  const n = t.teamCount == null ? 2 : t.teamCount; if (!Number.isInteger(n) || n < 2 || n > 4) return null;
  const teamNames = []; for (let i = 0; i < n; i++) { const x = Array.isArray(t.teamNames) && typeof t.teamNames[i] === 'string' ? t.teamNames[i].trim().slice(0, 12) : ''; teamNames.push(x || (i + 1) + '팀'); }
  let teams = null;
  if (t.teams != null) {
    if (!Array.isArray(t.teams) || t.teams.length !== n) return null; const seen = {}; teams = [];
    for (const list of t.teams) { if (!Array.isArray(list) || list.length > 40) return null; const ids = []; for (const id of list) { if (typeof id !== 'string' || !ID_RE.test(id) || seen[id]) return null; seen[id] = 1; ids.push(id); } teams.push(ids); }
  }
  return { name: name, mode: mode, teamCount: n, teamNames: teamNames, venue: tourVenue(t.venue), teams: teams };
}
/** 새 대회 문서. prevRev = 같은 파일이 있었으면 그 rev (멤버 화면의 rev 가 뒤로 가지 않게 이어 간다) */
function tourNewDoc(id, date, meta, st, prevRev, now) { return { v: 1, id: id, date: date, status: 'open', rev: (prevRev | 0) + 1, tour: meta, settings: st, attendance: {}, schedule: null, done: {}, results: {}, createdAt: now }; }
/** 대회 목록(index.json 의 tours) 항목 (archived = 결과 보관으로 닫힘) */
function tourIndexEntry(doc) { const s = doc.settings || {}; return { id: doc.id, date: doc.date, name: doc.tour.name, mode: doc.tour.mode, teamCount: doc.tour.teamCount, startTime: s.startTime, endTime: s.endTime, courts: s.courts | 0, archived: doc.status === 'closed' }; }
/** 대회 목록 갱신: entry 를 넣거나 바꾸고(removeId 면 그 항목을 뺀다) 다른 칸(sessions·past·levels·proxy)은 그대로 둔다. onlyListed 면 이미 목록에 있는 항목만 바꾼다(수정·보관이 목록에서 뺀 대회를 되살리지 않게). 바뀐 게 없으면 null */
function tourIndexPut(idx, entry, removeId, now, onlyListed) {
  const cur = idx && typeof idx === 'object' && !Array.isArray(idx) ? idx : { v: 1, sessions: [] };
  const list = (Array.isArray(cur.tours) ? cur.tours : []).filter((x) => x && typeof x === 'object' && TOUR_ID_RE.test(String(x.id || '')));
  const id = entry ? entry.id : removeId; const old = list.find((x) => x.id === id);
  if (entry ? (!old && onlyListed) || (!!old && JSON.stringify(old) === JSON.stringify(entry)) : !old) return null;
  const next = list.filter((x) => x.id !== id); if (entry) next.push(entry);
  next.sort((a, b) => (a.date < b.date ? 1 : a.date > b.date ? -1 : 0));
  cur.v = cur.v || 1; cur.tours = next.slice(0, 60); cur.updatedAt = now; return cur;
}
// ---- /tour shared ----
function applyWeeklyOp(doc, op) {
  const okId = (v) => typeof v === 'string' && ID_RE.test(v);
  if (op.op === 'set' && op.path === 'courtNames') { // 실제 코트 번호 (누구나): 배열 = 모든 시간대 공통, { '19': […], '20': […] } = 시간대별, null = 지움
    const v = op.value; doc.settings = doc.settings || {};
    if (v == null) { delete doc.settings.courtNames; delete doc.settings.courtNamesByHour; }
    else if (Array.isArray(v)) { const names = cleanCourtNames(v); if (names) doc.settings.courtNames = names; else delete doc.settings.courtNames; delete doc.settings.courtNamesByHour; }
    else if (typeof v === 'object') { const by = cleanCourtNamesByHour(v); if (by) doc.settings.courtNamesByHour = by; else delete doc.settings.courtNamesByHour; delete doc.settings.courtNames; }
    else return { code: 'INVALID' };
  } else if (op.op === 'set') {
    const m = /^(attendance|done|results)\.([A-Za-z0-9_:.-]{1,40})$/.exec(String(op.path || '')); if (!m) return { code: 'INVALID' };
    const coll = m[1], key = m[2]; doc[coll] = doc[coll] || {};
    if (op.value == null) delete doc[coll][key];
    else if (coll === 'attendance') {
      const v = op.value; if (!v || typeof v.n !== 'string' || !v.n.trim() || !['M', 'F'].includes(v.g) || !TIME_RE.test(v.from) || !TIME_RE.test(v.until) || v.from >= v.until) return { code: 'INVALID' };
      if (!doc.attendance[key] && Object.keys(doc.attendance).length >= 80) return { code: 'FULL' }; // 파일 무한 팽창 방지
      doc.attendance[key] = { n: v.n.trim().slice(0, 20), g: v.g, from: v.from, until: v.until, ...(v.guest ? { guest: true } : {}), ...(v.y ? { y: true } : {}), ...(Number.isFinite(v.lv) && v.lv >= 1 && v.lv <= 7 && Math.round(v.lv * 2) === v.lv * 2 ? { lv: v.lv } : {}) }; // y = 양보 (경기 수를 1 적게), lv = 게스트 NTRP (1~7, 0.5 단위)
    } else if (coll === 'done') { if (op.value !== true || !doc.schedule || !(doc.schedule.matches || []).some((x) => x.id === key)) return { code: 'INVALID' }; doc.done[key] = true; }
    else { const v = op.value; if (!v || !Number.isInteger(v.a) || !Number.isInteger(v.b) || v.a < 0 || v.a > SCORE_MAX || v.b < 0 || v.b > SCORE_MAX || !doc.schedule || !(doc.schedule.matches || []).some((x) => x.id === key)) return { code: 'INVALID' }; doc.results[key] = { a: v.a, b: v.b }; doc.done = doc.done || {}; doc.done[key] = true; } // 점수(게임 수 0~6)를 넣으면 완료로도 표시
  } else if (op.op === 'generate') {
    if ((op.base | 0) !== (doc.rev | 0)) return { code: 'STALE' };
    const v = op.value;
    if (v == null) { doc.schedule = null; doc.done = {}; doc.results = {}; }
    else {
      if (!v || !Array.isArray(v.matches) || v.matches.length > 64) return { code: 'INVALID' };
      for (const x of v.matches) if (!x || !MID_RE.test(String(x.id)) || !Number.isInteger(x.slot) || !Number.isInteger(x.court) || ![x.aIds, x.bIds].every((a) => Array.isArray(a) && a.length === 2 && a.every(okId))) return { code: 'INVALID' };
      doc.schedule = { seed: v.seed | 0, gen: v.gen | 0, fromSlot: v.fromSlot | 0, inputHash: String(v.inputHash || '').slice(0, 16), at: String(v.at || '').slice(0, 30), by: String(v.by || '').slice(0, 20), matches: v.matches.map((x) => ({ id: x.id, slot: x.slot, court: x.court, aIds: x.aIds, bIds: x.bIds })) };
      const fs = v.fromSlot | 0; const keep = new Set(fs > 0 ? v.matches.filter((x) => (x.slot | 0) < fs).map((x) => x.id) : []); // 전체 재편성(다시 섞기)은 완료 표시를 모두 비우고, 남은 시간대만 다시 짠 경우는 그대로 둔 시간대의 완료만 남긴다
      doc.done = doc.done || {}; for (const k of Object.keys(doc.done)) if (!keep.has(k)) delete doc.done[k];
      doc.results = doc.results || {}; for (const k of Object.keys(doc.results)) if (!keep.has(k)) delete doc.results[k]; // 점수도 같은 규칙
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
    doc.schedule.matches = next; doc.results = doc.results || {}; for (const e of list) delete doc.results[e.id]; // 조가 바뀐 경기의 점수는 지운다 (완료 표시는 그대로)
  } else if (op.op === 'tour-set') { // 대회 정보 수정 (대진표 비밀번호): 이름·방식·팀 수·팀 이름·회식·팀 구성·시간·코트. 시간·코트·방식·팀 수가 바뀌면 대진·완료·점수를 비운다 (팀 구성·이름·회식만 바꾸면 그대로)
    if (!TOUR_ID_RE.test(String(doc.id || '')) || !doc.tour || typeof doc.tour !== 'object') return { code: 'INVALID' };
    if ((op.base | 0) !== (doc.rev | 0)) return { code: 'STALE' };
    const v = op.value; if (!v || typeof v !== 'object' || Array.isArray(v)) return { code: 'INVALID' };
    const cur = doc.tour; const has = (k) => Object.prototype.hasOwnProperty.call(v, k); const pick = (k) => (has(k) ? v[k] : cur[k]);
    const sameShape = pick('mode') === cur.mode && (cur.mode === 'rotation' || pick('teamCount') === cur.teamCount); // 방식·팀 수가 그대로면 팀 구성을 유지 (개인전은 팀 수를 보지 않는다)
    const meta = tourMeta({ name: pick('name'), mode: pick('mode'), teamCount: pick('teamCount'), teamNames: pick('teamNames'), venue: pick('venue'), teams: has('teams') ? v.teams : sameShape ? cur.teams : null }); if (!meta) return { code: 'INVALID' };
    let st = doc.settings || {}; if (has('settings')) { st = tourSettings(v.settings); if (!st) return { code: 'INVALID' }; }
    const shape = (s) => [s.startTime, s.endTime, s.matchMinutes, s.courts, JSON.stringify(s.courtsByHour || null)].join('|');
    const reset = !sameShape || shape(st) !== shape(doc.settings || {});
    doc.tour = meta; doc.settings = st; if (reset) { doc.schedule = null; doc.done = {}; doc.results = {}; }
  } else if (op.op === 'tour-archive') { // 결과 보관 (대진표 비밀번호): true = 대회를 닫아 점수·참가·대진을 더 고칠 수 없게, false = 보관 취소. 둘 다 대회 후 7일 안 (closed 규칙)
    if (!TOUR_ID_RE.test(String(doc.id || '')) || !doc.tour || typeof doc.tour !== 'object' || typeof op.value !== 'boolean' || doc.deleted) return { code: 'INVALID' }; // 목록에서 뺀 대회(deleted)는 보관·취소 불가
    if ((op.base | 0) !== (doc.rev | 0)) return { code: 'STALE' };
    if (op.value && !(doc.schedule && Array.isArray(doc.schedule.matches) && doc.schedule.matches.length)) return { code: 'INVALID' }; // 대진이 있어야 보관
    doc.status = op.value ? 'closed' : 'open'; if (op.value) doc.archivedAt = new Date().toISOString(); else delete doc.archivedAt;
  } else return { code: 'INVALID' };
  doc.rev = (doc.rev | 0) + 1; doc.updatedAt = new Date().toISOString();
  return { ok: true };
}
