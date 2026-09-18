/* 테니스윗 정기 모임 저장 프록시 — Google Apps Script 웹앱
 * 멤버 폰에는 토큰이 없다. 이 스크립트가 GitHub 저장소(koozinsong/tennisweet)의 data/weekly/sessions/<날짜>.json 만 대신 커밋한다.
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
 *   edit: value = [{ id, aIds:[2], bIds:[2] }, …], prev? = { id: [aIds, bIds] } (최대 4경기, 같은 시간대 중복 금지, base=rev 필수, prev 와 현재 팀이 다르면 STALE, 완료 표시 유지)
 * 응답: { ok:true, rev, doc } | { ok:false, code:'INVALID'|'NOSESSION'|'CLOSED'|'STALE'|'FULL'|'BUSY'|'GITHUB', rev?, doc? }
 */
const CLUB = 'tennisweet';
const WK_PW_HASH = '3b4facb575a1dc30b189b7c01b746e68e952b3a94a4b9776a6f261aba87e2bac'; // 대진표 비밀번호 검증값 = PBKDF2-SHA256(비밀번호, 'tennisweet-wk-verify', 120000회) — app.js 의 WK_PW_HASH 와 동일. 클라이언트가 검증값을 보내고 서버는 비교만 한다 (평문은 어디에도 없음)
const DONE_GRACE_DAYS = 7; // 완료 표시 유예 (모임 후 7일)
const SCORE_MAX = 6; // 점수(게임 수) 상한 — app.js WK_SCORE_MAX 와 동일
const PROXY_VERSION = 3; // 앱의 '연결 확인'이 비교하는 서버 코드 버전 (app.js PROXY_VERSION_NEED): 2 = 대진표 비밀번호 검사 + 완료 표시 7일 유예, 3 = 경기 기록(results.<mid> = {a,b} 0~6, 완료 자동)
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
  if (!body || typeof body !== 'object' || body.club !== CLUB || !SESSION_RE.test(String(body.session || ''))) return out({ ok: false, code: 'INVALID' });
  if (String(e.postData.contents).length > 65536) return out({ ok: false, code: 'INVALID' });
  if (body.op === 'ping') return out({ ok: true, v: PROXY_VERSION, t: new Date().toISOString() });
  if ((body.op === 'generate' || body.op === 'edit') && String(body.auth || '') !== WK_PW_HASH) return out({ ok: false, code: 'AUTH' }); // 대진 생성·다시 섞기·조 조정은 대진표 비밀번호(검증값)가 있어야 한다. 참석·완료 표시는 누구나
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
    return out({ ok: true, rev: saved.doc.rev, doc: saved.doc });
  } catch (err) { return out({ ok: false, code: 'GITHUB', detail: String(err && err.message || err) }); }
  finally { lock.releaseLock(); }
}
/** 모임 다음날 0시(KST)부터는 수정 불가 */
function closed(doc, body) { if (doc.status === 'closed') return true; const t = Date.parse(String(doc.date) + 'T00:00:00+09:00'); if (!isFinite(t)) return false; const days = body && body.op === 'set' && /^(done|results)\./.test(String(body.path || '')) ? 1 + DONE_GRACE_DAYS : 1; return t + 86400000 * days <= Date.now(); } // 참석·대진·조 조정은 다음날 0시(KST)부터, 완료 표시는 모임 후 7일까지 (app.js wkOpAllowed 와 동일)
function commitMsg(body, doc) { const who = body.by ? ' by ' + String(body.by).slice(0, 20) : ''; if (body.op === 'edit') return '정기 모임 ' + doc.id + ' 조 조정 ' + (Array.isArray(body.value) ? body.value : [body.value]).map(function (e) { return e && e.id; }).join(',') + who; if (body.op === 'set') return '정기 모임 ' + doc.id + ' ' + String(body.path).slice(0, 60) + (body.value == null ? ' 삭제' : '') + who; return '정기 모임 ' + doc.id + ' 대진 ' + (body.value ? '#' + (body.value.seed | 0) : '삭제') + who; }
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
function applyWeeklyOp(doc, op) {
  const okId = (v) => typeof v === 'string' && ID_RE.test(v);
  if (op.op === 'set') {
    const m = /^(attendance|done|results)\.([A-Za-z0-9_:.-]{1,40})$/.exec(String(op.path || '')); if (!m) return { code: 'INVALID' };
    const coll = m[1], key = m[2]; doc[coll] = doc[coll] || {};
    if (op.value == null) delete doc[coll][key];
    else if (coll === 'attendance') {
      const v = op.value; if (!v || typeof v.n !== 'string' || !v.n.trim() || !['M', 'F'].includes(v.g) || !TIME_RE.test(v.from) || !TIME_RE.test(v.until) || v.from >= v.until) return { code: 'INVALID' };
      if (!doc.attendance[key] && Object.keys(doc.attendance).length >= 80) return { code: 'FULL' }; // 파일 무한 팽창 방지
      doc.attendance[key] = { n: v.n.trim().slice(0, 20), g: v.g, from: v.from, until: v.until, ...(v.guest ? { guest: true } : {}) };
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
  } else return { code: 'INVALID' };
  doc.rev = (doc.rev | 0) + 1; doc.updatedAt = new Date().toISOString();
  return { ok: true };
}
