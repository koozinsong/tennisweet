/* 테니스윗 정기 모임 저장 프록시 — Google Apps Script 웹앱
 * 멤버 폰에는 토큰이 없고, 이 스크립트가 GitHub 데이터 저장소(tennisweet-data)에 세션 파일을 대신 커밋한다.
 *
 * 배포 방법 (README 참고):
 *  1) script.google.com → 새 프로젝트 → 이 파일 내용을 Code.gs 에 붙여넣기
 *  2) 프로젝트 설정 → 스크립트 속성: GH_TOKEN = tennisweet-data 저장소만 Contents: Read and write 권한을 준 fine-grained 토큰
 *     (선택) OWNER / REPO / BRANCH 기본값 koozinsong / tennisweet-data / main
 *  3) 배포 → 새 배포 → 유형 '웹 앱', 실행: '나', 액세스: '모든 사용자' → 웹 앱 URL(…/exec) 을 관리자 화면 '저장 서버 주소'에 입력
 *  4) 코드를 고치면 배포 → 배포 관리 → 새 버전 (URL 유지)
 *
 * 요청: POST 본문 = JSON 문자열 (Content-Type 없이 보내면 CORS preflight 없음)
 *   { v:1, club:'tennisweet', session:'2026-09-20', op:'set'|'generate'|'ping', path?, value?, base?, by? }
 * 응답: { ok:true, rev, doc } | { ok:false, code:'INVALID'|'NOSESSION'|'CLOSED'|'STALE'|'BUSY'|'GITHUB', rev?, doc? }
 */
const CLUB = 'tennisweet';
const ID_RE = /^[A-Za-z0-9_:.-]{1,40}$/, TIME_RE = /^\d{2}:\d{2}$/, SESSION_RE = /^\d{4}-\d{2}-\d{2}[a-z]?$/, MID_RE = /^s\d{1,2}c\d{1,2}$/;
function cfg() { const p = PropertiesService.getScriptProperties(); return { token: p.getProperty('GH_TOKEN'), owner: p.getProperty('OWNER') || 'koozinsong', repo: p.getProperty('REPO') || 'tennisweet-data', branch: p.getProperty('BRANCH') || 'main' }; }

function doGet(e) { return out({ ok: true, v: 1, t: new Date().toISOString() }); }
function doPost(e) {
  let body; try { body = JSON.parse(e.postData.contents); } catch (err) { return out({ ok: false, code: 'INVALID' }); }
  if (!body || typeof body !== 'object' || body.club !== CLUB || !SESSION_RE.test(String(body.session || ''))) return out({ ok: false, code: 'INVALID' });
  if (String(e.postData.contents).length > 65536) return out({ ok: false, code: 'INVALID' });
  if (body.op === 'ping') return out({ ok: true, v: 1, t: new Date().toISOString() });
  const c = cfg(); if (!c.token) return out({ ok: false, code: 'GITHUB', detail: 'GH_TOKEN 속성이 없습니다' });
  const lock = LockService.getScriptLock(); if (!lock.tryLock(20000)) return out({ ok: false, code: 'BUSY' });
  try {
    const path = 'weekly/sessions/' + body.session + '.json';
    for (let attempt = 0; attempt < 3; attempt++) {
      const cur = ghGet(c, path); if (!cur) return out({ ok: false, code: 'NOSESSION' });
      const doc = cur.json; if (!doc || typeof doc !== 'object') return out({ ok: false, code: 'GITHUB', detail: '세션 파일 형식 오류' });
      if (closed(doc)) return out({ ok: false, code: 'CLOSED', rev: doc.rev | 0, doc: doc });
      const r = applyWeeklyOp(doc, body); if (!r.ok) return out({ ok: false, code: r.code, rev: doc.rev | 0, doc: doc });
      const code = ghPut(c, path, JSON.stringify(doc, null, 1) + '\n', cur.sha, commitMsg(body, doc));
      if (code === 200 || code === 201) return out({ ok: true, rev: doc.rev, doc: doc });
      if (code !== 409 && code !== 422) return out({ ok: false, code: 'GITHUB', detail: 'PUT ' + code });
    }
    return out({ ok: false, code: 'BUSY' });
  } catch (err) { return out({ ok: false, code: 'GITHUB', detail: String(err && err.message || err) }); }
  finally { lock.releaseLock(); }
}
/** 모임 다음날 0시(KST)부터는 수정 불가 */
function closed(doc) { if (doc.status === 'closed') return true; const t = Date.parse(String(doc.date) + 'T00:00:00+09:00'); return isFinite(t) && t + 86400000 <= Date.now(); }
function commitMsg(body, doc) { const who = body.by ? ' by ' + String(body.by).slice(0, 20) : ''; if (body.op === 'set') return 'weekly ' + doc.id + ' ' + String(body.path).slice(0, 60) + (body.value == null ? ' 삭제' : '') + who; return 'weekly ' + doc.id + ' 대진 ' + (body.value ? '#' + (body.value.seed | 0) : '삭제') + who; }
function hdr(c) { return { Authorization: 'Bearer ' + c.token, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' }; }
function ghGet(c, path) {
  const r = UrlFetchApp.fetch('https://api.github.com/repos/' + c.owner + '/' + c.repo + '/contents/' + path + '?ref=' + c.branch, { headers: hdr(c), muteHttpExceptions: true });
  if (r.getResponseCode() === 404) return null; if (r.getResponseCode() !== 200) throw new Error('GitHub GET ' + r.getResponseCode());
  const b = JSON.parse(r.getContentText()); const text = Utilities.newBlob(Utilities.base64Decode(String(b.content || '').replace(/\n/g, ''))).getDataAsString('UTF-8');
  let json = null; try { json = JSON.parse(text); } catch (err) {} return { sha: b.sha, json: json };
}
function ghPut(c, path, content, sha, message) {
  const r = UrlFetchApp.fetch('https://api.github.com/repos/' + c.owner + '/' + c.repo + '/contents/' + path, { method: 'put', contentType: 'application/json', headers: hdr(c), payload: JSON.stringify({ message: message, content: Utilities.base64Encode(content, Utilities.Charset.UTF_8), sha: sha, branch: c.branch }), muteHttpExceptions: true });
  return r.getResponseCode();
}
function out(o) { return ContentService.createTextOutput(JSON.stringify(o)).setMimeType(ContentService.MimeType.JSON); }

// ---- 아래 함수는 app.js 의 applyWeeklyOp 와 같은 로직. 한쪽을 고치면 다른 쪽도 같이 고칠 것 ----
function applyWeeklyOp(doc, op) {
  const okId = (v) => typeof v === 'string' && ID_RE.test(v);
  if (op.op === 'set') {
    const m = /^(attendance|done)\.([A-Za-z0-9_:.-]{1,40})$/.exec(String(op.path || '')); if (!m) return { code: 'INVALID' };
    const coll = m[1], key = m[2]; doc[coll] = doc[coll] || {};
    if (op.value == null) delete doc[coll][key];
    else if (coll === 'attendance') {
      const v = op.value; if (!v || typeof v.n !== 'string' || !v.n.trim() || !['M', 'F'].includes(v.g) || !TIME_RE.test(v.from) || !TIME_RE.test(v.until) || v.from >= v.until) return { code: 'INVALID' };
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
      const ids = new Set(v.matches.map((x) => x.id)); doc.done = doc.done || {}; for (const k of Object.keys(doc.done)) if (!ids.has(k)) delete doc.done[k];
    }
  } else return { code: 'INVALID' };
  doc.rev = (doc.rev | 0) + 1; doc.updatedAt = new Date().toISOString();
  return { ok: true };
}
