import { useState } from 'react'
import { createScan } from './api'
import { AI_AUTO_EXPLAIN } from './display'
import Icon from './Icons'

// 서버(uploads.py)와 같은 한도. 최종 검증은 서버가 한다.
const SLOTS = {
  pkg: { file: 'package.json', order: '1번 파일', limit: 1024 * 1024, limitText: '최대 1 MiB' },
  lock: { file: 'package-lock.json', order: '2번 파일', limit: 10 * 1024 * 1024, limitText: 'lockfile v2·v3 · 최대 10 MiB' },
}

const formatSize = (bytes) => (bytes >= 1024 * 1024 ? `${(bytes / 1024 / 1024).toFixed(1)} MB` : `${Math.max(1, Math.round(bytes / 102.4) / 10)} KB`)

// 고른 파일을 이 브라우저 안에서만 읽어 이름·버전을 보여준다. 서버 검증을 대신하지 않는다.
async function inspect(kind, file) {
  const spec = SLOTS[kind]
  if (!file.name.toLowerCase().endsWith('.json')) return { file, error: `${spec.file} 파일(.json)을 골라 주세요.` }
  if (file.size > spec.limit) return { file, error: `${spec.file}: ${spec.limitText.split(' · ').pop()}입니다.` }
  try {
    const json = JSON.parse(await file.text())
    if (kind === 'lock') {
      const version = json && json.lockfileVersion
      if (version !== 2 && version !== 3) return { file, error: '현재 package-lock.json v2/v3만 지원합니다.' }
      return { file, info: [['lockfile', `v${version}`], ['프로젝트', [json.name, json.version].filter(Boolean).join(' ') || '—']] }
    }
    return { file, info: [['프로젝트', [json.name, json.version].filter(Boolean).join(' ') || '—']] }
  } catch {
    return { file, error: `${spec.file}: 유효한 JSON이 아닙니다.` }
  }
}

function Slot({ kind, state, onPick }) {
  const spec = SLOTS[kind]
  const [drag, setDrag] = useState(false)
  const inputId = `oc-file-${kind}`
  const input = (
    <input id={inputId} className="oc-sr" type="file" accept=".json,application/json"
      onChange={(e) => { const f = e.target.files[0]; if (f) onPick(f); e.target.value = '' }} />
  )
  if (!state) {
    return (
      <div className={`oc-slot empty${drag ? ' drag' : ''}`}
        onDragOver={(e) => { e.preventDefault(); setDrag(true) }}
        onDragLeave={() => setDrag(false)}
        onDrop={(e) => { e.preventDefault(); setDrag(false); const f = e.dataTransfer.files[0]; if (f) onPick(f) }}>
        <span className="ico"><Icon name="upload" /></span>
        <span className="fname">{spec.file}</span>
        <span className="sub" style={{ fontSize: 13 }}>여기로 끌어다 놓거나</span>
        {input}
        <label htmlFor={inputId} className="oc-btn sea" style={{ cursor: 'pointer' }}>파일 선택</label>
        <span className="muted" style={{ fontSize: 12 }}>{spec.order} · {spec.limitText}</span>
      </div>
    )
  }
  return (
    <div className={`oc-slot ${state.error ? 'bad' : 'selected'}`}>
      <div className="shead">
        <div className="l">
          <span className="ico"><Icon name="doc" /></span>
          <div><div className="fname">{spec.file}</div><div className="muted" style={{ fontSize: 12 }}>{spec.order} · {spec.limitText}</div></div>
        </div>
        <span className="oc-pill"><span className={`oc-dot ${state.error ? 'sev-CRITICAL' : ''}`} style={state.error ? null : { background: 'var(--oc-sea)' }} />{state.error ? '다시 골라 주세요' : '선택됨'}</span>
      </div>
      <dl className="meta">
        <div><dt>파일명</dt><dd className="mono">{state.file.name}</dd></div>
        <div><dt>크기</dt><dd>{formatSize(state.file.size)}</dd></div>
        {(state.info || []).map(([k, v]) => <div key={k}><dt>{k}</dt><dd>{v}</dd></div>)}
      </dl>
      {state.error && <p className="err" style={{ fontSize: 13 }}>{state.error}</p>}
      {input}
      <label htmlFor={inputId} className="oc-link swap" style={{ cursor: 'pointer' }}>다른 파일로 바꾸기</label>
    </div>
  )
}

export default function Upload({ onCreated, projectId }) {
  const [files, setFiles] = useState({ pkg: null, lock: null })
  const [error, setError] = useState(null)
  const [sending, setSending] = useState(false)
  const [manual, setManual] = useState('')

  async function pick(kind, file) {
    setError(null)
    const state = await inspect(kind, file)
    setFiles((f) => ({ ...f, [kind]: state }))
  }

  const ready = files.pkg && files.lock && !files.pkg.error && !files.lock.error
  const missing = !files.pkg ? 'package.json' : !files.lock ? 'package-lock.json' : null

  async function submit() {
    if (!ready || sending) return
    setError(null); setSending(true)
    try {
      const result = await createScan(files.pkg.file, files.lock.file, projectId)
      onCreated(result.scan_id)
    } catch (err) {
      setError(err.message)
    } finally {
      setSending(false)
    }
  }

  return (
    <>
      <div className="oc-head">
        <div>
          <h1>{projectId ? '같은 프로젝트 재검사' : '새 검사'}</h1>
          <p>package.json과 package-lock.json을 올리면 취약점·라이선스·유지보수 상태를 검사합니다.</p>
        </div>
      </div>

      {projectId && <p className="oc-hint">기존 프로젝트의 새 검사로 저장합니다. 수정한 파일 두 개를 올려 주세요.</p>}
      <section className="oc-panel oc-upload">
        <div className="oc-slots">
          <Slot kind="pkg" state={files.pkg} onPick={(f) => pick('pkg', f)} />
          <Slot kind="lock" state={files.lock} onPick={(f) => pick('lock', f)} />
        </div>
        {error && <div role="alert" className="oc-alert">{error}</div>}
        <div className="oc-go">
          <span className="l"><Icon name="alert" size={20} />
            {missing ? `${missing}을 추가하면 검사를 시작할 수 있어요.`
              : ready ? '두 파일이 준비됐어요. 파일 내용은 서버에서 한 번 더 확인해요.' : '문제가 있는 파일을 다시 골라 주세요.'}
          </span>
          <button type="button" className="oc-btn primary big" disabled={!ready || sending} onClick={submit}>
            {sending ? '올리는 중…' : '검사 시작'}
          </button>
        </div>
      </section>

      <div className="oc-info">
        <section className="oc-panel">
          <div className="h"><span className="ico"><Icon name="box" /></span>올릴 수 있는 파일</div>
          <ul>
            <li>package.json, package-lock.json 두 개만 받아요</li>
            <li>압축 파일(zip)은 받지 않아요</li>
            <li>workspaces·로컬 경로 의존성은 미지원</li>
          </ul>
        </section>
        <section className="oc-panel">
          <div className="h"><span className="ico"><Icon name="check" /></span>검사하는 것</div>
          <ul>
            <li>알려진 취약점, 라이선스 조건, 유지보수 상태</li>
            <li>세 가지를 하나의 점수로 합치지 않아요</li>
            <li>실패한 검사는 '확인 불가'로 표시해요</li>
          </ul>
        </section>
        <section className="oc-panel">
          <div className="h"><span className="ico"><Icon name="gear" /></span>파일 처리</div>
          <ul>
            <li>소스 코드는 올리지 않아요</li>
            <li>올린 원본은 검사가 끝나면 서버에서 삭제돼요</li>
            <li>취약점 DB·GitHub 조회에 이름·버전 사용</li>
            {AI_AUTO_EXPLAIN && <li>CRITICAL·HIGH는 AI 설명용으로 ID도 전송</li>}
          </ul>
        </section>
      </div>

      <section className="oc-panel tint oc-tip">
        <b>package-lock.json이 없나요?</b>
        <span>프로젝트 폴더에서 <code>npm install</code>을 한 번 실행하면 만들어져요.</span>
      </section>

      <form className="oc-open" onSubmit={(e) => { e.preventDefault(); if (manual.trim()) onCreated(manual.trim()) }}>
        <span>이전 검사 열기</span>
        <input value={manual} onChange={(e) => setManual(e.target.value)} placeholder="검사 ID" aria-label="검사 ID" />
        <button type="submit" className="oc-btn">열기</button>
      </form>
    </>
  )
}
