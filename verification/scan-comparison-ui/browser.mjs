const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || 'playwright')
import fs from 'node:fs/promises'
import assert from 'node:assert/strict'
const fixture=JSON.parse(await fs.readFile('backend/tests/fixtures/scan_compare/examples/05-identifier-conflict.json','utf8'))
const partial=JSON.parse(await fs.readFile('backend/tests/fixtures/scan_compare/examples/04-target-partial.json','utf8'))
const {base,target}=fixture
const other='33333333-3333-3333-3333-333333333333'
const browser=await chromium.launch({headless:true,executablePath:process.env.CHROMIUM_PATH || undefined,args:['--no-sandbox']})
const page=await browser.newPage({viewport:{width:1440,height:1000}})
const errors=[];page.on('pageerror',e=>errors.push(e.message))
let submitted='';let delayFirst=false
await page.route('**/api/**',async route=>{
 const u=new URL(route.request().url()); const p=u.pathname
 let body={items:[],total:0,tool_status:{},snapshot_id:'s',result_state:'failed'}
 if(route.request().method()==='POST') {submitted=route.request().postData();body={scan_id:other,project_id:target.project_id,status:'queued'}}
 else if(p.endsWith('/compare')) {
   if(u.searchParams.get('base')===other) body={...partial,base:{...partial.base,scan_id:other},target}
   else {if(delayFirst) await new Promise(r=>setTimeout(r,500));body=fixture}
 }
 else if(p.includes('/projects/')) body={project:fixture.project,total:3,items:[target,base,{...base,scan_id:other,created_at:'2026-10-29T03:00:00Z'}]}
 else if(/\/scans\/[^/]+$/.test(p)) body={...target,scan_id:p.split('/').pop(),tool_status:{}}
 await route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(body)}).catch(()=>{})
})
await page.goto(`http://127.0.0.1:5173/#/scan/${target.scan_id}/compare`)
await page.getByRole('radio').first().check()
await page.getByText('식별자 검토 묶음',{exact:true}).waitFor()
assert.ok(await page.getByText('비교 불가 1',{exact:true}).isVisible())
assert.ok(await page.getByText('이번 검사에서 미검출 0',{exact:true}).isVisible())
// Rapid selection must keep the newest response, even when old requests finish late.
await page.getByRole('radio').nth(1).check()
await page.getByText('계속 발견 1',{exact:true}).waitFor()
delayFirst=true
await page.getByRole('radio').first().check()
await page.getByRole('radio').nth(1).check()
await page.waitForTimeout(700)
assert.ok(await page.getByText('계속 발견 1',{exact:true}).isVisible())
assert.equal(await page.getByText('식별자 검토 묶음',{exact:true}).count(),0)
await page.screenshot({path:'/tmp/oss-comparison-desktop.png',fullPage:true})
await page.setViewportSize({width:390,height:844})
assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth),false)
await page.setViewportSize({width:1440,height:1000})
await page.getByRole('button',{name:'이 프로젝트 재검사',exact:true}).click()
await page.getByRole('heading',{name:'같은 프로젝트 재검사'}).waitFor()
await page.locator('#oc-file-pkg').setInputFiles({name:'package.json',mimeType:'application/json',buffer:Buffer.from('{"name":"demo"}')})
await page.locator('#oc-file-lock').setInputFiles({name:'package-lock.json',mimeType:'application/json',buffer:Buffer.from('{"name":"demo","lockfileVersion":3}')})
await page.getByRole('button',{name:'검사 시작',exact:true}).click()
await page.waitForURL(`**/scan/${other}`)
assert.ok(submitted.includes('name="project_id"'))
assert.ok(submitted.includes(target.project_id))
assert.deepEqual(errors,[])
console.log('PASS browser: contract conflict, partial results, stale response, mobile overflow, project rescan upload')
await browser.close()
