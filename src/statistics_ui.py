"""Self-contained local dashboard; no CDN or third-party assets."""
from .web_localization import localize_page
PAGE = r'''<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title data-i18n="Carriex · Relay statistics">Carriex · Relay statistics</title>
<style>
:root{color-scheme:dark;font:15px system-ui;background:#101924;color:#e1ebf5}
body{max-width:1180px;margin:40px auto;padding:0 24px}h1{font-size:32px;margin-bottom:8px}h2{font-size:20px;margin:32px 0 14px}
p{color:#a9bbce;line-height:1.6}a{color:#8dcaff}header{display:flex;justify-content:space-between;gap:24px;align-items:center;flex-wrap:wrap}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}.card{background:#192737;border:1px solid #2b3d50;border-radius:12px;padding:20px}
.number{font-size:29px;font-weight:650;margin-top:10px}.label{font-size:13px;color:#b5c7d8}table{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums}
th,td{text-align:right;padding:11px 12px;border-bottom:1px solid #2b3d50}th:first-child,td:first-child{text-align:left}th{color:#a9bbce;font-size:12px;text-transform:uppercase}
.scroll{overflow:auto}svg{width:100%;height:190px;background:#192737;border-radius:12px}button{background:#284d6c;border:0;border-radius:6px;color:white;padding:9px 13px;cursor:pointer}
.status{font-size:13px;color:#83dfbe}.error{color:#ffb5a7}small{color:#9db1c6}.exports{display:flex;gap:16px;align-items:center}code{color:#c5e1f5}
</style>
<header><div><small data-i18n="CARRIEX / PRACTICAL OBSERVATION">CARRIEX / PRACTICAL OBSERVATION</small><h1 data-i18n="Relay statistics">Relay statistics</h1><div id="status" class="status" data-i18n="Loading measurements…">Loading measurements…</div></div>
<div class="exports"><button id="refresh" data-i18n="Refresh">Refresh</button><a href="/export.json" download="carriex-statistics.json">JSON</a><a href="/export.csv" download="carriex-statistics.csv">CSV</a></div></header>
<p data-i18n="Hourly measurements saved by this relay. Message contents, identities and private keys are not collected here.">Hourly measurements saved by this relay. Message contents, identities and private keys are not collected here.</p>
<div class="cards" id="cards"></div>
<h2 data-i18n="Accepted messages per hour · UTC">Accepted messages per hour · UTC</h2><svg id="chart" viewBox="0 0 1000 190" role="img" aria-label="Accepted messages per hour" data-i18n-aria="Accepted messages per hour"></svg>
<h2 data-i18n="Measurements">Measurements</h2><div class="scroll"><table><thead><tr><th data-i18n="Metric">Metric</th><th data-i18n="Samples">Samples</th><th data-i18n="Total">Total</th><th data-i18n="Mean">Mean</th><th data-i18n="Min">Min</th><th data-i18n="Max">Max</th></tr></thead><tbody id="metrics"></tbody></table></div>
<p><strong data-i18n="Acknowledgement delay">Acknowledgement delay</strong><span data-i18n=" runs from relay acceptance to recipient acknowledgement. It includes offline time, polling and client processing; it does not measure reading or isolated network latency. HTTP timing covers server handling only. Client encryption/decryption time is unavailable to the relay."> runs from relay acceptance to recipient acknowledgement. It includes offline time, polling and client processing; it does not measure reading or isolated network latency. HTTP timing covers server handling only. Client encryption/decryption time is unavailable to the relay.</span></p>
<p><small id="window"></small> · <span data-i18n="This page refreshes every five seconds. Instrumentation adds SQLite work; compare performance using the same collection mode.">This page refreshes every five seconds. Instrumentation adds SQLite work; compare performance using the same collection mode.</span></p>
<script>
const i18n=window.carriexI18n,t=i18n.t;
const $=s=>document.getElementById(s), number=n=>new Intl.NumberFormat(i18n.language,{maximumFractionDigits:2}).format(n);
function cell(row,value){const td=document.createElement('td');td.textContent=value;row.append(td)}
function card(label,value){const c=document.createElement('div');c.className='card';const l=document.createElement('div');l.className='label';l.textContent=label;const n=document.createElement('div');n.className='number';n.textContent=value;c.append(l,n);$('cards').append(c)}
async function refresh(){try{const response=await fetch('/api/statistics',{cache:'no-store'});if(!response.ok)throw Error(t('Server returned ')+response.status);const d=await response.json();
const total=m=>d.metrics[m]?.total||0;$('cards').replaceChildren();card(t('Accepted messages'),number(total('messages.accepted')));card(t('Recipient acknowledgements'),number(total('messages.acknowledged')));card(t('Queued now'),number(d.queue.messages));card(t('Queue bytes now'),number(d.queue.bytes));card(t('Claimed one-time keys'),number(total('prekeys.claimed')));card(t('Available keys now'),number(d.queue.available_prekeys));
$('metrics').replaceChildren();Object.entries(d.metrics).sort().forEach(([key,v])=>{const row=document.createElement('tr');[key,v.samples,v.total,v.mean,v.minimum,v.maximum].forEach((x,i)=>cell(row,i?number(x):x));$('metrics').append(row)});
const counts=new Map(d.hourly.filter(x=>x.metric==='messages.accepted').map(x=>[x.hour,x.total])),end=Math.floor(Date.now()/3600000)*3600;
const hours=Math.min(48,d.days*24),samples=Array.from({length:hours},(_,i)=>{const hour=end-(hours-1-i)*3600;return{total:counts.get(hour)||0,utc:new Date(hour*1000).toISOString()}}),svg=$('chart');svg.replaceChildren();
if(!counts.size){const empty=document.createElementNS('http://www.w3.org/2000/svg','text');empty.setAttribute('x','24');empty.setAttribute('y','95');empty.setAttribute('fill','#a9bbce');empty.textContent=t('No accepted messages recorded in this window');svg.append(empty)}
const max=Math.max(1,...samples.map(x=>x.total)),step=960/Math.max(1,samples.length);samples.forEach((x,i)=>{const b=document.createElementNS('http://www.w3.org/2000/svg','rect');b.setAttribute('x',20+i*step);b.setAttribute('y',160-x.total/max*130);b.setAttribute('width',Math.max(1,step-3));b.setAttribute('height',x.total/max*130);b.setAttribute('fill','#83dfbe');const title=document.createElementNS('http://www.w3.org/2000/svg','title');title.textContent=x.utc+': '+x.total;b.append(title);svg.append(b)});
$('status').className='status';$('status').textContent=(d.collection_enabled?t('Collection configured: enabled'):t('Collection configured: disabled (saved history remains)'))+t(' · Updated ')+new Date(d.generated_at).toLocaleTimeString(i18n.language);$('window').textContent=t('Window: {days} days; configured retention: {retention} days').replace('{days}',number(d.days)).replace('{retention}',number(d.retention_days));
}catch(e){$('status').className='error';$('status').textContent=t('Unable to load statistics: ')+e.message}}
window.addEventListener('carriex-language-change',refresh);$('refresh').onclick=refresh;refresh();setInterval(refresh,5000);
</script></html>'''


PAGE = localize_page(PAGE)
