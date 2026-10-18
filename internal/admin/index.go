package admin

// indexHTML is the single-page panel (no external assets — the panel must
// work offline inside a container). Vanilla JS, dark-mode aware.
const indexHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>出口管理</title>
<style>
:root{--bg:#0f1115;--card:#171a21;--fg:#e6e9ef;--dim:#8b93a7;--line:#262b36;--ok:#3fb26f;--bad:#e0564f;--accent:#5b8cff}
@media(prefers-color-scheme:light){:root{--bg:#f5f6f8;--card:#fff;--fg:#1a1d24;--dim:#6a7183;--line:#e3e6ec}}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--fg);font:14px/1.6 system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;padding:24px 16px;max-width:880px;margin:0 auto}
h1{font-size:18px;margin-bottom:4px}
.sub{color:var(--dim);font-size:12px;margin-bottom:20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:16px}
.card h2{font-size:14px;margin-bottom:12px;display:flex;align-items:center;gap:8px}
.dot{width:8px;height:8px;border-radius:50%;background:var(--dim);display:inline-block}
.dot.ok{background:var(--ok)}.dot.bad{background:var(--bad)}
label{display:block;font-size:12px;color:var(--dim);margin:10px 0 4px}
select,input[type=text],input[type=password]{width:100%;padding:8px 10px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg);font-size:13px}
.row{display:flex;gap:10px;flex-wrap:wrap}
.row>div{flex:1;min-width:180px}
button{padding:8px 14px;border:0;border-radius:6px;background:var(--accent);color:#fff;font-size:13px;cursor:pointer;margin-top:12px}
button.ghost{background:transparent;border:1px solid var(--line);color:var(--fg)}
button.warn{background:var(--bad)}
button:disabled{opacity:.5;cursor:not-allowed}
table{width:100%;border-collapse:collapse;font-size:12px;margin-top:8px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);white-space:nowrap}
th{color:var(--dim);font-weight:500}
.tag{padding:1px 8px;border-radius:10px;font-size:11px;background:var(--line)}
.tag.resi{color:var(--ok)}
#toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:var(--card);border:1px solid var(--line);padding:10px 18px;border-radius:8px;font-size:13px;display:none;box-shadow:0 4px 16px rgba(0,0,0,.25)}
.muted{color:var(--dim);font-size:12px}
.kv{display:grid;grid-template-columns:auto 1fr;gap:4px 12px;font-size:12px;margin-top:8px}
.kv b{color:var(--dim);font-weight:500}
details{margin-top:10px}
summary{cursor:pointer;color:var(--dim);font-size:12px}
</style>
</head>
<body>
<h1>出口管理</h1>
<div class="sub">WARP · VPNGate 家宽出口 · 节点内核</div>

<div class="card">
  <h2><span class="dot" id="dot-current"></span>当前状态</h2>
  <div class="kv" id="status-kv"></div>
</div>

<div class="card">
  <h2>出口模式</h2>
  <div class="row">
    <div>
      <label>WARP (Cloudflare)</label>
      <select id="warp_mode">
        <option value="off">关闭</option>
        <option value="all">全部流量</option>
        <option value="v6">仅 IPv6</option>
      </select>
    </div>
    <div>
      <label>VPNGate 家宽出口</label>
      <select id="vpngate">
        <option value="off">关闭</option>
        <option value="all">接管 IPv4 出口</option>
      </select>
    </div>
  </div>
  <div class="muted" style="margin-top:8px">合法组合：off / warp v6 / vpngate all / warp v6 + vpngate all。warp=all 会吞掉家宽出口，禁止同时启用。</div>
  <button id="save-mode">保存并重载内核</button>
</div>

<div class="card" id="vg-card">
  <h2>VPNGate 设置</h2>
  <label>订阅地址</label>
  <input type="text" id="sub_url" placeholder="https://…">
  <div class="row">
    <div>
      <label>最大纯净度 (0=不限，越低越干净)</label>
      <input type="text" id="max_fraud" placeholder="30">
    </div>
    <div>
      <label>国家过滤（逗号分隔，留空=全部）</label>
      <input type="text" id="countries" placeholder="Japan, Korea Republic of">
    </div>
  </div>
  <div class="row">
    <div>
      <label>入口 UUID（留空=公共默认）</label>
      <input type="text" id="manual_uuid" placeholder="495c7195-…">
    </div>
    <div>
      <label>固定节点 (host:port，留空=自动)</label>
      <input type="text" id="pinned" placeholder="vpn595476537.opengw.net:1405">
    </div>
  </div>
  <label style="display:flex;align-items:center;gap:8px;margin-top:12px">
    <input type="checkbox" id="residential_only" style="width:auto"> 只用家宽节点（机房节点剔除）
  </label>
  <div class="row">
    <button id="save-vg">保存设置</button>
    <button id="refresh" class="ghost">立即刷新订阅</button>
    <button id="switch" class="ghost">换一个节点</button>
  </div>
  <details>
    <summary>候选节点（按速度排序）</summary>
    <div style="overflow-x:auto"><table id="links-tbl">
      <thead><tr><th>节点</th><th>国家</th><th>类型</th><th>纯净度</th><th>速度 Mbps</th><th>落地 IP</th><th></th></tr></thead>
      <tbody></tbody>
    </table></div>
  </details>
</div>

<div class="card">
  <h2>WARP 账号</h2>
  <div class="kv" id="warp-kv"></div>
  <button id="warp-reset" class="warn">删除并重新注册设备</button>
</div>

<div class="card">
  <h2>面板安全</h2>
  <div class="row">
    <div>
      <label>访问路径（改后旧地址立即失效，页面自动跳转）</label>
      <input type="text" id="new-basepath" placeholder="留空=随机生成新路径">
    </div>
    <div>
      <label>新密码（≥8 位）</label>
      <input type="password" id="new-password" placeholder="留空不改">
    </div>
  </div>
  <div class="row">
    <button id="save-password">修改密码</button>
    <button id="save-basepath">修改访问路径</button>
    <button id="regen-basepath" class="ghost">随机新路径</button>
  </div>
  <div class="muted" style="margin-top:8px">当前路径：<code id="cur-path"></code>（改完记住新地址，只有这一处显示）</div>
</div>

<div id="toast"></div>
<script>
const $=id=>document.getElementById(id);
function toast(msg,ok){const t=$('toast');t.textContent=msg;t.style.display='block';
  t.style.borderColor=ok?'var(--ok)':'var(--bad)';clearTimeout(t._h);t._h=setTimeout(()=>t.style.display='none',3500)}
async function api(path,body){
  const opt=body?{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}:{method:'POST'};
  const r=await fetch(path,opt);const j=await r.json().catch(()=>({}));
  if(!r.ok)throw new Error(j.error||('HTTP '+r.status));return j}
async function loadState(){
  try{
    const j=await fetch('api/state').then(r=>r.json());
    $('warp_mode').value=j.state.warp_mode||'off';
    $('vpngate').value=j.state.vpngate||'off';
    $('sub_url').value=j.state.vpngate_source?.url||'';
    $('max_fraud').value=j.state.vpngate_source?.max_fraud_score||0;
    $('countries').value=(j.state.vpngate_source?.countries||[]).join(', ');
    $('manual_uuid').value=j.state.manual_uuid||'';
    $('pinned').value=j.state.pinned_node||'';
    $('residential_only').checked=!!j.state.vpngate_source?.residential_only;
    const kv=$('status-kv');
    const cur=j.current&&j.current.node?j.current.node:'—';
    kv.innerHTML='<b>家宽出口</b><span>'+cur+(j.has_current?'':'（未选择）')+'</span>';
    $('dot-current').className='dot'+(j.has_current?' ok':'');
    $('cur-path').textContent=location.pathname.replace(/\/$/,'');
    const wk=$('warp-kv');
    wk.innerHTML='<b>设备 ID</b><span>'+(j.warp_device||'未启用')+'</span>'+
      '<b>运行时间</b><span>'+fmtDur(j.uptime_s)+'</span>';
  }catch(e){toast('加载失败: '+e.message,false)}
}
async function loadLinks(){
  try{
    const j=await fetch('api/links').then(r=>r.json());
    const tb=$('links-tbl').querySelector('tbody');tb.innerHTML='';
    (j.links||[]).slice(0,60).forEach(l=>{
      const tr=document.createElement('tr');
      tr.innerHTML='<td>'+l.node+'</td><td>'+(l.country||'')+'</td>'+
        '<td><span class="tag'+(l.residential?' resi':'')+'">'+(l.known_type?(l.residential?'家宽':'机房'):'?')+'</span></td>'+
        '<td>'+(l.fraud<0?'-':l.fraud)+'</td><td>'+(l.speed_mbps||'-')+'</td><td>'+(l.exit_ip||'')+'</td>'+
        '<td><button class="ghost" data-pin="'+l.node+'" style="padding:2px 8px;margin:0">固定</button></td>';
      tb.appendChild(tr)});
    tb.querySelectorAll('[data-pin]').forEach(b=>b.onclick=async()=>{
      try{await api('api/vpngate/pin',{node:b.dataset.pin});toast('已固定 '+b.dataset.pin,true);loadState()}catch(e){toast(e.message,false)}});
  }catch(e){}
}
function fmtDur(s){if(!s)return'—';const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);
  return (d?d+'天':'')+(h?h+'时':'')+m+'分'}
$('save-mode').onclick=async()=>{
  try{const j=await api('api/state',{warp_mode:$('warp_mode').value,vpngate:$('vpngate').value});
    toast(j.note||'已保存',true)}catch(e){toast(e.message,false)}};
$('save-vg').onclick=async()=>{
  try{const body={
      sub_url:$('sub_url').value,residential_only:$('residential_only').checked,
      max_fraud_score:parseInt($('max_fraud').value)||0,
      countries:$('countries').value,manual_uuid:$('manual_uuid').value};
    const j=await api('api/state',body);
    const pin=$('pinned').value.trim();
    if(pin!==($('pinned').dataset.orig||'')){await api('api/vpngate/pin',{node:pin})}
    toast(j.note||'已保存',true);loadState()}catch(e){toast(e.message,false)}};
$('refresh').onclick=async()=>{try{const j=await api('api/vpngate/refresh');toast('刷新成功，'+j.links+' 个节点',true);loadLinks()}catch(e){toast(e.message,false)}};
$('switch').onclick=async()=>{try{await api('api/vpngate/switch');toast('已切换节点',true);setTimeout(loadState,1500)}catch(e){toast(e.message,false)}};
$('warp-reset').onclick=async()=>{if(!confirm('重新注册 WARP 设备？数据中心 IP 注册常被限流，可能失败。'))return;
  try{await api('api/warp/reset');toast('已重置，稍后查看设备 ID',true);setTimeout(loadState,3000)}catch(e){toast(e.message,false)}};
$('save-password').onclick=async()=>{const p=$('new-password').value;if(p&&p.length<8){toast('密码至少 8 位',false);return}
  if(!p){toast('未输入新密码',false);return}
  try{await api('api/password',{password:p});toast('密码已更新（后续请求用新密码）',true);$('new-password').value=''}catch(e){toast(e.message,false)}};
async function changeBasePath(v){
  try{const j=await api('api/basepath',{base_path:v});
    toast('路径已改为 '+j.base_path+'，正在跳转…',true);
    const u=new URL(location.href);u.pathname=j.base_path+'/';setTimeout(()=>location.replace(u.href),800);
  }catch(e){toast(e.message,false)}}
$('save-basepath').onclick=()=>changeBasePath($('new-basepath').value.trim());
$('regen-basepath').onclick=()=>changeBasePath('');
loadState();loadLinks();setInterval(loadState,15000);
</script>
</body>
</html>`
