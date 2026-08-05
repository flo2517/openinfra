const $=id=>document.getElementById(id);let active;
function text(id,value){$(id).textContent=value}
function status(value){const span=document.createElement('span');span.className=`status ${value}`;span.textContent=value;return span}
function row(values){const tr=document.createElement('tr');for(const value of values){const td=document.createElement('td');td.textContent=value;tr.append(td)}return tr}
async function refresh(){
  if(active)active.abort();active=new AbortController();text('sample','Actualisation…');
  try{
    const response=await fetch('/api/v1/overview',{signal:active.signal});if(!response.ok)throw new Error(`HTTP ${response.status}`);const data=await response.json();
    text('fresh',data.providers_fresh);text('total',`${data.providers_total} enregistrés`);text('cpu',Number(data.cpu_available).toFixed(1));text('memory',`${Math.round(data.memory_available_mb/1024)} GiB`);text('block',`#${data.finalized_block}`);text('chain',data.chain_syncing?'synchronisation en cours':`best #${data.best_block}`);text('workload-count',data.workloads.length);text('sample',new Date(data.generated_at).toLocaleTimeString());
    const providers=$('providers');providers.replaceChildren();for(const p of data.providers){const tr=row([p.provider_id,p.status,'',p.agent_version,p.cpu_available.toFixed(1),`${Math.round(p.memory_available_mb/1024)} GiB`,p.chain_state]);tr.children[2].append(status(p.liveness));providers.append(tr)}
    const workloads=$('workloads');workloads.replaceChildren();for(const w of data.workloads)workloads.append(row([w.workload_id,w.state,w.provider_id||'—',w.lease_id||'—',new Date(w.created_at).toLocaleString()]));
    const warning=$('warning');warning.hidden=!data.partial;warning.textContent=data.partial?'Certaines sources sont momentanément indisponibles. Les données affichées restent partielles.':'';
  }catch(error){if(error.name!=='AbortError'){text('sample','Indisponible');const warning=$('warning');warning.hidden=false;warning.textContent='Le dashboard ne peut pas charger les données.'}}
}
$('refresh').addEventListener('click',refresh);refresh();setInterval(refresh,10000);
