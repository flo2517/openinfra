const $=id=>document.getElementById(id);let active;
function text(id,value){$(id).textContent=value}
function status(value){const span=document.createElement('span');span.className=`status ${value}`;span.textContent=value;return span}
function row(values){const tr=document.createElement('tr');for(const value of values){const td=document.createElement('td');td.textContent=value;tr.append(td)}return tr}
// storage/bandwidth totals of 0 mean "not advertised" (see internal/dashboard's
// doc comments), not "genuinely zero capacity" -- shown as "—", never as "0",
// so an unconfigured provider never looks like a broken/empty one.
function storageCell(p){return p.storage_total_gb>0?`${p.storage_available_gb}/${p.storage_total_gb} Go`:'—'}
function bandwidthCell(p){return(p.bandwidth_ingress_mbps||p.bandwidth_egress_mbps)?`${p.bandwidth_ingress_mbps||0}/${p.bandwidth_egress_mbps||0} Mbps`:'—'}
// reputation===undefined: chain read never happened this pass (unavailable).
// reputation.available===false: chain read succeeded, no record yet -- a
// normal state for a freshly joined provider, not the same as unavailable.
function reputationCell(p){if(!p.reputation)return'—';return p.reputation.available?String(p.reputation.global):'pas encore noté'}
function offerCell(p){if(!p.offer)return'—';return p.offer.found?`${(p.offer.cpu_millicores/1000).toFixed(1)} vCPU / ${p.offer.ram_mb} Mo`:'aucune offre'}
async function refresh(){
  if(active)active.abort();active=new AbortController();text('sample','Actualisation…');
  try{
    const response=await fetch('/api/v1/overview',{signal:active.signal});if(!response.ok)throw new Error(`HTTP ${response.status}`);const data=await response.json();
    text('fresh',data.providers_fresh);text('total',`${data.providers_total} enregistrés`);text('cpu',Number(data.cpu_available).toFixed(1));text('memory',`${Math.round(data.memory_available_mb/1024)} GiB`);text('block',`#${data.finalized_block}`);text('chain',data.chain_syncing?'synchronisation en cours':`best #${data.best_block}`);text('workload-count',data.workloads.length);
    // validators_active is -1 when the read failed: show that as unknown,
    // never as zero, so an outage never reads as "no validators".
    text('validator-count',data.validators_active<0?'—':data.validators_active);
    text('sample',new Date(data.generated_at).toLocaleTimeString());
    const providers=$('providers');providers.replaceChildren();for(const p of data.providers){const tr=row([p.provider_id,p.status,'',p.agent_version,p.cpu_available.toFixed(1),`${Math.round(p.memory_available_mb/1024)} GiB`,storageCell(p),bandwidthCell(p),reputationCell(p),offerCell(p),p.chain_state]);tr.children[2].append(status(p.liveness));providers.append(tr)}
    const workloads=$('workloads');workloads.replaceChildren();for(const w of data.workloads)workloads.append(row([w.workload_id,w.state,w.provider_id||'—',w.lease_id||'—',new Date(w.created_at).toLocaleString()]));
    const validators=$('validators');validators.replaceChildren();for(const v of data.validators||[])validators.append(row([v]));
    $('validators-warning').hidden=data.validators_active>=0;
    const warning=$('warning');warning.hidden=!data.partial;warning.textContent=data.partial?'Certaines sources sont momentanément indisponibles. Les données affichées restent partielles.':'';
  }catch(error){if(error.name!=='AbortError'){text('sample','Indisponible');const warning=$('warning');warning.hidden=false;warning.textContent='Le dashboard ne peut pas charger les données.'}}
}
$('refresh').addEventListener('click',refresh);refresh();setInterval(refresh,10000);

// #76 validator score history: fetched on demand for a single provider_id
// rather than folded into refresh()'s periodic /api/v1/overview poll --
// scanning pallet-network-validator's Rounds NMap is real per-round chain
// I/O server-side (see internal/dashboard/validatorscores.go), so this
// stays an explicit, infrequent action, not a background one.
function scoreStatusLabel(status){
  // Mirrors blockchainbridge.RoundStatus.String() -- keep in sync with
  // internal/blockchainbridge/roundresult.go if a variant is ever added.
  const labels={final:'clos',disputed:'contesté',dispute_upheld:'contestation retenue',dispute_rejected:'contestation rejetée'};
  return labels[status]||status;
}
async function loadValidatorScores(){
  const providerId=$('score-provider-id').value.trim();
  const warning=$('score-warning');const rows=$('score-rows');
  warning.hidden=true;warning.textContent='';
  if(!providerId){warning.hidden=false;warning.textContent='Indiquez un provider_id.';return}
  rows.replaceChildren();
  try{
    const response=await fetch(`/api/v1/validator-scores/${encodeURIComponent(providerId)}`);
    if(response.status===404){warning.hidden=false;warning.textContent='Provider introuvable.';return}
    if(!response.ok)throw new Error(`HTTP ${response.status}`);
    const data=await response.json();
    if(data.partial){warning.hidden=false;warning.textContent='Lecture partielle — certains rounds n\'ont pas pu être lus on-chain.'}
    let any=false;
    for(const dimension of data.dimensions||[]){
      for(const round of dimension.rounds||[]){
        any=true;
        rows.append(row([dimension.dimension,round.round,(round.score_bps/100).toFixed(2)+' %',(round.previous_score_bps/100).toFixed(2)+' %',(round.confidence_bps/100).toFixed(0)+' %',`${round.submissions}/${round.committee_target}`,scoreStatusLabel(round.status),round.closed_at_block]));
      }
    }
    if(!any&&!data.partial){warning.hidden=false;warning.textContent='Aucun round clos pour ce provider dans la fenêtre récente.'}
  }catch(error){warning.hidden=false;warning.textContent='Impossible de charger l\'historique de scoring.'}
}
$('score-load').addEventListener('click',loadValidatorScores);
$('score-provider-id').addEventListener('keydown',e=>{if(e.key==='Enter')loadValidatorScores()});
