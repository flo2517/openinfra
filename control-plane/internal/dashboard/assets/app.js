// Wrapped in an IIFE for the reason spelled out at the top of auth.js:
// classic scripts share one global lexical environment, so a top-level
// `const` here and in auth.js is a redeclaration SyntaxError that stops
// this file from executing at all -- which is exactly what silently took
// this dashboard offline once. Function scope removes the hazard.
(() => {
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
// #76 pagination: providersOffset is the only piece of paging state kept
// client-side (validators stay unpaginated in the UI for now -- that
// table is far smaller in practice, and workloads are now a fixed-size
// per-state aggregate); refresh() always re-reads it
// so prev/next just mutate this and re-fetch, no separate code path.
let providersOffset=0,providersLimit=500;
async function refresh(){
  if(active)active.abort();active=new AbortController();text('sample','Actualisation…');
  try{
    const response=await fetch(`/api/v1/overview?providers_offset=${providersOffset}`,{signal:active.signal});if(!response.ok)throw new Error(`HTTP ${response.status}`);const data=await response.json();
    providersLimit=data.providers_limit||providersLimit;
    text('fresh',data.providers_fresh);text('total',`${data.providers_total} enregistrés`);text('cpu',Number(data.cpu_available).toFixed(1));text('memory',`${Math.round(data.memory_available_mb/1024)} GiB`);text('block',`#${data.finalized_block}`);text('chain',data.chain_syncing?'synchronisation en cours':`best #${data.best_block}`);text('workload-count',data.workloads_total);
    // validators_active is -1 when the read failed: show that as unknown,
    // never as zero, so an outage never reads as "no validators".
    text('validator-count',data.validators_active<0?'—':data.validators_active);
    text('sample',new Date(data.generated_at).toLocaleTimeString());
    const providers=$('providers');providers.replaceChildren();for(const p of data.providers){const tr=row([p.provider_id,p.status,'',p.agent_version,p.cpu_available.toFixed(1),`${Math.round(p.memory_available_mb/1024)} GiB`,storageCell(p),bandwidthCell(p),reputationCell(p),offerCell(p),p.chain_state]);tr.children[2].append(status(p.liveness));providers.append(tr)}
    // ADR-016 §3: this public endpoint no longer returns per-workload
    // rows, only counts by state. Per-workload detail lives behind
    // /api/v1/my/workloads, scoped to the authenticated owner.
    const workloads=$('workloads');workloads.replaceChildren();const byState=data.workloads_by_state||{};for(const state of Object.keys(byState).sort())workloads.append(row([state,byState[state]]));
    await loadValidatorHealth(data.validators||[],data.validators_active,active.signal);
    const warning=$('warning');warning.hidden=!data.partial;warning.textContent=data.partial?'Certaines sources sont momentanément indisponibles. Les données affichées restent partielles.':'';
    const shown=data.providers.length;
    const rangeStart=shown===0?0:data.providers_offset+1;
    const rangeEnd=data.providers_offset+shown;
    text('providers-range',`${rangeStart}–${rangeEnd} sur ${data.providers_total}`);
    $('providers-prev').disabled=data.providers_offset<=0;
    $('providers-next').disabled=data.providers_offset+shown>=data.providers_total;
  }catch(error){if(error.name!=='AbortError'){text('sample','Indisponible');const warning=$('warning');warning.hidden=false;warning.textContent='Le dashboard ne peut pas charger les données.'}}
}
// #76 validator health: /api/v1/overview already carries the active set's
// accounts, but abbreviated and with no lifecycle state at all.
// /api/v1/validator/health adds status/stake/registration per validator.
// It is fetched inside its own try so a failure here degrades this one
// table back to the overview's abbreviated list instead of breaking the
// whole refresh -- the same "partial beats blank" rule the rest of this
// dashboard follows.
function validatorStatusLabel(validator){
  if(validator.unavailable)return'lecture indisponible';
  // found===false with a successful read means the account is in
  // ActiveValidatorSet but has no Validators record -- an on-chain
  // inconsistency, shown as such rather than as a healthy validator.
  if(!validator.found)return'aucun enregistrement on-chain';
  const labels={ACTIVE:'actif',SUSPENDED:'suspendu',EXITING:'sortie en cours'};
  const label=labels[validator.status]||validator.status;
  return validator.status==='EXITING'&&validator.available_at_block?`${label} (retrait au bloc #${validator.available_at_block})`:label;
}
async function loadValidatorHealth(fallbackAccounts,activeCount,signal){
  const validators=$('validators');const warning=$('validators-warning');
  validators.replaceChildren();
  const unavailable='Ensemble des validateurs indisponible — ne pas confondre avec zéro validateur actif.';
  try{
    const response=await fetch('/api/v1/validator/health',{signal});
    if(!response.ok)throw new Error(`HTTP ${response.status}`);
    const data=await response.json();
    text('validator-quorum',data.min_quorum);text('validator-committee',data.target_committee_size);
    for(const validator of data.validators||[])validators.append(row([validator.validator,validatorStatusLabel(validator),validator.found?validator.stake:'—',validator.found?`#${validator.registered_at_block}`:'—']));
    if(activeCount<0){warning.hidden=false;warning.textContent=unavailable}
    else if(data.partial){warning.hidden=false;warning.textContent='État de certains validateurs illisible on-chain — les lignes concernées le disent explicitement.'}
    else if(data.truncated){warning.hidden=false;warning.textContent=`Ensemble actif tronqué : ${data.validators.length} validateurs affichés sur ${data.active_count}.`}
    else{warning.hidden=true}
  }catch(error){
    // An aborted read is a newer refresh superseding this one, not a
    // failure: it must not paint a stale fallback list over the table
    // the newer pass is about to fill.
    if(error.name==='AbortError')return;
    for(const account of fallbackAccounts)validators.append(row([account,'—','—','—']));
    warning.hidden=false;
    warning.textContent=activeCount<0?unavailable:'État détaillé des validateurs indisponible — seuls les comptes actifs sont affichés.';
  }
}
$('refresh').addEventListener('click',refresh);refresh();setInterval(refresh,10000);
$('providers-prev').addEventListener('click',()=>{providersOffset=Math.max(0,providersOffset-providersLimit);refresh()});
$('providers-next').addEventListener('click',()=>{providersOffset+=providersLimit;refresh()});

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
// #76 challenge queue: the open-round counterpart to the closed-round
// history above. Same provider_id, same explicit "Charger" action -- one
// input for both, since "what has this provider been scored on, and what
// is still in flight" is one question, and duplicating the control would
// let the two tables drift to different providers.
function shortAccount(account){return account.length>14?account.slice(0,10)+'…':account}
async function loadOpenRounds(){
  const providerId=$('score-provider-id').value.trim();
  const warning=$('rounds-warning');const rows=$('rounds-rows');
  warning.hidden=true;warning.textContent='';rows.replaceChildren();
  // An empty or unknown provider_id is already reported by the score
  // panel above; repeating it here would be two alerts for one mistake.
  if(!providerId)return;
  try{
    const response=await fetch(`/api/v1/validator/rounds/${encodeURIComponent(providerId)}`);
    if(response.status===404)return;
    if(!response.ok)throw new Error(`HTTP ${response.status}`);
    const data=await response.json();
    if(data.partial){warning.hidden=false;warning.textContent='Lecture partielle — certains rounds ouverts n\'ont pas pu être lus on-chain.'}
    let any=false;
    for(const dimension of data.dimensions||[]){
      for(const round of dimension.rounds||[]){
        any=true;
        const submissions=round.submissions||[];
        const detail=submissions.map(s=>`${shortAccount(s.validator)} · ${(s.score_bps/100).toFixed(2)} % · ${s.sample_count} éch.`).join(' | ')||'aucune soumission';
        const awaiting=(round.awaiting_response||[]).map(shortAccount).join(', ')||'—';
        const committee=round.committee_stale?`${(round.committee||[]).length} (indicatif)`:String((round.committee||[]).length);
        rows.append(row([dimension.dimension,round.round,`${submissions.length}/${round.quorum_required}`,round.quorum_reached?'atteint':'pas encore',awaiting,committee,detail]));
      }
    }
    // An empty list has two very different causes: nothing is pending, or
    // the challenge protocol is inert because no validator is active at
    // all. Saying "no open round" in the second case would read as "all
    // clear" when in fact nothing can be assigned or closed.
    if(!any&&!data.partial){
      warning.hidden=false;
      warning.textContent=data.active_validators===0
        ?'Aucun Network Validator actif on-chain : aucun round ne peut être assigné ni clos pour ce provider.'
        :'Aucun round en attente pour ce provider dans la fenêtre récente.';
    }
  }catch(error){warning.hidden=false;warning.textContent='Impossible de charger les rounds ouverts.'}
}
// #107: earnings (pallet-rewards) and availability proofs
// (pallet-availability) had no data path at all until
// /api/v1/provider/{id}/onchain -- the last two provider bullets of #14.
// Driven by the same provider_id control as the two tables above, for the
// reason given there: a second input would let the panels drift onto
// different providers while looking like one view.
async function loadProviderOnChain(){
  const providerId=$('score-provider-id').value.trim();
  const warning=$('onchain-warning');
  warning.hidden=true;warning.textContent='';
  const unknown='—';
  // Reset to "unknown" rather than leaving the previous provider's
  // figures on screen while the next request is in flight.
  for(const id of ['onchain-points','onchain-availability','onchain-samples','onchain-sequence','onchain-observed','onchain-hash'])$(id).textContent=unknown;
  if(!providerId)return;
  try{
    const response=await fetch(`/api/v1/provider/${encodeURIComponent(providerId)}/onchain`);
    if(response.status===404)return;
    if(!response.ok)throw new Error(`HTTP ${response.status}`);
    const data=await response.json();
    // available===false is a failed chain read. Showing 0 points would
    // tell a provider it has earned nothing, which is a much stronger
    // claim than "we could not ask".
    $('onchain-points').textContent=data.earnings.available?data.earnings.reward_points:'lecture indisponible';
    const proof=data.proof;
    if(!proof.available){
      $('onchain-availability').textContent='lecture indisponible';
    }else if(!proof.found){
      // A provider that has never submitted a proof is a normal state,
      // not a failure and not 0 % availability.
      $('onchain-availability').textContent='aucune preuve soumise';
    }else{
      $('onchain-availability').textContent=(proof.availability_bps/100).toFixed(2)+' %';
      $('onchain-samples').textContent=`${proof.successful_samples}/${proof.total_samples}`;
      $('onchain-sequence').textContent=proof.sequence;
      $('onchain-observed').textContent=`#${proof.observed_at_block}`;
      $('onchain-hash').textContent=proof.payload_hash;
    }
    if(data.partial){warning.hidden=false;warning.textContent='Lecture partielle — au moins une des deux sources on-chain n\'a pas pu être lue.'}
  }catch(error){warning.hidden=false;warning.textContent='Impossible de lire les gains et preuves on-chain de ce provider.'}
}
function loadValidatorViews(){loadValidatorScores();loadOpenRounds();loadProviderOnChain()}
$('score-load').addEventListener('click',loadValidatorViews);
$('score-provider-id').addEventListener('keydown',e=>{if(e.key==='Enter')loadValidatorViews()});
})();
