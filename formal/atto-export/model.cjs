"use strict";
// One-batch, capacity-one source-only exporter abstraction.
const init={phase:0,connected:true,delivered:false,receipt:false,redacted:false,deniedUnredacted:false,deniedQuota:false,outage:false,retried:false,acked:false};
function must(v,m){if(!v)throw Error("otel model: "+m);}
function valid(s){
 must(s.phase>=0&&s.phase<=5,"phase outside declared domain");
 must(!(s.phase>=3&&!s.redacted),"unredacted sensitive batch entered queue");
 must(!s.acked||s.receipt,"ack without receiver proof");
 must(!s.receipt||s.delivered,"receipt before transport delivery");
}
function next(s){
 const out=[];
 if(s.phase===0)out.push(["stage-sensitive-batch",{...s,phase:1}]);
 if(s.phase===1){
  out.push(["redact-before-enqueue",{...s,phase:2,redacted:true}]);
  out.push(["deny-unredacted-enqueue",{...s,deniedUnredacted:true}]);
 }
 if(s.phase===2)out.push(["enqueue-bounded",{...s,phase:3}]);
 if(s.phase===3 || s.phase===4)out.push(["reject-second-enqueue",{...s,deniedQuota:true}]);
 if(s.phase===3 && s.connected)
  out.push(["transport-delivery",{...s,phase:4,delivered:true,receipt:true}]);
 if(s.phase===4 && s.receipt)
  out.push(["ack-after-delivery",{...s,phase:5,acked:true}]);
 if(s.connected)out.push(["transport-outage",{...s,connected:false,outage:true}]);
 if(!s.connected)out.push(["reconnect",{...s,connected:true}]);
 if(s.phase===4&&!s.connected)
  out.push(["retry-ambiguous-ack",{...s,phase:3,receipt:false,retried:true}]);
 return out;
}
function run(){
 const MAX=12,seen=new Set([JSON.stringify(init)]),queue=[[init,0]];
 let edges=0;
 for(let i=0;i<queue.length;i++){
  const [s,d]=queue[i];valid(s);if(d===MAX)continue;
  for(const [a,t]of next(s)){
   valid(t);edges++;
   const k=JSON.stringify(t);if(!seen.has(k)){seen.add(k);queue.push([t,d+1]);}
  }
 }
 const states=[...seen].map(JSON.parse);
 for(const f of ["delivered","deniedUnredacted","deniedQuota","outage","retried","acked"])
  must(states.some(s=>s[f]),"missing witness "+f);
 for(const mutated of [{...init,phase:3},{...init,acked:true},{...init,receipt:true}]){
  let caught=false;try{valid(mutated);}catch{caught=true;}
  must(caught,"invalid mutation escaped");
 }
 return {states:seen.size,transitions:edges,bound:MAX,claim:"single-batch source-only model"};
}
const result=run();
if(typeof console!=="undefined")console.log(JSON.stringify(result));
