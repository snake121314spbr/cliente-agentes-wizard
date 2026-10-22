// Opt-in, bounded source review through the authenticated first-party backend.
// Model/provider credentials never leave that backend. Source is untrusted data.
import {createHash} from 'node:crypto';
import {lstat, readdir, readFile} from 'node:fs/promises';
import path from 'node:path';
import {CONSOLE_UPLOAD_ORIGIN, pipelineTokenValid, safePipelineUrl} from './upload.mjs';

export const AI_REVIEW_PATH='/console/api/pipeline/sast/ai-review';
export const AI_LIMITS=Object.freeze({maxFiles:12,maxFileBytes:128*1024,maxSnippetChars:2000,maxPayloadBytes:48*1024,maxCandidates:40,maxInventoryFiles:5000,maxReadBytes:2*1024*1024,maxReadFiles:120});
const extensions=new Set(['.js','.jsx','.mjs','.cjs','.ts','.tsx','.py','.java','.go','.rb','.php','.cs','.c','.cpp','.rs','.kt','.swift']);
const skipped=new Set(['.git','.hg','.svn','node_modules','vendor','coverage','.next','.nuxt','dist','build','target','out','.venv','venv','artifacts']);
const severityOrder={critical:4,high:3,medium:2,low:1,info:0};
const cleanText=(value,max)=>redactCode(String(value||'')).replace(/[\u0000-\u001f\u007f]/g,' ').trim().slice(0,max);
export function redactCode(value){
 return String(value||'')
  .replace(/-----BEGIN [^-\r\n]*PRIVATE KEY-----[\s\S]*?-----END [^-\r\n]*PRIVATE KEY-----/g,match=>match.replace(/[^\r\n]/g,'*'))
  .replace(/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,'[REDACTED_AWS_KEY]')
  .replace(/\b(?:sk-(?:proj-)?[A-Za-z0-9_-]{12,}|(?:sk|rk)_(?:live|test)_[A-Za-z0-9_-]{12,}|xox[baprs]-[A-Za-z0-9-]{10,}|re_[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{20,})\b/g,'[REDACTED_SECRET]')
  .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,'[REDACTED_JWT]')
  .replace(/\b(authorization\s*[:=]\s*["'`]?Bearer\s+)[A-Za-z0-9_.-]+/gi,'$1[REDACTED]')
  .replace(/\b((?:api[_-]?key|access[_-]?key|client[_-]?secret|secret|token|password|passwd|connection[_-]?string)\s*[:=]\s*)(["'`])[^\r\n]*?\2/gi,'$1"[REDACTED]"')
  .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi,'[REDACTED_EMAIL]')
  .replace(/(https?:\/\/)[^\s/@:]+:[^\s/@]+@/gi,'$1[REDACTED]@');
}
function sourceFile(relative){return /^[A-Za-z0-9_./@+-]+$/.test(relative)&&relative.length<=240&&!relative.split('/').some(part=>skipped.has(part)||part.startsWith('.'))&&extensions.has(path.extname(relative).toLowerCase())&&!/(?:^|\/)(?:secrets?|credentials?|config\.local)(?:[._-]|$)/i.test(relative);}
export async function collectAiFiles(root,result={}){
 const base=path.resolve(root),inventory=[];let visited=0,truncated=false;
 async function walk(directory){
  for(const entry of (await readdir(directory,{withFileTypes:true})).sort((a,b)=>a.name.localeCompare(b.name))){
   if(visited>=AI_LIMITS.maxInventoryFiles){truncated=true;return;}
   const absolute=path.join(directory,entry.name),relative=path.relative(base,absolute).split(path.sep).join('/');
   if(entry.isSymbolicLink())continue;
   if(entry.isDirectory()){if(!skipped.has(entry.name)&&!entry.name.startsWith('.'))await walk(absolute);continue;}
   visited++;
   if(entry.isFile()&&sourceFile(relative)){const info=await lstat(absolute);if(info.isFile()&&info.size<=AI_LIMITS.maxFileBytes)inventory.push({absolute,relative});}
  }
 }
 await walk(base);
 const deterministic=new Map((result.findings||[]).filter(f=>f.ruleId!=='LS-SAST-001').map(f=>[f.file,f.line]));
 const candidates=[];let readBytes=0,readFiles=0;
 for(const item of inventory){
  const info=await lstat(item.absolute);if(readFiles>=AI_LIMITS.maxReadFiles||readBytes+info.size>AI_LIMITS.maxReadBytes){truncated=true;break;}
  const text=await readFile(item.absolute,'utf8');readBytes+=Buffer.byteLength(text);readFiles++;if(text.includes('\0'))continue;
  const lines=redactCode(text).split('\n');
  const sink=lines.findIndex(line=>/\b(?:query|execute|exec|fetch|request|sendFile|readFile|deserialize|pickle\.loads|yaml\.load|verify|jwt|innerHTML|dangerouslySetInnerHTML)\b/.test(line));
  const center=deterministic.get(item.relative)||Math.max(1,sink+1),start=Math.max(0,center-8);
  let content='',index=start;
  while(index<lines.length&&content.length+lines[index].length+1<=AI_LIMITS.maxSnippetChars){content+=(content?'\n':'')+lines[index++];}
  if(!content.trim())continue;
  candidates.push({path:item.relative,startLine:start+1,content,priority:deterministic.has(item.relative)?2:sink>=0?1:0});
 }
 candidates.sort((a,b)=>b.priority-a.priority||a.path.localeCompare(b.path));
 return {files:candidates.slice(0,AI_LIMITS.maxFiles).map(({priority,...file})=>file),coverage:{eligibleFiles:inventory.length,reviewedFiles:Math.min(candidates.length,AI_LIMITS.maxFiles),bounded:true,inventoryTruncated:truncated}};
}
export function validateAiFindings(candidates,files,existing=[]){
 const accepted=[],occupied=new Set(existing.map(f=>`${f.file}:${f.line}:${String(f.title||f.message||'').trim().toLowerCase()}`));
 for(const candidate of (Array.isArray(candidates)?candidates:[]).slice(0,AI_LIMITS.maxCandidates)){
  const file=files.find(item=>item.path===candidate?.path),line=Number(candidate?.line),confidence=Number(candidate?.confidence),severity=String(candidate?.severity||'').toLowerCase();
  if(!file||!Number.isSafeInteger(line)||!Object.hasOwn(severityOrder,severity)||!Number.isFinite(confidence)||confidence<.7||confidence>1)continue;
  const sourceLine=file.content.split('\n')[line-file.startLine];
  const evidence=String(candidate.evidence||'').trim();
  if(sourceLine===undefined||evidence.length<4||evidence.length>500||!sourceLine.includes(evidence)||/REDACTED/.test(evidence))continue;
  const title=cleanText(candidate.title,240),recommendation=cleanText(candidate.recommendation,700);
  if(!title||!recommendation||occupied.has(`${file.path}:${line}:${title.toLowerCase()}`))continue;
  occupied.add(`${file.path}:${line}:${title.toLowerCase()}`);
  const fingerprint=createHash('sha256').update(`LS-SAST-AI|${file.path}|${line}|${title}`).digest('hex').slice(0,32);
  accepted.push({id:`LS-SAST-AI:${file.path}:${line}`,ruleId:'LS-SAST-AI',ruleName:'AI-assisted source review',severity,title,message:title,description:cleanText(candidate.description,700),recommendation,file:file.path,line,column:1,evidence:redactCode(evidence),fingerprint,source:'ai',confidence,reviewRequired:true,...(/^CWE-\d{1,5}$/.test(candidate.cwe||'')?{cwe:candidate.cwe}:{})});
 }
 return accepted;
}
export async function reviewWithAi(root,result,metadata,{token,consent=false,fetchImpl=fetch}={}){
 if(!consent)throw Error('A revisão IA requer --allow-ai-code-sharing: trechos higienizados serão enviados ao Console e ao provedor da IA.');
 if(!pipelineTokenValid(token))throw Error('A revisão IA requer um token de pipeline válido; a chave do provedor permanece no backend.');
 const collection=await collectAiFiles(root,result);
 if(!collection.files.length)return {findings:[],status:'not_applicable',coverage:collection.coverage,limitations:['Nenhum arquivo de código elegível para revisão IA.']};
 const safeMetadata={};for(const key of ['repository','release','commit','branch','originId','originLabel'])safeMetadata[key]=cleanText(metadata[key],key==='repository'?240:160);
 if(!safeMetadata.repository)throw Error('Informe --repository org/projeto para vincular a revisão IA ao repositório autorizado.');
 const payload={schemaVersion:'1.0',agentId:'pipeline-sast',consent:true,...safeMetadata,files:collection.files};
 let body=JSON.stringify(payload);while(Buffer.byteLength(body)>AI_LIMITS.maxPayloadBytes&&payload.files.length>1){payload.files.pop();body=JSON.stringify(payload);}
 collection.coverage.reviewedFiles=payload.files.length;
 if(Buffer.byteLength(body)>AI_LIMITS.maxPayloadBytes)throw Error('Limite de contexto IA excedido.');
 const endpoint=safePipelineUrl(CONSOLE_UPLOAD_ORIGIN+AI_REVIEW_PATH,[AI_REVIEW_PATH]);
 const response=await fetchImpl(endpoint,{method:'POST',redirect:'error',signal:AbortSignal.timeout(60000),headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json'},body});
 const raw=await response.text();if(Buffer.byteLength(raw)>64*1024)throw Error('Resposta IA excedeu o limite.');
 let data;try{data=JSON.parse(raw);}catch{throw Error('Resposta IA inválida.');}
 if(!response.ok||data.ok!==true||!['completed','partial'].includes(data.status)||!Array.isArray(data.findings))throw Error(`Revisão IA indisponível (HTTP ${response.status}); a análise determinística foi preservada.`);
 const findings=validateAiFindings(data.findings,collection.files,result.findings);
 return {status:data.status,findings,coverage:collection.coverage,rejectedCandidates:data.findings.length-findings.length,limitations:['Revisão complementar de contexto limitado; não prova ausência de vulnerabilidades.','Achados IA exigem validação humana; nenhuma correção é executada automaticamente.']};
}
export function mergeAiReview(result,review){
 const findings=[...result.findings,...(review.findings||[])],counts={};for(const finding of findings)counts[finding.severity]=(counts[finding.severity]||0)+1;
 const aiReview={...review,findings:undefined};
 return {...result,status:review.status==='partial'?'partial':result.status,findings,counts,aiReview,policy:{...result.policy,passed:!findings.some(f=>(severityOrder[f.severity]??0)>=(severityOrder[result.policy.failOn]??3))}};
}
