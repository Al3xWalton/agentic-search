"""Run frozen queries, preserve raw evidence; no query rewriting or answer-driven reranking."""
import json,time,subprocess,os,sys,hashlib,http.client,datetime
from pathlib import Path
root=Path(__file__).resolve().parents[1]; mode=sys.argv[1]
answer=root/'queries-answer-set.json'
raw=answer.read_bytes(); data=json.loads(raw)
assert data['status']=='frozen' and len(data['queries'])==50
meta={'answer_set_sha256':hashlib.sha256(raw).hexdigest(),'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'mode':mode,'queries':[]}
out=root/'data'/f'{mode}-runs.json'
assert not out.exists(), 'Refusing to overwrite recorded benchmark; archive it deliberately before a rerun.'
out.write_text(json.dumps(meta,indent=2)+'\n')
for q in data['queries']:
 st=time.perf_counter();result={'id':q['id'],'query':q['query'],'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
 try:
  if mode=='stract':
   conn=http.client.HTTPConnection('127.0.0.1',57300,timeout=60)
   body=json.dumps({'query':q['query'],'numResults':10,'page':0,'flattenResponse':True,'countResultsExact':True})
   conn.request('POST','/beta/api/search',body,{'Content-Type':'application/json'})
   r=conn.getresponse();b=r.read();result['http_status']=r.status;conn.close()
   p=root/'data'/f'stract-{q["id"]}.json';p.write_bytes(b);result['output_file']=str(p)
   result['success']=r.status==200
  else:
   p=root/'.firecrawl'/f'{q["id"]}.json'
   cmd=['firecrawl','search',q['query'],'--limit','10','--sources','web','--country','US','--timeout','60000','--json','-o',str(p)]
   env=os.environ.copy();env['FIRECRAWL_NO_SEARCH_FEEDBACK']='1';env['TMPDIR']=str(root/'tmp')
   with (root/'logs'/f'firecrawl-{q["id"]}.log').open('w') as log:
    r=subprocess.run(cmd,cwd=root,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=90)
   result.update({'command':cmd,'exit_code':r.returncode,'output_file':str(p),'success':r.returncode==0 and p.exists()})
 except Exception as e:result.update({'success':False,'error':type(e).__name__+': '+str(e)})
 result['latency_ms']=(time.perf_counter()-st)*1000
 meta['queries'].append(result);out.write_text(json.dumps(meta,indent=2)+'\n')
 print(json.dumps({k:v for k,v in result.items() if k in ['id','success','latency_ms','error']}),flush=True)
 # Added after the recorded 2026-09-09 run: never continue after credit/rate rejection.
 if mode=='firecrawl' and not result['success']:
  failure=(root/'logs'/f'firecrawl-{q["id"]}.log').read_text()
  if 'status code 402' in failure or 'status code 429' in failure:
   meta['stopped_reason']='Provider credit/rate rejection; remaining queries not attempted.'
   break
meta['finished_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat();out.write_text(json.dumps(meta,indent=2)+'\n')
