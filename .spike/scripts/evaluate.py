import json,math,statistics,hashlib,collections,re
from pathlib import Path
from urllib.parse import urlsplit,parse_qsl,urlencode,unquote
root=Path(__file__).resolve().parents[1]; report=Path('<WORKSPACE>/story-573-reports')
a_bytes=(root/'queries-answer-set.json').read_bytes();a=json.loads(a_bytes);ah=hashlib.sha256(a_bytes).hexdigest()
def norm(u):
 p=urlsplit(u);host=(p.hostname or '').lower();host=host[4:] if host.startswith('www.') else host
 qs=[(k,v) for k,v in parse_qsl(p.query,keep_blank_values=True) if not k.lower().startswith('utm_') and k.lower() not in ('gclid','fbclid')]
 return host+((':'+str(p.port)) if p.port and p.port not in [80,443] else '')+(p.path.rstrip('/') or '/')+('?' +urlencode(sorted(qs)) if qs else '')
def stats(xs):
 return {'n':len(xs),'p50_ms':statistics.median(xs) if xs else None,'p95_ms':sorted(xs)[math.ceil(.95*len(xs))-1] if xs else None}
corpus=set();n_docs=0
for name in ['cc','seeds']:
 for l in (root/'data'/f'{name}-indexed.jsonl').open():
  d=json.loads(l);corpus.add(norm(d['url'][0]));n_docs+=1
rows=[];modes={m:json.loads((root/'data'/f'{m}-runs.json').read_text()) for m in ['stract','firecrawl']}
for m,x in modes.items():assert x['answer_set_sha256']==ah and len(x['queries'])==50,(m,len(x['queries']))
for q in a['queries']:
 answers=set(map(norm,q['acceptable_urls']));assert answers and answers<=corpus
 row={'id':q['id'],'category':q['category'],'query':q['query'],'answers':q['acceptable_urls']}
 for mode in modes:
  run=next(r for r in modes[mode]['queries'] if r['id']==q['id']);u=[];error=None;duration=None
  if run['success']:
   d=json.loads(Path(run['output_file']).read_text());pages=d['webpages'] if mode=='stract' else d.get('data',{}).get('web',[]);u=[p['url'] for p in pages[:10]];duration=d.get('searchDurationMs')
   assert run['latency_ms']>=0
  elif mode=='firecrawl':error=(root/'logs'/f'firecrawl-{q["id"]}.log').read_text().strip()
  hit=len(set(map(norm,u))&answers)
  row[mode]={'success':run['success'],'top10_urls':u,'matched_urls':[x for x in u if norm(x) in answers],'recall_at_10':hit/len(answers) if run['success'] else None,'latency_ms':run['latency_ms'] if run['success'] else None,'failed_attempt_ms':run['latency_ms'] if not run['success'] else None,'server_duration_ms':duration,'error':error,'top10_urls_in_sample':sum(norm(x) in corpus for x in u)}
 rows.append(row)
summary={'answer_set_sha256':ah,'total_documents':n_docs,'unique_normalized_urls':len(corpus),'queries':len(rows),'answer_coverage':1.0,'modes':{},'categories':{},'rows':rows}
for cat in ['all']+list(dict.fromkeys(r['category'] for r in rows)):
 group=rows if cat=='all' else [r for r in rows if r['category']==cat];s={}
 for mode in modes:
  good=[r[mode] for r in group if r[mode]['success']];s[mode]={'attempts':len(group),'successes':len(good),'recall_at_10':statistics.mean(x['recall_at_10'] for x in good) if good else None,**stats([x['latency_ms'] for x in good]),'zero_results':sum(not x['top10_urls'] for x in good)}
 if cat=='all':summary['modes']=s
 else:summary['categories'][cat]=s
summary['firecrawl_errors']=dict(collections.Counter(r['firecrawl']['error'] for r in rows))
(root/'data/metrics.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps({k:v for k,v in summary.items() if k!='rows'},indent=2))
