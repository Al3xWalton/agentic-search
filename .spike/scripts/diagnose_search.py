import json,http.client,time
from pathlib import Path
root=Path(__file__).resolve().parents[1]
qs={q['id']:q for q in json.loads((root/'queries-answer-set.json').read_text())['queries']}
tests=[('q11','python venv'),('q12','python json'),('q13','read_to_string'),('q21','vanilla pods'),('q25','Felix First Class'),('q27','S203U-C15'),('q32','Rust 1.98.1'),('q33','rustup 1.29.1'),('q36','arrayref'),('q38','Firefox release cadence')]
rows=[]
for id,query in tests:
 c=http.client.HTTPConnection('127.0.0.1',57300,timeout=20);st=time.perf_counter();c.request('POST','/beta/api/search',json.dumps({'query':query,'numResults':10,'flattenResponse':True}),{'Content-Type':'application/json'});r=c.getresponse();d=json.loads(r.read());c.close();urls=[p['url'] for p in d.get('webpages',[])];row={'original_id':id,'diagnostic_query':query,'http_status':r.status,'latency_ms':(time.perf_counter()-st)*1000,'urls':urls,'known_answer_in_top10':bool(set(urls)&set(qs[id]['acceptable_urls']))};rows.append(row);print(id,query,row['known_answer_in_top10'],urls[:2])
(root/'data/keyword-diagnostics.json').write_text(json.dumps({'note':'Post-hoc, hand-chosen diagnostic subset; not a replacement recall result; no Firecrawl queries repeated.','rows':rows},indent=2)+'\n')
