import gzip,json,collections,hashlib
from pathlib import Path
p=Path('.spike/data/cc-sample.warc.gz');types=collections.Counter();status=collections.Counter();mimes=collections.Counter();dates=[];urls=set();htmls=set();n=0
with gzip.open(p,'rb') as f:
 while True:
  line=f.readline()
  if not line:break
  if line in (b'\r\n',b'\n'):continue
  assert line.startswith(b'WARC/'),line[:80]
  h={}
  while True:
   line=f.readline()
   if line in (b'\r\n',b'\n',b''):break
   k,_,v=line.decode('utf-8','replace').partition(':');h[k.lower()]=v.strip()
  b=f.read(int(h['content-length']));types[h['warc-type']]+=1;n+=1
  if h['warc-type']=='response':
   header,_,body=b.partition(b'\r\n\r\n');status[header.split(b'\r\n')[0].decode('ascii','replace')]+=1
   mime=h.get('warc-identified-payload-type','unknown');mimes[mime]+=1;url=h.get('warc-target-uri');urls.add(url);dates.append(h['warc-date'])
   if mime=='text/html':htmls.add(url)
s={'compressed_bytes':p.stat().st_size,'sha256':hashlib.file_digest(p.open('rb'),'sha256').hexdigest() if hasattr(hashlib,'file_digest') else hashlib.sha256(p.read_bytes()).hexdigest(),'raw_records':n,'record_types':types,'http_status':status,'payload_types':mimes,'response_unique_urls':len(urls),'html_response_unique_urls':len(htmls),'date_min':min(dates),'date_max':max(dates)}
Path('.spike/data/cc-stats.json').write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s,indent=2))
