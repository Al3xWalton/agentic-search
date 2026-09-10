from pathlib import Path
import json,re
root=Path(__file__).resolve().parents[1]
qs=json.loads((root/'data/query-candidates.json').read_text())['queries']
replace={
'q05':('Which four SI base units had new definitions in the 2018 revision?','https://www.bipm.org/en/measurement-units/si-base-units','2018'),
'q08':('How long does Mars take to orbit the Sun?','https://science.nasa.gov/mars/facts/','year on Mars'),
'q16':('How do I parse command line arguments in Python using argparse?','https://docs.python.org/3/library/argparse.html','argparse'),
'q21':('Find a Singapore supplier page for bulk vanilla pods in different grades.','https://naturalvanilla.sg/vanilla-pods/','grades'),
'q25':('Find the Felix First Class Wood chef knife with a 21 cm blade and olive handle.','https://pizzini.at/felix-first-class-wood-chef-knife-21-cm-olive-aktion.html?language=en','blade'),
'q26':('Find a product page for Magnesia Red pomegranate drink in a 1.5 litre bottle.','https://www.halusky.co.uk/magnesia-red-pommegranate-1-5l.html','Magnesia'),
'q27':('Find a distributor product page for the ABB S203U-C15.','https://proax.ca/en/product/21451/abbs203uc15','ABB'),
'q30':('Find the Black Tourmaline Rough Stone product at Earthbound Trading.','https://www.earthboundtrading.com/black-tourmaline-rough-stone','Dimensions')}
needles=['capital','88','general relativity','1945','2018','four chambers','above sea','year on Mars','Au','phase','venv','loads','read_to_string','Result','fetch','argparse','capture_output','soft','CREATE TABLE','publish']
idx={};source={}
for name in ['cc','seeds']:
 for l in (root/'data'/f'{name}-indexed.jsonl').open():
  x=json.loads(l);idx[x['url'][0]]=x;source[x['url'][0]]=name
manifest={x['url']:x for x in (json.loads(l) for l in (root/'data/seed-manifest.jsonl').open())}
review=[]
for i,q in enumerate(qs):
 if q['id'] in replace:
  query,url,needle=replace[q['id']];q.update({'original_query':q['query'],'original_candidate_url':q['candidate_url'],'query':query,'candidate_url':url,'replacement_reason':'Original seed unavailable; selected another captured indexed answer before either retrieval run' if q['id']!='q05' else 'Original question not directly supported by indexed clean text; adjusted to captured content'})
 else:needle=needles[i] if i<20 else ''
 u=q['candidate_url'];x=idx.get(u);assert x,u
 b=' '.join(x.get('stemmed_body',[]));pos=b.lower().find(needle.lower()) if needle else 0;pos=max(0,pos)
 excerpt=b[max(0,pos-100):pos+650]
 images=[]
 if q['category']=='image_bearing':
  h=Path(manifest[u]['body_file']).read_text();
  for match in re.finditer(r'<img\b[^>]*>',h,re.I):
   tag=match.group(0)
   if 'upload.wikimedia.org' in tag:
    images.append(tag[:600])
    if len(images)==2:break
 q['acceptable_urls']=[u];q['corpus']=source[u];q['label_status']='pending_manual_review';q['title']=x['title'][0]
 rec={'id':q['id'],'query':q['query'],'url':u,'title':q['title'],'excerpt':excerpt,'image_tags':images};review.append(rec);print(json.dumps(rec,ensure_ascii=False))
(root/'data/label-review.json').write_text(json.dumps(review,indent=2,ensure_ascii=False)+'\n')
(root/'data/reviewed-query-draft.json').write_text(json.dumps(qs,indent=2,ensure_ascii=False)+'\n')
