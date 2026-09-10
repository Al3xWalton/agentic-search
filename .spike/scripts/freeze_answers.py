from pathlib import Path
import json,hashlib,datetime,re,html
root=Path(__file__).resolve().parents[1];report=Path('<WORKSPACE>/story-573-reports')
qs=json.loads((root/'data/reviewed-query-draft.json').read_text())
reasons=[
'Captured article explicitly identifies Canberra as the Australian capital.',
'NASA facts state that Mercury circles the Sun every 88 Earth days.',
'Einstein article attributes general relativity development to Einstein during 1907–1915.',
'UN history records its official beginning on 24 October 1945.',
'BIPM names kilogram, ampere, kelvin and mole as the four revised base units.',
'Captured HTML describes the human heart as two atria and two ventricles.',
'Everest article identifies it as the highest mountain above sea level.',
'NASA states a Martian year is 687 Earth days.',
'Gold article identifies the element and its Au symbol in captured content.',
'NASA explains reflected sunlight and the changing visible illuminated portion.',
'Official venv reference describes virtual environments and their creation.',
'Official json reference documents decoding JSON objects into dictionaries.',
'Rust standard library page documents reading entire file contents into a string.',
'Rust Book explains Result, success/error variants and handling File::open failures.',
'MDN explains JavaScript fetch requests and response handling.',
'Python argparse reference covers defining and parsing command-line arguments.',
'Python subprocess reference explains capture_output and stdout/stderr handling.',
'Git reset documentation describes --soft preserving working tree and index.',
'PostgreSQL tutorial shows CREATE TABLE syntax and a cities example.',
'Cargo reference explains preparing and publishing a crate to crates.io.',
'Wholesale supplier page lists vanilla origins, grades and bulk/retail pack sizes.',
'Official Framework page describes configurable and repairable Laptop 13 hardware.',
'Apple specifications page lists MacBook Air display, ports and external-display capabilities.',
'Official Nintendo page describes OLED display, stand, storage and dock.',
'Product title specifies Felix First Class Wood, 21 cm and olive; text describes forged blade.',
'Product title specifies Magnesia Red Pommegranate 1.5l; retailer body describes Magnesia RED. Body has inconsistent raspberry wording, so no taste claim is labelled.',
'Proax product page identifies itself as an ABB S203U-C15 distributor.',
'Official Prusa product page identifies MK4S and its printer ecosystem.',
'Official Arduino store page identifies UNO Rev3 and board specifications.',
'Exact Earthbound product title and size information identify the rough stone. No health or metaphysical claim is endorsed.',
'Dated Rust survey results article describes participants and debugger experience.',
'Dated Rust 1.98.1 announcement explains the null-vtable-pointer regression fix.',
'Dated rustup 1.29.1 announcement describes concurrent update and component operations.',
'Dated announcement names the first Maintainers in Residence and grant recipients.',
'Dated Rust announcement describes enabling the new trait solver on nightly.',
'Dated security incident article describes malicious dependencies and the arrayref supply-chain compromise.',
'Dated Rust 1.98.0 announcement lists stabilized features, including algebraic floating-point methods.',
'Mozilla announcement dates the two-week cadence to Firefox 155 on 1 September 2026.',
'NASA article describes joint Hubble/Webb observations of trans-Neptunian objects.',
'NASA article describes a ten-sided atmospheric wave around Saturn’s south pole.',
'Captured Eiffel Tower page contains a photograph resource named Tour Eiffel Wikimedia Commons (cropped).jpg.',
'Captured Mona Lisa article contains the painting resource from C2RMF.',
'Captured Pillars of Creation article contains Eagle nebula pillars and Hubble/Webb images.',
'Captured Grand Canyon article contains canyon photographs and an aerial view.',
'Captured cherry blossom article contains Sakura and Moss Pink and other blossom photographs.',
'Captured red panda article includes Red Panda, Gentle Tree-Dweller of the Himalayas.jpg.',
'Captured Sydney Opera House article includes the Sydney Australia photograph.',
'Captured Rosetta Stone article includes Rosetta Stone.JPG.',
'Captured aurora article includes Aurora borealis over Eielson Air Force Base, Alaska.jpg.',
'Captured Webb article includes a spacecraft model and telescope photographs.'
]
idx={};linehash={}
for name in ['cc','seeds']:
 for l in (root/'data'/f'{name}-indexed.jsonl').open():
  d=json.loads(l);idx[d['url'][0]]=d;linehash[d['url'][0]]=hashlib.sha256(l.encode()).hexdigest()
m={d['url']:d for d in (json.loads(l) for l in (root/'data/seed-manifest.jsonl').open())}
for q,reason in zip(qs,reasons):
 u=q['acceptable_urls'][0];assert u in idx
 q.update({'label_status':'manually_accepted','label_reason':reason,'indexed_record_sha256':linehash[u],'acceptable_domains':[],'ground_truth_granularity':'one_known_answer_page','capture_date_utc':m[u]['date'] if u in m else '2026-08-07 (file capture date)'})
 if q['category']=='image_bearing':
  h=Path(m[u]['body_file']).read_text();q['image_evidence']=[html.unescape(x) for x in re.findall(r'<img\b[^>]*resource="([^"]+)"',h,re.I)][:8]
 q.pop('candidate_url',None)
assert len(qs)==50 and len(reasons)==50
f={'status':'frozen','frozen_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'upstream_commit':'8ac40b023e0a49f55cdd5b599841ea46d0503ec9','labeller':'Codex spike engineer; manual review of captured page text and image markup; one rater, no independent adjudication','labelling_rule':'A known acceptable page must directly address the query in captured content and have its URL present in the actual Stract index export. Accept exact page identity after declared URL normalization; no blanket domain credit. Image queries require relevant image markup in the captured parent page. These are 50 known-answer labels, not exhaustive judgements of every relevant page.','normalization':'lowercase host; remove leading www.; ignore http vs https and fragment; strip trailing slash except root; drop utm_*, gclid and fbclid parameters; sort remaining parameters; retain path case and meaningful parameters. No result filtering/backfilling before the top-10 cutoff.','corpus':{'cc_crawl':'CC-MAIN-2026-34','cc_indexed_documents':19285,'seed_indexed_documents':178,'seed_urls_attempted':200,'cc_capture_range_utc':['2026-08-07T10:19:29Z','2026-08-07T13:04:31Z'],'seed_capture_date':'2026-09-09','answer_sources':{'seeds':45,'cc':5}},'assumptions':['Balanced categories are deliberately constructed, not a representative sample of production agent traffic.','News queries refer to dated announcements within the combined corpus date range (August 7 through September 9), and all news answers are from September 9 seed captures rather than the August 7 CC segment.','The news category contains seven Rust posts, one Mozilla post and two NASA posts.','Five inaccessible commerce seeds were replaced by manually reviewed commerce pages already present in the CC index; two other unavailable targets and one unsupported factual question were revised before either retrieval run.','No image bytes were fetched; image-bearing relevance is established from page content and image-resource markup.','A relevant live Firecrawl answer at a different unlabelled URL receives no known-answer recall credit; this metric does not measure unrestricted live-web answer quality.'],'queries':qs}
raw=(json.dumps(f,indent=2,ensure_ascii=False)+'\n').encode();(root/'queries-answer-set.json').write_bytes(raw);(report/'queries-answer-set.json').write_bytes(raw)
print(json.dumps({'queries':len(qs),'sha256':hashlib.sha256(raw).hexdigest(),'sources':f['corpus']['answer_sources'],'frozen_at_utc':f['frozen_at_utc']}))
