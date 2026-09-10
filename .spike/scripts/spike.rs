// Story 573 bounded benchmark harness; AGPL-3.0-or-later, same as Stract core.
use std::{collections::{BTreeMap, HashSet}, fs::{self,File}, io::{BufWriter,Write}, path::PathBuf, sync::Mutex};
use std::sync::Arc;
use anyhow::Result;
use futures::{stream,StreamExt};
use serde_json::json;
use stract::{crawler::{self,DatumSink,CrawlDatum,Domain,JobExecutor,WorkerJob,WeightedUrl},config::{CrawlerConfig,S3Config,UserAgent}, warc, webpage::{Html,url_ext::UrlExt}};
use url::Url;
struct LocalSink { writer: Mutex<Option<warc::WarcWriter>>, manifest: Mutex<BufWriter<File>>, allowed: HashSet<String>, out: PathBuf }
impl DatumSink for LocalSink {
 async fn write(&self,d: CrawlDatum)->std::result::Result<(),crawler::Error>{
  // Upstream emits an empty datum for redirects; don't miscount it as a fetched page.
  if d.body.is_empty() || !self.allowed.contains(d.url.as_str()) {
   println!("{}",json!({"event":"empty_or_outside_seed_datum","url":d.url,"body_bytes":d.body.len()})); return Ok(());
  }
  let mut writer=self.writer.lock().unwrap(); let w=writer.as_mut().unwrap(); let id=w.num_writes();
  let file=self.out.join("seed-pages").join(format!("{id:04}.html")); fs::write(&file,&d.body).unwrap();
  let html=Html::parse(&d.body,d.url.as_str()).ok();
  let m=json!({"url":d.url,"date":d.date,"body_file":file,"bytes":d.body.len(),"fetch_time_ms":d.fetch_time_ms,"title":html.as_ref().and_then(|h|h.title()),"clean_text":html.as_ref().and_then(|h|h.clean_text()),"noindex":html.as_ref().map(|h|h.is_no_index())});
  writeln!(self.manifest.lock().unwrap(),"{}",m).unwrap();
  w.write(&warc::WarcRecord {request:warc::Request{url:d.url.to_string(),date:Some(d.date)},response:warc::Response{body:d.body,payload_type:Some(d.payload_type)},metadata:warc::Metadata{fetch_time_ms:d.fetch_time_ms}}).unwrap();
  println!("{}",json!({"event":"saved","url":d.url,"number":id+1})); Ok(())
 }
 async fn finish(&self)->std::result::Result<(),crawler::Error>{
  let w=self.writer.lock().unwrap().take().unwrap(); let n=w.num_writes();let bytes=w.finish().unwrap();
  fs::write(self.out.join("seeds.warc.gz"),&bytes).unwrap();self.manifest.lock().unwrap().flush().unwrap();
  println!("{}",json!({"event":"crawl_finished","pages":n,"warc_bytes":bytes.len()}));Ok(())
 }
}
async fn crawl(seed_path:&str,out:&str)->Result<()> {
 let seeds:Vec<serde_json::Value>=serde_json::from_slice(&fs::read(seed_path)?)?;let out=PathBuf::from(out);fs::create_dir_all(out.join("seed-pages"))?;
 let mut groups:BTreeMap<String,Vec<Url>>=BTreeMap::new();let mut allowed=HashSet::new();
 for s in &seeds {let mut u=Url::parse(s["url"].as_str().unwrap())?;u.normalize_in_place();allowed.insert(u.to_string());groups.entry(Domain::from(&u).as_str().to_string()).or_default().push(u);}
 let sink=Arc::new(LocalSink{writer:Mutex::new(Some(warc::WarcWriter::new())),manifest:Mutex::new(BufWriter::new(File::create(out.join("seed-manifest.jsonl"))?)),allowed,out});
 let cfg=Arc::new(CrawlerConfig{num_worker_threads:4,user_agent:UserAgent{full:"AVA-StractSpike/0.1 (bounded public-page research; no link expansion)".into(),token:"AVA-StractSpike".into()},robots_txt_cache_sec:86400,min_politeness_factor:0,start_politeness_factor:0,min_crawl_delay_ms:2000,max_crawl_delay_ms:600000,max_politeness_factor:4,max_url_slowdown_retry:1,timeout_seconds:20,s3:S3Config{bucket:"".into(),folder:"".into(),access_key:"".into(),secret_key:"".into(),endpoint:"".into()},router_hosts:vec![]});
 let client=crawler::robot_client::RobotClient::new(&cfg)?;
 stream::iter(groups.into_values()).for_each_concurrent(4,|urls|{let sink=sink.clone();let cfg=cfg.clone();let client=client.clone();async move{
  let domain=Domain::from(&urls[0]);let mut accepted=Vec::new();
  for u in urls {let robots=client.robots_txt_manager();let ok=robots.is_allowed(&u).await;let delay=robots.crawl_delay(&u).await;println!("{}",json!({"event":"robots_check","url":u,"allowed":ok,"crawl_delay_secs":delay.map(|d|d.as_secs_f64())}));if ok && delay.map(|d|d.as_secs()<=30).unwrap_or(true){accepted.push(u);}}
  let job=WorkerJob{domain,urls:accepted.into_iter().map(|url|WeightedUrl{url,weight:1.0}.into()).collect(),wandering_urls:0};
  JobExecutor::new(job,cfg,sink,client).run().await;
 }}).await;
 sink.finish().await?;Ok(())
}
fn inventory(warc_path:&str,output:&str)->Result<()> {
 let file=warc::WarcFile::open(warc_path)?;let mut out=BufWriter::new(File::create(output)?);let(mut n,mut errors,mut eligible)=(0,0,0);
 for record in file.records(){match record {Ok(r)=>{n+=1;let html=Html::parse(&r.response.body,&r.request.url).ok();let title=html.as_ref().and_then(|h|h.title());let noindex=html.as_ref().map(|h|h.is_no_index()).unwrap_or(true);if title.as_ref().map(|t|!t.trim().is_empty()).unwrap_or(false)&&!noindex{eligible+=1;}
 writeln!(out,"{}",json!({"url":r.request.url,"date":r.request.date,"body_bytes":r.response.body.len(),"payload_type":r.response.payload_type.map(|p|p.to_string()),"title":title,"noindex":noindex,"text_preview":html.as_ref().and_then(|h|h.clean_text()).map(|s|s.chars().take(600).collect::<String>())}))?;},Err(e)=>{errors+=1;if errors<6{eprintln!("WARC error: {e}")}}}}
 println!("{}",json!({"records":n,"parse_errors":errors,"title_and_noindex_eligible":eligible}));Ok(())
}
fn dump_index(path:&str,output:&str)->Result<()> {
 let index=stract::index::Index::open(path)?;let searcher=index.inverted_index.tv_searcher();let schema=index.inverted_index.schema();
 let mut out=BufWriter::new(File::create(output)?);let mut count=0;
 for (segment_ord,seg) in searcher.segment_readers().iter().enumerate(){for doc_id in seg.doc_ids(){let doc:tantivy::TantivyDocument=searcher.doc(tantivy::DocAddress::new(segment_ord as u32,doc_id))?;use tantivy::schema::document::Document;writeln!(out,"{}",doc.to_json(&schema))?;count+=1;}}
 println!("{}",json!({"documents":count,"reported_documents":index.inverted_index.num_documents()}));Ok(())
}
#[tokio::main(worker_threads=4)]
async fn main()->Result<()> {
 tracing_subscriber::fmt().with_ansi(false).with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();
 let a:Vec<_>=std::env::args().collect();match a.get(1).map(String::as_str){Some("crawl")=>crawl(&a[2],&a[3]).await,Some("inventory")=>inventory(&a[2],&a[3]),Some("dump-index")=>dump_index(&a[2],&a[3]),_=>anyhow::bail!("crawl SEEDS OUT | inventory WARC OUT | dump-index INDEX OUT")}
}
