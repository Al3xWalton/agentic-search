// SPDX-License-Identifier: AGPL-3.0-only
//! Build tiny real graph, host-store, index and English model fixtures for feature contracts.
//! All data is synthetic and owned by returned temporary directories. Fixed multiplicities
//! witness counting and content identity; this module never reads retained assets or labels.

use std::path::{Path, PathBuf};
use stract::{
    eval::features::Arguments,
    index::Index,
    webgraph::{Edge, Node, NodeID},
    webpage::{Html, Webpage},
};

/// A private synthetic feature fixture; its directory must outlive every reader.
pub struct Fixture {
    /// Owner of all graphs, stores, indexes, model files and output paths in this fixture.
    pub directory: file_store::temp::TempDir,
    /// CLI-equivalent inputs, with the optional checker omitted until explicitly trained.
    pub args: Arguments,
}

/// Build two duplicate-aware shards and a graph containing a duplicate and a self-edge.
/// Panics on fixture setup failure; never substitutes an empty index for a failed build.
pub fn fixture() -> Fixture {
    fixture_graph(false)
}

/// Add non-HTTP, over-bound, empty and exactly-8192-byte endpoints through the graph writer.
/// All other synthetic indexes and stores match fixture(); setup failures panic.
pub fn fixture_with_rejected_endpoints() -> Fixture {
    fixture_graph(true)
}

fn fixture_graph(rejected_endpoints: bool) -> Fixture {
    let directory = stract::gen_temp_dir().unwrap();
    let root = directory.as_ref();
    let graph = root.join("graph");
    let mut writer = stract::webgraph::Webgraph::open(&graph, 0.into()).unwrap();
    for (from, to) in [
        ("https://a.test/one", "https://b.test/two"),
        ("https://b.test/two", "https://b.test/two"),
        ("https://b.test/two", "https://c.test/three"),
    ] {
        writer
            .insert(Edge {
                from: Node::from(url::Url::parse(from).unwrap()),
                to: Node::from(url::Url::parse(to).unwrap()),
                ..Edge::empty()
            })
            .unwrap();
    }
    writer.commit().unwrap();
    // Separate commits preserve one duplicate through the real graph writer's batch dedup.
    writer
        .insert(Edge {
            from: Node::from(url::Url::parse("https://a.test/one").unwrap()),
            to: Node::from(url::Url::parse("https://b.test/two").unwrap()),
            ..Edge::empty()
        })
        .unwrap();
    writer.commit().unwrap();
    if rejected_endpoints {
        let long = Node::from(
            url::Url::parse(&format!("https://long.test/{}", "a".repeat(9000))).unwrap(),
        );
        // From<String> is crate-test-only; this public writer input preserves the same bytes.
        let empty = Node::from_str_not_validated("");
        assert!(long.as_str().len() > 8192);
        assert!(empty.as_str().is_empty());
        let bound = Node::from(
            url::Url::parse(&format!(
                "https://bound.test/{}",
                "a".repeat(8192 - "bound.test/".len())
            ))
            .unwrap(),
        );
        assert_eq!(bound.as_str().len(), 8192);
        for to in [
            Node::from(url::Url::parse("javascript:void(0)").unwrap()),
            long,
            empty,
            bound,
        ] {
            writer
                .insert(Edge {
                    from: Node::from(url::Url::parse("https://a.test/one").unwrap()),
                    to,
                    ..Edge::empty()
                })
                .unwrap();
            writer.commit().unwrap();
        }
    }
    writer.optimize_read().unwrap();
    drop(writer);
    let centrality = root.join("centrality");
    stores(&centrality);
    let paths = vec![root.join("index-0"), root.join("index-1")];
    build_index(
        &paths[0],
        0,
        &[
            ("https://a.test/one", "alpha", "the quick brown fox"),
            ("https://b.test/two", "beta", "privacy policy"),
        ],
    );
    build_index(
        &paths[1],
        1,
        &[
            ("https://a.test/four", "alpha", "the quick brown fox"),
            ("https://c.test/three", "gamma", "contact information"),
        ],
    );
    Fixture {
        args: Arguments {
            graph,
            centrality,
            index: paths,
            spell_model: None,
            out: root.join("reports/features.json"),
        },
        directory,
    }
}

/// Write actual harmonic stores: a.test positive with rank zero, b.test explicit zero/sentinel.
/// Other hosts remain absent; the parent must be a new fixture directory.
pub fn stores(parent: &Path) {
    let mut values = speedy_kv::Db::<NodeID, f64>::open_or_create(parent.join("harmonic")).unwrap();
    let mut ranks =
        speedy_kv::Db::<NodeID, u64>::open_or_create(parent.join("harmonic_rank")).unwrap();
    for (name, value, rank) in [
        ("https://a.test/", 1.5, 0),
        ("https://b.test/", 0.0, u64::MAX),
    ] {
        let node = Node::from(url::Url::parse(name).unwrap()).into_host().id();
        values.insert(node, value).unwrap();
        ranks.insert(node, rank).unwrap();
    }
    values.commit().unwrap();
    ranks.commit().unwrap();
}

/// Build real stored webpages with fixed timestamps and no centrality-dependent content.
/// Each tuple is (exact URL, title, body); duplicated tuples remain duplicated documents.
pub fn build_index(path: &Path, shard: u64, documents: &[(&str, &str, &str)]) {
    let mut index = Index::open(path).unwrap();
    index.set_shard_id(stract::inverted_index::ShardId::Backbone(shard));
    index.inverted_index.prepare_writer().unwrap();
    for (url, title, body) in documents {
        let html = format!("<html><head><title>{title}</title></head><body><main><p>{body}</p><p>Synthetic stable document material for local feature indexing contracts.</p></main></body></html>");
        let mut page = Webpage::from(Html::parse(&html, url).unwrap());
        page.fetch_time_ms = 500;
        page.inserted_at = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        index.insert(&page).unwrap();
    }
    index.commit().unwrap();
}

/// Train English with 512 correct, 16 typo and 32 alternate-context typo occurrences.
/// Returns the checker directory, not its parent; malformed fixture/trainer state panics.
pub fn train_model(root: &Path) -> PathBuf {
    let first = root.join("training");
    let mut trainer = web_spell::FirstTrainer::new(&first).unwrap();
    for _ in 0..512 {
        trainer.add("the quick brown fox");
    }
    for _ in 0..16 {
        trainer.add("the quik brown fox");
    }
    // The inherited backoff conditional gives identical scores for the two isolated phrases.
    // Alternate synthetic left context makes the specified typo's correction observable.
    for _ in 0..32 {
        trainer.add("a quik brown fox");
    }
    let first = trainer.next_training_step().unwrap();
    let checker = root.join("web-spell/checker");
    web_spell::SecondTrainer::new(vec![first], checker.join("eng"))
        .unwrap()
        .train()
        .unwrap();
    checker
}

/// Resolve only exact `sample` values and `sample/` prefixes in a parsed TOML value tree.
/// Does not expand environment variables, tilde or arbitrary substrings.
pub fn resolve(value: &mut toml::Value, sample: &Path) {
    match value {
        toml::Value::String(text) if text == "sample" => {
            *text = sample.to_str().unwrap().to_owned()
        }
        toml::Value::String(text) if text.starts_with("sample/") => {
            *text = sample.join(&text[7..]).to_str().unwrap().to_owned()
        }
        toml::Value::Table(table) => {
            for (_, value) in table.iter_mut() {
                resolve(value, sample);
            }
        }
        toml::Value::Array(array) => {
            for value in array {
                resolve(value, sample);
            }
        }
        _ => {}
    }
}

/// Deterministic local spelling observer spending 25 ms per invocation.
#[derive(Clone)]
pub struct SpellObserver {
    /// Ordered parsed model text and selected language codes.
    pub calls: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>,
    /// Whether the observer offers replacement of quik with quick.
    pub offer: bool,
}

impl stract::searcher::api::SpellModel for SpellObserver {
    fn correct(&self, text: &str, language: &whatlang::Lang) -> Option<web_spell::Correction> {
        self.calls
            .lock()
            .unwrap()
            .push((text.to_owned(), language.code().to_owned()));
        std::thread::sleep(std::time::Duration::from_millis(25));
        if !self.offer {
            return None;
        }
        let mut correction = web_spell::Correction::empty(text.to_owned());
        for word in text.split_whitespace() {
            correction.push(if word == "quik" {
                web_spell::CorrectionTerm::Corrected {
                    orig: word.to_owned(),
                    correction: "quick".to_owned(),
                }
            } else {
                web_spell::CorrectionTerm::NotCorrected(word.to_owned())
            });
        }
        Some(correction)
    }
}
