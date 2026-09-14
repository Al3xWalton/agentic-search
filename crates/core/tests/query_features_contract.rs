// SPDX-License-Identifier: AGPL-3.0-only
//! Exercise feature boundaries through real synthetic stores, API searches and CLI calls.
//! Every witness owns its data and model. No retained labels, retained indexes, public
//! network, replacement scorer or ranking tuning participates in these contracts.

#[path = "support/query_client.rs"]
mod query_client;
#[path = "support/query_features.rs"]
mod query_features;
#[path = "support/query_index.rs"]
mod query_index;

mod contracts {
    use super::{
        query_client::{Client, Probe},
        query_features as fixture, query_index,
    };
    use serde_json::{json, Value};
    use std::{
        fs,
        io::Cursor,
        os::unix::fs::{symlink, PermissionsExt},
        path::Path,
        process::Command,
        sync::{Arc, Mutex},
        time::Instant,
    };
    use stract::{
        eval::{
            self,
            features::{self, Arguments, ControlIdentity, FeatureCell, Limits},
            EvalError,
        },
        searcher::{
            api::{ApiSearcher, Config, HighlightedSpellCorrection, SpellCorrectionOffer},
            SearchQuery, SearchResult,
        },
    };

    const TEMPLATES: [(&str, &str); 16] = [
        (
            "webgraph",
            include_str!("../../../configs/eval/webgraph.toml"),
        ),
        (
            "index-cc-centrality",
            include_str!("../../../configs/eval/index-cc-centrality.toml"),
        ),
        (
            "index-seeds-centrality",
            include_str!("../../../configs/eval/index-seeds-centrality.toml"),
        ),
        (
            "index-cc-control",
            include_str!("../../../configs/eval/index-cc-control.toml"),
        ),
        (
            "index-seeds-control",
            include_str!("../../../configs/eval/index-seeds-control.toml"),
        ),
        (
            "web-spell",
            include_str!("../../../configs/eval/web-spell.toml"),
        ),
        (
            "api-spell-off",
            include_str!("../../../configs/eval/api-spell-off.toml"),
        ),
        (
            "api-spell-on",
            include_str!("../../../configs/eval/api-spell-on.toml"),
        ),
        (
            "search-cc-centrality",
            include_str!("../../../configs/eval/search-cc-centrality.toml"),
        ),
        (
            "search-seeds-centrality",
            include_str!("../../../configs/eval/search-seeds-centrality.toml"),
        ),
        (
            "search-cc-control",
            include_str!("../../../configs/eval/search-cc-control.toml"),
        ),
        (
            "search-seeds-control",
            include_str!("../../../configs/eval/search-seeds-control.toml"),
        ),
        (
            "api-off",
            include_str!("../../../configs/eval/api-off.toml"),
        ),
        ("api-on", include_str!("../../../configs/eval/api-on.toml")),
        (
            "search-cc",
            include_str!("../../../configs/eval/search-cc.toml"),
        ),
        (
            "search-seeds",
            include_str!("../../../configs/eval/search-seeds.toml"),
        ),
    ];
    fn template(name: &str) -> toml::Value {
        toml::from_str(TEMPLATES.iter().find(|(n, _)| *n == name).unwrap().1).unwrap()
    }
    fn typed<T: serde::de::DeserializeOwned>(name: &str, root: &Path) -> T {
        let mut value = template(name);
        fixture::resolve(&mut value, root);
        value.try_into().unwrap()
    }
    fn query(text: &str) -> SearchQuery {
        SearchQuery {
            query: text.to_owned(),
            num_results: 10,
            count_results_exact: true,
            ..Default::default()
        }
    }
    fn websites(result: SearchResult) -> stract::searcher::WebsitesResult {
        match result {
            SearchResult::Websites(result) => result,
            _ => panic!("expected websites"),
        }
    }
    fn read(path: &Path) -> Value {
        serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
    }
    fn cli(args: &Arguments) -> std::process::Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_stract"));
        command
            .args(["eval", "features", "--graph"])
            .arg(&args.graph)
            .arg("--centrality")
            .arg(&args.centrality);
        for path in &args.index {
            command.arg("--index").arg(path);
        }
        if let Some(path) = &args.spell_model {
            command.arg("--spell-model").arg(path);
        }
        command.arg("--out").arg(&args.out).output().unwrap()
    }
    fn complete(path: &Path) -> bool {
        path.with_extension("complete").exists()
    }

    #[test]
    fn feature_config_templates_complete() {
        for (name, text) in TEMPLATES {
            let value: toml::Value = toml::from_str(text).unwrap();
            fn relative(value: &toml::Value) {
                match value {
                    toml::Value::String(text) => assert!(
                        !text.starts_with('/')
                            && !text.contains('~')
                            && !text.contains("..")
                            && !text.contains('$')
                    ),
                    toml::Value::Table(table) => table.values().for_each(relative),
                    toml::Value::Array(array) => array.iter().for_each(relative),
                    _ => {}
                }
            }
            relative(&value);
            if name == "webgraph" {
                let config: stract::config::WebgraphConstructConfig = value.try_into().unwrap();
                assert_eq!(config.shard, 0.into());
                assert!(config.merge_all_segments);
                assert_eq!(config.limit_warc_files, Some(2));
                assert!(config.canonical_index_path.is_none());
                assert!(config
                    .host_centrality_store_path
                    .ends_with("centrality-empty/harmonic"));
                assert!(config
                    .host_rank_store_path
                    .ends_with("centrality-empty/harmonic_rank"));
            } else if name.starts_with("index-") {
                let config: stract::config::IndexerConfig = value.try_into().unwrap();
                assert_eq!(config.limit_warc_files, Some(1));
                assert_eq!(config.batch_size, 512);
                assert_eq!(config.autocommit_after_num_inserts, 5000);
                assert!(
                    config.host_centrality_threshold.is_none()
                        && config.minimum_clean_words.is_none()
                        && config.page_centrality_store_path.is_none()
                        && config.page_webgraph.is_none()
                        && config.safety_classifier_path.is_none()
                        && config.dual_encoder.is_none()
                );
                assert!(matches!(
                    config.warc_source,
                    stract::config::WarcSource::Local { .. }
                ));
            } else if name == "web-spell" {
                let config: stract::config::WebSpellConfig = value.try_into().unwrap();
                assert_eq!(config.languages, vec![whatlang::Lang::Eng]);
                assert_eq!(config.limit_warc_files, Some(2));
            } else if name.starts_with("api-") {
                let config: stract::config::ApiConfig = value.try_into().unwrap();
                assert_eq!(config.agent_query_planning, name.ends_with("-on"));
                assert_eq!(config.spell_check.is_some(), name.contains("spell"));
                if let Some(spell) = config.spell_check {
                    assert_eq!(spell.correction_config.misspelled_prob, 0.1);
                    assert_eq!(spell.correction_config.correction_threshold, 0.0);
                    assert_eq!(spell.correction_config.lm_prob_weight, 1.0);
                }
            } else {
                let config: stract::config::SearchServerConfig = value.try_into().unwrap();
                assert_eq!(config.shard, u64::from(name.contains("seeds")));
                assert_eq!(config.collector.max_docs_considered, 1000);
            }
        }
        for corpus in ["cc", "seeds"] {
            let mut centrality = template(&format!("index-{corpus}-centrality"));
            let control = template(&format!("index-{corpus}-control"));
            centrality["output_path"] = control["output_path"].clone();
            centrality["host_centrality_store_path"] =
                control["host_centrality_store_path"].clone();
            assert_eq!(centrality, control);
        }
    }

    #[tokio::test]
    async fn centrality_store_parent_contract() {
        let root = stract::gen_temp_dir().unwrap();
        fixture::stores(&root.as_ref().join("centrality-on"));
        let config: stract::config::IndexerConfig = typed("index-cc-centrality", root.as_ref());
        let worker = stract::entrypoint::indexer::worker::IndexingWorker::new(config.into()).await;
        let page=stract::entrypoint::indexer::worker::IndexableWebpage { record:None,url:"https://a.test/page".into(),body:"<html><head><title>Fixture</title></head><body><main>A synthetic text document for the host centrality parent contract with enough content to exercise the ordinary indexer preparation.</main></body></html>".into(),fetch_time_ms:1 };
        let pages = worker.prepare_webpages(&[page]).await;
        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0].host_centrality, 1.5);
        assert_eq!(pages[0].host_centrality_rank, 0);
    }

    #[tokio::test]
    async fn spell_checker_path_contract() {
        let mut fixture = fixture::fixture();
        let checker = fixture::train_model(fixture.directory.as_ref());
        let config: stract::config::ApiConfig = typed("api-spell-on", fixture.directory.as_ref());
        let (local, _index) = query_index::local(
            &[("https://a.test/", "fox", "the quik brown fox")],
            |_, _| {},
        );
        let searcher: ApiSearcher<_, stract::webgraph::Webgraph> = ApiSearcher::new(
            stract::searcher::LocalSearchClient::from(local),
            None,
            stract::bangs::Bangs::empty(),
            config,
        )
        .await;
        let result = websites(searcher.search(&query("the quik brown fox")).await.unwrap());
        assert!(result.spell_correction.is_some());
        assert_eq!(
            serde_json::to_value(result).unwrap()["spellCorrection"]["raw"],
            "the quick brown fox"
        );
        fixture.args.spell_model = Some(checker);
        features::run(fixture.args.clone()).unwrap();
        assert_eq!(
            read(&fixture.args.out)["spell_model"]["loadable_languages"],
            json!(["eng"])
        );
    }

    async fn observed(
        enabled: bool,
    ) -> (
        ApiSearcher<Client, stract::webgraph::Webgraph>,
        Arc<Mutex<Probe>>,
        file_store::temp::TempDir,
    ) {
        let (local, dir) = query_index::local(
            &[
                ("https://a.test/", "fox", "the quik brown fox"),
                ("https://b.test/", "fox", "the quick brown fox"),
            ],
            |_, _| {},
        );
        let probe = Arc::new(Mutex::new(Probe::default()));
        let mut config = Config {
            agent_query_planning: enabled,
            ..Default::default()
        };
        config.widgets.calculator_fetch_currencies_exchange = false;
        config.widgets.thesaurus_paths.clear();
        (
            ApiSearcher::new(
                Client {
                    local,
                    probe: probe.clone(),
                },
                None,
                stract::bangs::Bangs::from_json(
                    r#"[{"t":"fixture","u":"https://example.test/?q={{{s}}}"}]"#,
                ),
                config,
            )
            .await,
            probe,
            dir,
        )
    }
    fn observer(offer: bool) -> fixture::SpellObserver {
        fixture::SpellObserver {
            calls: Arc::new(Mutex::new(Vec::new())),
            offer,
        }
    }

    #[tokio::test]
    async fn spell_offer_invoked_once() {
        let (unconfigured, _unconfigured_dir) = query_index::searcher(
            &[("https://plain.test/", "fox", "the quik brown fox")],
            false,
        )
        .await;
        assert!(websites(unconfigured.search(&query("quik")).await.unwrap())
            .spell_correction
            .is_none());
        for (enabled, text, page, stages) in [
            (false, "the quik brown fox", 0, 1),
            (true, "please find quik omega sigma gamma delta", 0, 4),
            (true, "the quik brown fox", 1, 1),
            (false, "absent quik zorb", 0, 1),
        ] {
            let (searcher, _, _dir) = observed(enabled).await;
            let spy = observer(true);
            let calls = spy.calls.clone();
            let searcher = searcher.with_spell_model(Some(spy));
            let mut query = query(text);
            query.page = page;
            let start = Instant::now();
            let result = websites(searcher.search(&query).await.unwrap());
            assert_eq!(calls.lock().unwrap().len(), 1);
            assert!(result.spell_correction.is_some());
            assert!(result.search_duration_ms >= 25 && start.elapsed().as_millis() >= 25);
            assert_eq!(result.query_plan.unwrap().stages.len(), stages);
        }
        let (searcher, probe, _dir) = observed(true).await;
        let spy = observer(false);
        let calls = spy.calls.clone();
        let searcher = searcher.with_spell_model(Some(spy));
        assert!(websites(searcher.search(&query("quik")).await.unwrap())
            .spell_correction
            .is_none());
        assert_eq!(calls.lock().unwrap().len(), 1);
        calls.lock().unwrap().clear();
        assert!(searcher.search(&query("")).await.is_err());
        assert!(calls.lock().unwrap().is_empty());
        probe.lock().unwrap().failure =
            Some(stract::searcher::wire::QueryServiceError::RetrievalFailed);
        assert!(searcher.search(&query("quik")).await.is_err());
        assert!(calls.lock().unwrap().is_empty());
        probe.lock().unwrap().failure = None;
        assert!(matches!(
            searcher.search(&query("! quik")).await.unwrap(),
            SearchResult::Bang(_)
        ));
        assert!(calls.lock().unwrap().is_empty());
        assert!(matches!(
            searcher.search(&query("!fixture quik")).await.unwrap(),
            SearchResult::Bang(_)
        ));
        assert!(calls.lock().unwrap().is_empty());
        let searcher = searcher.with_spell_model::<fixture::SpellObserver>(None);
        assert!(websites(searcher.search(&query("quik")).await.unwrap())
            .spell_correction
            .is_none());
        assert!(calls.lock().unwrap().is_empty());
        let root = stract::gen_temp_dir().unwrap();
        let checker = fixture::train_model(root.as_ref());
        let model = web_spell::SpellChecker::open(
            checker,
            web_spell::CorrectionConfig {
                correction_threshold: 0.0,
                lm_prob_weight: 1.0,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(websites(
            searcher
                .with_spell_model(Some(model))
                .search(&query("the quik brown fox"))
                .await
                .unwrap()
        )
        .spell_correction
        .is_some());
    }

    fn observations(probe: &Probe) -> Value {
        json!({"sessions":probe.sessions,"searches":probe.searches,"retrievals":probe.retrievals,"original":probe.original_queries,"rendered":probe.rendered_queries,"candidates":probe.candidates,"retrieval_queries":probe.retrieval_queries,"retrieved_urls":probe.retrieved_urls,"rpcs":probe.rpc_count})
    }
    #[tokio::test]
    async fn spell_offers_never_rewrite() {
        for enabled in [false, true] {
            let (searcher, probe, _dir) = observed(enabled).await;
            let request = query("please find the quik brown fox");
            let base =
                serde_json::to_value(websites(searcher.search(&request).await.unwrap())).unwrap();
            let before = observations(&probe.lock().unwrap());
            *probe.lock().unwrap() = Probe::default();
            let spy = observer(true);
            let calls = spy.calls.clone();
            let mut offered = serde_json::to_value(websites(
                searcher
                    .with_spell_model(Some(spy))
                    .search(&request)
                    .await
                    .unwrap(),
            ))
            .unwrap();
            assert_eq!(offered["spellCorrection"]["applied"], false);
            assert!(offered["spellCorrection"]["raw"]
                .as_str()
                .unwrap()
                .contains("quick"));
            offered.as_object_mut().unwrap().remove("spellCorrection");
            assert_eq!(
                features::retrieval_identity(&base).unwrap(),
                features::retrieval_identity(&offered).unwrap()
            );
            assert_eq!(before, observations(&probe.lock().unwrap()));
            assert_eq!(calls.lock().unwrap().len(), 1);
            assert!(probe
                .lock()
                .unwrap()
                .original_queries
                .iter()
                .all(|bytes| bytes == &request.query));
            assert!(probe.lock().unwrap().searches.len() <= 4);
        }
    }

    fn response_offer(offer: Value, wrapped: bool) -> Value {
        let result: stract::searcher::WebsitesResult=serde_json::from_value(json!({"webpages":[],"numHits":{"_type":"exact","value":0},"searchDurationMs":25,"hasMoreResults":false,"spellCorrection":offer})).unwrap();
        if wrapped {
            serde_json::to_value(stract::api::search::ApiSearchResult::Websites(result)).unwrap()
        } else {
            serde_json::to_value(result).unwrap()
        }
    }
    #[test]
    fn spell_offer_escaped() {
        let malicious = "</script><img x=\"a&b\" onload='x'> λ\\";
        let escaped = "&lt;/script&gt;&lt;img x=&quot;a&amp;b&quot; onload=&#39;x&#39;&gt; λ\\";
        let correction: HighlightedSpellCorrection=serde_json::from_value(json!({"raw":format!("{malicious} unchanged&"),"highlighted":[{"kind":"highlighted","text":malicious},{"kind":"normal","text":" unchanged&"}]})).unwrap();
        let value = serde_json::to_value(SpellCorrectionOffer::new(correction.clone())).unwrap();
        assert_eq!(value["raw"], format!("{escaped} unchanged&amp;"));
        assert_eq!(value["highlighted"][0]["text"], escaped);
        assert_eq!(value["highlighted"][1]["text"], " unchanged&amp;");
        assert_eq!(value["highlighted"][0]["kind"], "highlighted");
        assert_eq!(value["highlighted"][1]["kind"], "normal");
        assert_eq!(
            serde_json::to_value(correction).unwrap()["highlighted"][0]["text"],
            malicious
        );
        for wrapped in [false, true] {
            assert_eq!(
                response_offer(value.clone(), wrapped)["spellCorrection"],
                value
            );
        }
    }
    #[test]
    fn spell_offer_applied_false() {
        use utoipa::PartialSchema;
        let offer = SpellCorrectionOffer::new(HighlightedSpellCorrection {
            raw: "quick".into(),
            highlighted: vec![],
        });
        let value = serde_json::to_value(offer).unwrap();
        assert_eq!(value["applied"], false);
        for wrapped in [false, true] {
            assert_eq!(
                response_offer(value.clone(), wrapped)["spellCorrection"]["applied"],
                false
            );
        }
        let mut hostile = value;
        hostile["applied"] = json!(true);
        assert!(serde_json::from_value::<SpellCorrectionOffer>(hostile).is_err());
        let old: stract::searcher::WebsitesResult=serde_json::from_value(json!({"webpages":[],"numHits":{"_type":"exact","value":0},"searchDurationMs":0,"hasMoreResults":false})).unwrap();
        assert!(old.spell_correction.is_none());
        assert!(serde_json::to_value(old)
            .unwrap()
            .get("spellCorrection")
            .is_none());
        assert!(serde_json::to_string(&SpellCorrectionOffer::schema())
            .unwrap()
            .contains("false"));
    }

    #[test]
    fn features_index_arity() {
        let fixture = fixture::fixture();
        assert_eq!(features::input_roots(&fixture.args).unwrap().len(), 4);
        for count in [1, 3] {
            let mut args = fixture.args.clone();
            args.index.resize(count, args.index[0].clone());
            assert!(features::input_roots(&args).is_err());
            assert!(!cli(&args).status.success());
            assert!(!args.out.exists());
        }
        for path in [
            fixture.args.index[0].clone(),
            fixture.args.index[0].join("inverted_index"),
        ] {
            let mut args = fixture.args.clone();
            args.index[1] = path;
            assert!(features::input_roots(&args).is_err());
        }
    }
    #[test]
    fn features_reject_links() {
        if std::env::var_os("FEATURE_SOCKET_CHILD").is_some() {
            let _listener = std::os::unix::net::UnixListener::bind("hostile-socket").unwrap();
            return;
        }
        let fixture = fixture::fixture();
        for (ordinal, name) in ["graph", "centrality", "index", "spell-model", "out"]
            .iter()
            .enumerate()
        {
            let link = fixture.directory.as_ref().join(format!("link-{ordinal}"));
            symlink(&fixture.args.graph, &link).unwrap();
            let mut args = fixture.args.clone();
            match *name {
                "graph" => args.graph = link,
                "centrality" => args.centrality = link,
                "index" => args.index[0] = link,
                "spell-model" => args.spell_model = Some(link),
                _ => args.out = link.join("result.json"),
            }
            let result = cli(&args);
            assert!(!result.status.success());
            let error = String::from_utf8(result.stderr).unwrap();
            assert!(
                error.contains(&format!("--{name}: path has a symlink component")),
                "{error}"
            );
        }
        let dangling = fixture.directory.as_ref().join("dangling");
        symlink(fixture.directory.as_ref().join("missing"), &dangling).unwrap();
        let mut args = fixture.args.clone();
        args.graph = dangling;
        assert!(String::from_utf8(cli(&args).stderr)
            .unwrap()
            .contains("--graph: path has a symlink component"));
        let fifo = fixture.args.graph.join("hostile-fifo");
        let name = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(matches!(
            features::run(fixture.args.clone()),
            Err(EvalError::Argument {
                argument: eval::Argument::Graph,
                ..
            })
        ));
        fs::remove_file(fifo).unwrap();
        let socket = fixture.args.index[0].join("hostile-socket");
        // A child-relative pathname fits Unix socket limits without changing parallel tests' cwd.
        assert!(Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "contracts::features_reject_links"])
            .env("FEATURE_SOCKET_CHILD", "1")
            .current_dir(&fixture.args.index[0])
            .status()
            .unwrap()
            .success());
        assert!(features::run(fixture.args.clone()).is_err());
        fs::remove_file(socket).unwrap();
        let unsafe_root = fixture.directory.as_ref().join("writable");
        fs::create_dir(&unsafe_root).unwrap();
        fs::set_permissions(&unsafe_root, fs::Permissions::from_mode(0o777)).unwrap();
        let mut args = fixture.args.clone();
        args.out = unsafe_root.join("report.json");
        assert!(features::run(args).is_err());
        fs::set_permissions(unsafe_root, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fn snapshots(
        roots: &[std::path::PathBuf],
        limits: &Limits,
    ) -> Result<features::Snapshots, EvalError> {
        features::snapshot_inputs(
            &roots
                .iter()
                .cloned()
                .map(|path| (path, eval::Argument::Index))
                .collect::<Vec<_>>(),
            limits,
        )
    }
    #[test]
    fn features_entry_bound() {
        let dir = stract::gen_temp_dir().unwrap();
        fs::create_dir(dir.as_ref().join("child")).unwrap();
        fs::write(dir.as_ref().join("child/a"), b"a").unwrap();
        fs::write(dir.as_ref().join("b"), b"b").unwrap();
        let limits = Limits {
            entries: 3,
            ..Default::default()
        };
        snapshots(&[dir.as_ref().to_owned()], &limits)
            .unwrap()
            .finish()
            .unwrap();
        fs::write(dir.as_ref().join("c"), b"c").unwrap();
        assert!(matches!(
            snapshots(&[dir.as_ref().to_owned()], &limits),
            Err(EvalError::Argument {
                reason: eval::ArgumentReason::Limit,
                ..
            })
        ));
        fs::remove_file(dir.as_ref().join("c")).unwrap();
        let other = stract::gen_temp_dir().unwrap();
        fs::write(other.as_ref().join("d"), b"d").unwrap();
        assert!(matches!(
            snapshots(
                &[dir.as_ref().to_owned(), other.as_ref().to_owned()],
                &limits
            ),
            Err(EvalError::Argument {
                reason: eval::ArgumentReason::Limit,
                ..
            })
        ));
    }
    #[test]
    fn features_depth_bound() {
        let dir = stract::gen_temp_dir().unwrap();
        fs::create_dir_all(dir.as_ref().join("a/b")).unwrap();
        let limits = Limits {
            depth: 2,
            ..Default::default()
        };
        snapshots(&[dir.as_ref().to_owned()], &limits)
            .unwrap()
            .finish()
            .unwrap();
        fs::create_dir(dir.as_ref().join("a/b/c")).unwrap();
        assert!(matches!(
            snapshots(&[dir.as_ref().to_owned()], &limits),
            Err(EvalError::Argument {
                reason: eval::ArgumentReason::Limit,
                ..
            })
        ));
    }
    #[test]
    fn features_binary_byte_bounds() {
        let limits = Limits {
            file_bytes: 3,
            total_bytes: 5,
            ..Default::default()
        };
        let mut total = 0;
        features::copy_stream(
            &mut Cursor::new(b"abc"),
            &mut Vec::new(),
            3,
            &mut total,
            &limits,
        )
        .unwrap();
        features::copy_stream(
            &mut Cursor::new(b"de"),
            &mut Vec::new(),
            2,
            &mut total,
            &limits,
        )
        .unwrap();
        assert_eq!(total, 5);
        assert_eq!(
            features::copy_stream(
                &mut Cursor::new(b"f"),
                &mut Vec::new(),
                1,
                &mut total,
                &limits
            ),
            Err(EvalError::InputLimit)
        );
        assert_eq!(
            features::copy_stream(
                &mut Cursor::new(b"abcd"),
                &mut Vec::new(),
                3,
                &mut 0,
                &limits
            ),
            Err(EvalError::InputLimit)
        );
        let mut overflowing = u64::MAX;
        assert_eq!(
            features::copy_stream(
                &mut Cursor::new(b"x"),
                &mut Vec::new(),
                1,
                &mut overflowing,
                &limits
            ),
            Err(EvalError::InputLimit)
        );
        let dir = stract::gen_temp_dir().unwrap();
        fs::write(dir.as_ref().join("binary"), b"abcd").unwrap();
        assert!(matches!(
            snapshots(&[dir.as_ref().to_owned()], &limits),
            Err(EvalError::Argument {
                reason: eval::ArgumentReason::Limit,
                ..
            })
        ));
    }
    #[test]
    fn features_metadata_bound() {
        let dir = stract::gen_temp_dir().unwrap();
        let path = dir.as_ref().join("meta.json");
        fs::write(&path, b"{} ").unwrap();
        let limits = Limits {
            metadata_bytes: 3,
            ..Default::default()
        };
        assert_eq!(features::read_metadata(&path, &limits).unwrap(), json!({}));
        fs::write(&path, b"{}  ").unwrap();
        assert_eq!(
            features::read_metadata(&path, &limits),
            Err(EvalError::InputLimit)
        );
        fs::write(&path, b"{!").unwrap();
        assert_eq!(
            features::read_metadata(&path, &limits),
            Err(EvalError::InvalidInput)
        );
        let fixture = fixture::fixture();
        fs::write(
            fixture.args.graph.join("edges/meta.json"),
            b"{\"segments\":[{\"segment_id\":\"../outside\",\"max_doc\":0}]}",
        )
        .unwrap();
        assert!(features::run(fixture.args.clone()).is_err());
        assert!(!complete(&fixture.args.out));
    }
    #[test]
    fn features_create_new_writer() {
        let fixture = fixture::fixture();
        fs::create_dir(fixture.args.out.parent().unwrap()).unwrap();
        fs::write(&fixture.args.out, b"protected existing report").unwrap();
        assert!(matches!(
            features::run(fixture.args.clone()),
            Err(EvalError::Argument {
                argument: eval::Argument::Out,
                ..
            })
        ));
        assert_eq!(
            fs::read(&fixture.args.out).unwrap(),
            b"protected existing report"
        );
        fs::remove_file(&fixture.args.out).unwrap();
        fs::write(
            fixture.args.out.with_extension("complete"),
            b"protected marker",
        )
        .unwrap();
        assert!(features::run(fixture.args.clone()).is_err());
        assert!(!fixture.args.out.exists());
        fs::remove_file(fixture.args.out.with_extension("complete")).unwrap();
        fs::remove_dir(fixture.args.out.parent().unwrap()).unwrap();
        features::run(fixture.args.clone()).unwrap();
        assert_eq!(
            fs::metadata(&fixture.args.out)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(fixture.args.out.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert!(complete(&fixture.args.out));
        struct CannotSerialize;
        impl serde::Serialize for CannotSerialize {
            fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("synthetic serialization failure"))
            }
        }
        let failed = fixture.directory.as_ref().join("serialization/report.json");
        assert!(features::finish_report(
            eval::output::Output::reserve(&failed, false).unwrap(),
            &CannotSerialize,
            &Limits::default()
        )
        .is_err());
        assert!(!complete(&failed));
        let capped = fixture.directory.as_ref().join("capped/report.json");
        assert_eq!(
            features::finish_report(
                eval::output::Output::reserve(&capped, false).unwrap(),
                &json!(0),
                &Limits {
                    metadata_bytes: 1,
                    ..Default::default()
                },
            ),
            Err(EvalError::InputLimit)
        );
        assert!(!complete(&capped));
        let collision = fixture.directory.as_ref().join("collision/report.json");
        fs::create_dir_all(collision.parent().unwrap()).unwrap();
        symlink(&fixture.args.out, &collision).unwrap();
        assert!(eval::output::Output::reserve(&collision, false).is_err());
        fs::remove_file(&collision).unwrap();
        symlink(&fixture.args.out, collision.with_extension("complete")).unwrap();
        assert!(eval::output::Output::reserve(&collision, false).is_err());
    }
    #[test]
    fn features_bounded_store_preflight() {
        let fixture = fixture::fixture();
        let snapshots = features::snapshot_inputs(
            &[(fixture.args.centrality.clone(), eval::Argument::Centrality)],
            &Limits::default(),
        )
        .unwrap();
        let store = snapshots.paths()[0].join("harmonic");
        let metadata = store.join("meta.json");
        let before = fs::read(&metadata).unwrap();
        let meta: Value = serde_json::from_slice(&before).unwrap();
        let bloom = store.join(format!("{}.blm", meta["segments"][0].as_str().unwrap()));
        features::preflight_store(
            &store,
            &Limits {
                metadata_bytes: 2048,
                ..Default::default()
            },
        )
        .unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(bloom)
            .unwrap()
            .set_len(2049)
            .unwrap();
        let limits = Limits {
            metadata_bytes: 2048,
            ..Default::default()
        };
        assert!(matches!(
            features::preflight_store(&store, &limits),
            Err(EvalError::Argument {
                argument: eval::Argument::Centrality,
                reason: eval::ArgumentReason::Limit
            })
        ));
        assert_eq!(fs::read(metadata).unwrap(), before);
        snapshots.finish().unwrap();
    }
    #[test]
    fn features_bounded_bloom_decode() {
        let fixture = fixture::fixture();
        let snapshots = features::snapshot_inputs(
            &[(fixture.args.centrality.clone(), eval::Argument::Centrality)],
            &Limits::default(),
        )
        .unwrap();
        let store = snapshots.paths()[0].join("harmonic");
        let metadata = store.join("meta.json");
        let before = fs::read(&metadata).unwrap();
        let meta: Value = serde_json::from_slice(&before).unwrap();
        let bloom = store.join(format!("{}.blm", meta["segments"][0].as_str().unwrap()));
        let genuine = fs::read(&bloom).unwrap();
        features::preflight_store(&store, &Limits::default()).unwrap();
        let prefix = bincode::encode_to_vec(1u64 << 40, common::bincode_config()).unwrap();
        assert!(genuine.len() > prefix.len() && genuine.len() < 2048);
        let mut claimed = genuine.clone();
        claimed[..prefix.len()].copy_from_slice(&prefix);
        let mut trailing = genuine;
        trailing.push(0);
        for malformed in [claimed, trailing] {
            fs::write(&bloom, malformed).unwrap();
            assert!(matches!(
                features::preflight_store(&store, &Limits::default()),
                Err(EvalError::Argument {
                    argument: eval::Argument::Centrality,
                    reason: eval::ArgumentReason::Structure
                })
            ));
            assert_eq!(fs::read(&metadata).unwrap(), before);
        }
        snapshots.finish().unwrap();
    }
    #[test]
    fn features_output_excludes_inputs() {
        let mut fixture = fixture::fixture();
        fixture.args.spell_model = Some(fixture::train_model(fixture.directory.as_ref()));
        for root in features::input_roots(&fixture.args).unwrap() {
            let mut args = fixture.args.clone();
            args.out = root.join("diagnostic.json");
            assert!(features::run(args.clone()).is_err());
            assert!(!args.out.exists());
        }
        let mut args = fixture.args.clone();
        args.out = "relative.json".into();
        assert!(features::run(args.clone()).is_err());
        args.out = std::env::current_dir()
            .unwrap()
            .join("features-must-not-write.json");
        assert!(features::run(args.clone()).is_err());
        assert!(!args.out.exists());
    }
    #[test]
    fn features_without_spell_model() {
        let fixture = fixture::fixture();
        let result = cli(&fixture.args);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let value = read(&fixture.args.out);
        assert_eq!(value["spell_model"], Value::Null);
        assert_eq!(value["spell_model_status"], "not_supplied");
        assert_eq!(value["inputs"].as_array().unwrap().len(), 4);
        let mut args = fixture.args.clone();
        args.out = fixture.directory.as_ref().join("other/features.json");
        args.spell_model = Some(fixture.directory.as_ref().join("missing"));
        assert!(!cli(&args).status.success());
        assert!(!complete(&args.out));
        fs::create_dir(args.spell_model.as_ref().unwrap()).unwrap();
        assert!(features::run(args.clone()).is_err());
        assert!(!complete(&args.out));
        let checker = fixture::train_model(fixture.directory.as_ref());
        let counts = checker.join("eng/stupid_backoff/n_counts.bin");
        fs::write(&counts, b"\xfc\xff\xff\xff\xff").unwrap();
        args.spell_model = Some(checker);
        assert!(features::run(args.clone()).is_err());
        assert!(!complete(&args.out));
    }
    #[test]
    fn features_coverage_counts() {
        let fixture = fixture::fixture();
        features::run(fixture.args.clone()).unwrap();
        let value = read(&fixture.args.out);
        for (key, expected) in [
            ("page_nodes", 3),
            ("host_nodes", 3),
            ("edge_records", 4),
            ("unique_page_edges", 3),
            ("unique_host_edges", 3),
            ("segments", 1),
        ] {
            assert_eq!(value["graph"][key], expected, "{key}");
        }
        assert_eq!(value["graph"]["rejected_endpoints"]["occurrences"], 0);
        assert_eq!(value["indexes"][0]["documents"], 2);
        assert_eq!(value["indexes"][1]["documents"], 2);
        assert_eq!(
            value["centrality"]["union"]["nonzero"],
            json!({"numerator":1,"denominator":3,"fraction":1.0/3.0})
        );
        assert_eq!(value["centrality"]["union"]["rank"]["numerator"], 1);
        assert_eq!(value["centrality"]["union"]["explicit_zero"], 1);
        assert_eq!(value["centrality"]["union"]["absent"], 1);
        for shard in [0, 1] {
            assert_eq!(
                value["centrality"]["shards"][shard]["nonzero"]["numerator"],
                1
            );
            assert_eq!(
                value["centrality"]["shards"][shard]["nonzero"]["denominator"],
                2
            );
        }
    }
    #[test]
    fn features_graph_counts_rejected_endpoints() {
        let fixture = fixture::fixture_with_rejected_endpoints();
        features::run(fixture.args.clone()).unwrap();
        let value = read(&fixture.args.out);
        assert_eq!(
            value["graph"]["rejected_endpoints"],
            json!({"occurrences":3,"empty_name":1,"over_long_name":1,"non_http_name":1})
        );
        for (key, expected) in [("page_nodes", 7), ("host_nodes", 6), ("edge_records", 8)] {
            assert_eq!(value["graph"][key], expected, "{key}");
        }
        assert_eq!(value["centrality"]["union"]["nonzero"]["denominator"], 3);
        assert_eq!(value["centrality"]["union"]["rank"]["denominator"], 3);
        for shard in [0, 1] {
            for kind in ["nonzero", "rank"] {
                assert_eq!(value["centrality"]["shards"][shard][kind]["denominator"], 2);
            }
        }
    }
    #[test]
    fn features_source_identity_stable() {
        let fixture = fixture::fixture();
        let roots = features::input_roots(&fixture.args).unwrap();
        let before = features::tree_identities(&roots, &Limits::default()).unwrap();
        features::run(fixture.args.clone()).unwrap();
        assert_eq!(
            before,
            features::tree_identities(&roots, &Limits::default()).unwrap()
        );
        let mut args = fixture.args.clone();
        args.out = fixture.directory.as_ref().join("changed/report.json");
        let changed = args.index[0].join("added");
        let result = features::run_with(args.clone(), Limits::default(), || {
            fs::write(&changed, b"source changed after snapshot").unwrap()
        });
        assert_eq!(
            result,
            Err(EvalError::Argument {
                argument: eval::Argument::Out,
                reason: eval::ArgumentReason::Changed
            })
        );
        assert!(!complete(&args.out));
        let snapshots = snapshots(&roots, &Limits::default()).unwrap();
        let paths = snapshots.paths().to_vec();
        snapshots.finish().unwrap();
        assert!(paths.iter().all(|path| !path.exists()));
    }

    fn identity() -> ControlIdentity {
        ControlIdentity {
            counts: vec![(0, 2), (1, 2)],
            documents: vec!["a".repeat(64), "b".repeat(64)],
            rankings: (0..16).map(|i| json!({
                "query": features::FIXED_CONTROL_QUERIES[i % 8],
                "mode": if i < 8 {"off"} else {"on"}, "status": 200, "error": null,
                "response": {"webpages":[{"url":"https://a.test/", "planStage":"strict", "snippet":"fixture"}],
                    "searchDurationMs":1, "queryPlan":{"mode":if i < 8 {"strict_only"} else {"staged"}, "version":1,
                    "stages":[{"id":"strict", "renderedQuery":"fixture", "elapsedMs":1}]}}
            })).collect(),
        }
    }
    fn comparable(retained: &ControlIdentity, control: &ControlIdentity) -> bool {
        retained
            .comparable(control, control, [(0, 2), (1, 2)])
            .comparable()
    }
    #[test]
    fn centrality_control_identity() {
        let retained = identity();
        assert!(comparable(&retained, &retained));
        for counts in [
            vec![(0, 1), (1, 3)],
            vec![(1, 2), (0, 2)],
            vec![(0, 2), (1, 1)],
            vec![(0, 2), (1, 3)],
            vec![(0, 4)],
        ] {
            let mut control = retained.clone();
            control.counts = counts;
            let verdict = retained.comparable(&control, &retained, [(0, 2), (1, 2)]);
            assert!(!verdict.counts_match());
            assert!(!verdict.comparable());
        }
        assert!(!identity()
            .comparable(&retained, &retained, [(0, 7), (1, 11)])
            .comparable());
    }
    #[test]
    fn centrality_control_content_identity() {
        let retained = identity();
        let mut control = retained.clone();
        control.documents[0] = "c".repeat(64);
        assert!(!comparable(&retained, &control));
        let a = fixture::fixture();
        let identities = features::document_identities(&a.args.index, &Limits::default()).unwrap();
        let b = fixture::fixture();
        let equal = features::document_identities(&b.args.index, &Limits::default()).unwrap();
        assert_eq!(identities[0].content_sha256, equal[0].content_sha256);
        let changed = b.directory.as_ref().join("changed-index");
        fixture::build_index(
            &changed,
            0,
            &[
                ("https://a.test/one", "ALTERED TITLE", "the quick brown fox"),
                ("https://b.test/two", "beta", "privacy policy"),
            ],
        );
        let altered =
            features::document_identities(&[changed, b.args.index[1].clone()], &Limits::default())
                .unwrap();
        assert_eq!(identities[0].documents, altered[0].documents);
        assert_ne!(identities[0].content_sha256, altered[0].content_sha256);
        let duplicate = b.directory.as_ref().join("duplicate-index");
        fixture::build_index(
            &duplicate,
            0,
            &[
                ("https://a.test/one", "alpha", "the quick brown fox"),
                ("https://a.test/one", "alpha", "the quick brown fox"),
            ],
        );
        let duplicates = features::document_identities(
            &[duplicate, b.args.index[1].clone()],
            &Limits::default(),
        )
        .unwrap();
        assert_eq!(duplicates[0].records.len(), 2);
        assert_eq!(duplicates[0].records[0], duplicates[0].records[1]);
    }
    #[test]
    fn centrality_control_fixed_queries() {
        let retained = identity();
        for key in ["url", "planStage", "snippet"] {
            let mut control = retained.clone();
            control.rankings[3]["response"]["webpages"][0][key] = json!("changed");
            assert!(!comparable(&retained, &control));
        }
        let mut one = json!({"webpages":[],"searchDurationMs":1,"queryPlan":{"stages":[{"id":"strict","elapsedMs":1,"renderedQuery":"same"}]}});
        let expected = features::retrieval_identity(&one).unwrap();
        one["searchDurationMs"] = json!(999);
        one["queryPlan"]["stages"][0]["elapsedMs"] = json!(998);
        assert_eq!(expected, features::retrieval_identity(&one).unwrap());
        assert_eq!(features::FIXED_CONTROL_QUERIES[0], "example");
        assert_eq!(
            features::FIXED_CONTROL_QUERIES[7],
            "please find information about software documentation"
        );
        assert!(features::fixed_query_identities(&[]).is_err());
    }
    fn control_files(
        root: &Path,
        retained: &ControlIdentity,
        control: &ControlIdentity,
    ) -> (std::path::PathBuf, [std::path::PathBuf; 4]) {
        let indexes = |identity: &ControlIdentity| {
            identity.counts.iter().zip(&identity.documents)
            .map(|((shard, documents), digest)| json!({"shard":shard,"documents":documents,"content_sha256":digest})).collect::<Vec<_>>()
        };
        let identities = root.join("identities.json");
        fs::write(&identities, serde_json::to_vec(&json!({"retained":indexes(retained),"reindexed":indexes(control),"centrality":indexes(control)})).unwrap()).unwrap();
        let paths = std::array::from_fn(|i| root.join(format!("observations-{i}.json")));
        for (i, path) in paths.iter().enumerate() {
            let rows = if i < 2 {
                &retained.rankings
            } else {
                &control.rankings
            };
            let rows: Vec<_> = rows.iter().skip((i % 2) * 8).take(8).collect();
            fs::write(path, serde_json::to_vec(&json!({"rows": rows})).unwrap()).unwrap();
        }
        (identities, paths)
    }
    #[test]
    fn control_gate_precedes_held_out() {
        let dir = stract::gen_temp_dir().unwrap();
        let digest = "a".repeat(64);
        let mut id = identity();
        id.rankings.clear();
        let (identities, observations) = control_files(dir.as_ref(), &id, &id);
        let pending =
            features::control_from_files(&identities, &observations, [(0, 2), (1, 2)], &digest)
                .unwrap();
        assert!(!pending.completed());
        assert!(features::require_control_before_held_out(
            &pending,
            true,
            FeatureCell::BaseOff,
            &digest,
            &identities,
            &observations,
            [(0, 2), (1, 2)]
        )
        .is_err());
        let id = identity();
        let (identities, observations) = control_files(dir.as_ref(), &id, &id);
        let passed =
            features::control_from_files(&identities, &observations, [(0, 2), (1, 2)], &digest)
                .unwrap();
        features::require_control_before_held_out(
            &passed,
            true,
            FeatureCell::CentralityOn,
            &digest,
            &identities,
            &observations,
            [(0, 2), (1, 2)],
        )
        .unwrap();
        assert!(features::require_control_before_held_out(
            &passed,
            true,
            FeatureCell::SpellOn,
            &"b".repeat(64),
            &identities,
            &observations,
            [(0, 2), (1, 2)]
        )
        .is_err());
        let mut other = id.clone();
        other.documents[0] = "f".repeat(64);
        let (identities, observations) = control_files(dir.as_ref(), &id, &other);
        let failed =
            features::control_from_files(&identities, &observations, [(0, 2), (1, 2)], &digest)
                .unwrap();
        for cell in [
            FeatureCell::BaseOff,
            FeatureCell::BaseOn,
            FeatureCell::SpellOff,
            FeatureCell::SpellOn,
        ] {
            features::require_control_before_held_out(
                &failed,
                true,
                cell,
                &digest,
                &identities,
                &observations,
                [(0, 2), (1, 2)],
            )
            .unwrap();
        }
        assert!(features::require_control_before_held_out(
            &failed,
            true,
            FeatureCell::CentralityOff,
            &digest,
            &identities,
            &observations,
            [(0, 2), (1, 2)]
        )
        .is_err());
    }
    #[test]
    fn control_verdict_is_derived() {
        let dir = stract::gen_temp_dir().unwrap();
        let id = identity();
        let mut other = id.clone();
        other.documents[0] = "f".repeat(64);
        let (identities, observations) = control_files(dir.as_ref(), &id, &other);
        let digest = "a".repeat(64);
        let verdict =
            features::control_from_files(&identities, &observations, [(0, 2), (1, 2)], &digest)
                .unwrap();
        assert!(verdict.completed());
        assert!(!verdict.comparable());
        let path = dir.as_ref().join("verdict.json");
        let mut forged = json!(verdict);
        forged["comparable"] = json!(true);
        fs::write(&path, serde_json::to_vec(&forged).unwrap()).unwrap();
        let forged = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            features::require_control_before_held_out(
                &forged,
                true,
                FeatureCell::CentralityOn,
                &digest,
                &identities,
                &observations,
                [(0, 2), (1, 2)]
            ),
            Err(EvalError::IdentityMismatch)
        );
        let (identities, observations) = control_files(dir.as_ref(), &id, &id);
        let genuine =
            features::control_from_files(&identities, &observations, [(0, 2), (1, 2)], &digest)
                .unwrap();
        features::require_control_before_held_out(
            &genuine,
            true,
            FeatureCell::CentralityOn,
            &digest,
            &identities,
            &observations,
            [(0, 2), (1, 2)],
        )
        .unwrap();
    }
    fn diagnostics() -> Value {
        json!({"indexes":[{"shard":0,"documents":2,"content_sha256":"d".repeat(64)}, {"shard":1,"documents":2,"content_sha256":"e".repeat(64)}]})
    }
    fn run_identity(cell: FeatureCell) -> Value {
        let mut run = raw_run_identity(cell);
        for (ordinal, digest) in ["d", "e"].into_iter().enumerate() {
            run["indexes"][ordinal]["manifest"]["content_sha256"] = json!(digest.repeat(64));
        }
        run
    }
    fn raw_run_identity(cell: FeatureCell) -> Value {
        let centrality = cell.centrality();
        let mut api = json!({"agent_query_planning":cell.planner()==eval::Planner::On});
        if cell.spelling() {
            api["spell_check"] = json!({"path":"/private/checker"});
        }
        json!({"schema_version":1,"cell":cell,"planner_expectation":cell.planner(),"executable":{"sha256":"a".repeat(64),"dirty_tree_sha256":"b".repeat(64),"revision":"synthetic"},"request":{"numResults":10},"timing_policy":"fixed","endpoint":"http://127.0.0.1:57300","metric_version":"spike573-v1","corpus":{"files":"same"},"labels":{"sha256":"c".repeat(64)},"rows":[{"id":"x","query":"fixture","category":"factual","acceptable_urls":["https://a.test/"]}],"configs":[{"resolved":{"index_path":if centrality {"/private/centrality-0"} else {"/private/base-0"},"shard":0}},{"resolved":{"index_path":if centrality {"/private/centrality-1"} else {"/private/base-1"},"shard":1}},{"resolved":api}],"indexes":[{"manifest":{"documents":2,"pre_open_files":if centrality {"new0"} else {"base0"}}},{"manifest":{"documents":2,"pre_open_files":if centrality {"new1"} else {"base1"}}}],"service":{"manifest":{"verified":true,"total_documents":4}}})
    }
    #[test]
    fn feature_matrix_separate_contrasts() {
        for feature in [
            FeatureCell::CentralityOff,
            FeatureCell::CentralityOn,
            FeatureCell::SpellOff,
            FeatureCell::SpellOn,
        ] {
            let expected = if feature.planner() == eval::Planner::On {
                FeatureCell::BaseOn
            } else {
                FeatureCell::BaseOff
            };
            assert_eq!(features::matching_base(feature), expected);
            let base = run_identity(expected);
            let after = run_identity(feature);
            features::validate_contrast(&base, &after, &diagnostics()).unwrap();
            let wrong = run_identity(if expected == FeatureCell::BaseOn {
                FeatureCell::BaseOff
            } else {
                FeatureCell::BaseOn
            });
            assert!(features::validate_contrast(&wrong, &after, &diagnostics()).is_err());
            for key in [
                "executable",
                "request",
                "timing_policy",
                "labels",
                "configs",
            ] {
                let mut changed = after.clone();
                changed[key] = Value::Null;
                assert!(
                    features::validate_contrast(&base, &changed, &diagnostics()).is_err(),
                    "{key}"
                );
            }
            let mut changed = after.clone();
            changed["rows"][0]["query"] = json!("new query");
            assert!(features::validate_contrast(&base, &changed, &diagnostics()).is_err());
        }
        assert!(serde_json::from_value::<FeatureCell>(json!("centrality-spell-on")).is_err());
        assert_eq!(
            features::matching_base(FeatureCell::BaseOff),
            FeatureCell::BaseOff
        );
        assert_eq!(
            features::matching_base(FeatureCell::BaseOn),
            FeatureCell::BaseOn
        );
        let mut combined = run_identity(FeatureCell::CentralityOn);
        combined["configs"][2]["resolved"]["spell_check"] = json!({"path":"checker"});
        assert!(features::validate_contrast(
            &run_identity(FeatureCell::BaseOn),
            &combined,
            &diagnostics()
        )
        .is_err());
    }
    #[test]
    fn feature_contrast_binds_index_identity() {
        let base = run_identity(FeatureCell::BaseOff);
        for feature in [FeatureCell::CentralityOff, FeatureCell::SpellOff] {
            let mut run = run_identity(feature);
            features::validate_contrast(&base, &run, &diagnostics()).unwrap();
            run["indexes"][0]["manifest"]["content_sha256"] = json!("f".repeat(64));
            assert_eq!(
                features::validate_contrast(&base, &run, &diagnostics()),
                Err(EvalError::IdentityMismatch)
            );
        }
    }
    #[test]
    fn spell_offer_bincode_rejects_applied() {
        #[derive(bincode::Encode)]
        struct WireOffer {
            correction: HighlightedSpellCorrection,
            applied: bool,
        }
        for applied in [false, true] {
            let wire = WireOffer {
                correction: HighlightedSpellCorrection {
                    raw: "fixture".into(),
                    highlighted: Vec::new(),
                },
                applied,
            };
            let bytes = bincode::encode_to_vec(wire, bincode::config::standard()).unwrap();
            let decoded = bincode::decode_from_slice::<SpellCorrectionOffer, _>(
                &bytes,
                bincode::config::standard(),
            );
            assert_eq!(decoded.is_err(), applied);
            let borrowed = bincode::borrow_decode_from_slice::<SpellCorrectionOffer, _>(
                &bytes,
                bincode::config::standard(),
            );
            assert_eq!(borrowed.is_err(), applied);
        }
    }
    #[test]
    fn features_reject_hard_links() {
        let fixture = fixture::fixture();
        let file = fixture.args.graph.join("linked-input");
        fs::write(&file, b"synthetic bytes").unwrap();
        let alias = fixture.directory.as_ref().join("alias");
        fs::hard_link(&file, &alias).unwrap();
        assert!(matches!(
            features::run(fixture.args.clone()),
            Err(EvalError::Argument {
                argument: eval::Argument::Graph,
                reason: eval::ArgumentReason::Components
            })
        ));
        assert!(matches!(
            features::open_input(&file),
            Err(EvalError::UnsafePath)
        ));
        fs::remove_file(alias).unwrap();
        features::open_input(&file).unwrap();
    }
    #[test]
    fn features_spell_model_entry_bound() {
        let dir = stract::gen_temp_dir().unwrap();
        for name in ["one", "two", "three"] {
            fs::write(dir.as_ref().join(name), b"synthetic model-root entry").unwrap();
        }
        let limits = Limits {
            entries: 2,
            ..Default::default()
        };
        assert!(matches!(
            features::preflight_model(dir.as_ref(), &limits),
            Err(EvalError::Argument {
                argument: eval::Argument::SpellModel,
                reason: eval::ArgumentReason::Limit
            })
        ));
    }
}
