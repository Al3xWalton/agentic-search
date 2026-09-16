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
        os::unix::fs::{symlink, DirBuilderExt, MetadataExt, PermissionsExt},
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
    fn features_accepts_trusted_temporary_roots() {
        let temporary = std::env::temp_dir().canonicalize().unwrap();
        let root = [
            "/dev/shm",
            "/var/tmp",
            "/private/var/tmp",
            "/private/tmp",
            "/tmp",
        ]
        .into_iter()
        .filter_map(|candidate| Path::new(candidate).canonicalize().ok())
        .find(|candidate| {
            fs::symlink_metadata(candidate).is_ok_and(|metadata| {
                metadata.is_dir()
                    && eval::input::trusted_temporary_root(
                        candidate,
                        metadata.uid(),
                        metadata.mode(),
                    )
                    && !temporary.starts_with(candidate)
            })
        });
        let Some(root) = root else {
            eprintln!(
                "SKIP features_accepts_trusted_temporary_roots: no trusted root outside {}",
                temporary.display()
            );
            return;
        };
        eprintln!("trusted temporary witness root: {}", root.display());

        struct PrivateDirectory(std::path::PathBuf);
        impl PrivateDirectory {
            fn new(parent: &Path) -> Self {
                let path = parent.join(format!("stract-features-{}", uuid::Uuid::new_v4()));
                fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
                Self(path)
            }
        }
        impl Drop for PrivateDirectory {
            fn drop(&mut self) {
                fs::remove_dir_all(&self.0).unwrap();
            }
        }

        let accepted = PrivateDirectory::new(&root);
        let args = fixture::fixture_at(&accepted.0);
        assert_eq!(features::input_roots(&args).unwrap().len(), 4);
        features::run(args.clone()).unwrap();
        let value = read(&args.out);
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
        assert_eq!(value["indexes"][0]["documents"], 2);
        assert_eq!(value["indexes"][1]["documents"], 2);
        assert_eq!(value["centrality"]["union"]["nonzero"]["numerator"], 1);
        assert_eq!(value["centrality"]["union"]["nonzero"]["denominator"], 3);
        assert_eq!(value["source_unchanged"], true);

        let outside =
            PrivateDirectory::new(&std::env::current_dir().unwrap().canonicalize().unwrap());
        let invalid = fixture::fixture_at(&outside.0);
        assert_eq!(
            features::input_roots(&invalid).unwrap_err(),
            EvalError::Argument {
                argument: eval::Argument::Graph,
                reason: eval::ArgumentReason::IndexTemporary,
            }
        );
        for alias in [
            root.clone(),
            format!("{}/", root.display()).into(),
            format!("{}/.", root.display()).into(),
        ] {
            for argument in [
                eval::Argument::Graph,
                eval::Argument::Centrality,
                eval::Argument::Index,
                eval::Argument::SpellModel,
            ] {
                let mut root_itself = args.clone();
                match argument {
                    eval::Argument::Graph => root_itself.graph = alias.clone(),
                    eval::Argument::Centrality => root_itself.centrality = alias.clone(),
                    eval::Argument::Index => root_itself.index[0] = alias.clone(),
                    eval::Argument::SpellModel => root_itself.spell_model = Some(alias.clone()),
                    _ => unreachable!(),
                }
                assert_eq!(
                    features::input_roots(&root_itself).unwrap_err(),
                    EvalError::Argument {
                        argument,
                        reason: eval::ArgumentReason::IndexTemporary,
                    },
                    "{argument:?} root alias {}",
                    alias.display()
                );
            }
        }
        let mut dotted_child = args;
        dotted_child.graph = dotted_child.graph.join(".");
        assert!(features::input_roots(&dotted_child).is_err());
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
                "response": {"_type":"websites","numHits":{"_type":"exact","value":1},"hasMoreResults":false,
                    "webpages":[{"url":"https://a.test/", "title":"fixture", "planStage":"strict", "snippet":{"text":"fixture"}}],
                    "searchDurationMs":1, "queryPlan":{"mode":if i < 8 {"strict_only"} else {"staged"}, "version":1,
                    "stages":[{"id":"strict", "renderedQuery":"fixture", "elapsedMs":1}]}}
            })).collect(),
        }
    }
    fn comparable(
        retained: &ControlIdentity,
        control: &ControlIdentity,
        centrality: &ControlIdentity,
    ) -> bool {
        retained
            .comparable(control, centrality, [(0, 2), (1, 2)])
            .comparable()
    }
    #[test]
    fn centrality_control_identity() {
        let retained = identity();
        assert!(comparable(&retained, &retained, &retained));
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
        for expected in [[(1, 2), (0, 2)], [(0, u64::MAX), (1, 2)]] {
            assert!(!retained
                .comparable(&retained, &retained, expected)
                .completed());
        }
        let mut centrality = retained.clone();
        centrality.counts = vec![(0, 1), (1, 3)];
        let verdict = retained.comparable(&retained, &centrality, [(0, 2), (1, 2)]);
        assert!(verdict.completed());
        assert!(verdict.counts_match());
        assert!(!verdict.content_matches());
        assert!(!verdict.centrality_content_matches());
        assert!(!verdict.comparable());
        let mut malformed = retained.clone();
        malformed.counts.clear();
        malformed.documents.clear();
        assert!(!retained
            .comparable(&malformed, &malformed, [(0, 2), (1, 2)])
            .content_matches());
    }
    #[test]
    fn centrality_control_same_binary_base() {
        let control = identity();
        let centrality = identity();
        let mut retained = identity();
        retained.counts = vec![(0, 8), (1, 3)];
        retained.documents = vec!["c".repeat(64), "f".repeat(64)];
        retained.rankings[0]["response"]["numHits"]["value"] = json!(200);
        retained.rankings[0]["response"]["webpages"] = json!([]);
        let verdict = retained.comparable(&control, &centrality, [(0, 2), (1, 2)]);
        assert!(verdict.completed());
        assert!(verdict.counts_match());
        assert!(verdict.content_matches());
        assert!(verdict.rankings_match());
        assert!(verdict.centrality_content_matches());
        assert!(verdict.comparable());
    }
    #[test]
    fn centrality_control_content_identity() {
        let retained = identity();
        let mut control = retained.clone();
        control.documents[0] = "c".repeat(64);
        assert!(!comparable(&retained, &control, &retained));
        assert!(!retained
            .comparable(&control, &retained, [(0, 2), (1, 2)])
            .content_matches());
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
    fn document_identity_ignores_keywords() {
        let root = stract::gen_temp_dir().unwrap();
        let pairs: [Vec<_>; 3] = std::array::from_fn(|pair| {
            (0..2)
                .map(|shard| root.as_ref().join(format!("pair-{pair}-{shard}")))
                .collect()
        });
        for (pair, paths) in pairs.iter().enumerate() {
            for (shard, path) in paths.iter().enumerate() {
                fixture::build_index_with_keywords(
                    path,
                    shard as u64,
                    &[
                        (
                            "https://a.test/one",
                            if pair == 2 && shard == 0 {
                                "ALTERED TITLE"
                            } else {
                                "alpha"
                            },
                            "the quick brown fox",
                        ),
                        ("https://b.test/two", "beta", "privacy policy"),
                    ],
                    if pair == 0 {
                        &["alpha", "beta", "gamma"]
                    } else {
                        &["beta", "alpha", "delta"]
                    },
                    if pair == 0 { 0.0 } else { 1.5 },
                    if pair == 0 { u64::MAX } else { 2 },
                );
            }
        }
        for (a, b) in pairs[0].iter().zip(&pairs[1]) {
            let a = fixture::stored_keywords(a);
            let b = fixture::stored_keywords(b);
            assert_ne!(a, b);
            for ((url_a, words_a), (url_b, words_b)) in a.iter().zip(&b) {
                assert_eq!(url_a, url_b);
                assert!(words_a.contains("gamma") && !words_a.contains("delta"));
                assert!(words_b.contains("delta") && !words_b.contains("gamma"));
                assert!(words_a.find("alpha").unwrap() < words_a.find("beta").unwrap());
                assert!(words_b.find("beta").unwrap() < words_b.find("alpha").unwrap());
            }
        }
        let identities = pairs
            .iter()
            .map(|paths| features::document_identities(paths, &Limits::default()).unwrap())
            .collect::<Vec<_>>();
        for (a, b) in identities[0].iter().zip(&identities[1]) {
            assert_eq!(a.records, b.records);
            assert_eq!(a.content_sha256, b.content_sha256);
            assert_eq!(a.documents, b.documents);
            assert_eq!(a.shard, b.shard);
        }
        assert_ne!(
            identities[0][0].content_sha256,
            identities[2][0].content_sha256
        );
        assert_eq!(
            identities[0][1].content_sha256,
            identities[2][1].content_sha256
        );
    }
    #[test]
    fn centrality_control_fixed_queries() {
        let retained = identity();
        let control = identity();
        let mut centrality = identity();
        for row in &mut centrality.rankings {
            row["response"]["webpages"][0]["url"] = json!("https://other.test/");
            row["response"]["webpages"][0]["title"] = json!("another title");
            row["response"]["webpages"][0]["snippet"] =
                json!({"different":{"rich":[1,null,"value"]}});
            row["response"]["numHits"]["value"] = json!(42);
            row["response"]["hasMoreResults"] = json!(true);
            row["response"]["searchDurationMs"] = json!(12);
        }
        centrality.rankings[0]["response"]["webpages"] = json!([]);
        centrality.rankings[8]["response"]["queryPlan"]["stages"]
            .as_array_mut()
            .unwrap()
            .push(json!({"id":"relaxed","renderedQuery":"other","elapsedMs":5}));
        centrality.rankings[8]["response"]["webpages"][0]["planStage"] = json!("relaxed");
        assert!(comparable(&retained, &control, &centrality));
        let mut count_type = control.clone();
        count_type.rankings[0]["response"]["numHits"]["_type"] = json!("approximate");
        let mismatch = retained.comparable(&control, &count_type, [(0, 2), (1, 2)]);
        assert!(mismatch.completed());
        assert!(!mismatch.rankings_match());
        assert!(!mismatch.comparable());
        for pair in 0..3 {
            let mut identities = [identity(), identity(), identity()];
            identities[pair].rankings.pop();
            let verdict =
                identities[0].comparable(&identities[1], &identities[2], [(0, 2), (1, 2)]);
            assert_eq!(verdict.completed(), pair == 0);
            assert_eq!(verdict.comparable(), pair == 0);
        }
        for mutation in 0..15 {
            let mut bad = identity();
            match mutation {
                0 => {
                    bad.rankings.swap(0, 1);
                }
                1 => {
                    bad.rankings[1] = bad.rankings[0].clone();
                }
                2 => bad.rankings[0]["mode"] = json!("on"),
                3 => bad.rankings[0]["status"] = json!(500),
                4 => bad.rankings[0]["error"] = json!("failed"),
                5 => bad.rankings[0]["response"]["_type"] = json!("other"),
                6 => bad.rankings[0]["response"]["numHits"]["value"] = json!(-1),
                7 => bad.rankings[0]["response"]["numHits"]["_type"] = json!("unknown"),
                8 => bad.rankings[0]["response"]["hasMoreResults"] = Value::Null,
                9 => bad.rankings[0]["response"]["webpages"][0]["title"] = Value::Null,
                10 => bad.rankings[0]["response"]["webpages"][0]["snippet"] = json!("string"),
                11 => bad.rankings[0]["response"]["webpages"][0]["planStage"] = json!("core"),
                12 => bad.rankings[0]["response"]["queryPlan"]["mode"] = json!("staged"),
                13 => bad.rankings[0]["response"]["queryPlan"]["version"] = json!(2),
                _ => {
                    bad.rankings[0]["response"]["webpages"] =
                        json!(vec![bad.rankings[0]["response"]["webpages"][0].clone(); 11])
                }
            }
            assert!(
                features::fixed_query_identities(&bad.rankings).is_err(),
                "mutation {mutation}"
            );
            let verdict = retained.comparable(&control, &bad, [(0, 2), (1, 2)]);
            assert!(!verdict.completed(), "mutation {mutation}");
            assert!(!verdict.rankings_match(), "mutation {mutation}");
            assert!(!verdict.comparable(), "mutation {mutation}");
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
    fn control_envelope() -> Value {
        let mut envelope = json!({"freeze":{"binary_sha256":"a".repeat(64)},
            "provenance":{"indexes":{},"services":{},"configs":{"off":"b".repeat(64),"on":"c".repeat(64)}}});
        for pair in ["retained", "reindexed", "centrality"] {
            envelope["provenance"]["indexes"][pair] = json!(
                [0, 1].map(|shard| eval::input::sha256(format!("{pair}/{shard}").as_bytes()))
            );
            envelope["provenance"]["search_configs"][pair] = json!([0,1].map(|i|json!({"path":format!("/synthetic/{pair}/search-{i}.toml"),"sha256":eval::input::sha256(format!("config/{pair}/{i}").as_bytes())})));
            for mode in ["off", "on"] {
                envelope["provenance"]["services"][pair][mode] = json!(eval::input::sha256(
                    format!("served/{pair}/{mode}").as_bytes()
                ));
            }
        }
        envelope
    }
    fn control_files(
        root: &Path,
        retained: &ControlIdentity,
        control: &ControlIdentity,
        centrality: &ControlIdentity,
    ) -> (std::path::PathBuf, [std::path::PathBuf; 6]) {
        let envelope = control_envelope();
        let indexes = |pair: &str, identity: &ControlIdentity| {
            identity.counts.iter().zip(&identity.documents)
            .map(|((shard, documents), digest)| json!({"shard":shard,"documents":documents,"content_sha256":digest,"manifest_sha256":envelope["provenance"]["indexes"][pair][*shard as usize],"executable_sha256":envelope["freeze"]["binary_sha256"]})).collect::<Vec<_>>()
        };
        let identities = root.join("identities.json");
        fs::write(&identities, serde_json::to_vec(&json!({"retained":indexes("retained",retained),"reindexed":indexes("reindexed",control),"centrality":indexes("centrality",centrality)})).unwrap()).unwrap();
        let paths = std::array::from_fn(|i| {
            root.join(format!(
                "live/{}-{}.json",
                ["retained", "control", "centrality"][i / 2],
                ["off", "on"][i % 2]
            ))
        });
        for (i, path) in paths.iter().enumerate() {
            let rows = &[retained, control, centrality][i / 2].rankings;
            let mut rows: Vec<_> = rows.iter().skip((i % 2) * 8).take(8).cloned().collect();
            let pair = ["retained", "reindexed", "centrality"][i / 2];
            let mode = ["off", "on"][i % 2];
            let report = features::reporting_observation_path(path).unwrap();
            fs::create_dir_all(report.parent().unwrap()).unwrap();
            fs::write(report, serde_json::to_vec(&json!({"rows":rows})).unwrap()).unwrap();
            for row in &mut rows {
                row["response"] = features::retrieval_identity(&row["response"]).unwrap();
            }
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            write_receipt(
                path,
                json!({"schema_version":1,"status":"passed","measured_at":"2026-09-16T00:00:00Z","rows": rows,"pair":if pair == "reindexed" {"control"} else {pair},"mode":mode,"service_sha256":envelope["provenance"]["services"][pair][mode],"config_sha256":envelope["provenance"]["configs"][mode],"executable_sha256":envelope["freeze"]["binary_sha256"]}),
            );
        }
        (identities, paths)
    }
    fn write_receipt(path: &Path, mut receipt: Value) {
        if receipt.get("pair_binding").is_none() {
            let pair = if receipt["pair"] == "control" {
                "reindexed"
            } else {
                receipt["pair"].as_str().unwrap()
            }
            .to_owned();
            let envelope = control_envelope();
            receipt["management_endpoint"] = json!("http://127.0.0.1:57311");
            receipt["pair_binding"] = json!({"verified":true,"management_endpoint":"http://127.0.0.1:57311",
                "cluster_members":[[0,"127.0.0.1:57302"],[1,"127.0.0.1:57303"]],
                "shards":([0,1].map(|i|json!({"shard_id":i,"socket":format!("127.0.0.1:{}",57302+i),
                "documents":2,"wire_documents":2,"index_path":format!("/synthetic/{pair}/{i}"),
                "manifest_sha256":envelope["provenance"]["indexes"][pair.as_str()][i],"files_sha256":"f".repeat(64),
                "config_path":envelope["provenance"]["search_configs"][pair.as_str()][i]["path"],
                "config_sha256":envelope["provenance"]["search_configs"][pair.as_str()][i]["sha256"]})))});
        }
        receipt["seal"] = json!(features::measurement_seal(&receipt).unwrap());
        fs::write(path, serde_json::to_vec(&receipt).unwrap()).unwrap();
    }
    #[test]
    fn control_gate_precedes_held_out() {
        let dir = stract::gen_temp_dir().unwrap();
        let digest = control_envelope();
        let mut id = identity();
        id.rankings.clear();
        let (identities, observations) = control_files(dir.as_ref(), &id, &id, &id);
        let pending =
            features::control_from_files(&identities, &observations, [(0, 2), (1, 2)], &digest)
                .unwrap();
        assert!(!pending.completed());
        assert!(features::validate_control_evidence(
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
        let (identities, observations) = control_files(dir.as_ref(), &id, &id, &id);
        let passed =
            features::control_from_files(&identities, &observations, [(0, 2), (1, 2)], &digest)
                .unwrap();
        features::validate_control_evidence(
            &passed,
            true,
            FeatureCell::CentralityOn,
            &digest,
            &identities,
            &observations,
            [(0, 2), (1, 2)],
        )
        .unwrap();
        assert!(features::validate_control_evidence(
            &passed,
            true,
            FeatureCell::SpellOn,
            &json!({"changed":true}),
            &identities,
            &observations,
            [(0, 2), (1, 2)]
        )
        .is_err());
        let mut other = id.clone();
        other.documents[0] = "f".repeat(64);
        let (identities, observations) = control_files(dir.as_ref(), &id, &other, &id);
        let failed =
            features::control_from_files(&identities, &observations, [(0, 2), (1, 2)], &digest)
                .unwrap();
        for cell in [
            FeatureCell::BaseOff,
            FeatureCell::BaseOn,
            FeatureCell::SpellOff,
            FeatureCell::SpellOn,
        ] {
            features::validate_control_evidence(
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
        for held_out in [false, true] {
            for cell in [FeatureCell::CentralityOff, FeatureCell::CentralityOn] {
                assert!(features::validate_control_evidence(
                    &failed,
                    held_out,
                    cell,
                    &digest,
                    &identities,
                    &observations,
                    [(0, 2), (1, 2)]
                )
                .is_err());
            }
        }
    }
    #[test]
    fn control_verdict_is_derived() {
        let dir = stract::gen_temp_dir().unwrap();
        let id = identity();
        let mut other = id.clone();
        other.documents[0] = "f".repeat(64);
        let (identities, observations) = control_files(dir.as_ref(), &id, &other, &id);
        let digest = control_envelope();
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
            features::validate_control_evidence(
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
        for key in [
            "completed",
            "control_receipts_present",
            "centrality_receipts_present",
            "counts_match",
            "content_matches",
            "rankings_match",
            "centrality_content_matches",
            "comparable",
        ] {
            let mut forged = json!(verdict);
            forged[key] = json!(!forged[key].as_bool().unwrap());
            let forged: features::ControlVerdict = serde_json::from_value(forged).unwrap();
            let forged = forged
                .sealed(json!(verdict)["input_identity"].as_str().unwrap())
                .unwrap();
            assert!(
                features::validate_control_evidence(
                    &forged,
                    false,
                    FeatureCell::BaseOff,
                    &digest,
                    &identities,
                    &observations,
                    [(0, 2), (1, 2)]
                )
                .is_err(),
                "{key}"
            );
        }
        let (identities, observations) = control_files(dir.as_ref(), &id, &id, &id);
        let genuine =
            features::control_from_files(&identities, &observations, [(0, 2), (1, 2)], &digest)
                .unwrap();
        features::validate_control_evidence(
            &genuine,
            true,
            FeatureCell::CentralityOn,
            &digest,
            &identities,
            &observations,
            [(0, 2), (1, 2)],
        )
        .unwrap();
        assert!(features::validate_control_evidence(
            &genuine,
            true,
            FeatureCell::BaseOff,
            &digest,
            &identities,
            &observations,
            [(0, 1), (1, 3)]
        )
        .is_err());
        let envelope = dir.as_ref().join("freeze.json");
        fs::write(&envelope, b"changed frozen envelope").unwrap();
        let changed_envelope = eval::input::hash_file(&envelope).unwrap();
        assert!(features::validate_control_evidence(
            &genuine,
            true,
            FeatureCell::BaseOff,
            &json!({"changed":changed_envelope}),
            &identities,
            &observations,
            [(0, 2), (1, 2)]
        )
        .is_err());
        let mut observed = read(&observations[4]);
        observed["rows"][0]["response"]["numHits"]["value"] = json!(99);
        fs::write(&observations[4], serde_json::to_vec(&observed).unwrap()).unwrap();
        assert!(features::validate_control_evidence(
            &genuine,
            true,
            FeatureCell::BaseOff,
            &digest,
            &identities,
            &observations,
            [(0, 2), (1, 2)]
        )
        .is_err());
        write_receipt(&observations[4], observed);
        let updated =
            features::control_from_files(&identities, &observations, [(0, 2), (1, 2)], &digest)
                .unwrap();
        assert!(updated.comparable());
        for extra in [false, true] {
            let (identities, paths) = control_files(dir.as_ref(), &id, &id, &id);
            let mut file = read(&paths[4]);
            if extra {
                let row = file["rows"][0].clone();
                file["rows"].as_array_mut().unwrap().push(row);
            } else {
                file["rows"].as_array_mut().unwrap().pop();
            }
            fs::write(&paths[4], serde_json::to_vec(&file).unwrap()).unwrap();
            assert!(
                features::control_from_files(&identities, &paths, [(0, 2), (1, 2)], &digest)
                    .map_or(true, |v| !v.completed())
            );
        }
    }
    #[test]
    fn control_observations_bound_to_service() {
        let dir = stract::gen_temp_dir().unwrap();
        let id = identity();
        let envelope = control_envelope();
        let (documents, paths) = control_files(dir.as_ref(), &id, &id, &id);
        let derive = || {
            features::control_from_files(&documents, &paths, [(0, 2), (1, 2)], &envelope).unwrap()
        };
        assert!(
            derive().comparable(),
            "equal legitimate rankings are comparable"
        );
        let genuine = read(&paths[4]);
        let mut copied = read(&paths[2]);
        copied["pair"] = json!("centrality");
        copied["pair_binding"] = genuine["pair_binding"].clone();
        write_receipt(&paths[4], copied);
        assert!(
            !derive().completed(),
            "copied control service cannot produce centrality observations"
        );
        for (key, wrong) in [
            ("pair", json!("reindexed")),
            ("mode", json!("on")),
            ("config_sha256", json!("d".repeat(64))),
            ("executable_sha256", json!("e".repeat(64))),
        ] {
            let mut altered = genuine.clone();
            altered[key] = wrong;
            write_receipt(&paths[4], altered);
            assert!(!derive().completed(), "{key}");
        }
        fs::write(&paths[4], serde_json::to_vec(&genuine).unwrap()).unwrap();
        assert!(derive().completed());
    }
    fn live_fixture_inputs(
        root: &Path,
        services: &fixture::GateServices,
        endpoint: &str,
    ) -> (
        Value,
        std::path::PathBuf,
        [std::path::PathBuf; 6],
        std::path::PathBuf,
    ) {
        let id = identity();
        fs::create_dir(root.join("evidence")).unwrap();
        let (original_identities, observations) =
            control_files(&root.join("evidence"), &id, &id, &id);
        fs::create_dir(root.join("evidence/documents")).unwrap();
        let identities = root.join("evidence/documents/identities.json");
        fs::rename(original_identities, &identities).unwrap();
        for path in observations.iter().skip(2) {
            fs::remove_file(path).unwrap();
        }
        let mut envelope = control_envelope();
        let documents = json!({"retained":services.indexes,"reindexed":services.indexes,"centrality":services.indexes});
        fs::write(&identities, serde_json::to_vec(&documents).unwrap()).unwrap();
        let config = root.join("native/api.toml");
        fs::write(
            &config,
            format!(
                "host = {:?}\nmanagement_host = {:?}\n",
                endpoint.strip_prefix("http://").unwrap(),
                services.management.strip_prefix("http://").unwrap()
            ),
        )
        .unwrap();
        for mode in ["off", "on"] {
            envelope["provenance"]["configs"][mode] =
                json!(eval::input::hash_file(&config).unwrap());
        }
        for pair in ["retained", "reindexed", "centrality"] {
            envelope["provenance"]["indexes"][pair] = json!(services
                .indexes
                .as_array()
                .unwrap()
                .iter()
                .map(|index| index["manifest_sha256"].clone())
                .collect::<Vec<_>>());
            envelope["provenance"]["search_configs"][pair] = json!(services
                .search_configs
                .iter()
                .map(|path| json!({"path":path,"sha256":eval::input::hash_file(path).unwrap()}))
                .collect::<Vec<_>>());
        }
        (envelope, identities, observations, config)
    }
    fn live_fixture_served(root: &Path) -> std::path::PathBuf {
        let served = root.join("native/served.json");
        fs::write(
            &served,
            serde_json::to_vec(&json!({"schema_version":1,"verified":true,
            "shards":[{"shard_id":0,"documents":2},{"shard_id":1,"documents":2}]}))
            .unwrap(),
        )
        .unwrap();
        served
    }
    #[tokio::test]
    async fn gate_measures_fixed_queries_itself() {
        use features::{ControlGateInputs, GateMeasurements, LiveControlCheck};
        let dir = stract::gen_temp_dir().unwrap();
        let root = dir.as_ref();
        fs::create_dir(root.join("native")).unwrap();
        let services = fixture::GateServices::start(&root.join("native"), [2, 2]).await;
        let id = identity();
        let responses = (0..32)
            .map(|i| id.rankings[i % 16]["response"].clone())
            .collect();
        let (endpoint, requests, server) = fixture::gate_http(responses).await;
        let (envelope, identities, observations, config) =
            live_fixture_inputs(root, &services, &endpoint.base);
        let served = live_fixture_served(root);
        let final_verdict = root.join("verdict/verdict-final.json");
        let inputs = ControlGateInputs {
            held_out: false,
            cell: FeatureCell::BaseOff,
            envelope: &envelope,
            identities: &identities,
            observations: &observations,
            expected_counts: [(0, 2), (1, 2)],
            final_verdict: &final_verdict,
        };
        let live = LiveControlCheck {
            endpoint: &endpoint.base,
            management_endpoint: &services.management,
            search_configs: &services.search_configs,
            identities: &identities,
            envelope: &envelope,
            pair: "control",
            planner: eval::Planner::Off,
            served: &served,
            config: &config,
            executable_sha256: envelope["freeze"]["binary_sha256"].as_str().unwrap(),
            receipt: &observations[2],
        };
        let mut measurements = GateMeasurements::default();
        let first = features::require_control_before_held_out(&inputs, &live, &mut measurements)
            .await
            .unwrap();
        assert!(!first.completed());
        features::require_control_before_held_out(&inputs, &live, &mut measurements)
            .await
            .unwrap();
        assert_eq!(
            requests.lock().unwrap().len(),
            8,
            "later cell must reuse its measurement"
        );
        let receipt = features::read_measurement(&observations[2]).unwrap();
        assert_eq!(receipt["pair_binding"]["verified"], true);
        for (row, response) in receipt["rows"]
            .as_array()
            .unwrap()
            .iter()
            .zip(&id.rankings[..8])
        {
            assert_eq!(
                row["response"],
                features::retrieval_identity(&response["response"]).unwrap()
            );
        }
        let original = fs::read(&observations[2]).unwrap();
        for case in ["row", "seal", "service", "binding"] {
            let mut altered = receipt.clone();
            match case {
                "row" => {
                    altered["rows"][0]["response"]["webpages"][0]["url"] =
                        json!("https://tampered.test/")
                }
                "seal" => altered["seal"] = json!("f".repeat(64)),
                "service" => altered["service_sha256"] = json!("f".repeat(64)),
                _ => altered["pair_binding"]["shards"][0]["config_sha256"] = json!("f".repeat(64)),
            }
            fs::write(&observations[2], serde_json::to_vec(&altered).unwrap()).unwrap();
            assert!(
                features::require_control_before_held_out(&inputs, &live, &mut measurements)
                    .await
                    .is_err(),
                "tampered {case}"
            );
            fs::write(&observations[2], &original).unwrap();
        }
        assert!(
            features::require_control_before_held_out(
                &inputs,
                &live,
                &mut GateMeasurements::default()
            )
            .await
            .is_err(),
            "fresh gate cannot adopt prewritten receipt"
        );
        assert_eq!(requests.lock().unwrap().len(), 8);
        let centrality = ControlGateInputs {
            cell: FeatureCell::CentralityOff,
            ..inputs
        };
        assert!(!measurements
            .verdict(&centrality)
            .unwrap()
            .centrality_receipts_present());
        assert!(!final_verdict.exists());
        for (pair, mode, slot, cell) in [
            ("control", eval::Planner::On, 3, FeatureCell::BaseOn),
            (
                "centrality",
                eval::Planner::Off,
                4,
                FeatureCell::CentralityOff,
            ),
            (
                "centrality",
                eval::Planner::On,
                5,
                FeatureCell::CentralityOn,
            ),
        ] {
            let inputs = ControlGateInputs {
                held_out: true,
                cell,
                ..centrality
            };
            let live = LiveControlCheck {
                pair,
                planner: mode,
                receipt: &observations[slot],
                ..live
            };
            if slot == 5 {
                let unsafe_verdict = root.join("index-0/verdict.json");
                let rejected = ControlGateInputs {
                    final_verdict: &unsafe_verdict,
                    ..inputs
                };
                assert!(features::require_control_before_held_out(
                    &rejected,
                    &live,
                    &mut measurements
                )
                .await
                .is_err());
                assert!(
                    !unsafe_verdict.exists(),
                    "final verdict must not change a measured index"
                );
                assert_eq!(requests.lock().unwrap().len(), 32);
            }
            let result =
                features::require_control_before_held_out(&inputs, &live, &mut measurements).await;
            assert_eq!(requests.lock().unwrap().len(), (slot - 1) * 8);
            if slot == 4 {
                assert_eq!(
                    result.unwrap_err(),
                    features::LiveControlError::PendingMeasurements
                );
                assert!(!final_verdict.exists());
            } else {
                let verdict = result.unwrap();
                assert!(verdict.control_receipts_present());
                assert_eq!(verdict.completed(), slot == 5);
            }
        }
        server.await.unwrap();
        for (ordinal, request) in requests.lock().unwrap().iter().enumerate() {
            assert_eq!(request.line, "POST /beta/api/search HTTP/1.1");
            assert_eq!(
                request.body,
                eval::runner::request(features::FIXED_CONTROL_QUERIES[ordinal % 8])
            );
            let headers = request.headers.to_ascii_lowercase();
            assert!(headers.contains("accept-encoding: identity"));
            assert!(headers.contains("connection: close"));
        }
        assert_eq!(read(&final_verdict)["verdict"]["comparable"], true);
    }
    #[tokio::test]
    async fn gate_binds_endpoint_to_pair() {
        use features::{ControlGateInputs, GateMeasurements, LiveControlCheck};
        let temporary = std::env::temp_dir().canonicalize().unwrap();
        let trusted_root = [
            "/dev/shm",
            "/var/tmp",
            "/private/var/tmp",
            "/private/tmp",
            "/tmp",
        ]
        .into_iter()
        .filter_map(|candidate| Path::new(candidate).canonicalize().ok())
        .find(|candidate| {
            fs::symlink_metadata(candidate).is_ok_and(|metadata| {
                metadata.is_dir()
                    && eval::input::trusted_temporary_root(
                        candidate,
                        metadata.uid(),
                        metadata.mode(),
                    )
                    && !temporary.starts_with(candidate)
            })
        })
        .expect("gate witness requires a trusted root outside temp_dir");
        let untrusted_parent = std::env::current_dir().unwrap().canonicalize().unwrap();
        assert!(!untrusted_parent.ancestors().any(|ancestor| {
            let metadata = fs::symlink_metadata(ancestor).unwrap();
            eval::input::trusted_temporary_root(ancestor, metadata.uid(), metadata.mode())
        }));
        struct PrivateDirectory(std::path::PathBuf);
        impl PrivateDirectory {
            fn new(parent: &Path) -> Self {
                let path = parent.join(format!("stract-gate-roots-{}", uuid::Uuid::new_v4()));
                fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
                Self(path)
            }
        }
        impl Drop for PrivateDirectory {
            fn drop(&mut self) {
                fs::remove_dir_all(&self.0).unwrap();
            }
        }
        for case in [
            "valid",
            "trusted-root-outside-temp",
            "no-trusted-ancestor",
            "different-socket",
            "third-member",
            "wrong-index",
            "wire-count",
            "config-digest",
            "api-endpoint",
            "output-in-index",
            "output-in-identities",
        ] {
            let dir = stract::gen_temp_dir().unwrap();
            let relocated = match case {
                "trusted-root-outside-temp" => Some(PrivateDirectory::new(&trusted_root)),
                "no-trusted-ancestor" => Some(PrivateDirectory::new(&untrusted_parent)),
                _ => None,
            };
            let root = relocated.as_ref().map_or(dir.as_ref(), |d| d.0.as_path());
            if relocated.is_some() {
                eprintln!("gate index-root witness {case}: {}", root.display());
            }
            let accepted = matches!(case, "valid" | "trusted-root-outside-temp");
            fs::create_dir(root.join("native")).unwrap();
            let services = fixture::GateServices::start(
                &root.join("native"),
                if case == "wire-count" { [3, 2] } else { [2, 2] },
            )
            .await;
            let (endpoint, requests, server) = fixture::gate_http(
                identity().rankings[..8]
                    .iter()
                    .map(|r| r["response"].clone())
                    .collect(),
            )
            .await;
            let (mut envelope, identities, mut observations, config) =
                live_fixture_inputs(root, &services, &endpoint.base);
            let served = live_fixture_served(root);
            let final_verdict = root.join("verdict/final.json");
            match case {
                "output-in-index" => observations[2] = root.join("index-0/receipt.json"),
                "output-in-identities" => {
                    observations[2] = root.join("evidence/documents/receipt.json")
                }
                "different-socket" => {
                    services.members.lock().unwrap()[0].1 = "127.0.0.1:1".parse().unwrap()
                }
                "third-member" => services
                    .members
                    .lock()
                    .unwrap()
                    .push((2, "127.0.0.1:1".parse().unwrap())),
                "wrong-index" => {
                    let path = &services.search_configs[0];
                    let mut config: toml::Value =
                        toml::from_str(&fs::read_to_string(path).unwrap()).unwrap();
                    let wrong = root.join("native/wrong-index");
                    fs::create_dir(&wrong).unwrap();
                    fs::write(wrong.join("physical-data"), b"different bytes").unwrap();
                    config["index_path"] = toml::Value::String(wrong.to_str().unwrap().into());
                    fs::write(path, toml::to_string(&config).unwrap()).unwrap();
                    envelope["provenance"]["search_configs"]["reindexed"][0]["sha256"] =
                        json!(eval::input::hash_file(path).unwrap());
                }
                "config-digest" => fs::write(&services.search_configs[0], b"changed").unwrap(),
                "api-endpoint" => {
                    let mut api: toml::Value =
                        toml::from_str(&fs::read_to_string(&config).unwrap()).unwrap();
                    api["host"] = toml::Value::String("127.0.0.1:1".into());
                    fs::write(&config, toml::to_string(&api).unwrap()).unwrap();
                    envelope["provenance"]["configs"]["off"] =
                        json!(eval::input::hash_file(&config).unwrap());
                }
                _ => {}
            }
            let inputs = ControlGateInputs {
                held_out: false,
                cell: FeatureCell::BaseOff,
                envelope: &envelope,
                identities: &identities,
                observations: &observations,
                expected_counts: [(0, 2), (1, 2)],
                final_verdict: &final_verdict,
            };
            let live = LiveControlCheck {
                endpoint: &endpoint.base,
                management_endpoint: &services.management,
                search_configs: &services.search_configs,
                identities: &identities,
                envelope: &envelope,
                pair: "control",
                planner: eval::Planner::Off,
                served: &served,
                config: &config,
                executable_sha256: envelope["freeze"]["binary_sha256"].as_str().unwrap(),
                receipt: &observations[2],
            };
            let result = features::require_control_before_held_out(
                &inputs,
                &live,
                &mut GateMeasurements::default(),
            )
            .await;
            server.abort();
            let _ = server.await;
            assert_eq!(result.is_ok(), accepted, "case {case}: {result:?}");
            if case == "no-trusted-ancestor" {
                assert_eq!(
                    result,
                    Err(features::LiveControlError::Evidence(EvalError::UnsafePath))
                );
            }
            assert_eq!(
                requests.lock().unwrap().len(),
                if accepted { 8 } else { 0 },
                "case {case}: refused before search"
            );
            if accepted {
                let receipt = features::read_measurement(&observations[2]).unwrap();
                assert_eq!(
                    receipt["pair_binding"]["cluster_members"],
                    json!(*services.members.lock().unwrap())
                );
            } else {
                assert!(!observations[2].exists());
            }
        }
    }
    #[tokio::test]
    async fn gate_native_responses_are_bounded() {
        use eval::{Argument, ArgumentReason};
        use features::{ControlGateInputs, GateMeasurements, LiveControlCheck, LiveControlError};
        assert_eq!(Limits::default().native_response_bytes, 64 * 1024);
        assert!(GateMeasurements::with_binding_limits(Limits {
            native_response_bytes: 64 * 1024 + 1,
            ..Limits::default()
        })
        .is_err());
        for case in ["valid", "oversized-frame", "seventeen-members"] {
            let dir = stract::gen_temp_dir().unwrap();
            let root = dir.as_ref();
            fs::create_dir(root.join("native")).unwrap();
            let services = fixture::GateServices::start(&root.join("native"), [2, 2]).await;
            if case == "seventeen-members" {
                services
                    .members
                    .lock()
                    .unwrap()
                    .extend((2..17).map(|i| (i, "127.0.0.1:1".parse().unwrap())));
            }
            let (endpoint, requests, server) = fixture::gate_http(
                identity().rankings[..8]
                    .iter()
                    .map(|r| r["response"].clone())
                    .collect(),
            )
            .await;
            let (envelope, identities, observations, config) =
                live_fixture_inputs(root, &services, &endpoint.base);
            let served = live_fixture_served(root);
            let final_verdict = root.join("verdict/final.json");
            let inputs = ControlGateInputs {
                held_out: false,
                cell: FeatureCell::BaseOff,
                envelope: &envelope,
                identities: &identities,
                observations: &observations,
                expected_counts: [(0, 2), (1, 2)],
                final_verdict: &final_verdict,
            };
            let live = LiveControlCheck {
                endpoint: &endpoint.base,
                management_endpoint: &services.management,
                search_configs: &services.search_configs,
                identities: &identities,
                envelope: &envelope,
                pair: "control",
                planner: eval::Planner::Off,
                served: &served,
                config: &config,
                executable_sha256: envelope["freeze"]["binary_sha256"].as_str().unwrap(),
                receipt: &observations[2],
            };
            // A genuine, small management response declares more than this reduced cap.
            // Removing the header check lets it decode and authorize all eight searches.
            let limits = Limits {
                native_response_bytes: if case == "oversized-frame" {
                    1
                } else {
                    64 * 1024
                },
                ..Limits::default()
            };
            let result = features::require_control_before_held_out(
                &inputs,
                &live,
                &mut GateMeasurements::with_binding_limits(limits).unwrap(),
            )
            .await;
            server.abort();
            let _ = server.await;
            if case == "valid" {
                result.unwrap();
                assert_eq!(requests.lock().unwrap().len(), 8);
            } else {
                assert_eq!(
                    result,
                    Err(LiveControlError::Evidence(EvalError::Argument {
                        argument: Argument::ServiceManifest,
                        reason: ArgumentReason::Limit,
                    })),
                    "case {case}"
                );
                assert_eq!(
                    requests.lock().unwrap().len(),
                    0,
                    "refused before any search"
                );
                assert!(!observations[2].exists());
            }
        }
    }

    #[test]
    fn manifest_walk_is_byte_bounded() {
        use eval::{Argument, ArgumentReason};
        let dir = stract::gen_temp_dir().unwrap();
        let root = dir.as_ref();
        let sparse = root.join("sparse");
        fs::File::create(&sparse).unwrap().set_len(4096).unwrap();
        let mut hashed = Vec::new();
        let result = features::bounded_index_manifest(
            root,
            &Limits {
                file_bytes: 1024,
                total_bytes: 8192,
                ..Limits::default()
            },
            |path| hashed.push(path.to_path_buf()),
        );
        assert!(
            hashed.is_empty(),
            "oversized sparse file must not be hashed"
        );
        assert_eq!(
            result,
            Err(EvalError::Argument {
                argument: Argument::Index,
                reason: ArgumentReason::Limit,
            })
        );
        fs::File::create(root.join("second"))
            .unwrap()
            .set_len(4096)
            .unwrap();
        let result = features::bounded_index_manifest(
            root,
            &Limits {
                file_bytes: 4096,
                total_bytes: 6144,
                ..Limits::default()
            },
            |path| hashed.push(path.to_path_buf()),
        );
        assert!(
            hashed.is_empty(),
            "aggregate preflight must finish before hashing"
        );
        assert_eq!(
            result,
            Err(EvalError::Argument {
                argument: Argument::Index,
                reason: ArgumentReason::Limit,
            })
        );
        let result = features::bounded_index_manifest(
            root,
            &Limits {
                file_bytes: 4096,
                total_bytes: 8192,
                ..Limits::default()
            },
            |path| hashed.push(path.to_path_buf()),
        )
        .unwrap();
        assert_eq!(hashed.len(), 2);
        assert_eq!(result, eval::index::manifest(root).unwrap());
        fs::create_dir(root.join("a")).unwrap();
        fs::write(root.join("a/child"), b"nested").unwrap();
        fs::write(root.join("a.txt"), b"sibling").unwrap();
        assert_eq!(
            features::bounded_index_manifest(root, &Limits::default(), |_| {}).unwrap(),
            eval::index::manifest(root).unwrap(),
            "preserve component-sorted depth-first order"
        );
    }

    #[test]
    fn verdict_observations_come_from_receipts() {
        let dir = stract::gen_temp_dir().unwrap();
        let id = identity();
        let (documents, paths) = control_files(dir.as_ref(), &id, &id, &id);
        let envelope = control_envelope();
        let derive = || {
            features::control_from_files(&documents, &paths, [(0, 2), (1, 2)], &envelope).unwrap()
        };
        let genuine = derive();
        assert!(genuine.comparable());
        let report = features::reporting_observation_path(&paths[4]).unwrap();
        let mut reporting = read(&report);
        reporting["rows"][0]["response"]["numHits"]["_type"] = json!("approximate");
        reporting["rows"][0]["response"]["webpages"][0]["url"] = json!("https://fabricated.test/");
        fs::write(&report, serde_json::to_vec(&reporting).unwrap()).unwrap();
        assert_eq!(
            derive(),
            genuine,
            "reporting observations have no authority"
        );
        let mut measured = read(&paths[4]);
        measured["rows"][0]["response"]["numHits"]["_type"] = json!("approximate");
        write_receipt(&paths[4], measured);
        assert!(derive().completed());
        assert!(!derive().rankings_match());
        assert!(!derive().comparable());
        for path in &paths[4..] {
            fs::remove_file(path).unwrap();
        }
        let partial = derive();
        assert!(partial.control_receipts_present());
        assert!(!partial.centrality_receipts_present());
        assert!(!partial.completed());
        assert!(features::validate_control_evidence(
            &partial,
            false,
            FeatureCell::CentralityOn,
            &envelope,
            &documents,
            &paths,
            [(0, 2), (1, 2)]
        )
        .is_err());
        let mut forged = json!(partial);
        for key in ["completed", "comparable", "centrality_receipts_present"] {
            forged[key] = json!(true);
        }
        let forged = serde_json::from_value(forged).unwrap();
        assert!(features::validate_control_evidence(
            &forged,
            false,
            FeatureCell::CentralityOn,
            &envelope,
            &documents,
            &paths,
            [(0, 2), (1, 2)]
        )
        .is_err());
    }
    #[test]
    fn control_identities_bound_to_manifests() {
        let dir = stract::gen_temp_dir().unwrap();
        let id = identity();
        let envelope = control_envelope();
        let (documents, paths) = control_files(dir.as_ref(), &id, &id, &id);
        let derive = || {
            features::control_from_files(&documents, &paths, [(0, 2), (1, 2)], &envelope).unwrap()
        };
        assert!(derive().completed());
        let genuine = read(&documents);
        for pair in ["retained", "reindexed", "centrality"] {
            for shard in 0..2 {
                let mut changed = genuine.clone();
                changed[pair][shard]["manifest_sha256"] = json!("f".repeat(64));
                fs::write(&documents, serde_json::to_vec(&changed).unwrap()).unwrap();
                assert!(!derive().completed(), "{pair}/{shard} manifest");
                changed = genuine.clone();
                changed[pair][shard]["executable_sha256"] = json!("f".repeat(64));
                fs::write(&documents, serde_json::to_vec(&changed).unwrap()).unwrap();
                assert!(!derive().completed(), "{pair}/{shard} executable");
            }
        }
        fs::write(&documents, serde_json::to_vec(&genuine).unwrap()).unwrap();
        assert!(derive().comparable());
    }
    fn diagnostics() -> Value {
        json!({"indexes":[{"shard":0,"documents":2,"content_sha256":"d".repeat(64)}, {"shard":1,"documents":2,"content_sha256":"e".repeat(64)}]})
    }
    fn contrast_control() -> ControlIdentity {
        let mut control = identity();
        control.documents = vec!["d".repeat(64), "e".repeat(64)];
        control
    }
    fn run_identity(cell: FeatureCell) -> Value {
        let mut run = raw_run_identity(cell);
        for (ordinal, digest) in ["d", "e"].into_iter().enumerate() {
            run["indexes"][ordinal]["manifest"]["content_sha256"] = json!(digest.repeat(64));
            run["indexes"][ordinal]["manifest"]["shard"] = json!(ordinal);
        }
        run["suite"] = json!("diagnostic");
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
            features::validate_contrast(&base, &after, &diagnostics(), &contrast_control())
                .unwrap();
            let wrong = run_identity(if expected == FeatureCell::BaseOn {
                FeatureCell::BaseOff
            } else {
                FeatureCell::BaseOn
            });
            assert!(features::validate_contrast(
                &wrong,
                &after,
                &diagnostics(),
                &contrast_control()
            )
            .is_err());
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
                    features::validate_contrast(
                        &base,
                        &changed,
                        &diagnostics(),
                        &contrast_control()
                    )
                    .is_err(),
                    "{key}"
                );
            }
            let mut changed = after.clone();
            changed["rows"][0]["query"] = json!("new query");
            assert!(features::validate_contrast(
                &base,
                &changed,
                &diagnostics(),
                &contrast_control()
            )
            .is_err());
            if feature.centrality() {
                let mut anchor = base.clone();
                anchor["suite"] = json!("frozen");
                assert!(features::validate_contrast(
                    &anchor,
                    &after,
                    &diagnostics(),
                    &contrast_control()
                )
                .is_err());
                let mut acceptance_feature = after.clone();
                acceptance_feature["suite"] = json!("frozen");
                assert!(features::validate_contrast(
                    &base,
                    &acceptance_feature,
                    &diagnostics(),
                    &contrast_control()
                )
                .is_err());
            }
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
            &diagnostics(),
            &contrast_control()
        )
        .is_err());
    }
    #[test]
    fn feature_contrast_binds_index_identity() {
        let base = run_identity(FeatureCell::BaseOff);
        for feature in [FeatureCell::CentralityOff, FeatureCell::SpellOff] {
            let mut run = run_identity(feature);
            features::validate_contrast(&base, &run, &diagnostics(), &contrast_control()).unwrap();
            run["indexes"][0]["manifest"]["content_sha256"] = json!("f".repeat(64));
            assert_eq!(
                features::validate_contrast(&base, &run, &diagnostics(), &contrast_control()),
                Err(EvalError::IdentityMismatch)
            );
        }
        let feature = run_identity(FeatureCell::CentralityOff);
        let control = contrast_control();
        for side in 0..2 {
            for mutation in 0..6 {
                let mut runs = [base.clone(), feature.clone()];
                match mutation {
                    0 => {
                        runs[side]["indexes"][0]["manifest"]["content_sha256"] =
                            json!("f".repeat(64))
                    }
                    1 => runs[side]["indexes"][0]["manifest"]["content_sha256"] = Value::Null,
                    2 => runs[side]["indexes"].as_array_mut().unwrap().swap(0, 1),
                    3 => {
                        runs[side]["indexes"].as_array_mut().unwrap().pop();
                    }
                    4 => {
                        let extra = runs[side]["indexes"][0].clone();
                        runs[side]["indexes"].as_array_mut().unwrap().push(extra);
                    }
                    _ => runs[side]["indexes"][0]["manifest"]["shard"] = json!(1),
                }
                assert!(
                    features::validate_contrast(&runs[0], &runs[1], &diagnostics(), &control)
                        .is_err(),
                    "side {side}, mutation {mutation}"
                );
            }
        }
        let mut stale = diagnostics();
        stale["indexes"][0]["content_sha256"] = json!("f".repeat(64));
        assert!(features::validate_contrast(&base, &feature, &stale, &control).is_err());
        let mut wrong_control = control.clone();
        wrong_control.documents[0] = "a".repeat(64);
        assert!(
            features::validate_contrast(&base, &feature, &diagnostics(), &wrong_control).is_err()
        );
        let mut wrong_source = feature.clone();
        wrong_source["configs"][0]["resolved"]["index_path"] =
            base["configs"][0]["resolved"]["index_path"].clone();
        assert!(
            features::validate_contrast(&base, &wrong_source, &diagnostics(), &control).is_err()
        );
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
