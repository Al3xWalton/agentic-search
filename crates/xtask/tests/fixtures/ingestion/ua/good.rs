//! Valid identity-builder input for the syntax guard; never compiled or sent.
//! Fixed builder settings are the invariant; runtime transport is outside this fixture.
fn build_http_client() { let c = reqwest::Client::builder().no_proxy().referer(false).http1_only().pool_max_idle_per_host(0).dns_resolver(resolver).redirect(reqwest::redirect::Policy::none()).user_agent(build_user_agent(identity)?).build()?; }
