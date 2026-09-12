//! Forbidden direct-client input for the syntax guard; never compiled or sent.
//! The fixture must be rejected outside identity.rs; it grants no network capability.
fn f() { let _ = reqwest::Client::new(); }
