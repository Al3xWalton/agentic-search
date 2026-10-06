// SPDX-License-Identifier: AGPL-3.0-only
//! Portable defect replay for the unfixed sonic reader and its valid-frame control.
//! Only APIs shared by the unfixed base and fixed tree participate in these checks.
//! Synthetic loopback frames do not exercise application message handling.

use std::{future::Future, net::SocketAddr, time::Duration};

use stract::distributed::sonic;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

// A fixed deadline separates fixture failures from the defect observation.
async fn bounded<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("REPLAY_HARNESS_DEADLINE")
}

// Reserve/drop/bind retries account only for the OS port-selection race.
async fn server() -> (sonic::Server<u32, u32>, SocketAddr) {
    for _ in 0..16 {
        let reservation = bounded(TcpListener::bind("127.0.0.1:0"))
            .await
            .expect("REPLAY_RESERVE");
        let addr = reservation.local_addr().expect("REPLAY_ADDRESS");
        if (57300..=57320).contains(&addr.port()) {
            continue;
        }
        drop(reservation);
        match bounded(sonic::Server::bind(addr)).await {
            Ok(server) => return (server, addr),
            Err(sonic::Error::IO(error)) if error.kind() == std::io::ErrorKind::AddrInUse => {}
            Err(_) => panic!("REPLAY_BIND"),
        }
    }
    panic!("REPLAY_PORT_ATTEMPTS");
}

// Always reap an owned task, including when its deadline expires.
async fn joined<T>(mut task: JoinHandle<T>) -> Result<T, tokio::task::JoinError> {
    match tokio::time::timeout(Duration::from_secs(5), &mut task).await {
        Ok(result) => result,
        Err(_) => {
            task.abort();
            let _ = task.await;
            panic!("REPLAY_TASK_DEADLINE");
        }
    }
}

// Whole independent facts keep a source observation from replacing runtime evidence.
#[derive(PartialEq)]
struct ReplayObservation {
    task_panicked: bool,
    old_cap: bool,
    eager_body: bool,
}

#[tokio::test]
#[ignore = "Gate-2 defect replay; expected red on the fixed tree"]
async fn sonic_defect_replay() {
    let (server, addr) = server().await;
    let mut peer = bounded(TcpStream::connect(addr))
        .await
        .expect("REPLAY_CONNECT");
    bounded(peer.write_all(&1usize.to_ne_bytes()))
        .await
        .expect("REPLAY_HEADER");
    bounded(peer.write_all(&[0xff])).await.expect("REPLAY_BODY");
    let task = tokio::spawn(async move {
        let mut connection = server.accept().await?;
        connection.request().await.map(|_| ())
    });
    let outcome: Result<Result<(), sonic::Error>, _> = joined(task).await;
    let source = include_str!("../src/distributed/sonic/mod.rs");
    let observation = ReplayObservation {
        task_panicked: outcome
            .as_ref()
            .is_err_and(tokio::task::JoinError::is_panic),
        old_cap: source
            .contains("const MAX_BODY_SIZE_BYTES: usize = 1024 * 1024 * 1024 * 1024; // 1TB"),
        eager_body: source.contains("let mut buf = vec![0; header.body_size];"),
    };
    println!(
        "REPLAY_FACTS task_panicked={} old_cap={} eager_body={}",
        observation.task_panicked, observation.old_cap, observation.eager_body,
    );
    assert!(
        observation
            == ReplayObservation {
                task_panicked: true,
                old_cap: true,
                eager_body: true
            },
        "DEFECT_REPLAY_PRESENT"
    );
    assert!(observation.task_panicked, "DEFECT_REPLAY_TASK_PANICKED");
    assert!(observation.old_cap, "DEFECT_REPLAY_OLD_CAP");
    assert!(observation.eager_body, "DEFECT_REPLAY_EAGER_BODY");
}

#[tokio::test]
async fn sonic_defect_positive_control() {
    let (server, addr) = server().await;
    let mut peer = bounded(TcpStream::connect(addr))
        .await
        .expect("CONTROL_CONNECT");
    bounded(peer.write_all(&1usize.to_ne_bytes()))
        .await
        .expect("CONTROL_HEADER");
    bounded(peer.write_all(&[7])).await.expect("CONTROL_BODY");
    let task = tokio::spawn(async move {
        let mut connection = server.accept().await?;
        let request = connection.request().await?;
        let value = *request.body();
        request.respond(9).await?;
        Ok::<_, sonic::Error>(value)
    });
    let outcome = joined(task).await;
    let mut wire = Vec::new();
    bounded(peer.read_to_end(&mut wire))
        .await
        .expect("CONTROL_READ");
    let mut expected = 1usize.to_ne_bytes().to_vec();
    expected.push(9);
    let decoded = wire.get(std::mem::size_of::<usize>()..).map(|body| {
        bincode::decode_from_slice::<u32, _>(body, common::bincode_config())
            .expect("CONTROL_DECODE")
    });
    assert!(
        matches!(outcome, Ok(Ok(7))) && wire == expected && decoded == Some((9, 1)),
        "DEFECT_REPLAY_POSITIVE_CONTROL"
    );
}
