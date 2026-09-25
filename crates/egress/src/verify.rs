//! Bounded local file reads and signature-first verification shared by CLI and API startup.

use crate::{
    crypto::verify_signature, parse_envelope, parse_payload, strict::base64, validate_payload,
    Error, Result, TrustedKeys, VerifiedInventory, MAX_PAYLOAD_BYTES,
};
use std::{fs::File, io::Read, path::Path, time::SystemTime};

/// A FIFO opened for reading waits for a writer; metadata refusal avoids that open.
/// Metadata follows symlinks, matching the later open's path resolution.
fn refuse_non_regular(path: &Path) -> Result<()> {
    if !std::fs::metadata(path).map_err(|_| Error::Io)?.is_file() {
        return Err(Error::Io);
    }
    Ok(())
}

/// Reads at most limit+1 bytes from a regular local file; input symlinks may resolve normally.
pub fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let bound = limit
        .checked_add(1)
        .and_then(|n| u64::try_from(n).ok())
        .ok_or(Error::InputTooLarge)?;
    refuse_non_regular(path)?;
    let file = File::open(path).map_err(|_| Error::Io)?;
    if !file.metadata().map_err(|_| Error::Io)?.is_file() {
        return Err(Error::Io);
    }
    let mut bytes = Vec::new();
    file.take(bound)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Io)?;
    if bytes.len() > limit {
        return Err(Error::InputTooLarge);
    }
    Ok(bytes)
}

/// Authenticates exact bytes before payload JSON validation, without DNS or observation lookup.
pub fn verify_file(bytes: &[u8], keys: &TrustedKeys, now: SystemTime) -> Result<VerifiedInventory> {
    let envelope = parse_envelope(bytes)?;
    let public_key = keys.lookup(&envelope.key_id)?;
    let payload_bytes = base64(&envelope.payload_base64)?;
    if payload_bytes.len() > MAX_PAYLOAD_BYTES {
        return Err(Error::InputTooLarge);
    }
    let signature = base64(&envelope.signature_base64)?;
    if signature.len() != 64 {
        return Err(Error::SignatureLength);
    }
    verify_signature(&envelope, &payload_bytes, &signature, public_key)?;
    let payload = parse_payload(&payload_bytes)?;
    validate_payload(&payload, now)?;
    Ok(VerifiedInventory::from_verified(payload, envelope.key_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf, process::Command, sync::mpsc, thread, time::Duration};

    struct TempRoot(PathBuf);

    impl Drop for TempRoot {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn refuse_non_regular_refuses_a_fifo() {
        let parent = PathBuf::from(std::env::var_os("STORY584_SCRATCH").expect("owned scratch"));
        let root = TempRoot(
            parent
                .canonicalize()
                .unwrap()
                .join(format!("egress-file-kind-{}", std::process::id())),
        );
        fs::create_dir(&root.0).unwrap();
        let regular = root.0.join("regular");
        fs::write(&regular, b"abc").unwrap();
        assert!(refuse_non_regular(&regular).is_ok());
        let fifo = root.0.join("fifo");
        assert!(Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());
        assert!(
            matches!(refuse_non_regular(&fifo), Err(Error::Io)),
            "assertion failed: pre-open guard must refuse a FIFO"
        );
        assert!(matches!(refuse_non_regular(&root.0), Err(Error::Io)));
    }

    #[test]
    fn read_bounded_refuses_a_fifo_without_blocking() {
        let parent = PathBuf::from(std::env::var_os("STORY584_SCRATCH").expect("owned scratch"));
        let root = TempRoot(
            parent
                .canonicalize()
                .unwrap()
                .join(format!("egress-fifo-{}", std::process::id())),
        );
        fs::create_dir(&root.0).unwrap();
        let regular = root.0.join("regular");
        fs::write(&regular, b"abc").unwrap();
        assert_eq!(read_bounded(&regular, 3).unwrap(), b"abc");
        let fifo = root.0.join("fifo");
        assert!(Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());
        let (send, receive) = mpsc::channel();
        let child = thread::spawn(move || {
            let _ = send.send(read_bounded(&fifo, 3));
        });
        // A thread blocked on the FIFO is left to die with the test process.
        let answer = receive
            .recv_timeout(Duration::from_secs(2))
            .expect("read_bounded must reject the FIFO within two seconds");
        assert!(matches!(answer, Err(Error::Io)));
        child.join().unwrap();
    }
}
