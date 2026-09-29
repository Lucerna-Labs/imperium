//! Atomic first-run creation of a key file.
//!
//! Two nodes starting at once on a fresh host both find the file missing and
//! both generate a key. With an `exists()` check followed by a plain write, both
//! keep their own key in memory and one silently overwrites the other on disk —
//! so the two nodes end up with **different** operator keys, and each rejects
//! the other's operator-signed identity binding.
//!
//! That is not hypothetical. It reproduced intermittently in the three-node
//! live test as `mesh hello rejected error=operator identity binding invalid`,
//! on whichever node lost the race.
//!
//! The fix is to let the filesystem arbitrate. The new file is written under a
//! per-call temporary name and then `link`ed into place; `link` fails with
//! `AlreadyExists` if another process got there first. Exactly one writer wins,
//! and every loser loads the winner's file. Linking also means the final path is
//! only ever a *complete* file, so a concurrent reader can never see a partial
//! write.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Create `path` with `contents`, or report that it already exists.
///
/// `Ok(true)` means this call created it. `Ok(false)` means another process
/// created it first, and the caller should load it instead of using the key it
/// just generated.
pub fn create_new(path: &Path, contents: &[u8]) -> io::Result<bool> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    let temp = temp_path(path);
    // A leftover from a crashed attempt must not be linked by accident.
    let _ = fs::remove_file(&temp);
    // CREATE at 0600 rather than chmod afterwards. chmod'ing after the write
    // leaves the key readable at its temporary path for the window between the
    // two, and that window is exactly when another process is racing to read
    // it. `mode` on open applies at creation, so the file never exists at a
    // wider mode than intended.
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    {
        let mut file = options.open(&temp)?;
        file.write_all(contents)?;
        file.sync_all()?;
    }

    let linked = fs::hard_link(&temp, path);
    let _ = fs::remove_file(&temp);

    match linked {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        // Some filesystems do not support hard links. Fall back to exclusive
        // creation, which still arbitrates the winner; the only thing lost is
        // the guarantee that a concurrent reader sees a complete file, and the
        // file is small enough that a torn read is a corrupt-file error the
        // caller already handles.
        Err(_) => create_new_exclusive(path, contents),
    }
}

fn create_new_exclusive(path: &Path, contents: &[u8]) -> io::Result<bool> {
    // `mode` on `open` applies at creation, so the file never exists with wider
    // permissions than intended.
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(mut file) => {
            file.write_all(contents)?;
            file.sync_all()?;
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(error),
    }
}

/// Serial number making each temporary name unique within this process.
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// A temporary name beside the target, unique per CALL.
///
/// Unique per call, not merely per process. Two concurrent callers inside one
/// process — threads, or two `load_or_generate` calls racing — would otherwise
/// share a single temporary file and corrupt each other's key material. The
/// process id separates processes; the sequence number separates everything
/// else.
fn temp_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "key".to_string());
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let mut temp = path.to_path_buf();
    temp.set_file_name(format!(".{name}.tmp.{}.{}", std::process::id(), sequence));
    temp
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "imperium-keyfile-test-{}-{}",
            name,
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_first_writer_wins_and_the_second_is_told_to_load() {
        let dir = temp_dir("race");
        let path = dir.join("key");

        assert!(
            create_new(&path, b"first").unwrap(),
            "the first write creates"
        );
        assert!(
            !create_new(&path, b"second").unwrap(),
            "the second must be told the file already exists"
        );
        assert_eq!(
            fs::read(&path).unwrap(),
            b"first",
            "the winner is not overwritten"
        );
    }

    #[cfg(unix)]
    #[test]
    fn neither_the_temp_file_nor_the_target_is_wider_than_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("perms");
        let path = dir.join("key");

        // Watch the directory while the key is created, so the TEMPORARY file
        // is observed rather than only the final one. A post-write chmod would
        // be caught here; creation-time mode is not.
        let observed = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let watcher_dir = dir.clone();
        let seen = std::sync::Arc::clone(&observed);
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_flag = std::sync::Arc::clone(&stop);
        let watcher = std::thread::spawn(move || {
            while !stop_flag.load(std::sync::atomic::Ordering::Relaxed) {
                if let Ok(entries) = fs::read_dir(&watcher_dir) {
                    for entry in entries.flatten() {
                        if let Ok(meta) = entry.metadata() {
                            seen.lock().expect("test mutex").push((
                                entry.file_name().to_string_lossy().into_owned(),
                                meta.permissions().mode() & 0o777,
                            ));
                        }
                    }
                }
                std::thread::yield_now();
            }
        });

        create_new(&path, b"secret").unwrap();
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        watcher.join().unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "key file must be 0600, got {mode:o}");

        // Every observed mode for a key material file must be owner-only. The
        // directory itself is 0755 and that is fine; what must never appear is a
        // readable key file.
        let bad: Vec<(String, u32)> = observed
            .lock()
            .expect("test mutex")
            .iter()
            .filter(|(name, mode)| name.contains("key") && *mode & 0o077 != 0)
            .cloned()
            .collect();
        assert!(
            bad.is_empty(),
            "key files observed with group/other bits: {bad:?}"
        );
    }

    #[test]
    fn no_temporary_files_are_left_behind() {
        let dir = temp_dir("cleanup");
        let path = dir.join("key");
        create_new(&path, b"value").unwrap();
        create_new(&path, b"other").unwrap();
        let leftovers: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "left temporary files: {leftovers:?}");
    }

    #[test]
    fn concurrent_writers_produce_exactly_one_winner() {
        // The real case: several processes creating the same file at once. The
        // point is that exactly one is told it created the file, so the others
        // load rather than keep their own key.
        let dir = temp_dir("concurrent");
        let path = dir.join("key");
        let winners: Vec<bool> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|i| {
                    let path = path.clone();
                    scope
                        .spawn(move || create_new(&path, format!("writer-{i}").as_bytes()).unwrap())
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert_eq!(
            winners.iter().filter(|won| **won).count(),
            1,
            "exactly one writer must win: {winners:?}"
        );
        // And the file holds that winner's contents, intact.
        let contents = fs::read(&path).unwrap();
        let text = String::from_utf8(contents).unwrap();
        assert!(text.starts_with("writer-"), "unexpected contents: {text:?}");
    }
}
