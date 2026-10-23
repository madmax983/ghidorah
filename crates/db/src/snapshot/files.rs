//! The shard files of a snapshot of format version 3 (ADR-0031).
//!
//! Each analysis shard has one file in the directory `shards` of the project: the JCS text of
//! its tables. The name holds the index of the shard and the SHA-256 of the text:
//! `<index as 16 hex digits>-<SHA-256 as 64 hex digits>.json`. The snapshot file lists the
//! names in shard order.
//!
//! A write puts each shard file that is not on disk yet. Each file gets the steps of AC-120a:
//! `create_new` of a temporary file of this process, `write_all`, `sync_file` and `rename`.
//! Then `sync_dir` of `shards` follows. The snapshot file goes last. After that, the write removes each shard
//! file that the snapshot does not name. A shard with no change keeps its file, so a write
//! costs the changed shards only.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use ghidorah_base::{Sha256, hex, sha256};
use ghidorah_json::Value;

use super::{SNAPSHOT_LIMITS, SnapshotError};
use crate::codec::{set_from_json, tables_jcs_to};
use crate::fs::{Fs, FsError, create_temp};
use crate::program::{AnalysisSet, ShardId};

/// The directory of the shard files in a project directory.
pub const SHARDS_DIR: &str = "shards";

/// The start of the name of a temporary shard file.
pub const SHARD_TMP: &str = "shard.json.tmp";

/// Gives the file name of the shard `id` with the SHA-256 `hash`.
#[must_use]
pub fn shard_name(id: ShardId, hash: &[u8; 32]) -> String {
    format!("{:016x}-{}.json", id.index(), hex::encode(hash))
}

/// Gives the shard and the SHA-256 of a shard file name, or `None` for another name.
#[must_use]
pub fn parse_name(name: &str) -> Option<(ShardId, [u8; 32])> {
    let stem = name.strip_suffix(".json")?;
    let (index, hash) = stem.split_once('-')?;
    if index.len() != 16 || hash.len() != 64 {
        return None;
    }
    let index = u64::from_str_radix(index, 16).ok()?;
    let bytes = hex::decode(hash).ok()?;
    Some((ShardId::from_index(index), bytes.try_into().ok()?))
}

/// Gives the file names of the shards of `set` in shard order.
pub(super) fn names(set: &AnalysisSet) -> Vec<String> {
    set.shards()
        .filter_map(|(id, _)| Some(shard_name(id, &set.shard_hash(id)?)))
        .collect()
}

/// Gives the text of each shard file of `set` by name.
///
/// # Errors
///
/// Returns [`SnapshotError::Jcs`] when a shard has no JCS form. The tables of a set have
/// unique member names and integer numbers only, so the error does not occur.
pub fn shard_texts(set: &AnalysisSet) -> Result<BTreeMap<String, String>, SnapshotError> {
    let mut out = BTreeMap::new();
    for (id, t) in set.shards() {
        let mut text = String::new();
        tables_jcs_to(t, &mut |p| text.push_str(p))
            .map_err(|e| SnapshotError::Jcs(e.to_string()))?;
        let name = shard_name(id, &sha256(text.as_bytes()));
        out.insert(name, text);
    }
    Ok(out)
}

/// Writes each shard file of `set` that `dir/shards` does not hold yet. Gives the file names
/// in shard order.
///
/// # Errors
///
/// Returns the [`FsError`] of the first failed operation. A shard with no JCS form gives
/// [`FsError::Io`] of `write_all`.
pub(super) fn write_shards(
    fs: &mut dyn Fs,
    dir: &Path,
    set: &AnalysisSet,
) -> Result<Vec<String>, FsError> {
    let shards = dir.join(SHARDS_DIR);
    // A project with no shard directory yet holds no shard file.
    let held: BTreeSet<String> = fs.list(&shards).unwrap_or_default().into_iter().collect();
    let mut wrote = false;
    for (id, t) in set.shards() {
        let name = shard_name(id, &set.shard_hash(id).unwrap_or_default());
        if held.contains(&name) {
            continue;
        }
        if !wrote {
            fs.create_dir_all(&shards)?;
        }
        let own = create_temp(fs, &shards.join(SHARD_TMP))?;
        let mut fill = |put: &mut dyn FnMut(&[u8])| {
            tables_jcs_to(t, &mut |p| put(p.as_bytes())).map_err(|e| e.to_string())
        };
        let done = fs
            .write_from(&own, &mut fill)
            .and_then(|()| fs.sync_file(&own))
            .and_then(|()| fs.rename(&own, &shards.join(&name)));
        if done.is_err() {
            // The first error is the result. A failed remove leaves a file that no name uses.
            let _ = fs.remove(&own);
        }
        done?;
        wrote = true;
    }
    if wrote {
        fs.sync_dir(&shards)?;
    }
    Ok(names(set))
}

/// Removes each file of `dir/shards` that is not in `keep`: an old shard file or a temporary
/// file. The caller holds the project lock, so no other process writes a shard file. A failed
/// remove leaves the file for the next write.
pub(super) fn sweep(fs: &mut dyn Fs, dir: &Path, keep: &[String]) {
    let shards = dir.join(SHARDS_DIR);
    let Ok(held) = fs.list(&shards) else {
        return;
    };
    let keep: BTreeSet<&str> = keep.iter().map(String::as_str).collect();
    for name in held {
        let ours = parse_name(&name).is_some() || name.starts_with(SHARD_TMP);
        if ours && !keep.contains(name.as_str()) {
            let _ = fs.remove(&shards.join(&name));
        }
    }
}

/// Reads the analysis set of the shard file names `names`. `read` gives the bytes of a file
/// by name. Each file must have the SHA-256 of its name and hold the facts of its shard only.
///
/// # Errors
///
/// Returns [`SnapshotError::Shard`] for a bad name, a missing file, another hash, a shard out
/// of order or a fact of another shard. Returns the error of the JSON text of a file.
pub(super) fn read_set(
    names: &Value,
    read: &mut dyn FnMut(&str) -> Option<Vec<u8>>,
) -> Result<AnalysisSet, SnapshotError> {
    let list = names
        .as_array()
        .ok_or_else(|| SnapshotError::Shard("the shard list is not an array".to_owned()))?;
    let mut out = AnalysisSet::new();
    let mut prev: Option<ShardId> = None;
    for item in list {
        let name = item
            .as_str()
            .ok_or_else(|| SnapshotError::Shard("a shard name is not a string".to_owned()))?;
        let bad = |why: &str| SnapshotError::Shard(format!("{name}: {why}"));
        let (id, hash) = parse_name(name).ok_or_else(|| bad("not a shard name"))?;
        if prev.is_some_and(|l| l >= id) {
            return Err(bad("out of shard order"));
        }
        prev = Some(id);
        let bytes = read(name).ok_or_else(|| bad("no file"))?;
        let mut hasher = Sha256::default();
        hasher.update(&bytes);
        if hasher.finalize() != hash {
            return Err(bad("another SHA-256"));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| bad("not UTF-8"))?;
        let value = ghidorah_json::parse(text, &SNAPSHOT_LIMITS)
            .map_err(|e| SnapshotError::Json(format!("{name}: {e}")))?;
        let part = set_from_json(&value)?;
        if part.shards().any(|(other, _)| other != id) {
            return Err(bad("a fact of another shard"));
        }
        out.absorb(part, id, hash);
    }
    Ok(out)
}
