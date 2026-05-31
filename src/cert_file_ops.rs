use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, ErrorKind, Write};
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

pub(crate) fn create_directory(path: &Path, mode: u32) -> io::Result<()> {
    let mut builder = DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    builder.mode(mode);
    builder.create(path)
}

pub(crate) fn write_new_file_with_mode(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    let mut file = open_new_file_with_mode(path, mode)?;
    file.write_all(contents)?;
    Ok(())
}

pub(crate) fn replace_file_atomically_with_mode(
    path: &Path,
    contents: &[u8],
    mode: u32,
) -> io::Result<()> {
    let Some(parent) = path.parent() else {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "missing parent directory",
        ));
    };

    let Some(filename) = path.file_name() else {
        return Err(io::Error::new(ErrorKind::InvalidInput, "missing filename"));
    };

    for attempt in 0..16 {
        let temporary_path = parent.join(format!(
            ".{}.runewarp-tmp-{}-{attempt}",
            filename.to_string_lossy(),
            std::process::id()
        ));
        let mut file = match open_new_file_with_mode(&temporary_path, mode) {
            Ok(file) => file,
            Err(source) if source.kind() == ErrorKind::AlreadyExists => continue,
            Err(source) => return Err(source),
        };
        if let Err(source) = file.write_all(contents) {
            let _ = fs::remove_file(&temporary_path);
            return Err(source);
        }
        drop(file);
        if let Err(source) = fs::rename(&temporary_path, path) {
            let _ = fs::remove_file(&temporary_path);
            return Err(source);
        }
        return Ok(());
    }

    Err(io::Error::new(
        ErrorKind::AlreadyExists,
        "failed to allocate a temporary file for atomic replacement",
    ))
}

fn open_new_file_with_mode(path: &Path, mode: u32) -> io::Result<std::fs::File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(mode);
    options.open(path)
}

#[cfg(test)]
mod tests {
    use super::{create_directory, replace_file_atomically_with_mode, write_new_file_with_mode};
    use std::fs;
    use std::io::ErrorKind;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    #[test]
    fn create_directory_is_idempotent() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nested/material");

        create_directory(&path, 0o700).unwrap();
        create_directory(&path, 0o700).unwrap();

        assert!(path.is_dir());
    }

    #[test]
    fn write_new_file_refuses_to_overwrite_existing_material() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("private.key");

        write_new_file_with_mode(&path, b"first", 0o600).unwrap();
        let error = write_new_file_with_mode(&path, b"second", 0o600).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&path).unwrap(), b"first");
    }

    #[test]
    fn atomic_replace_updates_existing_material_without_temp_leaks() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("server.crt");
        fs::write(&path, b"old").unwrap();

        replace_file_atomically_with_mode(&path, b"new", 0o644).unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"new");
        let leftover_temps = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().contains("runewarp-tmp"))
            .count();
        assert_eq!(leftover_temps, 0);
    }

    #[cfg(unix)]
    #[test]
    fn atomic_replace_applies_mode_to_new_files() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("server.key");

        replace_file_atomically_with_mode(&path, b"secret", 0o600).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
