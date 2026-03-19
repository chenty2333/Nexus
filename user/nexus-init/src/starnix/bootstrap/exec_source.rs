use super::super::*;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

pub(super) fn resolve_exec_payload_source(
    namespace: &nexus_io::ProcessNamespace,
    args: &[String],
) -> Result<(String, Vec<u8>), zx_status_t> {
    let path = requested_exec_path(args).ok_or(ZX_ERR_INVALID_ARGS)?;
    read_exec_image_bytes_from_namespace(namespace, path.as_str())
}

fn requested_exec_path(args: &[String]) -> Option<String> {
    match args.first().map(String::as_str) {
        Some("") => None,
        Some(path) if path.contains('/') => Some(String::from(path)),
        Some(name) => Some(format!("bin/{name}")),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::vec;
    use nexus_io::{NamespaceTrie, ProcessNamespace};

    #[test]
    fn resolve_exec_payload_source_requires_explicit_exec_path() {
        let namespace = ProcessNamespace::new(NamespaceTrie::new());
        assert_eq!(
            resolve_exec_payload_source(&namespace, &[]).expect_err("missing path should fail"),
            ZX_ERR_INVALID_ARGS
        );
    }

    #[test]
    fn resolve_exec_payload_source_does_not_fallback_to_embedded_payloads() {
        let namespace = ProcessNamespace::new(NamespaceTrie::new());
        let args = vec![String::from("linux-hello")];
        let status =
            resolve_exec_payload_source(&namespace, &args).expect_err("missing namespace entry");
        assert_eq!(status, ZX_ERR_NOT_FOUND);
    }
}
