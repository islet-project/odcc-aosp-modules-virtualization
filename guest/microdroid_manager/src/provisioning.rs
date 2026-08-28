// Copyright (c) 2026 Samsung Electronics Co., Ltd. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use libc::VMADDR_CID_HOST;
use nix::fcntl::{openat, OFlag};
use nix::sys::stat::{fchmod, Mode};
use nix::unistd::{fchown, Gid};
use std::fs;
use std::os::unix::io::RawFd;
use std::path::{Path, Component};
use std::process::{Child, Command};
use url::Url;
use android_system_virtualization_payload::aidl::android::system::virtualization::payload::IVmPayloadService::VM_APK_CONTENTS_PATH;

use crate::{VSOCK_CID_STRIDE, STREAM_VSOCK_PROXY_PORT_OFFSET};

pub fn run_provisioning_command(url: &str, ca_cert: &Path, destination: &Path) -> Result<Child> {

    // The stream vsock proxy listens on port == (CID of VM) + 1
    let local_cid = vsock::get_local_cid().context("Could not determine local CID")?;
    if local_cid % VSOCK_CID_STRIDE != 0 {
        return Err(anyhow::anyhow!("local_cid ({}) is invalid", local_cid));
    }
    let stream_vsock_proxy_port = local_cid.saturating_add(STREAM_VSOCK_PROXY_PORT_OFFSET);

    let mut cmd = Command::new("/system/bin/ratls_get");
    cmd
        .arg("-u")
        .arg(url)
        .arg("-r")
        .arg(ca_cert)
        .arg("-o")
        .arg(destination)
        .arg("--vsock-cid")
        .arg(VMADDR_CID_HOST.to_string())
        .arg("--vsock-port")
        .arg(stream_vsock_proxy_port.to_string())
        .arg("--conproto");
    cmd.spawn().context("provisioning failed")
}

/// Checks if a user provided path can be safely concatenated to the encryptedstore mountpoint
/// We don't want to allow paths that could escape from /mnt/encryptedstore.
/// Thus we disallow relative paths that contain parent directory (..)
pub fn is_destination_path_valid(user_path: &str) -> bool {
    let user_path = Path::new(user_path);

    if user_path.is_absolute() {
        return false;
    }

    for comp in user_path.components() {
        match comp {
            // only normal and cur dir are allowed in path
            Component::Normal(_) | Component::CurDir => {},
            // everything else (especially ParentDir) are not
            _ => return false,
        }
    }

    true
}

/// Checks if the ca_cert_path points to a resource located in the assets directory of the application
pub fn is_ca_cert_path_valid(ca_cert_path: &str) -> bool {
    let apk_path = Path::new(VM_APK_CONTENTS_PATH);
    let assets = Path::new("assets");
    let assets_full_path = match fs::canonicalize(apk_path.join(assets)) {
        Ok(path) => path,
        Err(_) => return false,
    };

    let ca_cert_path = Path::new(ca_cert_path);
    let full_ca_cert_path = match fs::canonicalize(assets_full_path.join(ca_cert_path)) {
        Ok(path) => path,
        Err(_) => return false,
    };

    full_ca_cert_path.starts_with(&assets_full_path)
}

/// Verifies if the provided url is valid
pub fn is_url_valid(url: &str) -> bool {
    Url::parse(url).is_ok()
}

/// Performs chown and chmod on a file ensuring that the file is withing the path provided as base_fd
pub fn secure_chown_chmod(
    base_fd: RawFd,
    relative_path: &str,
    gid: Gid,
    mode: Mode,
) -> nix::Result<()> {
    // Reject absolute paths
    if relative_path.starts_with('/') {
        return Err(nix::Error::EINVAL);
    }

    let fd = openat(
        Some(base_fd),
        relative_path,
        OFlag::O_NOFOLLOW,   // prevent following symlinks
        Mode::empty(),
    )?;

    fchown(fd, None, Some(gid))?;
    fchmod(fd, mode)?;

    Ok(())
}
