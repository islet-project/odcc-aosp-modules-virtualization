// Copyright 2022, The Android Open Source Project
// Copyright (c) 2026 Samsung Electronics Co., Ltd. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Samsung's changes: add support for Islet/Arm CCA

//! Implementation of the AIDL interface `IVmPayloadService`.

use crate::arm_cca::is_arm_cca_supported;
use crate::provisioning::{is_ca_cert_path_valid, is_destination_path_valid, is_url_valid, secure_chown_chmod, run_provisioning_command};
use nix::unistd::sync;
use android_system_virtualization_payload::aidl::android::system::virtualization::payload::IVmPayloadService::{
    BnVmPayloadService, IVmPayloadService, VM_PAYLOAD_SERVICE_SOCKET_NAME, AttestationResult::AttestationResult,
    ENCRYPTEDSTORE_MOUNTPOINT, STATUS_FAILED_TO_PREPARE_CSR_AND_KEY, STATUS_FAILED_TO_REQUEST_ARM_CCA_ATTESTATION_TOKEN, STATUS_FAILED_TO_EXTEND_ARM_CCA_REM_SLOT,
    ARM_CCA_CHALLENGE_LEN, ARM_CCA_MAX_MEASUREMENT_LEN, VM_APK_CONTENTS_PATH
};

use android_system_virtualization_payload::aidl::android::system::virtualization::payload::IProvisioningCallback::IProvisioningCallback;
use android_system_virtualization_payload::aidl::android::system::virtualization::payload::ProvisioningError::ProvisioningError;
use android_system_virtualmachineservice::aidl::android::system::virtualmachineservice::IVirtualMachineService::IVirtualMachineService;
use anyhow::{anyhow, Context, Result};
use avflog::LogResult;
use binder::{Interface, BinderFeatures, ExceptionCode, Strong, IntoBinderResult, Status};
use client_vm_csr::{generate_attestation_key_and_csr, ClientVmAttestationData};
use log::{info, warn};
use rpcbinder::RpcServer;
use rsi::{attestation_token, measurement_extend};
use crate::vm_secret::VmSecret;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::io::OwnedFd;
use std::path::Path;
use std::thread;
use nix::sys::stat::Mode;
use nix::unistd::Gid;

/// Implementation of `IVmPayloadService`.
struct VmPayloadService {
    allow_restricted_apis: bool,
    virtual_machine_service: Strong<dyn IVirtualMachineService>,
    secret: VmSecret,
}

impl IVmPayloadService for VmPayloadService {
    fn notifyPayloadReady(&self) -> binder::Result<()> {
        self.virtual_machine_service.notifyPayloadReady()
    }

    fn getVmInstanceSecret(&self, identifier: &[u8], size: i32) -> binder::Result<Vec<u8>> {
        if !(0..=32).contains(&size) {
            return Err(anyhow!("size {size} not in range (0..=32)"))
                .or_binder_exception(ExceptionCode::ILLEGAL_ARGUMENT);
        }
        let mut instance_secret = vec![0; size.try_into().unwrap()];
        self.secret
            .derive_payload_sealing_key(identifier, &mut instance_secret)
            .context("Failed to derive VM instance secret")
            .with_log()
            .or_service_specific_exception(-1)?;
        Ok(instance_secret)
    }

    fn getDiceAttestationChain(&self) -> binder::Result<Vec<u8>> {
        if is_arm_cca_supported() {
            return Err(anyhow!("Use of DICE API on Arm CCA platform is not allowed"))
                .or_binder_exception(ExceptionCode::UNSUPPORTED_OPERATION)
        }
        self.check_restricted_apis_allowed()?;
        if let Some(bcc) = self.secret.dice_artifacts().bcc() {
            Ok(bcc.to_vec())
        } else {
            Err(anyhow!("bcc is none")).or_binder_exception(ExceptionCode::ILLEGAL_STATE)
        }
    }

    fn getDiceAttestationCdi(&self) -> binder::Result<Vec<u8>> {
        if is_arm_cca_supported() {
            return Err(anyhow!("Use of DICE API on Arm CCA platform is not allowed"))
                .or_binder_exception(ExceptionCode::UNSUPPORTED_OPERATION)
        }
        self.check_restricted_apis_allowed()?;
        Ok(self.secret.dice_artifacts().cdi_attest().to_vec())
    }

    fn requestAttestation(
        &self,
        challenge: &[u8],
        test_mode: bool,
    ) -> binder::Result<AttestationResult> {
        if is_arm_cca_supported() {
            return Err(anyhow!("Use of DICE API on Arm CCA platform is not allowed"))
                .or_binder_exception(ExceptionCode::UNSUPPORTED_OPERATION)
        }
        let ClientVmAttestationData { private_key, csr } =
            generate_attestation_key_and_csr(challenge, self.secret.dice_artifacts())
                .map_err(|e| {
                    Status::new_service_specific_error_str(
                        STATUS_FAILED_TO_PREPARE_CSR_AND_KEY,
                        Some(format!("Failed to prepare the CSR and key pair: {e:?}")),
                    )
                })
                .with_log()?;
        let csr = csr
            .into_cbor_vec()
            .map_err(|e| {
                Status::new_service_specific_error_str(
                    STATUS_FAILED_TO_PREPARE_CSR_AND_KEY,
                    Some(format!("Failed to serialize CSR into CBOR: {e:?}")),
                )
            })
            .with_log()?;
        let cert_chain = self.virtual_machine_service.requestAttestation(&csr, test_mode)?;
        Ok(AttestationResult {
            privateKey: private_key.as_slice().to_vec(),
            certificateChain: cert_chain,
        })
    }

    fn requestArmCcaAttestation(
        &self,
        challenge: &[u8; ARM_CCA_CHALLENGE_LEN as usize],
    ) -> binder::Result<Vec<u8>> {
        if !is_arm_cca_supported() {
            return Err(anyhow!("Arm CCA attestation is not supported"))
                .or_binder_exception(ExceptionCode::UNSUPPORTED_OPERATION)
        }
        let token = attestation_token(challenge)
            .map_err(|e| {
                Status::new_service_specific_error_str(
                    STATUS_FAILED_TO_REQUEST_ARM_CCA_ATTESTATION_TOKEN,
                    Some(format!("Failed to request the Arm CCA token: {e:?}")),
                )
            })
            .with_log()?;
        Ok(token)
    }

    fn extendArmCcaRemSlot(
        &self,
        index: i32,
        measurement: &[u8],
    ) -> binder::Result<()> {
        if !is_arm_cca_supported() {
            return Err(anyhow!("Arm CCA is not supported"))
                .or_binder_exception(ExceptionCode::UNSUPPORTED_OPERATION)
        }

        if measurement.len() > ARM_CCA_MAX_MEASUREMENT_LEN as usize {
            return Err(anyhow!("Measurement length exceeds {}", ARM_CCA_MAX_MEASUREMENT_LEN))
                .or_binder_exception(ExceptionCode::ILLEGAL_ARGUMENT)
        }

        measurement_extend(index as u32, measurement)
            .map_err(|e| {
                Status::new_service_specific_error_str(
                    STATUS_FAILED_TO_EXTEND_ARM_CCA_REM_SLOT,
                    Some(format!("Failed to extend Arm CCA REM slot: {e:?}")),
                )
            })
            .with_log()?;
        Ok(())
    }

    fn startProvisioning(
        &self,
        url: &str,
        ca_cert: &str,
        destination: &str,
        callback: &Strong<dyn IProvisioningCallback>
    ) -> binder::Result<()> {

        if !is_arm_cca_supported() {
            return Err(anyhow!("Arm CCA is not supported"))
                .or_binder_exception(ExceptionCode::UNSUPPORTED_OPERATION)
        }

        info!("startProvisioning has been called {} {} {}", url, ca_cert, destination);

        if !is_destination_path_valid(destination) {
            warn!("The provided destination path {} is invalid!", destination);
            return Err(anyhow!("Provided path is not within the encryptedstore directory"))
                .or_binder_exception(ExceptionCode::ILLEGAL_ARGUMENT)
        }

        if !is_ca_cert_path_valid(ca_cert) {
            warn!("The provided ca_cert path {} is invalid!", ca_cert);
            return Err(anyhow!("Provided path is not within the encryptedstore directory"))
                .or_binder_exception(ExceptionCode::ILLEGAL_ARGUMENT)
        }

        if !is_url_valid(url) {
            warn!("The provided url {} is invalid!", url);
            return Err(anyhow!("Provided url is invalid"))
                .or_binder_exception(ExceptionCode::ILLEGAL_ARGUMENT)
        }

        let callback = callback.clone();
        let url = url.to_string();
        let ca_cert = ca_cert.to_string();
        let destination = destination.to_string();

        thread::spawn(move || {
            let base_path = Path::new(ENCRYPTEDSTORE_MOUNTPOINT);
            let destination_path = base_path.join(&destination);
            let assets_path = Path::new(VM_APK_CONTENTS_PATH);
            let ca_cert_path = assets_path.join("assets").join(&ca_cert);

            info!("Start provisioning operation url: {} ca_cert: {} destination: {}",
                url, ca_cert_path.display(), destination_path.display());

            match run_provisioning_command(&url, &ca_cert_path, &destination_path) {
                Ok(mut child) => {
                    let exitcode = child.wait().context("Wait for provisioning client child process");
                    if !exitcode.expect("Failed to wait on provisioning client child process").success() {
                        warn!("The provisioning client returned an error!");
                        // TODO: map errors returned by the provisioning client to ProvisioningError codes
                        let _ = callback.onError(ProvisioningError::SYSTEM_ERROR);
                        return;
                    }
                },
                Err(_) => {
                    warn!("Cannot launch the provisioning client process");
                    let _ = callback.onError(ProvisioningError::SYSTEM_ERROR);
                    return;
                }
            };

            // Sync filesystem buffers and flush all caches to the disk
            sync();

            // Change the group to and mode to grant access to the provisioned file
            if let Ok(base_dir) = File::open(ENCRYPTEDSTORE_MOUNTPOINT) {
                let base_fd = base_dir.as_raw_fd();
                let mode = Mode::S_IRUSR | Mode::S_IWUSR | Mode::S_IRGRP | Mode::S_IWGRP;
                if secure_chown_chmod(base_fd, &destination, Gid::from_raw(microdroid_uids::MICRODROID_PAYLOAD_GID), mode).is_err() {
                    warn!("Cannot grant access rights to the privisioned file");
                    let _ = callback.onError(ProvisioningError::SYSTEM_ERROR);
                    return;
                }
            } else {
                warn!("Encryptedstore is not enabled!");
                let _ = callback.onError(ProvisioningError::ENCRYPTEDSTORE_IS_NOT_ENABLED);
                return;
            }

            info!("Provisioning of {} to {} succeded", url, destination);
            let _ = callback.onSuccess(&url, &destination);
        });

        Ok(())
    }
}

impl Interface for VmPayloadService {}

impl VmPayloadService {
    /// Creates a new `VmPayloadService` instance from the `IVirtualMachineService` reference.
    fn new(
        allow_restricted_apis: bool,
        vm_service: Strong<dyn IVirtualMachineService>,
        secret: VmSecret,
    ) -> VmPayloadService {
        Self { allow_restricted_apis, virtual_machine_service: vm_service, secret }
    }

    fn check_restricted_apis_allowed(&self) -> binder::Result<()> {
        if self.allow_restricted_apis {
            Ok(())
        } else {
            Err(anyhow!("Use of restricted APIs is not allowed"))
                .with_log()
                .or_binder_exception(ExceptionCode::SECURITY)
        }
    }
}

/// Registers the `IVmPayloadService` service.
pub(crate) fn register_vm_payload_service(
    allow_restricted_apis: bool,
    vm_service: Strong<dyn IVirtualMachineService>,
    secret: VmSecret,
    vm_payload_service_fd: OwnedFd,
) -> Result<()> {
    let vm_payload_binder = BnVmPayloadService::new_binder(
        VmPayloadService::new(allow_restricted_apis, vm_service, secret),
        BinderFeatures::default(),
    );

    let server = RpcServer::new_bound_socket(vm_payload_binder.as_binder(), vm_payload_service_fd)?;
    info!("The RPC server '{}' is running.", VM_PAYLOAD_SERVICE_SOCKET_NAME);
    // Move server reference into a background thread and run it forever.
    std::thread::spawn(move || {
        server.join();
    });
    Ok(())
}
