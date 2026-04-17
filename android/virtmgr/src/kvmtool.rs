#![allow(unused)]
// Copyright 2021, The Android Open Source Project
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

use anyhow::{bail, Error, Result};
use command_fds::CommandFdExt;
use log::{debug, error, info, warn};
use regex::{Captures, Regex};
use rustutils::system_properties;
use shared_child::SharedChild;
use std::fs::{read_to_string, File};
use std::num::NonZero;
use std::os::unix::io::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Command;
use std::ptr;
use std::{io::Read, io::Write, path::PathBuf};

use android_system_virtualizationcommon::aidl::android::system::virtualizationcommon::DeathReason::DeathReason;
use android_system_virtualizationservice::aidl::android::system::virtualizationservice::VirtualMachineAppConfig::DebugLevel::DebugLevel;
use crate::common::VmInstanceBackend;
use crate::common::add_preserved_fd;
use crate::common::Rss;
use crate::common::DiskRole;
use crate::properties::use_realm;

const KVMTOOL_PATH: &str = "/apex/com.android.virt/bin/lkvm";
/// Serial device for VM console input.
/// Hypervisor (virtio-console)
const CONSOLE_HVC0: &str = "hvc0";
/// Serial (emulated uart)
const CONSOLE_TTYS0: &str = "ttyS0";

/// The size of memory (in MiB) reserved for ramdump
const RAMDUMP_RESERVED_MIB: u32 = 17;

/// The default size of memory (in MiB) reserved for Realm VM hosting CC service
const CC_SERVICE_VM_DEFAULT_MEM_SIZE: u32 = 2048;

const NULL_SINK: &str = "/dev/null";

#[derive(Debug)]
pub(crate) struct KvmToolVmBackend {
    kvmtool_sock: PathBuf,
    temporary_dir: PathBuf,
}

#[repr(C, packed(1))]
#[allow(non_camel_case_types)]
struct __virtio_balloon_stat {
    tag: u16,
    val: u64,
}

const VIRTIO_BALLOON_S_SWAP_IN: usize = 0; /* Amount of memory swapped in */
const VIRTIO_BALLOON_S_SWAP_OUT: usize = 1; /* Amount of memory swapped out */
const VIRTIO_BALLOON_S_MAJFLT: usize = 2; /* Number of major faults */
const VIRTIO_BALLOON_S_MINFLT: usize = 3; /* Number of minor faults */
const VIRTIO_BALLOON_S_MEMFREE: usize = 4; /* Total amount of free memory */
const VIRTIO_BALLOON_S_MEMTOT: usize = 5; /* Total amount of memory */
const VIRTIO_BALLOON_S_AVAIL: usize = 6; /* Available memory as in /proc */
const VIRTIO_BALLOON_S_CACHES: usize = 7; /* Disk caches */
const VIRTIO_BALLOON_S_HTLB_PGALLOC: usize = 8; /* Hugetlb page allocations */
const VIRTIO_BALLOON_S_HTLB_PGFAIL: usize = 9; /* Hugetlb page allocation failures */
const VIRTIO_BALLOON_S_NR: usize = 10;

#[repr(u32)]
#[allow(non_camel_case_types, dead_code)]
enum __kvm_ipc_cmd {
    Balloon = 1,
    Debug = 2,
    Stat = 3,
    Pause = 4,
    Resume = 5,
    Stop = 6,
    Pid = 7,
    VmState = 8,
}

#[allow(dead_code, unused)]
impl KvmToolVmBackend {
    pub fn new(temporary_dir: &Path, name: &str) -> Result<Self, Error> {
        Ok(Self {
            kvmtool_sock: temporary_dir.join(format!("{name}.sock")),
            temporary_dir: temporary_dir.to_owned(),
        })
    }

    fn connect(&self) -> Result<UnixStream, Error> {
        Ok(UnixStream::connect(&self.kvmtool_sock)?)
    }

    fn write_ipc_command(
        &self,
        io: &mut dyn Write,
        ty: __kvm_ipc_cmd,
        arg: Option<&[u8]>,
    ) -> Result<(), Error> {
        let mut data = Vec::new();
        data.extend_from_slice(&(ty as u32).to_le_bytes());
        data.extend_from_slice(&(arg.map_or(0u32, |i| i.len() as u32).to_le_bytes()));

        if let Some(v) = arg {
            data.extend_from_slice(v);
        }

        Ok(io.write_all(data.as_slice())?)
    }

    fn transaction<T: Sized + Default>(
        &self,
        ty: __kvm_ipc_cmd,
        arg: Option<&[u8]>,
    ) -> Result<T, Error> {
        let mut conn = self.connect()?;
        self.write_ipc_command(&mut conn, ty, arg)?;

        let result_size = size_of::<T>();
        if result_size > 0 {
            let mut response = vec![0u8; result_size];
            conn.read_exact(&mut response)?;

            // SAFETY: This will work as read_exact must read size_of::<T> bytes
            Ok(unsafe { ptr::read(response.as_ptr() as *const T) })
        } else {
            Ok(T::default())
        }
    }
}

#[allow(dead_code, unused)]
impl VmInstanceBackend for KvmToolVmBackend {
    fn run_vm(
        &self,
        config: crate::common::CommonVmConfig,
        failure_pipe_write: std::fs::File,
    ) -> Result<shared_child::SharedChild, Error> {
        let mut command = Command::new(KVMTOOL_PATH);
        command
            .arg("run")
            .arg("--name")
            .arg(config.name)
            .arg("--vsock")
            .arg(config.cid.to_string());

        if system_properties::read_bool("hypervisor.memory_reclaim.supported", false)?
            && !config.no_balloon
        {
            command.arg("--balloon");
        }

        let mut memory_mib = config.memory_mib;

        if config.protected {
            warn!("Protected vm unsupported with kvmtool");
        } else if config.ramdump.is_some() {
            command.arg("--params").arg(format!("crashkernel={RAMDUMP_RESERVED_MIB}M"));
        }
        if config.debug_config.debug_level == DebugLevel::NONE
            && config.debug_config.should_prepare_console_output()
        {
            // bootconfig.normal will be used, but we need log.
            command.arg("--params").arg("printk.devkmsg=on");
            command.arg("--params").arg("console=hvc0");
        }

        command.arg("--mem").arg(memory_mib.to_string());

        if let Some(cpus) = config.cpus {
            command.arg("--cpus").arg(cpus.to_string());
        }

        if let Some(gdb_port) = config.gdb_port {
            warn!("GDB is not supported by kvmtool");
        }

        // Keep track of what file descriptors should be mapped to the crosvm process.
        let mut preserved_fds = config.indirect_files.into_iter().map(|f| f.into()).collect();

        // Setup the serial devices.
        // 1. uart device: used as the output device by bootloaders and as early console by linux
        // 2. uart device: used to report the reason for the VM failing.
        // 3. virtio-console device: used as the console device where kmsg is redirected to
        // 4. virtio-console device: used as the ramdump output
        // 5. virtio-console device: used as the logcat output
        //
        // When [console|log]_fd is not specified, the devices are attached to sink, which means
        // what's written there is discarded.
        let console_out_arg = format_serial_out_arg(&mut preserved_fds, config.console_out_fd);
        let console_in_arg = config
            .console_in_fd
            .map(|fd| add_preserved_fd(&mut preserved_fds, fd))
            .unwrap_or(NULL_SINK.to_string());
        let log_arg = format_serial_out_arg(&mut preserved_fds, config.log_fd);
        let failure_serial_path = add_preserved_fd(&mut preserved_fds, failure_pipe_write);
        let ramdump_arg = format_serial_out_arg(&mut preserved_fds, config.ramdump);
        let console_input_device = config.console_input_device.as_deref().unwrap_or(CONSOLE_HVC0);
        match console_input_device {
            CONSOLE_HVC0 | CONSOLE_TTYS0 => {}
            _ => bail!("Unsupported serial device {console_input_device}"),
        };

        // Warning: Adding more serial devices requires you to shift the PCI device ID of the boot
        // disks in bootconfig.x86_64. This is because x86 crosvm puts serial devices and the block
        // devices in the same PCI bus and serial devices comes before the block devices. Arm crosvm
        // doesn't have the issue.
        // /dev/ttyS0
        command.arg("--term-file").arg(format!(
            "n=0,out={},in={}",
            &console_out_arg,
            if console_input_device == CONSOLE_TTYS0 { &console_in_arg } else { NULL_SINK }
        ));
        // /dev/ttyS1
        command.arg("--term-file").arg(format!("n=1,out={}", &failure_serial_path));
        // /dev/hvc0
        command.arg("--term-file").arg(format!(
            "n=4,out={},in={}",
            &console_out_arg,
            if console_input_device == CONSOLE_HVC0 { &console_in_arg } else { NULL_SINK }
        ));

        // TODO: /dev/hvc1..7 currently unsupported on kvmtool
        warn!("/dev/hvc1..7 is not supported on kvmtool");
        // /dev/hvc1
        // command.arg(format!("--serial={},hardware=virtio-console,num=2", &ramdump_arg));
        // /dev/hvc2
        // command.arg(format!("--serial={},hardware=virtio-console,num=3", &log_arg));

        if let Some(bootloader) = config.bootloader {
            command.arg("--firmware").arg(add_preserved_fd(&mut preserved_fds, bootloader));
        }

        if let Some(initrd) = config.initrd {
            command.arg("--initrd").arg(add_preserved_fd(&mut preserved_fds, initrd));
        }

        if let Some(params) = &config.params {
            command.arg("--params").arg(params);
        }

        for disk in config.disks {
            // Disk file locking is disabled because of missing SELinux policies.
            let mut disk_param = add_preserved_fd(&mut preserved_fds, disk.image);

            // Add encryptedstore suffix for encrypted storage disks
            if let DiskRole::EncryptedStore = disk.role {
                disk_param.push_str(",encryptedstore");
            } else if let DiskRole::VmInstance = disk.role {
                disk_param.push_str(",vm-instance");
            }
            command.arg("--disk").arg(disk_param);
        }

        if let Some(kernel) = config.kernel {
            command.arg("--kernel").arg(add_preserved_fd(&mut preserved_fds, kernel));
        }

        if use_realm() {
            if let Some(metadata) = config.metadata {
                if memory_mib == NonZero::new(CC_SERVICE_VM_DEFAULT_MEM_SIZE).unwrap() {
                    command.arg("--metadata").arg(add_preserved_fd(&mut preserved_fds, metadata));
                } else {
                    warn!("The realm metadata is currently only supported for VMs hosting CC Services!");
                    warn!("By default they are pre-configured to use {} MiB of RAM.", CC_SERVICE_VM_DEFAULT_MEM_SIZE);
                }
            }
        }

        command.arg("--ipc-dir").arg(&self.temporary_dir);

        if let Some(dt_overlay) = config.device_tree_overlay {
            warn!("DTB overlay is not suported in kvmtool");
        }

        if cfg!(paravirtualized_devices) {
            if let Some(gpu_config) = &config.gpu_config {
                warn!("GPU is not supported by kvmtool");
            }
            if let Some(display_config) = &config.display_config {
                warn!("Display config is not supported by kvmtool");
            }
        }

        let mut network = false;
        if cfg!(network) {
            if let Some(tap) = config.tap {
                add_preserved_fd(&mut preserved_fds, tap);
                let tap_fd = preserved_fds.last().unwrap().as_raw_fd();
                command.arg("--network").arg(format!("fd={tap_fd},nosetip=1"));
                network = true;
            }
        }
        if ! network {
            // kvmtool uses user-mode network by default, disable that
            command.arg("--network").arg("mode=none");
        }

        if cfg!(paravirtualized_devices) {
            warn!("Input devices are not supported by kvmtool");
        }

        if config.hugepages {
            warn!("Huge pages are not supported yet :(");
        }

        if config.boost_uclamp {
            warn!("boot_uclamp is not supported in kvmtool");
        }
        command.arg("--debug");

        if use_realm() {
            warn!("add --realm argument to lkvm");
            command.arg("--realm");
            command.arg("--restricted_mem");
        }

        // TODO: Kvmtool support this?
        // for device in config.vfio_devices {
        //     command.arg(vfio_argument_for_platform_device(&device)?);
        // }

        debug!("Preserving FDs {:?}", preserved_fds);
        command.preserved_fds(preserved_fds);

        // TODO: Kvmtool doesn't support sound
        if cfg!(paravirtualized_devices) {
            if let Some(audio_config) = &config.audio_config {
                warn!("Sound is no supported in kvmtool");
            }
        }

        // Set the Realm Personalization Value that acts here as instance_id.
        // This is used as one of the inputs by the derivation process for Realm Sealing Keys.
        command.arg("--realm-pv-hex").arg(hex::encode(config.instance_id));

        print_kvmtool_args(&command);

        let result = SharedChild::spawn(&mut command)?;
        debug!("Spawned crosvm({}).", result.id());
        Ok(result)
    }

    fn get_rss(&self, pid: u32) -> Result<crate::common::Rss> {
        let file = read_to_string(format!("/proc/{}/smaps", pid))?;
        let lines: Vec<_> = file.split('\n').collect();

        let mut rss_vm_total = 0i64;
        for line in lines {
            if line.contains("Rss:") {
                let data_list: Vec<_> = line.split_whitespace().collect();
                if data_list.len() < 2 {
                    bail!("Failed to parse command result for getting rss :\n{}", line);
                }
                let rss = data_list[1].parse::<i64>()?;

                rss_vm_total += rss;
            }
        }

        Ok(Rss { vm: rss_vm_total, crosvm: rss_vm_total })
    }

    fn check_cpu_stall(&self, _status: &std::process::ExitStatus) {
        warn!("Checking if the CPU has stalled is not yet supported in kvmtool");
    }

    fn get_memory_balloon(&self) -> Result<u64, Error> {
        Ok(0u64)
    }

    fn set_memory_balloon(&self, num_bytes: u64) -> Result<(), Error> {
        Ok(())
    }

    fn translate_death_reason(&self, result: &Result<std::process::ExitStatus, std::io::Error>, failure_reason: &str) -> android_system_virtualizationcommon::mangled::_7_android_6_system_20_virtualizationcommon_11_DeathReason{
        let mut failure_reason = failure_reason;
        if let Some((reason, info)) = failure_reason.split_once('|') {
            // Separator indicates extra context information is present after the failure name.
            error!("Failure info: {info}");
            failure_reason = reason;
        }
        if let Ok(status) = result {
            match failure_reason {
                "PVM_FIRMWARE_PUBLIC_KEY_MISMATCH" => {
                    return DeathReason::PVM_FIRMWARE_PUBLIC_KEY_MISMATCH
                }
                "PVM_FIRMWARE_INSTANCE_IMAGE_CHANGED" => {
                    return DeathReason::PVM_FIRMWARE_INSTANCE_IMAGE_CHANGED
                }
                "MICRODROID_FAILED_TO_CONNECT_TO_VIRTUALIZATION_SERVICE" => {
                    return DeathReason::MICRODROID_FAILED_TO_CONNECT_TO_VIRTUALIZATION_SERVICE
                }
                "MICRODROID_PAYLOAD_HAS_CHANGED" => {
                    return DeathReason::MICRODROID_PAYLOAD_HAS_CHANGED
                }
                "MICRODROID_PAYLOAD_VERIFICATION_FAILED" => {
                    return DeathReason::MICRODROID_PAYLOAD_VERIFICATION_FAILED
                }
                "MICRODROID_INVALID_PAYLOAD_CONFIG" => {
                    return DeathReason::MICRODROID_INVALID_PAYLOAD_CONFIG
                }
                "MICRODROID_UNKNOWN_RUNTIME_ERROR" => {
                    return DeathReason::MICRODROID_UNKNOWN_RUNTIME_ERROR
                }
                "HANGUP" => return DeathReason::HANGUP,
                _ => {}
            }
            match status.code() {
                None => DeathReason::KILLED,
                Some(0) => DeathReason::SHUTDOWN,
                Some(_) => DeathReason::UNKNOWN,
            }
        } else {
            DeathReason::INFRASTRUCTURE_ERROR
        }
    }

    fn suspend(&self) -> Result<(), Error> {
        self.transaction(__kvm_ipc_cmd::Pause, None)
    }

    fn resume(&self) -> Result<(), Error> {
        self.transaction(__kvm_ipc_cmd::Resume, None)
    }
}

fn print_kvmtool_args(command: &Command) {
    let re = Regex::new(r"/proc/self/fd/[\d]+").unwrap();
    info!(
        "Running kvmtool with args: {:?}",
        command
            .get_args()
            .map(|s| s.to_string_lossy())
            .map(|s| {
                re.replace_all(&s, |caps: &Captures| {
                    let path = &caps[0];
                    if let Ok(realpath) = std::fs::canonicalize(path) {
                        format!("{} ({})", path, realpath.to_string_lossy())
                    } else {
                        path.to_owned()
                    }
                })
                .into_owned()
            })
            .collect::<Vec<_>>()
    );
}

fn format_serial_out_arg(preserved_fds: &mut Vec<OwnedFd>, file: Option<File>) -> String {
    if let Some(f) = file {
        add_preserved_fd(preserved_fds, f)
    } else {
        "/dev/null".to_string()
    }
}
