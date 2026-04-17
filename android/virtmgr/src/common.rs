// Copyright 2021, The Android Open Source Project
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

use crate::crosvm::CrosVmBackend;
use crate::debug_config::DebugConfig;
use crate::kvmtool::KvmToolVmBackend;
use std::num::{NonZeroU16, NonZeroU32};
use std::fs::File;
use std::process::ExitStatus;
use semver::VersionReq;
use binder::Strong;
use android_system_virtualizationservice_internal::aidl::android::system::virtualizationservice_internal::IBoundDevice::IBoundDevice;
use crate::aidl::Cid;
use anyhow::{anyhow, Result, Error, bail, Context};
use android_system_virtualizationservice::aidl::android::system::virtualizationservice::{
    AudioConfig::AudioConfig as AudioConfigParcelable,
    DisplayConfig::DisplayConfig as DisplayConfigParcelable,
    GpuConfig::GpuConfig as GpuConfigParcelable,
    UsbConfig::UsbConfig as UsbConfigParcelable,
};
use shared_child::SharedChild;
use std::cmp::max;
use std::path::{PathBuf, Path};
use android_system_virtualizationservice_internal::aidl::android::system::virtualizationservice_internal::IGlobalVmContext::IGlobalVmContext;
use rpcbinder::RpcServer;
use std::sync::{Arc, Condvar, Mutex, LazyLock};
use android_system_virtualmachineservice::aidl::android::system::virtualmachineservice::IVirtualMachineService::IVirtualMachineService;
use crate::aidl::VirtualMachineCallbacks;
use log::{info, error, debug};
use std::borrow::Cow;
use nix::{fcntl::OFlag, unistd::pipe2, unistd::Uid, unistd::User};
use std::fmt;
use std::io;
use android_system_virtualizationcommon::aidl::android::system::virtualizationcommon::DeathReason::DeathReason;
use crate::atom::write_vm_exited_stats_sync;
use crate::aidl::{GLOBAL_SERVICE, remove_temporary_files};
use binder::ParcelFileDescriptor;
use std::os::unix::io::OwnedFd;
use std::fmt::Debug;
use std::io::Read;
use std::os::unix::process::ExitStatusExt;
use tombstoned_client::{TombstonedConnection, DebuggerdDumpType};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime};
use libc::{sysconf, _SC_CLK_TCK};
use std::fs::read_to_string;
use std::mem;
use std::os::fd::AsRawFd;
use crate::properties::use_kvmtool;

const MILLIS_PER_SEC: i64 = 1000;

/// If the VM doesn't move to the Started state within this amount time, a hang-up error is
/// triggered.
static BOOT_HANGUP_TIMEOUT: LazyLock<Duration> = LazyLock::new(|| {
    if nested_virt::is_nested_virtualization().unwrap() {
        // Nested virtualization is slow, so we need a longer timeout.
        Duration::from_secs(3000)
    } else {
        Duration::from_secs(30)
    }
});

pub(crate) type VfioDevice = Strong<dyn IBoundDevice>;

/// Configuration for a VM to run with crosvm.
#[derive(Debug)]
pub struct CommonVmConfig {
    pub cid: Cid,
    pub name: String,
    pub bootloader: Option<File>,
    pub kernel: Option<File>,
    pub initrd: Option<File>,
    pub metadata: Option<File>,
    pub disks: Vec<DiskFile>,
    pub params: Option<String>,
    pub protected: bool,
    pub debug_config: DebugConfig,
    pub memory_mib: NonZeroU32,
    pub cpus: Option<NonZeroU32>,
    pub host_cpu_topology: bool,
    pub console_out_fd: Option<File>,
    pub console_in_fd: Option<File>,
    pub log_fd: Option<File>,
    pub ramdump: Option<File>,
    pub indirect_files: Vec<File>,
    pub platform_version: VersionReq,
    pub detect_hangup: bool,
    pub gdb_port: Option<NonZeroU16>,
    pub vfio_devices: Vec<VfioDevice>,
    pub dtbo: Option<File>,
    pub device_tree_overlay: Option<File>,
    pub display_config: Option<DisplayConfig>,
    pub input_device_options: Vec<InputDeviceOption>,
    pub hugepages: bool,
    pub tap: Option<File>,
    pub console_input_device: Option<String>,
    pub boost_uclamp: bool,
    pub gpu_config: Option<GpuConfig>,
    pub audio_config: Option<AudioConfig>,
    pub no_balloon: bool,
    pub usb_config: UsbConfig,
    pub instance_id: [u8; 64],
}

/// RSS values of VM and CrosVM process itself.
#[derive(Copy, Clone, Debug, Default)]
pub struct Rss {
    pub vm: i64,
    pub crosvm: i64,
}

/// Metrics regarding the VM.
#[derive(Debug, Default)]
pub struct VmMetric {
    /// Recorded timestamp when the VM is started.
    pub start_timestamp: Option<SystemTime>,
    /// Update most recent guest_time periodically from /proc/[crosvm pid]/stat while VM is
    /// running.
    pub cpu_guest_time: Option<i64>,
    /// Update maximum RSS values periodically from /proc/[crosvm pid]/smaps while VM is running.
    pub rss: Option<Rss>,
}

fn try_into_non_zero_u32(value: i32) -> Result<NonZeroU32> {
    let u32_value = value.try_into()?;
    NonZeroU32::new(u32_value).ok_or(anyhow!("value should be greater than 0"))
}

/// A disk image to pass to crosvm for a VM.
#[derive(Debug)]
pub struct DiskFile {
    pub image: File,
    pub writable: bool,
    pub role: DiskRole,
}

/// Semantic role of a disk.
///
/// Most disks have no special meaning (`Undefined`).
/// Some runners (e.g. lkvm/kvmtool) may need to identify disks by role.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DiskRole {
    Undefined,
    EncryptedStore,
    VmInstance,
}

#[derive(Debug)]
pub struct AudioConfig {
    pub use_microphone: bool,
    pub use_speaker: bool,
}

impl AudioConfig {
    pub fn new(raw_config: &AudioConfigParcelable) -> Self {
        AudioConfig { use_microphone: raw_config.useMicrophone, use_speaker: raw_config.useSpeaker }
    }
}

#[derive(Debug)]
pub struct UsbConfig {
    pub controller: bool,
}

impl UsbConfig {
    pub fn new(raw_config: &UsbConfigParcelable) -> Result<UsbConfig> {
        Ok(UsbConfig { controller: raw_config.controller })
    }
}

#[derive(Debug)]
pub struct DisplayConfig {
    pub width: NonZeroU32,
    pub height: NonZeroU32,
    pub horizontal_dpi: NonZeroU32,
    pub vertical_dpi: NonZeroU32,
    pub refresh_rate: NonZeroU32,
}

impl DisplayConfig {
    pub fn new(raw_config: &DisplayConfigParcelable) -> Result<DisplayConfig> {
        let width = try_into_non_zero_u32(raw_config.width)?;
        let height = try_into_non_zero_u32(raw_config.height)?;
        let horizontal_dpi = try_into_non_zero_u32(raw_config.horizontalDpi)?;
        let vertical_dpi = try_into_non_zero_u32(raw_config.verticalDpi)?;
        let refresh_rate = try_into_non_zero_u32(raw_config.refreshRate)?;
        Ok(DisplayConfig { width, height, horizontal_dpi, vertical_dpi, refresh_rate })
    }
}

#[derive(Debug)]
pub struct GpuConfig {
    pub backend: Option<String>,
    pub context_types: Option<Vec<String>>,
    pub pci_address: Option<String>,
    pub renderer_features: Option<String>,
    pub renderer_use_egl: Option<bool>,
    pub renderer_use_gles: Option<bool>,
    pub renderer_use_glx: Option<bool>,
    pub renderer_use_surfaceless: Option<bool>,
    pub renderer_use_vulkan: Option<bool>,
}

impl GpuConfig {
    pub fn new(raw_config: &GpuConfigParcelable) -> Result<GpuConfig> {
        Ok(GpuConfig {
            backend: raw_config.backend.clone(),
            context_types: raw_config.contextTypes.clone().map(|context_types| {
                context_types.iter().filter_map(|context_type| context_type.clone()).collect()
            }),
            pci_address: raw_config.pciAddress.clone(),
            renderer_features: raw_config.rendererFeatures.clone(),
            renderer_use_egl: Some(raw_config.rendererUseEgl),
            renderer_use_gles: Some(raw_config.rendererUseGles),
            renderer_use_glx: Some(raw_config.rendererUseGlx),
            renderer_use_surfaceless: Some(raw_config.rendererUseSurfaceless),
            renderer_use_vulkan: Some(raw_config.rendererUseVulkan),
        })
    }
}

///
/// virtio-input device configuration from `external/crosvm/src/crosvm/config.rs`
#[derive(Debug)]
#[allow(dead_code)]
pub enum InputDeviceOption {
    EvDev(File),
    SingleTouch { file: File, width: u32, height: u32, name: Option<String> },
    Keyboard(File),
    Mouse(File),
    Switches(File),
    MultiTouchTrackpad { file: File, width: u32, height: u32, name: Option<String> },
    MultiTouch { file: File, width: u32, height: u32, name: Option<String> },
}

/// The lifecycle state which the payload in the VM has reported itself to be in.
///
/// Note that the order of enum variants is significant; only forward transitions are allowed by
/// [`VmInstance::update_payload_state`].
#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PayloadState {
    Starting,
    Started,
    Ready,
    Finished,
    Hangup, // Hasn't reached to Ready before timeout expires
}

/// The current state of the VM itself.
#[derive(Debug)]
pub enum VmState {
    /// The VM has not yet tried to start.
    NotStarted {
        ///The configuration needed to start the VM, if it has not yet been started.
        config: Box<CommonVmConfig>,
    },
    /// The VM has been started.
    Running {
        /// The crosvm child process.
        child: Arc<SharedChild>,
        /// The thread waiting for crosvm to finish.
        monitor_vm_exit_thread: Option<JoinHandle<()>>,
    },
    /// The VM died or was killed.
    Dead,
    /// The VM failed to start.
    Failed,
}

impl Rss {
    pub(crate) fn extract_max(x: &Rss, y: &Rss) -> Rss {
        Rss { vm: max(x.vm, y.vm), crosvm: max(x.crosvm, y.crosvm) }
    }
}

/// Internal struct that holds the handles to globally unique resources of a VM.
#[derive(Debug)]
pub struct VmContext {
    #[allow(dead_code)] // Keeps the global context alive
    pub(crate) global_context: Strong<dyn IGlobalVmContext>,
    #[allow(dead_code)] // Keeps the server alive
    pub(crate) vm_server: RpcServer,
}

impl VmContext {
    /// Construct new VmContext.
    pub fn new(global_context: Strong<dyn IGlobalVmContext>, vm_server: RpcServer) -> VmContext {
        VmContext { global_context, vm_server }
    }
}

#[derive(Debug)]
pub struct CommonVmInstance {
    /// The current state of the VM.
    pub vm_state: Mutex<VmState>,
    /// Global resources allocated for this VM.
    #[allow(dead_code)] // Keeps the context alive
    pub(crate) vm_context: VmContext,
    /// The CID assigned to the VM for vsock communication.
    pub cid: Cid,
    /// Path to crosvm control socket
    pub name: String,
    /// Whether the VM is a protected VM.
    pub protected: bool,
    /// Directory of temporary files used by the VM while it is running.
    pub temporary_directory: PathBuf,
    /// The UID of the process which requested the VM.
    pub requester_uid: u32,
    /// The PID of the process which requested the VM. Note that this process may no longer exist
    /// and the PID may have been reused for a different process, so this should not be trusted.
    pub requester_debug_pid: i32,
    /// Callbacks to clients of the VM.
    pub callbacks: VirtualMachineCallbacks,
    /// VirtualMachineService binder object for the VM.
    #[allow(dead_code)]
    pub vm_service: Mutex<Option<Strong<dyn IVirtualMachineService>>>,
    /// Recorded metrics of VM such as timestamp or cpu / memory usage.
    pub vm_metric: Mutex<VmMetric>,
    /// The latest lifecycle state which the payload reported itself to be in.
    payload_state: Mutex<PayloadState>,
    /// Represents the condition that payload_state was updated
    payload_state_updated: Condvar,
    /// The human readable name of requester_uid
    requester_uid_name: String,
    /// Vm backend
    backend: Box<dyn VmInstanceBackend + Send + Sync>,
}

impl fmt::Display for CommonVmInstance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let adj = if self.protected { "Protected" } else { "Non-protected" };
        write!(
            f,
            "{} virtual machine \"{}\" (owner: {}, cid: {})",
            adj, self.name, self.requester_uid_name, self.cid
        )
    }
}

pub(crate) trait VmInstanceBackend: Debug {
    fn run_vm(
        &self,
        config: CommonVmConfig,
        failure_pipe_write: File,
    ) -> Result<SharedChild, Error>;
    fn check_cpu_stall(&self, status: &ExitStatus);
    fn translate_death_reason(
        &self,
        result: &Result<ExitStatus, io::Error>,
        failure_reason: &str,
    ) -> DeathReason;
    fn get_rss(&self, pid: u32) -> Result<Rss>;
    fn get_memory_balloon(&self) -> Result<u64, Error>;
    fn set_memory_balloon(&self, num_bytes: u64) -> Result<(), Error>;
    fn suspend(&self) -> Result<(), Error>;
    fn resume(&self) -> Result<(), Error>;
}

impl CommonVmInstance {
    pub(crate) fn new(
        config: CommonVmConfig,
        temporary_directory: PathBuf,
        requester_uid: u32,
        requester_debug_pid: i32,
        vm_context: VmContext,
    ) -> Result<CommonVmInstance, Error> {
        let cid = config.cid;
        let name = config.name.clone();
        let protected = config.protected;
        let requester_uid_name = User::from_uid(Uid::from_raw(requester_uid))
            .ok()
            .flatten()
            .map_or_else(|| format!("{}", requester_uid), |u| u.name);

        let backend = if use_kvmtool() {
            Box::new(KvmToolVmBackend::new(&temporary_directory, &config.name)?)
                as Box<dyn VmInstanceBackend + Send + Sync>
        } else {
            Box::new(CrosVmBackend::new(&temporary_directory))
                as Box<dyn VmInstanceBackend + Send + Sync>
        };

        let instance = CommonVmInstance {
            vm_state: Mutex::new(VmState::NotStarted { config: Box::new(config) }),
            vm_context,
            cid,
            name,
            protected,
            temporary_directory,
            requester_uid,
            requester_debug_pid,
            callbacks: Default::default(),
            vm_service: Mutex::new(None),
            vm_metric: Mutex::new(Default::default()),
            payload_state: Mutex::new(PayloadState::Starting),
            payload_state_updated: Condvar::new(),
            requester_uid_name,
            backend,
        };
        info!("{} created", &instance);
        Ok(instance)
    }

    pub(crate) fn start(self: &Arc<Self>) -> Result<(), Error> {
        let mut vm_metric = self.vm_metric.lock().unwrap();
        vm_metric.start_timestamp = Some(SystemTime::now());

        let mut vm_state = self.vm_state.lock().unwrap();
        let previous_vm_state = mem::replace(&mut *vm_state, VmState::Failed);
        if let VmState::NotStarted { config } = previous_vm_state {
            let config = *config;
            let detect_hangup = config.detect_hangup;
            let (failure_pipe_read, failure_pipe_write) = create_pipe()?;
            let vfio_devices = config.vfio_devices.clone();
            let tap =
                if let Some(tap_file) = &config.tap { Some(tap_file.try_clone()?) } else { None };

            // If this fails and returns an error, `self` will be left in the `Failed` state.
            let child = Arc::new(self.backend.run_vm(config, failure_pipe_write)?);

            let instance_monitor_status = self.clone();
            let child_monitor_status = child.clone();
            thread::spawn(move || {
                instance_monitor_status.clone().monitor_vm_status(child_monitor_status);
            });

            let child_clone = child.clone();
            let instance_clone = self.clone();
            let monitor_vm_exit_thread = Some(thread::spawn(move || {
                instance_clone.monitor_vm_exit(child_clone, failure_pipe_read, vfio_devices, tap);
            }));

            if detect_hangup {
                let child_clone = child.clone();
                let instance_clone = self.clone();
                thread::spawn(move || {
                    instance_clone.monitor_payload_hangup(child_clone);
                });
            }

            // If it started correctly, update the state.
            *vm_state = VmState::Running { child, monitor_vm_exit_thread };
            info!("{} started", &self);
            Ok(())
        } else {
            *vm_state = previous_vm_state;
            bail!("VM already started or failed")
        }
    }

    /// Returns the last reported state of the VM payload.
    pub fn payload_state(&self) -> PayloadState {
        *self.payload_state.lock().unwrap()
    }

    /// Updates the payload state to the given value, if it is a valid state transition.
    pub fn update_payload_state(&self, new_state: PayloadState) -> Result<(), Error> {
        let mut state_locked = self.payload_state.lock().unwrap();
        // Only allow forward transitions, e.g. from starting to started or finished, not back in
        // the other direction.
        if new_state > *state_locked {
            *state_locked = new_state;
            self.payload_state_updated.notify_all();
            Ok(())
        } else {
            bail!("Invalid payload state transition from {:?} to {:?}", *state_locked, new_state)
        }
    }

    pub(crate) fn kill(&self) -> Result<(), Error> {
        let monitor_vm_exit_thread = {
            let vm_state = &mut *self.vm_state.lock().unwrap();
            if let VmState::Running { child, monitor_vm_exit_thread } = vm_state {
                let id = child.id();
                debug!("Killing crosvm({})", id);
                // TODO: Talk to crosvm to shutdown cleanly.
                child.kill().with_context(|| format!("Error killing crosvm({id}) instance"))?;
                monitor_vm_exit_thread.take()
            } else {
                bail!("VM is not running")
            }
        };

        // Wait for monitor_vm_exit() to finish. Must release vm_state lock
        // first, as monitor_vm_exit() takes it as well.
        monitor_vm_exit_thread.map(JoinHandle::join);

        // Now that the VM has been killed, shut down the VirtualMachineService
        // server to eagerly free up the server threads.
        self.vm_context.vm_server.shutdown()?;

        Ok(())
    }

    pub(crate) fn get_memory_balloon(&self) -> Result<u64, Error> {
        self.backend.get_memory_balloon()
    }

    pub(crate) fn set_memory_balloon(&self, num_bytes: u64) -> Result<(), Error> {
        self.backend.set_memory_balloon(num_bytes)
    }

    pub(crate) fn suspend(&self) -> Result<(), Error> {
        self.backend.suspend()
    }

    pub(crate) fn resume(&self) -> Result<(), Error> {
        self.backend.resume()
    }

    fn send_ramdump_to_tombstoned(ramdump_path: &Path) -> Result<(), Error> {
        let mut input = File::open(ramdump_path)
            .context(format!("Failed to open ramdump {:?} for reading", ramdump_path))?;

        let pid = std::process::id() as i32;
        let conn = TombstonedConnection::connect(pid, DebuggerdDumpType::Tombstone)
            .context("Failed to connect to tombstoned")?;
        let mut output = conn
            .text_output
            .as_ref()
            .ok_or_else(|| anyhow!("Could not get file to write the tombstones on"))?;

        std::io::copy(&mut input, &mut output).context("Failed to send ramdump to tombstoned")?;
        info!("Ramdump {:?} sent to tombstoned", ramdump_path);

        conn.notify_completion()?;
        Ok(())
    }

    /// Checks if ramdump has been created. If so, send it to tombstoned.
    fn handle_ramdump(&self) -> Result<(), Error> {
        let ramdump_path = self.temporary_directory.join("ramdump");
        if !ramdump_path.as_path().try_exists()? {
            return Ok(());
        }
        if std::fs::metadata(&ramdump_path)?.len() > 0 {
            Self::send_ramdump_to_tombstoned(&ramdump_path)?;
        }
        Ok(())
    }

    fn monitor_vm_status(&self, child: Arc<SharedChild>) {
        let pid = child.id();

        loop {
            {
                // Check VM state
                let vm_state = &*self.vm_state.lock().unwrap();
                if let VmState::Dead = vm_state {
                    break;
                }

                let mut vm_metric = self.vm_metric.lock().unwrap();

                // Get CPU Information
                match get_guest_time(pid) {
                    Ok(guest_time) => vm_metric.cpu_guest_time = Some(guest_time),
                    Err(e) => error!("Failed to get guest CPU time: {e:?}"),
                }

                // Get Memory Information
                match self.backend.get_rss(pid) {
                    Ok(rss) => {
                        vm_metric.rss = match &vm_metric.rss {
                            Some(x) => Some(Rss::extract_max(x, &rss)),
                            None => Some(rss),
                        }
                    }
                    Err(e) => error!("Failed to get guest RSS: {}", e),
                }
            }

            thread::sleep(Duration::from_secs(1));
        }
    }

    /// Monitors the exit of the VM (i.e. termination of the `child` process). When that happens,
    /// handles the event by updating the state, noityfing the event to clients by calling
    /// callbacks, and removing temporary files for the VM.
    fn monitor_vm_exit(
        &self,
        child: Arc<SharedChild>,
        mut failure_pipe_read: File,
        vfio_devices: Vec<VfioDevice>,
        tap: Option<File>,
    ) {
        let result = child.wait();
        match &result {
            Err(e) => error!("Error waiting for crosvm({}) instance to die: {}", child.id(), e),
            Ok(status) => {
                info!("crosvm({}) exited with status {}", child.id(), status);
                self.backend.check_cpu_stall(status);
            }
        }

        let mut vm_state = self.vm_state.lock().unwrap();
        *vm_state = VmState::Dead;
        // Ensure that the mutex is released before calling the callbacks.
        drop(vm_state);
        info!("{} exited", &self);

        // Read the pipe to see if any failure reason is written
        let mut failure_reason = String::new();
        match failure_pipe_read.read_to_string(&mut failure_reason) {
            Err(e) => error!("Error reading VM failure reason from pipe: {}", e),
            Ok(len) if len > 0 => info!("VM returned failure reason '{}'", &failure_reason),
            _ => (),
        };

        // In case of hangup, the pipe doesn't give us any information because the hangup can't be
        // detected on the VM side (otherwise, it isn't a hangup), but in the
        // monitor_payload_hangup function below which updates the payload state to Hangup.
        let failure_reason =
            if failure_reason.is_empty() && self.payload_state() == PayloadState::Hangup {
                Cow::from("HANGUP")
            } else {
                Cow::from(failure_reason)
            };

        self.handle_ramdump().unwrap_or_else(|e| error!("Error handling ramdump: {}", e));

        let death_reason = self.backend.translate_death_reason(&result, &failure_reason);
        let exit_signal = exit_signal(&result);

        self.callbacks.callback_on_died(self.cid, death_reason);

        let vm_metric = self.vm_metric.lock().unwrap();
        write_vm_exited_stats_sync(
            self.requester_uid as i32,
            &self.name,
            death_reason,
            exit_signal,
            &vm_metric,
        );

        // Delete temporary files. The folder itself is removed by VirtualizationServiceInternal.
        remove_temporary_files(&self.temporary_directory).unwrap_or_else(|e| {
            error!("Error removing temporary files from {:?}: {}", self.temporary_directory, e);
        });

        if let Some(tap_file) = tap {
            GLOBAL_SERVICE
                .deleteTapInterface(&ParcelFileDescriptor::new(OwnedFd::from(tap_file)))
                .unwrap_or_else(|e| {
                    error!("Error deleting TAP interface: {e:?}");
                });
        }

        drop(vfio_devices); // Cleanup devices.
    }
    ///
    /// Waits until payload is started, or timeout expires. When timeout occurs, kill
    /// the VM to prevent indefinite hangup and update the payload_state accordingly.
    fn monitor_payload_hangup(&self, child: Arc<SharedChild>) {
        debug!("Starting to monitor hangup for Microdroid({})", child.id());
        let (state, result) = self
            .payload_state_updated
            .wait_timeout_while(self.payload_state.lock().unwrap(), *BOOT_HANGUP_TIMEOUT, |s| {
                *s < PayloadState::Started
            })
            .unwrap();
        drop(state); // we are not interested in state
        let child_still_running = child.try_wait().ok() == Some(None);
        if result.timed_out() && child_still_running {
            error!(
                "Microdroid({}) failed to start payload within {} secs timeout. Shutting down.",
                child.id(),
                BOOT_HANGUP_TIMEOUT.as_secs()
            );
            self.update_payload_state(PayloadState::Hangup).unwrap();
            if let Err(e) = self.kill() {
                error!("Error stopping timed-out VM with CID {}: {:?}", child.id(), e);
            }
        }
    }
}

fn exit_signal(result: &Result<ExitStatus, io::Error>) -> Option<i32> {
    match result {
        Ok(status) => status.signal(),
        Err(_) => None,
    }
}

// Get guest time from /proc/[crosvm pid]/stat
fn get_guest_time(pid: u32) -> Result<i64> {
    let file = read_to_string(format!("/proc/{}/stat", pid))?;
    let data_list: Vec<_> = file.split_whitespace().collect();

    // Information about guest_time is at 43th place of the file split with the whitespace.
    // Example of /proc/[pid]/stat :
    // 6603 (kworker/104:1H-kblockd) I 2 0 0 0 -1 69238880 0 0 0 0 0 88 0 0 0 -20 1 0 1845 0 0
    // 18446744073709551615 0 0 0 0 0 0 0 2147483647 0 0 0 0 17 104 0 0 0 0 0 0 0 0 0 0 0 0 0
    if data_list.len() < 43 {
        bail!("Failed to parse command result for getting guest time : {}", file);
    }

    let guest_time_ticks = data_list[42].parse::<i64>()?;
    // SAFETY: It just returns an integer about CPU tick information.
    let ticks_per_sec = unsafe { sysconf(_SC_CLK_TCK) };
    Ok(guest_time_ticks * MILLIS_PER_SEC / ticks_per_sec)
}

/// Creates a new pipe with the `O_CLOEXEC` flag set, and returns the read side and write side.
fn create_pipe() -> Result<(File, File), Error> {
    let (read_fd, write_fd) = pipe2(OFlag::O_CLOEXEC)?;
    Ok((read_fd.into(), write_fd.into()))
}

/// Adds the file descriptor for `file` to `preserved_fds`, and returns a string of the form
/// "/proc/self/fd/N" where N is the file descriptor.
pub(crate) fn add_preserved_fd<F: Into<OwnedFd>>(
    preserved_fds: &mut Vec<OwnedFd>,
    file: F,
) -> String {
    let fd = file.into();
    let raw_fd = fd.as_raw_fd();
    preserved_fds.push(fd);
    format!("/proc/self/fd/{}", raw_fd)
}
