# Run Realm as Microdroid using kvmtool 

This guide provides a walkthrough for running a **Realm** as a **Microdroid** instance using **kvmtool**.    
Microdroid is a (very) lightweight version of Android that is intended to run on on-device virtual machines.    
By utilizing kvmtool, you can deploy Microdroid instances as a realm.  

## Table of contents
- [Prerequisite](#prerequisite)
- [Manual Build](#manual-build)
    - [Build TF-RMM, Host EDK2 and TF-A](#build-tf-rmm-host-edk2-and-tf-a)
    - [Build Host and Guest Android Kernel](#build-host-and-guest-android-kernel)
    - [Ramdisk Repacking](#ramdisk-repacking)
- [Run Host Android on QEMU with manually built images](#run-host-android-on-qemu-with-manually-built-images)
- [Run Host Android on QEMU with prebuilt images](#run-host-android-on-qemu-with-prebuilt-images)
- [How to run Realm as Microdroid using kvmtool](#how-to-run-realm-as-microdroid-using-kvmtool)
- [How to access the realm](#how-to-access-the-realm)
- [Run Demo Apps](#run-demo-apps)

## Prerequisite
```bash
# Go to the odcc-islet-script-qemu-rme root directory (https://github.sec.samsung.net/SYSSEC/odcc-islet-script-qemu-rme)
#
# NOTE: We can't use the public islet directory at the moment. This is because the internal dependent repositories required
# to run Microdroid as a realm using kvmtool shouldn't be public for now. 
git clone https://github.sec.samsung.net/SYSSEC/odcc-islet-script-qemu-rme.git
cd odcc-islet-script-qemu-rme

# Download & Build build components that we need (qemu, aosp, android-kernel, etc)
./scripts/init_android_on_qemu.sh
```

## Manual Build
The required images can be built manually by following the instructions provided in this guide.

### Build TF-RMM, Host EDK2 and TF-A
To build `flash.bin` which is combinded image with `TF-RMM`, `Host EDK2` and `TF-A`, you should build them manually.

This build process is based on the instructions provided in [this reference](https://linaro.atlassian.net/wiki/pages/viewpage.action?pageId=29596450823&pageVersion=3)

#### TF-RMM
```bash
git clone https://git.codelinaro.org/linaro/dcap/rmm.git -b cca/v4
cd rmm
git submodule update --init --recursive

# NOTE: Set CROSS_COMPILE properly to your path of the binaries
export CROSS_COMPILE=aarch64-none-elf- 
cmake -DCMAKE_BUILD_TYPE=Debug -DRMM_CONFIG=qemu_virt_defcfg -B build-qemu
cmake --build build-qemu
```

#### Host EDK2
```bash
git clone https://github.com/tianocore/edk2.git
cd edk2/
git checkout 2839fed575

git submodule update --init --recursive
source edksetup.sh
make -j -C BaseTools

# NOTE: Set GCC5_AARCH64_PREFIX properly to your path of the binaries
export GCC5_AARCH64_PREFIX=/usr/bin/aarch64-linux-gnu-
build -b RELEASE -a AARCH64 -t GCC5 -p ArmVirtPkg/ArmVirtQemuKernel.dsc
```

#### TF-A
```bash
git clone https://git.codelinaro.org/linaro/dcap/TF-A/trusted-firmware-a.git -b cca/v4
cd trusted-firmware-a

# Embed the RMM image and edk2 into the Final Image Package (FIP)
make -j CROSS_COMPILE=/usr/bin/aarch64-linux-gnu- PLAT=qemu ENABLE_RME=1 DEBUG=1 LOG_LEVEL=40 \
    QEMU_USE_GIC_DRIVER=QEMU_GICV3 RMM=../rmm/build-qemu/Debug/rmm.img \
    BL33=../edk2/Build/ArmVirtQemuKernel-AARCH64/RELEASE_GCC5/FV/QEMU_EFI.fd all fip

# Pack whole image into flash.bin
dd if=build/qemu/debug/bl1.bin of=flash.bin
dd if=build/qemu/debug/fip.bin of=flash.bin seek=64 bs=4096
```

### Build Host and Guest Android Kernel
#### Guest Android Kernel
```bash
repo init -b android15-6.6/cca-guest/manifest/v7 -u https://github.com/islet-project/3rd-android-kernel.git
repo sync
tools/bazel run //common:kernel_aarch64_microdroid_dist
```

Copy the built kernel image to the Android source tree directly, and build the virt APEX.

For ARM64,
```bash
cp out/kernel_aarch64_microdroid/dist/Image <android_checkout>/packages/modules/Virtualization/guest/kernel/android15-6.6/arm64/kernel-6.6
```

#### Host Android Kernel
```bash
repo init -b android16-6.12/cca-host/manifest/v5 -u https://github.com/islet-project/3rd-android-kernel.git
repo sync
tools/bazel run //common-modules/virtual-device:virtual_device_aarch64_dist
```

Then we can find the output files:
- out/kernel_aarch64_microdroid/dist/Image
- out/kernel_aarch64_microdroid/dist/initramfs.img

### Ramdisk Repacking
There are [some issues](https://confluence.sec.samsung.net/spaces/SYSSECC/pages/1023473329/Trials+to+run+Android+on+QEMU-RME?focusedCommentId=1066644686#comment-1066644686) when we use `launch_cvd` command with the images built by manual build:
- The kernel try to uses kernel modules in existing ramdisk image other than the ones built with kernel together
- The bootconfig is not properly set.

We should find out why these issues are happening. But for now, we can use [workaround solution](https://confluence.sec.samsung.net/spaces/SYSSECC/pages/1078706094/2.+Android+on+QEMU-RME#id-2.AndroidonQEMURME-Run) to fix those issues.

The ramdisk repacking is needed on the following cases:
- When you change your host linux kernel
- When you change your ramdisk (e.g, modify AOSP Virtualization module)

After repacking it, we can get `aosp_rme_ramdisk.img` to run microdroid manually.

#### 1. Extract host bootconfig
Whenever you change your host linux, you should extract the bootconfig. 
```bash
cd <aosp root>
source build/envsetup.sh
lunch aosp_cf_arm64_only_phone-trunk_staging-userdebug

launch_cvd -vm_manager qemu_cli -console=true \
	--memory_mb 8192 \
	-qemu_binary_dir <odcc-islet-script-qemu-rme root>/third-party/android_on_qemu/qemu/build \
	-enable_host_bluetooth false -report_anonymous_usage_stats=n \
	-kernel_path  <host android kernel root>/out/virtual_device_aarch64/dist/Image \
	-initramfs_path <host android kernel root>/out/virtual_device_aarch64/dist/initramfs.img 

# After launching, extract bootconfig  
adb shell cat /proc/bootconfig > host_bootconfig
```

#### 2. Build bootconfig tool
To add your boot config file to ramdisk, you need the bootconfig tool
```bash
cd <host android kernel root>/common
make -C tools/bootconfig
```

#### 3. Save repack_ramdisk.sh
Save the below `repack_ramdisk.sh` into your aosp root directory after modifying the path to suit your environment

```bash
#!/bin/bash

repacked="~/cuttlefish/instances/cvd-1/vendor_boot_repacked.img"
aosp_out="<aosp root>/out/target/product/vsoc_arm64_only"
bootconfig_exec="<host android kernel root>/common/tools/bootconfig"
bootconfig="<Your extracted host bootconfig path (e.g, host_bootconfig)>"
 
 
if [ ! -f ${repacked} ]; then
    echo "No $repacked"
    exit 0
fi
 
if [ ! -f ${bootconfig_exec}/bootconfig ]; then
  echo "bootconfig util exec does not exist @ ${bootconfig_exec}/bootconfig "
  exit 0
fi
 
if [ ! -f ${bootconfig} ]; then
  echo "bootconfig config does not exist: $bootconfig"
  exit 0
fi
 
if [ ! -f ${aosp_out}/ramdisk.img ]; then
  echo "ramdisk.img does not exist"
  exit 0
fi
 
if [ -d ${aosp_out}/vendor_boot_repacked ]; then
    rm -rf ${aosp_out}/vendor_boot_repacked
fi
 
unpack_bootimg --boot_img ${repacked} --out ${aosp_out}/vendor_boot_repacked
 
if [ ! -d ${aosp_out}/vendor_boot_repacked ]; then
  echo "No vendor boot repacked"
  exit 0
fi
 
cd ${aosp_out}
pwd
cat ${aosp_out}/vendor_boot_repacked/vendor_ramdisk00 ./ramdisk.img > ./aosp_rme_ramdisk.img
${bootconfig_exec}/bootconfig -a ${bootconfig} aosp_rme_ramdisk.img
ls -al aosp_rme_ramdisk.img
cd -
```

#### 4. Repack ramdisk
```bash
cd <aosp root>
source build/envsetup.sh
lunch aosp_cf_arm64_only_phone-trunk_staging-userdebug

# (Optional) If you don't have vendor_boot_repacked.img in your cvd-1 directory, you need the below command:
launch_cvd -vm_manager qemu_cli -console=true \
	--memory_mb 8192 \
	-qemu_binary_dir <odcc-islet-script-qemu-rme root>/third-party/android_on_qemu/qemu/build \
	-enable_host_bluetooth false -report_anonymous_usage_stats=n \
	-kernel_path  <host android kernel root>/out/virtual_device_aarch64/dist/Image \
	-initramfs_path <host android kernel root>/out/virtual_device_aarch64/dist/initramfs.img 

# After the vendor_boot_repacked.img is generated, you can stop the launch_cvd command 
# And run the below command to repack ramdisk
./repack_ramdisk.sh

# Finally, you can check aosp_rme_ramdisk.img
ls out/target/product/vsoc_arm64_only/aosp_rme_ramdisk.img 
out/target/product/vsoc_arm64_only/aosp_rme_ramdisk.img
```

## Run Host Android on QEMU with manually built images
```bash
cd <aosp root>
source build/envsetup.sh
lunch aosp_cf_arm64_only_phone-trunk_staging-userdebug

# NOTE: Modify <the paths> to suit your environment
launch_cvd -vm_manager qemu_cli -console=true \
	--memory_mb 8192 \
	-qemu_binary_dir <odcc-islet-script-qemu-rme root>/third-party/android_on_qemu/qemu/build \
	-enable_host_bluetooth false -report_anonymous_usage_stats=n \
	-kernel_path  <host android kernel root>/out/virtual_device_aarch64/dist/Image \
	-initramfs_path <host android kernel root>/out/virtual_device_aarch64/dist/initramfs.img \
	-extra_kernel_cmdline "androidboot.hypervisor.vm.supported=1 vmw_vsock_virtio_transport_common.virtio_transport_max_vsock_pkt_buf_size=16384 console=ttynull stack_depot_disable=on cgroup_disable=pressure kasan.stacktrace=off bootconfig  printk.devkmsg=on audit=1 panic=-1 8250.nr_uarts=1 cma=0 firmware_class.path=/vendor/etc/ loop.max_part=7 init=/init bootconfig  console=hvc0 earlycon=pl011,mmio32,0x9000000 <aosp_root>/out/target/product/vsoc_arm64_only/aosp_rme_ramdisk.img" \
	-bootloader  <trusted-firmware-a root>/flash.bin
```

## Run Host Android on QEMU with prebuilt images
The `qemu-cca.py` will use the following images to run Host Android on QEMU:
- flash.bin: combinded image with `TF-RMM`, `Host EDK2` and `TF-A`
- host.Image: Host kernel image for android
- host.initramfs.img: Host initramfs image for android
- aosp_rme_ramdisk.img: Android ramdisk image

The prebuilt images are uploaded in [islet/asset](https://github.com/islet-project/assets/tree/main/prebuilt/qemu_rme).

```bash
# Run Host Android on QEMU
./scripts/qemu-cca.py -nw aosp-prebuilt
```


## How to run Realm as Microdroid using kvmtool

To run CCA supported microdroid in the android, follow the below steps:
```bash
adb root
# It's needed to create /data/crosvm_raw images
adb shell setenforce 0

# Access to the host android
adb shell

# Run crosvm first to create crosvm_raw images which would be used by kvmtool
/apex/com.android.virt/bin/vm run-microdroid

# Check crosvm_raw images in /data
vsoc_arm64_only:/ # ls -ltr /data/crosvm*
-rw-rw-rw- 1 root root 50528256 2025-04-22 11:23 /data/crosvm_raw_0
-rw-rw-rw- 1 root root  7012352 2025-04-22 11:23 /data/crosvm_raw_2
-rw-rw-rw- 1 root root 10551296 2025-04-22 12:41 /data/crosvm_raw_1

# Then create use_kvmtool in /data
# If it's not exist, the 'vm' binary just runs microdroid using crosvm as default
touch /data/use_kvmtool
# It adds '--realm' option into kvmtool
touch /data/use_realm

# Run microdroid realm
/apex/com.android.virt/bin/vm run-microdroid
```

Then you can see the microdroid logs in the terminal:
``` bash
found path /apex/com.android.virt/app/EmptyPayloadApp@AP4A.241205.013.B1/EmptyPayloadApp.apk
creating work dir /data/local/tmp/microdroid/oew0yEw5MBofV47ni
apk.idsig path: /data/local/tmp/microdroid/oew0yEw5MBofV47ni/apk.idsig
instance.img path: /data/local/tmp/microdroid/oew0yEw5MBofV47ni/instance.img
instance_id file path: /data/local/tmp/microdroid/oew0yEw5MBofV47ni/instance_id
Created debuggable VM from "/apex/com.android.virt/app/EmptyPayloadApp@AP4A.241205.013.B1/EmptyPayloadApp.apk"!PayloadConfig(VirtualMachinePayloadConfig { payloadBinaryName: "MicrodroidEmptyPayloadJniLib.so", extraApks: [] }) with CID 2050, state is STARTING.
  Debug: (arm/aarch64/kvm.c) validate_realm_cfg:82: Realm Hash algorithm: Using default SHA256

  Info: # lkvm run -k /proc/self/fd/38 -m 256 -c 1 --name VmRunApp
  Debug: (arm/aarch64/kvm.c) kvm__get_vm_type:184: max_ipa 8fffffff ipa_bits 33 max_ipa_bits 52
  Debug: (arm/aarch64/kvm.c) kvm__arch_enable_mte:218: MTE capability not available
  Debug: (arm/aarch64/kvm.c) kvm__arch_enable_exit_hypcall:241: EXIT HYPERCALL capability not available
  Debug: (arm/kvm.c) kvm__init_ram:143: RAM created at 0x80000000 - 0x8fffffff (host ram_start 0x76e3c00000)
  Debug: (arm/kvm.c) kvm__arch_load_kernel_image:238: Loaded kernel to 0x80000000 - 0x80c10000 (12242944 bytes actual)
  Debug: (arm/kvm.c) kvm__arch_load_kernel_image:271: Placing fdt at 0x8fe00000 - 0x8fffffff
  Debug: (arm/kvm.c) kvm__arch_load_kernel_image:299: Loaded initrd to 0x8fbfeed4 (2101544 bytes)
  Debug: (arm/aarch64/realm.c) realm_init_ipa_range:186: Initialized IPA range (80000000 - 90000000) as RAM

  Debug: (arm/aarch64/realm.c) __realm_populate:211: Populated Realm memory area : 80000000 - 80bad000 (size 12242944 bytes)
  Debug: (arm/aarch64/realm.c) __realm_populate:211: Populated Realm memory area : 8fbfeed4 - 8fdffffc (size 2101544 bytes)
  Debug: (arm/aarch64/realm.c) __realm_populate:211: Populated Realm memory area : 8fe00000 - 8fe10000 (size 65536 bytes)
  Debug: (kvm.c) unmap_bank:599: unmap_bank hva 0x76e3c00000 (size: 268435456)
  Debug: (kvm.c) set_guest_bank_private:616: set_guest_bank_private gpa 0x80000000 (size: 268435456)
nux on physical CPU 0x0000000000 [0x000f0510]
[    0.000000][    T0] Linux version 6.6.82-android15-8-maybe-dirty (kleaf@build-host) (Android (11368308, +pgo, +bolt, +lto, +mlgo, based on r510928) clang version 18.0.0 (https://android.googlesource.com/toolchain/llvm-project 477610d4d0d988e69dbc3fae4fe86bff3f07f2b5), LLD 18.0.0) #1 SMP PREEMPT Thu Jan  1 00:00:00 UTC 1970
...
[    0.000000][    T0] RME: Using RSI version 1.0
...
payload is ready
```

## How to access the realm
Once the 'payload is ready' log appears, you can access the realm using adb.
```bash
adb shell /apex/com.android.virt/bin/vm list
Running VMs: [
    VirtualMachineDebugInfo {
        cid: 2049, # Check this cid number
        temporaryDirectory: "/data/misc/virtualizationservice/2049",
        requesterUid: 0,
        requesterPid: 4136,
        hostConsoleName: None,
    },
]

# Connect the realm using the above cid number
adb forward tcp:9876 vsock:2049:5555
adb connect localhost:9876
adb -s localhost:9876 root

# Access to the realm 
adb -s localhost:9876 shell

# Check linux version of the realm
$ uname -a
Linux (none) 6.6.82-android15-8-maybe-dirty #1 SMP PREEMPT Thu Jan  1 00:00:00 UTC 1970 aarch64 Toybox
```

## Run Demo Apps
There are two different apps, **CCPlugIn** and **OdccExampleClientOrig**

**CCPlugIn** is a host-side Android application that runs user-defined services inside a realm world (by using Microdroid) and exposes the service to other normal-world (NW) apps via a stable AIDL interface.

A separate **OdccExampleClientOrig** app talks to **CCPlugIn** over that AIDL, invokes the user service running in the realm, and renders the results in its UI.
### Build
```bash
cd <AOSP Root>
source build/envsetup.sh
lunch aosp_cf_arm64_only_phone-trunk_staging-userdebug
m OdccExampleClientOrig CCPlugIn
```

### Install
```bash
cd <AOSP Root>/out/target/product/vsoc_arm64_only/system/app/
adb install-multi-package -t -g OdccExampleClientOrig/OdccExampleClientOrig.apk CCPlugIn/CCPlugIn.apk
```

### Run using crosvm
```bash
adb root
adb shell
setenforce 0

# Run the client and the CCPlugIn apps.
# The client calls 'bindService' to the CCPlugIn with BIND_AUTO_CREATE flag. So CCPlugIn will be launched automatically.
# NOTE: But it takes some time to run realm. Don't touch any buttons in client UI.
am start -n com.examplecc.client/.MainActivity

# Check the log "VM service connection successful"
# If you can see the log, then the realm is running.
grep "VM service connection successful" /data/data/com.examplecc.service/files/service2.txt
```
Then press any button and see the result in the UI like the below image:

![image](https://github.sec.samsung.net/SYSSEC/odcc-aosp-modules-virtualization/assets/72559/2724d36b-5993-43e8-800b-cbed8874db17)

### Run using kvmtool
```bash
adb root
adb shell
setenforce 0

# Create files which are some kinds of flags to use kvmtool
touch /data/use_kvmtool /data/use_realm

# Run the CCPlugIn app first.
# The kvmtool is slower than crosvm. So it would be better to runs realm first.
am start -n com.examplecc.client/.MainActivity

# Check the log "VM service connection successful"
# If you can see the log, then the realm is running.
grep "VM service connection successful" /data/data/com.examplecc.service/files/service2.txt

# Run the client app.
am start -n com.examplecc.client/.MainActivity
```
