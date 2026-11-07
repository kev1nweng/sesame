// SPDX-License-Identifier: AGPL-3.0-or-later
//! Minimal Mach wrappers: task port, memory region iteration, memory reads.
//!
//! Uses only stable libSystem C symbols, no third-party crates.

use std::ffi::c_void;

pub type KernReturn = i32;
pub type MachPort = u32;

const KERN_SUCCESS: KernReturn = 0;
const VM_REGION_BASIC_INFO_64: i32 = 9;

pub const VM_PROT_READ: i32 = 1;
pub const VM_PROT_WRITE: i32 = 2;

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct VmRegionBasicInfo64 {
    protection: i32,
    max_protection: i32,
    inheritance: u32,
    shared: u32,
    reserved: u32,
    offset: u64,
    behavior: i32,
    user_wired_count: u16,
}

extern "C" {
    static mach_task_self_: MachPort;
    fn task_for_pid(target_t: MachPort, pid: i32, task: *mut MachPort) -> KernReturn;
    fn mach_vm_region(
        target_task: MachPort,
        address: *mut u64,
        size: *mut u64,
        flavor: i32,
        info: *mut i32,
        info_count: *mut u32,
        object_name: *mut MachPort,
    ) -> KernReturn;
    fn mach_vm_read_overwrite(
        target_task: MachPort,
        address: u64,
        size: u64,
        data: u64,
        outsize: *mut u64,
    ) -> KernReturn;
    fn proc_listallpids(buffer: *mut c_void, buffersize: i32) -> i32;
    fn proc_pidpath(pid: i32, buffer: *mut c_void, buffersize: u32) -> i32;
    fn proc_pid_rusage(pid: i32, flavor: i32, buffer: *mut c_void) -> i32;
}

#[derive(Debug, Clone, Copy)]
pub struct Region {
    pub addr: u64,
    pub size: u64,
    pub protection: i32,
}

impl Region {
    pub fn readable(&self) -> bool {
        self.protection & VM_PROT_READ != 0
    }
    pub fn writable(&self) -> bool {
        self.protection & VM_PROT_WRITE != 0
    }
}

/// Obtain the target task port. Returns a kernel error code on failure (5 = permission denied).
pub fn task_for(pid: i32) -> Result<MachPort, KernReturn> {
    let mut task: MachPort = 0;
    let kr = unsafe { task_for_pid(mach_task_self_, pid, &mut task) };
    if kr == KERN_SUCCESS && task != 0 {
        Ok(task)
    } else {
        Err(kr)
    }
}

pub fn list_pids() -> Vec<i32> {
    unsafe {
        // note: proc_listallpids returns a process count, not a byte count.
        let count = proc_listallpids(std::ptr::null_mut(), 0);
        if count <= 0 {
            return Vec::new();
        }
        let mut buf: Vec<i32> = vec![0; count as usize + 128];
        let got = proc_listallpids(buf.as_mut_ptr() as *mut c_void, (buf.len() * 4) as i32);
        if got <= 0 {
            return Vec::new();
        }
        buf.truncate(got as usize);
        buf.into_iter().filter(|p| *p > 0).collect()
    }
}

pub fn pid_path(pid: i32) -> Option<String> {
    let mut buf = vec![0u8; 4096];
    let n = unsafe { proc_pidpath(pid, buf.as_mut_ptr() as *mut c_void, buf.len() as u32) };
    if n <= 0 {
        return None;
    }
    buf.truncate(n as usize);
    Some(String::from_utf8_lossy(&buf).to_string())
}

/// Iterate the target's virtual memory regions. Callers filter by protection.
pub fn regions(task: MachPort) -> Vec<Region> {
    let mut out = Vec::new();
    let mut addr: u64 = 0;
    loop {
        let mut size: u64 = 0;
        let mut info = VmRegionBasicInfo64::default();
        let mut count: u32 =
            (std::mem::size_of::<VmRegionBasicInfo64>() / std::mem::size_of::<i32>()) as u32;
        let mut object: MachPort = 0;
        let kr = unsafe {
            mach_vm_region(
                task,
                &mut addr,
                &mut size,
                VM_REGION_BASIC_INFO_64,
                &mut info as *mut VmRegionBasicInfo64 as *mut i32,
                &mut count,
                &mut object,
            )
        };
        if kr != KERN_SUCCESS || size == 0 {
            break;
        }
        out.push(Region {
            addr,
            size,
            protection: info.protection,
        });
        let next = addr.saturating_add(size);
        if next <= addr {
            break;
        }
        addr = next;
    }
    out
}

/// Read a memory range. Returns None on failure (region gone or unreadable).
pub fn read_mem(task: MachPort, addr: u64, size: usize) -> Option<Vec<u8>> {
    if size == 0 {
        return None;
    }
    let mut buf = vec![0u8; size];
    let mut out: u64 = 0;
    let kr = unsafe {
        mach_vm_read_overwrite(
            task,
            addr,
            size as u64,
            buf.as_mut_ptr() as u64,
            &mut out,
        )
    };
    if kr != KERN_SUCCESS || out == 0 {
        return None;
    }
    buf.truncate(out as usize);
    Some(buf)
}

/// Resident memory size (diagnostics).
pub fn rss_bytes(pid: i32) -> Option<u64> {
    // Must match struct rusage_info_v2 exactly: the kernel writes all 19 fields, so a
    // short struct overflows the stack and aborts the process later (found the hard way).
    #[repr(C)]
    #[derive(Default)]
    struct RusageInfoV2 {
        ri_uuid: [u8; 16],
        ri_user_time: u64,
        ri_system_time: u64,
        ri_pkg_idle_wkups: u64,
        ri_interrupt_wkups: u64,
        ri_pageins: u64,
        ri_wired_size: u64,
        ri_resident_size: u64,
        ri_phys_footprint: u64,
        ri_proc_start_abstime: u64,
        ri_proc_exit_abstime: u64,
        ri_child_user_time: u64,
        ri_child_system_time: u64,
        ri_child_pkg_idle_wkups: u64,
        ri_child_interrupt_wkups: u64,
        ri_child_pageins: u64,
        ri_child_elapsed_abstime: u64,
        ri_diskio_bytesread: u64,
        ri_diskio_byteswritten: u64,
    }
    let mut info = RusageInfoV2::default();
    let r = unsafe {
        proc_pid_rusage(
            pid,
            2, // RUSAGE_INFO_V2
            &mut info as *mut RusageInfoV2 as *mut c_void,
        )
    };
    if r == 0 {
        Some(info.ri_phys_footprint)
    } else {
        None
    }
}