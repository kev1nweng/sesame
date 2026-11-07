// SPDX-License-Identifier: AGPL-3.0-or-later
//! Minimal injector: create a thread in the target and run `dlopen(our library)`.
//!
//! No Frida, no ptrace. Requires signing sesame with
//! `com.apple.security.cs.debugger` (`sesame sign`), or running as root.

use std::ffi::{c_char, c_int, c_void, CStr, CString};

use anyhow::{bail, Context, Result};

type KernReturn = i32;
type MachPort = u32;

const VM_FLAGS_ANYWHERE: i32 = 1;
const ARM_THREAD_STATE64: i32 = 6;
const ARM_THREAD_STATE64_COUNT: u32 = 68;
/// TASK_DYLD_INFO's flavor has been seen as both 17 and 5 across SDKs; try both.
const TASK_DYLD_INFO_FLAVORS: [i32; 2] = [17, 5];
const RTLD_DEFAULT: *mut c_void = -2isize as *mut c_void;
const RTLD_NOW: c_int = 0x2;
const VM_PROT_READ: i32 = 1;
const VM_PROT_WRITE: i32 = 2;
const VM_PROT_EXEC: i32 = 4;

#[repr(C)]
struct TaskDyldInfo {
    all_image_info_addr: u64,
    all_image_info_size: u64,
    all_image_info_format: i32,
}

#[repr(C)]
struct DlInfo {
    dli_fname: *const c_char,
    dli_fbase: *mut c_void,
    dli_sname: *const c_char,
    dli_saddr: *mut c_void,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct ArmThreadState64 {
    x: [u64; 29],
    fp: u64,
    lr: u64,
    sp: u64,
    pc: u64,
    cpsr: u32,
    pad: u32,
}

extern "C" {
    static mach_task_self_: MachPort;
    fn task_info(task: MachPort, flavor: i32, info: *mut i32, count: *mut u32) -> KernReturn;
    fn mach_vm_allocate(task: MachPort, address: *mut u64, size: u64, flags: i32) -> KernReturn;
    fn mach_vm_write(task: MachPort, address: u64, data: usize, len: u32) -> KernReturn;
    fn thread_create(
        task: MachPort,
        thread: *mut MachPort,
    ) -> KernReturn;
    fn thread_set_state(
        thread: MachPort,
        flavor: i32,
        state: *const u32,
        count: u32,
    ) -> KernReturn;
    fn mach_vm_protect(
        task: MachPort,
        address: u64,
        size: u64,
        set_maximum: i32,
        new_protection: i32,
    ) -> KernReturn;
    fn thread_resume(thread: MachPort) -> KernReturn;
    fn thread_terminate(thread: MachPort) -> KernReturn;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn dladdr(addr: *const c_void, info: *mut DlInfo) -> c_int;
}

fn kr_ok(kr: KernReturn, what: &str) -> Result<()> {
    if kr == 0 {
        Ok(())
    } else {
        bail!("{what} failed (kernel returned {kr})")
    }
}

/// (path, base address) of every image loaded in the target.
fn remote_images(task: MachPort) -> Result<Vec<(String, u64)>> {
    let mut info = TaskDyldInfo {
        all_image_info_addr: 0,
        all_image_info_size: 0,
        all_image_info_format: 0,
    };
    let mut ok = false;
    let mut last = 0;
    for flavor in TASK_DYLD_INFO_FLAVORS {
        let mut count: u32 = 5;
        let kr = unsafe {
            task_info(
                task,
                flavor,
                &mut info as *mut TaskDyldInfo as *mut i32,
                &mut count,
            )
        };
        last = kr;
        if kr == 0 && info.all_image_info_addr != 0 && info.all_image_info_size > 0 {
            ok = true;
            break;
        }
    }
    kr_ok(if ok { 0 } else { last }, "task_info(TASK_DYLD_INFO)")?;

    let read = |addr: u64, size: usize| -> Option<Vec<u8>> { crate::mach::read_mem(task, addr, size) };

    let head = read(info.all_image_info_addr, 24).context("reading dyld_all_image_infos failed")?;
    let array_count = u32::from_le_bytes([head[4], head[5], head[6], head[7]]) as usize;
    let array_addr = u64::from_le_bytes([
        head[8], head[9], head[10], head[11], head[12], head[13], head[14], head[15],
    ]);
    let table = read(array_addr, (array_count * 24).max(24)).context("reading the image table failed")?;

    let mut out = Vec::new();
    for i in 0..array_count {
        let off = i * 24;
        if off + 24 > table.len() {
            break;
        }
        let load = u64::from_le_bytes(table[off..off + 8].try_into().unwrap());
        let path_ptr = u64::from_le_bytes(table[off + 8..off + 16].try_into().unwrap());
        if load == 0 || path_ptr == 0 {
            continue;
        }
        if let Some(raw) = read(path_ptr, 512) {
            let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
            if end > 0 {
                out.push((String::from_utf8_lossy(&raw[..end]).to_string(), load));
            }
        }
    }
    Ok(out)
}

/// Translate a symbol address from our own process into the target's address space.
fn remote_address_of(task: MachPort, symbol: &str) -> Result<u64> {
    let name = CString::new(symbol)?;
    let local = unsafe { dlsym(RTLD_DEFAULT, name.as_ptr()) };
    anyhow::ensure!(!local.is_null(), "symbol {symbol} not found locally");

    let mut di = DlInfo {
        dli_fname: std::ptr::null(),
        dli_fbase: std::ptr::null_mut(),
        dli_sname: std::ptr::null(),
        dli_saddr: std::ptr::null_mut(),
    };
    anyhow::ensure!(unsafe { dladdr(local, &mut di) } != 0, "dladdr failed");
    let local_base = di.dli_fbase as u64;
    let local_path = unsafe { CStr::from_ptr(di.dli_fname) }.to_string_lossy().to_string();
    let local_name = local_path.rsplit('/').next().unwrap_or(&local_path).to_string();
    let offset = local as u64 - local_base;

    let images = remote_images(task)?;
    let hit = images
        .iter()
        .find(|(p, _)| p.rsplit('/').next().unwrap_or(p) == local_name)
        .with_context(|| format!("image {local_name} not found in the target process"))?;
    Ok(hit.1 + offset)
}

/// dlopen a library by path inside the target process.
///
/// `watch` points at the log the hook writes: a `"status"` line means the constructor
/// finished, at which point the carrier thread is retired (pthread cleanup on a foreign
/// stack spins forever, so it cannot simply be left running).
pub fn inject(pid: i32, dylib_path: &str) -> Result<()> {
    inject_watched(pid, dylib_path, None, std::time::Duration::from_secs(3))
}

pub fn inject_watched(
    pid: i32,
    dylib_path: &str,
    watch: Option<&std::path::Path>,
    wait: std::time::Duration,
) -> Result<()> {
    let task = crate::mach::task_for(pid)
        .map_err(|c| anyhow::anyhow!("cannot read process memory ({c}); run `sesame sign` or use sudo"))?;

    // make sure CommonCrypto is loaded in the target (the hook dlopens it too)
    let dlopen_addr = remote_address_of(task, "dlopen")?;
    let pthread_exit_addr = remote_address_of(task, "pthread_exit")?;
    // turn the Mach thread into a real pthread, otherwise locks inside dlopen hang
    let pcfmt = remote_address_of(task, "pthread_create_from_mach_thread").ok();
    let _ = unsafe { mach_task_self_ };

    let path = CString::new(dylib_path)?;
    let path_len = path.as_bytes_with_nul().len();
    let mut path_addr: u64 = 0;
    kr_ok(
        unsafe { mach_vm_allocate(task, &mut path_addr, path_len as u64 + 16, VM_FLAGS_ANYWHERE) },
        "allocating argument memory",
    )?;
    kr_ok(
        unsafe {
            mach_vm_write(
                task,
                path_addr,
                path.as_ptr() as usize,
                path_len as u32,
            )
        },
        "writing library path",
    )?;

    // trampoline (arm64): mov w1,#2 ; ldr x16,#12 ; br x16 ; nop ; .quad dlopen
    let mut stub: u64 = 0;
    let stub_page = 4096u64;
    kr_ok(
        unsafe {
            mach_vm_allocate(
                task,
                &mut stub,
                stub_page,
                VM_FLAGS_ANYWHERE,
            )
        },
        "allocating trampoline memory",
    )?;
    let mut code: Vec<u8> = Vec::with_capacity(24);
    code.extend_from_slice(&0x5280_0041u32.to_le_bytes()); // mov w1, #2 (RTLD_NOW)
    code.extend_from_slice(&0x5800_0060u32.to_le_bytes()); // ldr x16, #12
    code.extend_from_slice(&0xD61F_0200u32.to_le_bytes()); // br x16
    code.extend_from_slice(&0xD503_201Fu32.to_le_bytes()); // nop
    code.extend_from_slice(&dlopen_addr.to_le_bytes());
    kr_ok(
        unsafe { mach_vm_write(task, stub, code.as_ptr() as usize, code.len() as u32) },
        "writing trampoline",
    )?;
    kr_ok(
        unsafe { mach_vm_protect(task, stub, stub_page, 0, VM_PROT_READ | VM_PROT_EXEC) },
        "making trampoline executable",
    )?;

    // pthread_t output slot
    let mut out_slot: u64 = 0;
    kr_ok(
        unsafe { mach_vm_allocate(task, &mut out_slot, 64, VM_FLAGS_ANYWHERE) },
        "allocating pthread_t slot",
    )?;

    let mut stack: u64 = 0;
    let stack_size = 8 * 1024 * 1024u64;
    kr_ok(
        unsafe { mach_vm_allocate(task, &mut stack, stack_size, VM_FLAGS_ANYWHERE) },
        "allocating thread stack",
    )?;
    let sp = (stack + stack_size - 64) & !15u64;

    let mut state = ArmThreadState64::default();
    state.sp = sp;
    state.lr = pthread_exit_addr;
    match pcfmt {
        Some(pc) => {
            // pthread_create_from_mach_thread(&thread, NULL, dlopen, path)
            state.pc = pc;
            state.x[0] = out_slot;
            state.x[1] = 0;
            state.x[2] = dlopen_addr;
            state.x[3] = path_addr;
        }
        None => {
            // fallback: run dlopen(path, RTLD_NOW) directly on the new thread
            state.pc = dlopen_addr;
            state.x[0] = path_addr;
            state.x[1] = RTLD_NOW as u64;
        }
    }

    let mut thread: MachPort = 0;
    kr_ok(unsafe { thread_create(task, &mut thread) }, "creating thread")?;
    kr_ok(
        unsafe {
            thread_set_state(
                thread,
                ARM_THREAD_STATE64,
                &state as *const ArmThreadState64 as *const u32,
                ARM_THREAD_STATE64_COUNT,
            )
        },
        "setting thread state",
    )?;
    if std::env::var("WXKEY_DEBUG").is_ok() {
        eprintln!(
            "[debug] dlopen={dlopen_addr:#x} pcfmt={:#x} stub={stub:#x} path={path_addr:#x} sp={sp:#x}",
            pcfmt.unwrap_or(0)
        );
    }
    kr_ok(unsafe { thread_resume(thread) }, "resuming remote thread")?;

    // Wait for the constructor, then retire the carrier thread. If the marker never shows up
    // the thread is left alone: spinning is better than interrupting initialisation.
    let deadline = std::time::Instant::now() + wait;
    let mut finished = watch.is_none();
    loop {
        std::thread::sleep(std::time::Duration::from_millis(150));
        if let Some(path) = watch {
            if let Ok(text) = std::fs::read_to_string(path) {
                if text.contains("\"status\"") || text.contains("\"loaded\"") {
                    finished = true;
                    break;
                }
            }
        }
        if std::time::Instant::now() > deadline {
            break;
        }
    }
    if finished {
        std::thread::sleep(std::time::Duration::from_millis(400));
        let _ = unsafe { thread_terminate(thread) };
    } else {
        eprintln!("warning: hook library never reported initialisation; carrier thread left running (may burn a core)");
    }
    Ok(())
}