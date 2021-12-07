use crate::Verbose;
use crate::cfg;

use ntapi::ntpebteb;
use ntapi::ntpsapi;
use ntapi::ntrtl;

use winapi::um::errhandlingapi;
use winapi::um::handleapi;
use winapi::um::memoryapi;
use winapi::um::sysinfoapi;
use winapi::um::processthreadsapi;
use winapi::um::tlhelp32;

use winapi::um::winnt::HANDLE;
use winapi::um::winnt::MEMORY_BASIC_INFORMATION;
use winapi::um::winnt::PAGE_NOACCESS;
use winapi::um::winnt::{MEM_COMMIT, MEM_FREE, MEM_RESERVE};
use winapi::um::winnt::{MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE};
use winapi::um::winnt::{STANDARD_RIGHTS_REQUIRED, SYNCHRONIZE};
use winapi::um::sysinfoapi::SYSTEM_INFO;

use winapi::shared::basetsd::SIZE_T;
use winapi::shared::minwindef::{BOOL, DWORD, FALSE, LPVOID, TRUE};
use winapi::shared::ntdef::NULL as NULLPTR;
use winapi::shared::ntdef::{NTSTATUS, PVOID, ULONG, UNICODE_STRING};

use std::mem::size_of;
use std::mem::zeroed;

type MEMORY_REGION = MEMORY_BASIC_INFORMATION;

const LOCKFILE_REL_PATH: &str = "\\lockfile";

macro_rules! log {
    ( $x:expr , $($arg:tt)* ) => {
        if $x != false { print!($($arg)*); }
    }
}

macro_rules! read_flow_suspend {
    ( $x:expr ) => {
        std::thread::sleep_ms($x)
    };
}

fn slice_i8_to_u8_cstr(src: &[i8]) -> Vec<u8> {
    let n = src.len() as usize;
    let mut vec = Vec::<u8>::new();
    for i in 0..n {
        if src[i] == 0 { break; }
        vec.push(src[i] as u8);
    }
    return vec;
}

pub unsafe fn __find_process(verbose: Verbose, config: &cfg::Config)
    -> winapi::um::winnt::HANDLE
{
    let target = cfg::TARGET_PROCESS;
    macro_rules! proc_info_format_string { ( ) => {
        //"  {:#016x} <- {:#016x}  {:2} threads  '{}'\n"
        "  {:06} <- {:06}  {:2} threads  '{}'\n"
    } };
    let mut result: BOOL = 0;
    let mut pid: DWORD = 0;
    let mut handle: HANDLE = NULLPTR;
    log!(verbose.0, "Target: {}\n", target);
    log!(verbose.1, "Getting snapshot <TH32CS_SNAPPROCESS>...\n");
    let snapshot = tlhelp32::CreateToolhelp32Snapshot(
        tlhelp32::TH32CS_SNAPPROCESS, 0);
    if snapshot == NULLPTR { panic!(); }
    /* (C/C++)
        typedef struct tagPROCESSENTRY32 {
            DWORD     dwSize;
            DWORD     cntUsage;
            DWORD     th32ProcessID;
            ULONG_PTR th32DefaultHeapID;
            DWORD     th32ModuleID;
            DWORD     cntThreads;
            DWORD     th32ParentProcessID;
            LONG      pcPriClassBase;
            DWORD     dwFlags;
            CHAR      szExeFile[MAX_PATH];
        } PROCESSENTRY32;
    */
    let mut pe32 = tlhelp32::PROCESSENTRY32 {
        dwSize: size_of::<tlhelp32::PROCESSENTRY32>() as DWORD,
        ..zeroed::<tlhelp32::PROCESSENTRY32>()
    };
    log!(verbose.0, "Searching for the process...\n");
    read_flow_suspend!(config.debug.rfsuspv[0]/2);
    result = tlhelp32::Process32First(snapshot, &mut pe32);
    if result == FALSE {
        panic!();
    }
    let mut absname = String::new(); /* */
    while {
        read_flow_suspend!(config.debug.rfsuspv[1]);
        result = tlhelp32::Process32Next(snapshot, &mut pe32);
        let _handle = processthreadsapi::OpenProcess(
            STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF,
            FALSE,
            pe32.th32ProcessID,
        );
        let _v = slice_i8_to_u8_cstr(&pe32.szExeFile);
        let executable_name = String::from_utf8_lossy(&_v);
        log!(verbose.1, proc_info_format_string!(),
            pe32.th32ProcessID,
            pe32.th32ParentProcessID,
            pe32.cntThreads,
            executable_name
        );
        // we have to iterate over all processes in debug build
        if executable_name == target {
            handle = _handle;
            pid = pe32.th32ProcessID;
            absname = executable_name.to_string();
        } else {
            handleapi::CloseHandle(_handle);
        }
        result != FALSE
    } {}
    if handle == NULLPTR {
        panic!("cannot find the process");
    }
    log!(verbose.0, "process found: pid={}, absname='{}'\n", pid, absname);
    read_flow_suspend!(config.debug.rfsuspv[0]/4);
    return handle;
}

pub unsafe fn __locate_peb_block(verbose: Verbose, config: &cfg::Config,
                                 handle: HANDLE) -> ntpebteb::PPEB
{
    const INFO_CLASS: ntpsapi::PROCESSINFOCLASS = 0;
    assert!(handle != NULLPTR);
    let mut status: NTSTATUS;
    let mut reqsz: ULONG = 0;
    let mut pbi = ntpsapi::PROCESS_BASIC_INFORMATION {
        ..zeroed::<ntpsapi::PROCESS_BASIC_INFORMATION>()
    };
    let pbi_ptr: ntpsapi::PPROCESS_BASIC_INFORMATION = &mut pbi;
    let pbi_sz = size_of::<ntpsapi::PROCESS_BASIC_INFORMATION>() as ULONG;
    log!(verbose.0, "Searching the PEB in process memory...\n");
    read_flow_suspend!(config.debug.rfsuspv[0]);
    status = ntpsapi::NtQueryInformationProcess(
        handle, INFO_CLASS, pbi_ptr as PVOID, pbi_sz, &mut reqsz);
    if status != 0 { panic!(); }
    log!(verbose.1, "  PEB address: {:#016x}\n", pbi.PebBaseAddress as u32);
    return pbi.PebBaseAddress;
}

pub unsafe fn __get_proc_params(verbose: Verbose, config: &cfg::Config,
                                handle: HANDLE, peb_addr: ntpebteb::PPEB)
    -> ntrtl::RTL_USER_PROCESS_PARAMETERS
{
    assert!(handle != NULLPTR);
    assert!(peb_addr as u32 != 0);
    let mut result: BOOL = 0;
    let mut sz: SIZE_T;
    let mut reqsz: SIZE_T = 0;
    let mut peb = ntpebteb::PEB { ..zeroed::<ntpebteb::PEB>() };
    let peb_ptr: ntpebteb::PPEB = &mut peb;
    sz = size_of::<ntpebteb::PEB>();
    log!(verbose.0, "Reading the PEB structure...\n");
    read_flow_suspend!(config.debug.rfsuspv[0]/2);
    result = memoryapi::ReadProcessMemory(
        handle, peb_addr as PVOID, peb_ptr as LPVOID,
        sz, &mut reqsz
    );
    if result == FALSE { panic!(); }
    let mut rtl_proc_params = ntrtl::RTL_USER_PROCESS_PARAMETERS {
        ..zeroed::<ntrtl::RTL_USER_PROCESS_PARAMETERS>()
    };
    let rtl_proc_params_ptr:
        ntrtl::PRTL_USER_PROCESS_PARAMETERS = &mut rtl_proc_params;
    let address: ntrtl::PRTL_USER_PROCESS_PARAMETERS = peb.ProcessParameters;
    sz = size_of::<ntrtl::RTL_USER_PROCESS_PARAMETERS>();
    log!(verbose.1, "  RTL_PROC_PARAMS address: {:#016x}\n", address as u32);
    log!(verbose.1, "Reading RTL_PROC_PARAMS structure...\n");
    read_flow_suspend!(config.debug.rfsuspv[0]);
    result = memoryapi::ReadProcessMemory(
        handle,
        address as PVOID,
        rtl_proc_params_ptr as LPVOID,
        sz, &mut reqsz,
    );
    if result == FALSE { panic!(); }
    return rtl_proc_params;
}

pub unsafe fn __get_proc_cmd(verbose: Verbose, config: &cfg::Config, handle: HANDLE,
                             rtl_proc_params: &ntrtl::RTL_USER_PROCESS_PARAMETERS)
    -> std::string::String
{
    let strlen = rtl_proc_params.CommandLine.Length;
    let buffer_ptr = rtl_proc_params.CommandLine.Buffer;
    let buffer_size = rtl_proc_params.CommandLine.MaximumLength;
    assert!(buffer_ptr != NULLPTR as *mut u16);
    assert!(buffer_size as usize >= cfg::USTR_SWAP_BUFFER_SIZE);

    log!(verbose.1, "Retrieving process command line...\n");
    log!(verbose.1, "  UNICODE_STRING buffer address: {:#016X}\n",
        buffer_ptr as u32);
    log!(verbose.1, "  UNICODE_STRING buffer size: {} ({} bytes)\n",
        buffer_size, buffer_size * 2);

    log!(verbose.1, "Reading UNICODE_STRING buffer...\n");
    assert!(handle != NULLPTR);
    let mut result: BOOL = 0;
    let mut reqsz: SIZE_T = 0;
    let mut sb: [u16; cfg::USTR_SWAP_BUFFER_SIZE] =
        [0; cfg::USTR_SWAP_BUFFER_SIZE];
    let sb_ptr = &mut sb;
    let sb_ptr: PVOID = sb_ptr.as_mut_ptr() as PVOID;
    let sb_sz: SIZE_T = size_of::<[u16; cfg::USTR_SWAP_BUFFER_SIZE]>();
    result = memoryapi::ReadProcessMemory(
        handle, buffer_ptr as PVOID, sb_ptr, sb_sz, &mut reqsz);
    if result == FALSE { panic!(); }
    log!(verbose.1, "content(raw): [ ");
    for ch in &sb {
        log!(verbose.1, "{} ", *ch);
    }
    log!(verbose.1, "]\n");
    let outp = String::from_utf16_lossy(&sb);

    log!(verbose.1, "extracted launch command: {}\n", &outp);
    return outp;
}

fn parse_proc_cmd(verbose: Verbose, proc_cmd: String) -> (u32, String) {
    const OP1: &str = "--riotclient-app-port";
    const OP2: &str = "--riotclient-auth-token";
    //const OP2: &str = "--remoting-auth-token";
    log!(verbose.0, "Parsing command line string...\n");
    let options = proc_cmd.split_whitespace();
    let mut port_str: Option<String> = None;
    let mut auth_token: Option<String> = None;
    log!(verbose.1, "----- BEGIN PARTS -----\n");
    for v in options {
        let v = v.trim_matches('"');
        if v.contains(OP1) {
            let idx = v.find('=');
            if idx.is_some() {
                port_str = Some(v.split_at(idx.unwrap() + 1).1.to_string());
            }
        }
        if v.contains(OP2) {
            let idx = v.find('=');
            if idx.is_some() {
                auth_token = Some(v.split_at(idx.unwrap() + 1).1.to_string());
            }
        }
        log!(verbose.1, "{}\n", v);
    }
    log!(verbose.1, "----- END PARTS -----\n");
    log!(verbose.1, "port={}\n", port_str.as_ref().unwrap());
    log!(verbose.1, "token={}\n", auth_token.as_ref().unwrap());
    (
        port_str.unwrap().parse::<u32>().unwrap(),
        auth_token.unwrap(),
    )
}

pub fn get_auth_data(verbose: Verbose, config: &cfg::Config) -> (u32, String) {
    let proc_launch_cmd: String;
    let lf_params: (u32, String);
    unsafe {
        let handle = __find_process(verbose, config);
        let peb_addr = __locate_peb_block(verbose, config, handle);
        let proc_params = __get_proc_params(verbose, config, handle, peb_addr);
        proc_launch_cmd = __get_proc_cmd(verbose, config, handle, &proc_params);
        lf_params = _get_lf_data(verbose, config); /* */
    }
    let cl_params = parse_proc_cmd(verbose, proc_launch_cmd);
    log!(verbose.1, "lf diff: {:#x} +000\n", lf_params.0 - cl_params.0);
    //return cl_params;
    return lf_params;
}

pub fn _get_lf_data(verbose: Verbose, config: &cfg::Config) -> (u32, String) {
    log!(verbose.1, "(debug) Getting LF parameters...\n");
    log!(verbose.1, "lf path: {}\n", config.general.game_folder);
    let lf_data = std::fs::read_to_string(
            config.general.game_folder.clone() + LOCKFILE_REL_PATH
        ).expect("lf read error");
    let parts = lf_data.split(':');
    let port_str = parts.clone().into_iter().nth(2).unwrap();
    let token_str = parts.clone().into_iter().nth(3).unwrap();
    let _package = format!("{}:?:{}", port_str, token_str);
    log!(verbose.1, "lf data: {}\n", base64::encode(_package));
    (port_str.parse::<u32>().unwrap(), token_str.to_owned())
}

// Convert size in bytes to human-readable format.
fn hrs(bytes: u64) -> String {
    let base = [1024, 1048576, 1073741824];
    let mut i: usize = 0;
    while i < base.len() {
        if bytes < base[i] { break; }
        i += 1;
    }
    match i {
        0 => format!("{} bytes", bytes),
        1 => format!("{:.2} KiB", bytes/base[i-1]),
        2 => format!("{:.2} MiB", bytes/base[i-1]),
        _ => format!("{:.2} GiB", bytes/base[i-1]),
    }
}

pub unsafe fn __get_proc_memory_regions(verbose: Verbose, config: &cfg::Config,
                                        handle: HANDLE) -> Vec<MEMORY_REGION>
{
    assert!(handle != NULLPTR);
    let mut nbytes: SIZE_T; // return value
    let mut total: u64 = 0; // bytes total
    let mut addr: usize = 0;
    let mut mbi = MEMORY_BASIC_INFORMATION {
        ..zeroed::<MEMORY_BASIC_INFORMATION>()
    };
    let mbi_sz = size_of::<MEMORY_BASIC_INFORMATION>();
    let mut vec = Vec::<MEMORY_REGION>::with_capacity(10);
    log!(verbose.0, "Querying memory allocated by the target process...\n");
    read_flow_suspend!(config.debug.rfsuspv[0]);
    let mut i: usize = 0;
    let mut stats = (0, 0, 0);
    while {
        read_flow_suspend!(config.debug.rfsuspv[2]);
        nbytes = memoryapi::VirtualQueryEx(handle, addr as PVOID, &mut mbi, mbi_sz);
        log!(
            verbose.1,
            "  region {:03x}  [B]:{:#016X}  [AB]:{:#016X}  \
             AP:{:<#4x}  P:{:<#5x}  {}  {}  {:7}\n",
            i,
            mbi.BaseAddress as u32,
            mbi.AllocationBase as u32,
            mbi.AllocationProtect,
            mbi.Protect,
            match mbi.State {
                MEM_COMMIT => "MEM_COMMIT ",
                MEM_FREE => "MEM_FREE   ",
                MEM_RESERVE => "MEM_RESERVE",
                _ => "???????????",
            },
            match mbi.Type {
                MEM_IMAGE => "MEM_IMAGE  ",
                MEM_MAPPED => "MEM_MAPPED ",
                MEM_PRIVATE => "MEM_PRIVATE",
                _ => "???????????",
            },
            format!("{} bytes", mbi.RegionSize)
            //hrs(mbi.RegionSize as u64)
        );
        let _wc = mbi.Protect & 0x08 > 0;
        if mbi.Protect & 0x02 > 0 || mbi.Protect & 0x04 > 0 || _wc {
            total += mbi.RegionSize as u64;
            stats.0 += 1;
        } else if mbi.Protect & 0x20 > 0 || mbi.Protect & 0x80 > 0 {
            total += mbi.RegionSize as u64;
            stats.0 += 1; stats.2 += 1;
        }
        if mbi.Protect & 0x100 > 0 { stats.1 += 1; }

        vec.push(mbi.clone());
        addr += mbi.RegionSize;
        i += 1;
        nbytes != 0
    } {}
    log!(verbose.1, "  zero bytes returned\n");
    log!(verbose.0, "{} region(s) found in the virtual memory\n", vec.len());
    log!(verbose.0, "  {} region(s) available for safe read ({} in total)\n",
         stats.0, hrs(total));
    log!(verbose.0, "  {} region(s) with PAGE_GUARD flag\n", stats.1);
    log!(verbose.0, "  {} region(s) with executable flag\n", stats.2);
    return vec;
}

pub unsafe fn __get_memory_defaults(verbose: Verbose, config: &cfg::Config)
                                    -> (usize, usize)
{
    log!(verbose.1, "Getting system info...\n");
    let mut sysinfo = SYSTEM_INFO { .. zeroed::<SYSTEM_INFO>() };
    sysinfoapi::GetNativeSystemInfo(&mut sysinfo);
    log!(verbose.1, "  the size of memory page: {}\n", sysinfo.dwPageSize);
    log!(verbose.1, "  allocation granularity: {}\n",
         sysinfo.dwAllocationGranularity);
    read_flow_suspend!(config.debug.rfsuspv[0]);
    (
        sysinfo.dwPageSize as usize,
        sysinfo.dwAllocationGranularity as usize
    )
}

pub unsafe fn __dump_memory_region(verbose: Verbose,
                                   config: &cfg::Config,
                                   handle: HANDLE,
                                   file: &mut std::fs::File,
                                   meminfo: (usize, usize),
                                   region: &MEMORY_REGION) -> usize
{
    use std::io::Write;
    assert!(handle != NULLPTR);
    assert_ne!(meminfo, (0, 0));
    assert_eq!(meminfo.0, config.winapi.memory_page_size);
    let mut nbytes: usize = 0;
    let mut result: BOOL = 0;
    let mut offset: usize = 0;
    let mut reqsz: SIZE_T = 0;
    let chunk_size = cfg::MEMORY_PAGE_SIZE;
    let mut buff: [u8; cfg::MEMORY_PAGE_SIZE] = [0; cfg::MEMORY_PAGE_SIZE];
    let mut addr: usize = region.BaseAddress as usize;
    let npages = region.RegionSize / cfg::MEMORY_PAGE_SIZE; // both must be integer
    log!(verbose.0, "Dumping memory region {:#016X} ({} pages)...",
        region.BaseAddress as u32, /*region.RegionSize*/ npages);
    std::io::stdout().flush().unwrap();
    if verbose.0 { read_flow_suspend!(config.debug.rfsuspv[4]); }
    if region.RegionSize % cfg::MEMORY_PAGE_SIZE != 0 {
        log!(verbose.0, "\n  WARNING: region is not page aligned\n");
        std::process::exit(1); /* TEMP */
    }

    if region.State != MEM_COMMIT && region.Type != MEM_PRIVATE {
        if verbose.1 {
            log!(verbose.1, "\n  The region is swapped or shared. Skipping...\n");
        } else {
            log!(verbose.0, "SKIPPING...\n");
        }
        return 0;
    }
    if region.Protect != 0x2 && region.Protect != 0x4 {
        if verbose.1 {
            log!(verbose.1, "\n  A risk of ACCESS_VIOLATION exception. Skipping...\n");
        } else {
            log!(verbose.0, "SKIPPING...\n");
        }
        return 0;
    }
    if region.Protect & 0x100 > 0 { /* unreachable */
        if verbose.1 {
            log!(verbose.1, "\n  The region has a GUARD flag. Skipping...\n");
        } else {
            log!(verbose.0, "SKIPPING...\n");
        }
        return 0;
    }

    log!(verbose.1 & verbose.0, "\n");
    while offset < region.RegionSize as usize {
        log!(verbose.1, "  [..] reading memory chunk {:#016X}[{}]...",
             addr, chunk_size);
        std::io::stdout().flush().unwrap();
        if verbose.1 { read_flow_suspend!(config.debug.rfsuspv[4]); }
        result = memoryapi::ReadProcessMemory(
            handle, addr as PVOID,
            buff.as_mut_ptr() as LPVOID,
            chunk_size, &mut reqsz,
        );
        //if result == FALSE { panic!(); }
        if result == FALSE {
            log!(verbose.0, "FAIL\n");
            let error: DWORD = errhandlingapi::GetLastError();
            log!(verbose.0, "  SYSTEM_ERROR_CODE: {}\n", error);
            return nbytes;
        }
        let n = file.write(&buff).unwrap();
        //log!(verbose.1, "OK, {} bytes written\r", n);
        log!(verbose.1, "\r  [OK]\r");
        offset += chunk_size;
        addr += chunk_size;
        nbytes += n;
    }
    if verbose.1 {
        log!(verbose.0,
             "\n  The memory region has been successfully read and saved.\n");
    } else {
        log!(verbose.0, "OK\n");
    }
    return nbytes;
}
