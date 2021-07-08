extern crate winapi;
extern crate user32;
use winapi::shared::minwindef::{
    BOOL, DWORD, LPBYTE, LPCVOID, LPDWORD, LPFILETIME, LPVOID, PBOOL, PDWORD, PULONG, UINT, WORD, TRUE, FALSE
};
use winapi::um::winnt::{
    HANDLE
};
use winapi::um::processthreadsapi::{
    GetProcessInformation, OpenProcess
};

use winapi::um::winnt::{
    LPSTR
};

use winapi::um::winbase::{
    QueryFullProcessImageNameA
};



use std::mem::size_of;
use std::slice;

// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-app_memory_information
struct AppMemoryInformation {
    AvailableCommit : u64,
    PrivateCommitUsage : u64,
    PeakPrivateCommitUsage : u64,
    TotalCommitUsage : u64
}

enum PROCESS_INFORMATION_CLASS {
    ProcessMemoryPriority,
    ProcessMemoryExhaustionInfo,
    ProcessAppMemoryInfo,
    ProcessInPrivateInfo,
    ProcessPowerThrottling,
    ProcessReservedValue1,
    ProcessTelemetryCoverageInfo,
    ProcessProtectionLevelInfo,
    ProcessLeapSecondInfo,
    ProcessMachineTypeInfo,
    ProcessInformationClassMax
}

fn get_process_app_memory(handle : HANDLE) -> AppMemoryInformation {
    let mut process_memory_struct = AppMemoryInformation {
        AvailableCommit : 0,
        PrivateCommitUsage : 0,
        PeakPrivateCommitUsage : 0,
        TotalCommitUsage : 0
    };
    let process_memory_struct_ptr : *mut AppMemoryInformation = &mut process_memory_struct;
    let lpvoid : LPVOID = process_memory_struct_ptr as LPVOID;

    unsafe {
        let success = GetProcessInformation(handle, PROCESS_INFORMATION_CLASS::ProcessAppMemoryInfo as u32, lpvoid, size_of::<AppMemoryInformation>() as u32);
        if success == TRUE {
            println!("success!");
        } else if success == FALSE {
            println!("failed!");
        }
    }

    process_memory_struct
}

fn get_active_process_handle() -> HANDLE {
    let handle : HANDLE;
    let mut process_id : u32 = 0;

    // https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights;
    // PROCESS_QUERY_INFORMATION (0x0400)
    let desired_access : DWORD = 0x0400 | 0x0010;

    unsafe {
        let ptr = user32::GetForegroundWindow();
        let process_id_ptr : *mut u32 = &mut process_id;
        user32::GetWindowThreadProcessId(ptr, process_id_ptr);
        handle = OpenProcess(desired_access, FALSE, process_id);
    }

    handle
}

fn get_process_name(handle : HANDLE) {
    let mut size : u32 = 2048;
    let mut buffer_content : [u8; 2048] = [0; 2048];
    let buffer : LPSTR = buffer_content.as_mut_ptr() as *mut i8;
    let whatisit : *mut u32 = &mut size;

    unsafe {
        let success = QueryFullProcessImageNameA(handle, 0, buffer, whatisit);
        if success == TRUE {
            println!("success");
        } else {
            println!("failed");
        }
    }

    use std::str;

    let s = match str::from_utf8(&buffer_content[..]) {
        Ok(v) => v,
        Err(e) => panic!("Invalid UTF8 sequence {}", e),
    };

    println!("{}", s);
}

use std::{thread, time};

fn main() {
    let half_second = time::Duration::from_millis(500);
    loop {
        let handle = get_active_process_handle();
        get_process_name(handle);
        thread::sleep(half_second);
    }
}