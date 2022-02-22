use pelib::process::{get_fn_ptr, get_loaded_module_ptr};

#[link(name = "Kernel32")]
extern "system" {
    fn GetModuleHandleA(module_name: *const u8) -> *const std::ffi::c_void;
    fn GetProcAddress(module: *const std::ffi::c_void, name: *const u8) -> *const std::ffi::c_void;
}

fn main() {
    println!("PEB pointer: {:?}", pelib::peb::Peb::get_ptr());

    println!(
        "Pointer to ntdll: {:?}. HMODULE from GetModuleHandleA(\"ntdll.dll\"): {:?}",
        get_loaded_module_ptr("ntdll.dll"),
        unsafe { GetModuleHandleA("ntdll.dll\0".as_ptr()) }
    );

    println!(
        "Actual dll containing api-ms-win-core-io-l1-1: {:?}",
        unsafe {
            (*pelib::peb::Peb::get_ptr())
                .api_set_map
                .get_actual_name("api-ms-win-core-io-l1-1-1.dll", "kernel32.dll")
        },
    );

    println!(
        "Address of HeapAlloc: {:?}, actual HeapAlloc: {:?}",
        get_fn_ptr(get_loaded_module_ptr("Kernel32.dll").unwrap(), "HeapAlloc").unwrap(),
        unsafe {
            GetProcAddress(
                GetModuleHandleA("Kernel32.dll\0".as_ptr()),
                "HeapAlloc\0".as_ptr(),
            )
        },
    );
}
