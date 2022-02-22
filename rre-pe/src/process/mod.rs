use core::slice;
use std::ffi::{c_void, CStr};

use crate::peb::Peb;

// Derived from https://github.com/microsoft/windows-rs/blob/a100332cb8434bc85f1e190a64cad6cc6771c1cd/crates/libs/sys/src/Windows/Win32/System/SystemServices/mod.rs#L3422
// See licenses/windows-rs.LICENSE for license (MIT).
#[repr(C, packed(2))]
pub struct ImageDosHeader {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,
}

// Derived from https://github.com/microsoft/windows-rs/blob/a100332cb8434bc85f1e190a64cad6cc6771c1cd/crates/libs/sys/src/Windows/Win32/System/Diagnostics/Debug/mod.rs#L8158-L8177
// See licenses/windows-rs.LICENSE for license (MIT).
#[repr(C)]
pub struct ImageNtHeaders {
    pub signature: u32,
    pub file_header: ImageFileHeader,
    pub optional_header: ImageOptionalHeaders,
}

// Derived from https://github.com/microsoft/windows-rs/blob/a100332cb8434bc85f1e190a64cad6cc6771c1cd/crates/libs/sys/src/Windows/Win32/System/Diagnostics/Debug/mod.rs#L7909
// See licenses/windows-rs.LICENSE for license (MIT).
#[repr(C)]
pub struct ImageFileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

// Derived from https://github.com/microsoft/windows-rs/blob/a100332cb8434bc85f1e190a64cad6cc6771c1cd/crates/libs/sys/src/Windows/Win32/System/Diagnostics/Debug/mod.rs#L8186
// See licenses/windows-rs.LICENSE for license (MIT).
#[cfg(target_arch = "x86")]
#[repr(C)]
pub struct ImageOptionalHeaders {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: u32,
    pub image_base: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u32,
    pub size_of_stack_commit: u32,
    pub size_of_heap_reserve: u32,
    pub size_of_heap_commit: u32,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: [ImageDataDirectory; 16],
}

// Derived from https://github.com/microsoft/windows-rs/blob/a100332cb8434bc85f1e190a64cad6cc6771c1cd/crates/libs/sys/src/Windows/Win32/System/Diagnostics/Debug/mod.rs#L8227
// See licenses/windows-rs.LICENSE for license (MIT).
#[cfg(target_arch = "x86_64")]
#[repr(C, packed(4))]
pub struct ImageOptionalHeaders {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: [ImageDataDirectory; 16],
}

// Derived from https://github.com/microsoft/windows-rs/blob/a100332cb8434bc85f1e190a64cad6cc6771c1cd/crates/libs/sys/src/Windows/Win32/System/Diagnostics/Debug/mod.rs#L7682
// See licenses/windows-rs.LICENSE for license (MIT).
#[repr(C)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

// Derived from https://github.com/microsoft/windows-rs/blob/a100332cb8434bc85f1e190a64cad6cc6771c1cd/crates/libs/sys/src/Windows/Win32/System/SystemServices/mod.rs#L3561
// See licenses/windows-rs.LICENSE for license (MIT).
#[repr(C)]
pub struct ImageExportDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name: u32,
    pub ordinal_base: u32,
    pub number_of_functions: u32,
    pub number_of_names: u32,
    pub address_of_functions: u32,
    pub address_of_names: u32,
    pub address_of_name_ordinals: u32,
}

pub fn get_loaded_module_ptr(module: &str) -> Option<*const ImageDosHeader> {
    // TODO find other ways to find the correct module in memory, possibly from
    // the actual module. Eventually find other ways to detect "fake" entries.
    // There may be other places to look for the dll name, such as the export address
    // table, don't know if that is better?
    unsafe {
        (*(*Peb::get_ptr()).ldr)
            .in_memory_order_module_list
            .into_iter()
            .find(|&data_table_entry| {
                (*data_table_entry)
                    .base_dll_name
                    .try_to_string()
                    .map_or(false, |dll_name| {
                        println!("{}", dll_name);
                        dll_name.eq_ignore_ascii_case(module)
                    })
            })
            .map(|data_table_entry| (*data_table_entry).dll_base)
    }
}

// TODO GetProcAddress https://github.com/stephenfewer/ReflectiveDLLInjection/blob/178ba2a6a9feee0a9d9757dcaa65168ced588c12/inject/src/GetProcAddressR.c
// Derived from https://github.com/stephenfewer/ReflectiveDLLInjection/blob/178ba2a6a9feee0a9d9757dcaa65168ced588c12/inject/src/GetProcAddressR.c#L32
// See licenses/reflectivedllinjection.LICENSE for license.

pub fn get_fn_ptr(module: *const ImageDosHeader, fn_name: &str) -> Option<*const c_void> {
    let base_ptr = module as usize;

    unsafe {
        let nt_header = &*((base_ptr + (*module).e_lfanew as usize) as *const ImageNtHeaders);
        //                                                                 IMAGE_DIRECTORY_ENTRY_EXPORT
        let data_directory = &nt_header.optional_header.data_directory[0];
        let export_directory =
            &*((base_ptr + data_directory.virtual_address as usize) as *const ImageExportDirectory);

        let address_virtualptr_slice = slice::from_raw_parts(
            (base_ptr + export_directory.address_of_functions as usize) as *const u32,
            export_directory.number_of_functions as usize,
        );
        let name_virtualptr_slice = slice::from_raw_parts(
            (base_ptr + export_directory.address_of_names as usize) as *const u32,
            export_directory.number_of_names as usize,
        );
        let ordinal_virtualptr_slice = slice::from_raw_parts(
            (base_ptr + export_directory.address_of_name_ordinals as usize) as *const u16,
            export_directory.number_of_names as usize,
        );

        name_virtualptr_slice
            .binary_search_by(|name_virtual_ptr| {
                let name_ptr = (base_ptr + *name_virtual_ptr as usize) as *const i8;

                CStr::from_ptr(name_ptr).to_str().unwrap_or("").cmp(fn_name)
            })
            .ok()
            .and_then(|name_index| {
                let adress_ptr = ordinal_virtualptr_slice.get(name_index)?;

                let ptr = base_ptr + *address_virtualptr_slice.get(*adress_ptr as usize)? as usize;
                let export_dir_ptr = export_directory as *const _ as usize;
                // https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#export-address-table
                // "If the address specified is not within the export section (as defined by the address and length that are indicated in the optional header), the field is an export RVA"
                if ptr >= export_dir_ptr && ptr < (export_dir_ptr + data_directory.size as usize) {
                    let forwarded_str = CStr::from_ptr(ptr as *const i8).to_str().ok()?;

                    let (forwarded_dll, forwarded_function) = forwarded_str.split_once(".")?;
                    let full_forwarded_dll;

                    if forwarded_dll.to_ascii_lowercase().starts_with("api-")
                        || forwarded_dll.to_ascii_lowercase().starts_with("ext-")
                    {
                        let importing_dll_name = CStr::from_ptr(
                            (base_ptr + export_directory.name as usize) as *const i8,
                        )
                        .to_str()
                        .ok()?;
                        full_forwarded_dll = (*Peb::get_ptr())
                            .api_set_map
                            .get_actual_name(forwarded_dll, importing_dll_name)?
                    } else {
                        full_forwarded_dll = format!("{}.dll", forwarded_dll);
                    }

                    if let Some(ordinal) = forwarded_function.strip_prefix('#') {
                        get_fn_ptr_by_ordinal(
                            get_loaded_module_ptr(&full_forwarded_dll)?,
                            ordinal.parse().ok()?,
                        )
                    } else {
                        get_fn_ptr(
                            get_loaded_module_ptr(&full_forwarded_dll)?,
                            forwarded_function,
                        )
                    }
                } else {
                    Some(ptr as *const c_void)
                }
            })
    }
}

fn get_fn_ptr_by_ordinal(module: *const ImageDosHeader, ordinal: u32) -> Option<*const c_void> {
    let base_ptr = module as usize;

    unsafe {
        let nt_header = &*((base_ptr + (*module).e_lfanew as usize) as *const ImageNtHeaders);
        //                                                                 IMAGE_DIRECTORY_ENTRY_EXPORT
        let data_directory = &nt_header.optional_header.data_directory[0];
        let export_directory =
            &*((base_ptr + data_directory.virtual_address as usize) as *const ImageExportDirectory);

        let address_virtualptr_slice = slice::from_raw_parts(
            (base_ptr + export_directory.address_of_functions as usize) as *const u32,
            export_directory.number_of_functions as usize,
        );
        let ordinal_virtualptr_slice = slice::from_raw_parts(
            (base_ptr + export_directory.address_of_name_ordinals as usize) as *const u16,
            export_directory.number_of_names as usize,
        );

        let address_virtualptr = ordinal_virtualptr_slice.get(ordinal as usize)?;

        Some(
            (base_ptr + (*address_virtualptr_slice.get(*address_virtualptr as usize)? as usize))
                as *const c_void,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[link(name = "Kernel32")]
    extern "system" {
        fn GetModuleHandleA(module_name: *const u8) -> *const ImageDosHeader;
        fn GetProcAddress(
            module: *const std::ffi::c_void,
            name: *const u8,
        ) -> *const std::ffi::c_void;
    }

    #[test]
    fn test_get_ntdll_ptr() {
        let self_ptr =
            get_loaded_module_ptr("ntdll.dll").expect("Unable to find ntdll module in memory.");
        let actual_ptr = unsafe { GetModuleHandleA("ntdll.dll\0".as_ptr()) };

        assert_eq!(
            self_ptr, actual_ptr,
            "Pointer to ntdll not the same as the one returned by GetModuleHandleA."
        );
    }

    #[test]
    fn test_get_heapalloc_ptr() {
        unsafe {
            assert_eq!(
                get_fn_ptr(
                    get_loaded_module_ptr("kernel32.dll")
                        .expect("Unable to find kernel32 module in memory."),
                    "HeapAlloc"
                )
                .expect("Unable to find HeapAlloc function."),
                GetProcAddress(
                    GetModuleHandleA("Kernel32.dll\0".as_ptr()) as *const _,
                    "HeapAlloc\0".as_ptr()
                ),
            );
        }
    }
}
