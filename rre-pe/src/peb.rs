use crate::{process::ImageDosHeader, structs::UnicodeString};

use std::ffi::c_void;

extern "C" {
    fn get_peb() -> *const Peb;
}

// Derived from https://sourceforge.net/p/mingw-w64/mingw-w64/ci/3fb0b9bd05b99762c12492e92e359e69281a0938/tree/mingw-w64-headers/include/ntdef.h#l663
#[repr(C)]
pub struct LdrDataTableListEntry {
    pub flink: *const LdrDataTableListEntry,
    pub blink: *const LdrDataTableListEntry,
}

// If you are wondering what happens here, I am walking the list backwards.
// Apparently, certain EDRs have started placing decoy ntdll objects in the
// list, and as far as I have heard, the fake entries are placed before the
// actual ntdll entry, so walking backwards _should_ find the actual ntdll
// first.
impl IntoIterator for &LdrDataTableListEntry {
    type Item = *const LdrDataTableEntry;
    type IntoIter = LdrDataTableListIterator;

    fn into_iter(self) -> Self::IntoIter {
        LdrDataTableListIterator {
            current: unsafe { (*self.blink).flink },
            top: Some(unsafe { (*self.flink).flink }),
        }
    }
}

pub struct LdrDataTableListIterator {
    current: *const LdrDataTableListEntry,
    top: Option<*const LdrDataTableListEntry>,
}

impl Iterator for LdrDataTableListIterator {
    type Item = *const LdrDataTableEntry;

    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            if (*self.current).blink.is_null() || self.top == None {
                return None;
            }

            if self.top == Some((*self.current).flink) {
                self.top = None;
            }

            self.current = (*self.current).blink;

            let ptr = self.current as usize;

            Some((ptr - std::mem::size_of::<LdrDataTableListEntry>()) as *const LdrDataTableEntry)
        }
    }
}

// Derived from https://sourceforge.net/p/mingw-w64/mingw-w64/ci/3fb0b9bd05b99762c12492e92e359e69281a0938/tree/mingw-w64-headers/include/winternl.h#l44
#[repr(C)]
pub struct LdrData {
    pub reserved1: [u8; 8],
    pub reserved2: [*const c_void; 3],
    pub in_memory_order_module_list: LdrDataTableListEntry,
}

// Derived from https://github.com/stephenfewer/ReflectiveDLLInjection/blob/4a1b9bbbeed9a80758e12586796e67b3f54fa3d6/dll/src/ReflectiveLoader.h#L89
// See licenses/reflectivedllinjection.LICENSE for license.
#[repr(C)]
pub struct LdrDataTableEntry {
    pub in_load_order_links: LdrDataTableListEntry,
    pub in_memory_order_module_list: LdrDataTableListEntry,
    pub in_initialization_order_module_list: LdrDataTableListEntry,
    pub dll_base: *const ImageDosHeader,
    pub entry_point: *const c_void,
    pub size_of_image: u32,
    pub full_dll_name: UnicodeString,
    pub base_dll_name: UnicodeString,
    pub flags: u32,
    pub load_count: i16,
    pub tls_index: i16,
    pub hash_table_entry: LdrDataTableListEntry,
    pub time_date_stamp: u32,
}

// Derived from https://github.com/CylanceVulnResearch/ReflectiveDLLRefresher/blob/c19b83e715454fd62d7d4070d8f61d64e278802f/src/ReflectiveLoader.h#L147
// Which in turn was based on a more recent(?) version of
// https://github.com/stephenfewer/ReflectiveDLLInjection/blob/178ba2a6a9feee0a9d9757dcaa65168ced588c12/dll/src/ReflectiveLoader.h#L127 as far as I can tell
// See licenses/reflectivedllinjection.LICENSE for the license of the original struct and licenses/reflectivedllrefresher.LICENSE for the license of the modified version.
// TODO consider whether it is worth it to remove anything after api_set_map if it is not needed
#[repr(C)]
pub struct Peb {
    pub inherited_address_space: u8,
    pub read_image_file_exec_options: u8,
    pub being_debugged: u8,
    pub spare_bool: u8,
    pub mutant: *const c_void,
    pub image_base_address: *const c_void,
    pub ldr: *const LdrData,
    pub process_parameters: *const RtlUserProcessParameters,
    pub sub_system_data: *const c_void,
    pub process_heap: *const c_void,
    pub fast_peb_lock: *const c_void,
    pub fast_peb_lock_routine: *const c_void,
    pub fast_peb_unlock_routine: *const c_void,
    pub environment_update_count: u32,
    pub kernel_callback_table: *const c_void,
    pub system_reserved: u32,
    pub atl_thunk_slist_ptr32: u32,
    pub api_set_map: crate::api_set_map::ApiSetMap,
    pub tls_expansion_counter: u32,
    pub tls_bitmap: *const c_void,
    pub tls_bitmap_bits: [u32; 2],
    pub read_only_shared_memory_base: *const c_void,
    pub read_only_shared_memory_heap: *const c_void,
    pub read_only_static_server_data: *const c_void,
    pub ansi_code_page_data: *const c_void,
    pub oem_code_page_data: *const c_void,
    pub unicode_case_table_data: *const c_void,
    pub number_of_processors: u32,
    pub nt_global_flag: u32,
    pub critical_section_timeout: i64,
    pub heap_segment_reserve: u32,
    pub heap_segment_commit: u32,
    pub heap_de_commit_total_free_threshold: u32,
    pub heap_de_commit_free_block_threshold: u32,
    pub number_of_heaps: u32,
    pub maximum_number_of_heaps: u32,
    pub process_heaps: *const c_void,
    pub gdi_shared_handle_table: *const c_void,
    pub process_starter_helper: *const c_void,
    pub gdi_dcattribute_list: u32,
    pub loader_lock: *const c_void,
    pub os_major_version: u32,
    pub os_minor_version: u32,
    pub os_build_number: u16,
    pub os_csd_version: u16,
    pub os_platform_id: u32,
    pub image_subsystem: u32,
    pub image_subsystem_major_version: u32,
    pub image_subsystem_minor_version: u32,
    pub image_process_affinity_mask: u32,
    pub gdi_handle_buffer: [u32; 34],
    pub post_process_init_routine: *const c_void,
    pub tls_expansion_bitmap: *const c_void,
    pub tls_expansion_bitmap_bits: [u32; 32],
    pub session_id: u32,
    pub app_compat_flags: u64,
    pub app_compat_flags_user: u64,
    pub shim_data: *const c_void,
    pub app_compat_info: *const c_void,
    pub csd_version: crate::structs::UnicodeString,
    pub activation_context_data: *const c_void,
    pub process_assembly_storage_map: *const c_void,
    pub system_default_activation_context_data: *const c_void,
    pub system_assembly_storage_map: *const c_void,
    pub minimum_stack_commit: u32,
}

impl Peb {
    pub fn get_ptr() -> *const Self {
        unsafe { get_peb() }
    }
}

// Derived from https://sourceforge.net/p/mingw-w64/mingw-w64/ci/3fb0b9bd05b99762c12492e92e359e69281a0938/tree/mingw-w64-headers/include/winternl.h#l66
#[repr(C)]
pub struct RtlUserProcessParameters {
    pub reserved1: [u8; 16],
    pub reserved2: [*const c_void; 10],
    pub image_path_name: UnicodeString,
    pub commandline: UnicodeString,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_commandline() {
        let commandline = unsafe {
            let peb = &*Peb::get_ptr();

            &(*peb.process_parameters).commandline
        };

        let commandline_string = commandline
            .try_to_string()
            .expect("Unable to create string from commandline in PEB.");

        assert_eq!(
            commandline_string.contains(".exe"),
            true,
            "The process's command line does not contain .exe, and is probably not read correctly."
        );
    }
}
