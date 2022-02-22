use crate::structs::UnicodeString;

// ApiSet structs derived from https://github.com/CylanceVulnResearch/ReflectiveDLLRefresher/blob/c19b83e715454fd62d7d4070d8f61d64e278802f/src/ApiSetMap.h
// ApiSet function based on https://github.com/CylanceVulnResearch/ReflectiveDLLRefresher/blob/c19b83e715454fd62d7d4070d8f61d64e278802f/src/ApiSetMap.c
// Author: Jeff Tang <jtang@cylance.com>, see licenses/reflectivedllrefresher.LICENSE for license.

#[repr(C)]
struct ValueEntry {
    flags: u32,
    origin_offset: u32,
    origin_length: u32,
    value_offset: u32,
    value_length: u32,
}

#[repr(C)]
struct ValueArray {
    flags: u32,
    count: u32,
    array: [ValueEntry; 1],
}

impl ValueArray {
    fn get_array_slice(&self) -> &[ValueEntry] {
        let array_ptr = &self.array as *const ValueEntry;

        unsafe { std::slice::from_raw_parts(array_ptr, self.count as usize) }
    }
}

#[repr(C)]
pub(super) struct NamespaceEntry {
    flags: u32,
    name_offset: u32,
    name_length: u32,
    alias_offset: u32,
    alias_length: u32,
    data_offset: u32,
}

#[repr(C)]
pub(super) struct NamespaceArray {
    version: u32,
    size: u32,
    flags: u32,
    count: u32,
    array: [NamespaceEntry; 1],
}

impl NamespaceArray {
    fn get_array_slice(&self) -> &[NamespaceEntry] {
        let array_ptr = &self.array as *const NamespaceEntry;

        unsafe { std::slice::from_raw_parts(array_ptr, self.count as usize) }
    }
}

pub(super) unsafe fn get_actual_name(
    ptr: *const NamespaceArray,
    virtual_library: &str,
    importing_module: &str,
) -> Option<String> {
    let base_ptr = ptr as usize;
    let array = (*ptr).get_array_slice();

    // It seems like namespace entries are sorted alphabetically, so binary search can be used
    // Should allow for fewer copies of memory from WASM
    let entry_index = array
        .binary_search_by(|candidate| {
            let candidate_name = UnicodeString {
                length: candidate.name_length as u16,
                maximum_length: candidate.name_length as u16,
                buffer: (base_ptr + candidate.name_offset as usize) as *const u16,
            };

            candidate_name
                .try_to_string()
                // If string conversion fails, something is seriously wrong.
                // I don't think we care what this is?
                .unwrap_or_else(|_| "".into())
                .as_str()
                .cmp(virtual_library)
        })
        .ok()?;

    let entry = array.get(entry_index)?;

    let value_array = (base_ptr + entry.data_offset as usize) as *const ValueArray;

    (*value_array)
        .get_array_slice()
        .iter()
        .rev()
        .find(|candidate| {
            // origin_length == 0 is the default value(?)
            if candidate.origin_length == 0 {
                return true;
            }

            let origin_string = UnicodeString {
                length: candidate.origin_length as u16,
                maximum_length: candidate.origin_length as u16,
                buffer: (base_ptr + candidate.origin_offset as usize) as *const u16,
            };

            origin_string.try_to_string().map_or_else(
                |_| false,
                |origin_string| origin_string.as_str().eq(importing_module),
            )
        })
        .and_then(|actual_library| {
            let actual_name = UnicodeString {
                length: actual_library.value_length as u16,
                maximum_length: actual_library.value_length as u16,
                buffer: (base_ptr + actual_library.value_offset as usize) as *const u16,
            };

            actual_name.try_to_string().ok()
        })
}

// TODO test with custom ApiSetMap structures
