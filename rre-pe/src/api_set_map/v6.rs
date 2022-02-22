use crate::structs::UnicodeString;

// ApiSet structs derived from https://github.com/CylanceVulnResearch/ReflectiveDLLRefresher/blob/c19b83e715454fd62d7d4070d8f61d64e278802f/src/ApiSetMap.h
// ApiSet function based on https://github.com/CylanceVulnResearch/ReflectiveDLLRefresher/blob/c19b83e715454fd62d7d4070d8f61d64e278802f/src/ApiSetMap.c
// Author: Jeff Tang <jtang@cylance.com>, see licenses/reflectivedllrefresher.LICENSE for license.

#[repr(C)]
struct ValueEntry {
    pub flags: u32,
    pub origin_offset: u32,
    pub origin_length: u32,
    pub value_offset: u32,
    pub value_length: u32,
}

// For future reference if needed
// #[repr(C)]
// struct NamespaceHashEntry {
// pub hash: u32,
// pub index: u32,
// }

#[repr(C)]
pub(super) struct NamespaceEntry {
    flags: u32,
    name_offset: u32,
    size: u32,
    name_length: u32,
    data_offset: u32,
    count: u32,
}

// TODO function to get slice (array)
#[repr(C)]
pub(super) struct NamespaceArray {
    version: u32,
    size: u32,
    flags: u32,
    count: u32,
    data_offset: u32,
    hash_offset: u32,
    multiplier: u32,
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

    let value_array = std::slice::from_raw_parts(
        (base_ptr + entry.data_offset as usize) as *const ValueEntry,
        entry.count as usize,
    );

    //let actual_library = value_array.iter().rev().find(|candidate| {
    value_array
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
#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct TestStruct {
        namespace_array: NamespaceArray,
        additional_entries: [NamespaceEntry; 4],
        // 1-3 and 5 share a ValueEntry
        // 4 has two ValueEntries, a specific (correct) and one wrong
        value_entries: [ValueEntry; 3],
        virtual_name_1: [u16; 19],
        virtual_name_2: [u16; 19],
        virtual_name_3: [u16; 19],
        virtual_name_4: [u16; 19],
        virtual_name_5: [u16; 15],
        specific_dll: [u16; 12],
        correct_dll: [u16; 11],
        wrong_dll: [u16; 9],
    }

    #[test]
    fn test_find_default() {
        let test_struct = get_test_memory();

        unsafe {
            assert_eq!(
                get_actual_name(
                    &test_struct.namespace_array,
                    "api-api-test-l2-0",
                    "dontcare.dll"
                ),
                Some("correct.dll".into())
            );
        }
    }

    #[test]
    fn test_find_with_specific_importing_module() {
        let test_struct = get_test_memory();

        unsafe {
            assert_eq!(
                get_actual_name(
                    &test_struct.namespace_array,
                    "api-test-api-l1-0",
                    "specific.dll"
                ),
                Some("correct.dll".into())
            );
        }
    }

    #[test]
    fn test_return_none_on_invalid() {
        let test_struct = get_test_memory();

        unsafe {
            assert_eq!(
                get_actual_name(
                    &test_struct.namespace_array,
                    "api-does-not-exist-l1-0",
                    "dontcare.dll"
                ),
                None
            );
        }
    }

    fn get_test_memory() -> TestStruct {
        let virtual_name_1: Vec<u16> = "api-api-test-l1-0-0".encode_utf16().collect();
        let virtual_name_2: Vec<u16> = "api-api-test-l2-0-0".encode_utf16().collect();
        let virtual_name_3: Vec<u16> = "api-api-test-l3-0-0".encode_utf16().collect();
        let virtual_name_4: Vec<u16> = "api-test-api-l1-0-0".encode_utf16().collect();
        let virtual_name_5: Vec<u16> = "ext-test-l1-0-0".encode_utf16().collect();

        let specific_dll: Vec<u16> = "specific.dll".encode_utf16().collect();

        let correct_dll: Vec<u16> = "correct.dll".encode_utf16().collect();
        let wrong_dll: Vec<u16> = "wrong.dll".encode_utf16().collect();

        let mut test_struct = TestStruct {
            namespace_array: NamespaceArray {
                version: 6,
                size: 0,
                flags: 0,
                count: 5,
                data_offset: 0,
                hash_offset: 0,
                multiplier: 0,
                array: [NamespaceEntry {
                    flags: 0,
                    name_offset: 0,
                    size: (virtual_name_1.len() * 2) as u32,
                    name_length: (virtual_name_1.len() * 2 - 4) as u32,
                    data_offset: 0,
                    count: 1,
                }],
            },
            additional_entries: [
                NamespaceEntry {
                    flags: 0,
                    name_offset: 0,
                    size: (virtual_name_2.len() * 2) as u32,
                    name_length: (virtual_name_2.len() * 2 - 4) as u32,
                    data_offset: 0,
                    count: 1,
                },
                NamespaceEntry {
                    flags: 0,
                    name_offset: 0,
                    size: (virtual_name_3.len() * 2) as u32,
                    name_length: (virtual_name_3.len() * 2 - 4) as u32,
                    data_offset: 0,
                    count: 1,
                },
                NamespaceEntry {
                    flags: 0,
                    name_offset: 0,
                    size: (virtual_name_4.len() * 2) as u32,
                    name_length: (virtual_name_4.len() * 2 - 4) as u32,
                    data_offset: 0,
                    count: 2,
                },
                NamespaceEntry {
                    flags: 0,
                    name_offset: 0,
                    size: (virtual_name_5.len() * 2) as u32,
                    name_length: (virtual_name_5.len() * 2 - 4) as u32,
                    data_offset: 0,
                    count: 1,
                },
            ],
            value_entries: [
                ValueEntry {
                    flags: 0,
                    origin_offset: 0,
                    origin_length: 0,
                    value_offset: 0,
                    value_length: (correct_dll.len() * 2) as u32,
                },
                ValueEntry {
                    flags: 0,
                    origin_offset: 0,
                    origin_length: 0,
                    value_offset: 0,
                    value_length: (wrong_dll.len() * 2) as u32,
                },
                ValueEntry {
                    flags: 0,
                    origin_offset: 0,
                    origin_length: (specific_dll.len() * 2) as u32,
                    value_offset: 0,
                    value_length: (correct_dll.len() * 2) as u32,
                },
            ],
            virtual_name_1: virtual_name_1.try_into().unwrap(),
            virtual_name_2: virtual_name_2.try_into().unwrap(),
            virtual_name_3: virtual_name_3.try_into().unwrap(),
            virtual_name_4: virtual_name_4.try_into().unwrap(),
            virtual_name_5: virtual_name_5.try_into().unwrap(),
            specific_dll: specific_dll.try_into().unwrap(),
            correct_dll: correct_dll.try_into().unwrap(),
            wrong_dll: wrong_dll.try_into().unwrap(),
        };

        let base_ptr = &test_struct as *const _ as usize;
        test_struct.namespace_array.array[0].name_offset =
            ((&test_struct.virtual_name_1 as *const _ as usize) - base_ptr) as u32;
        test_struct.namespace_array.array[0].data_offset =
            ((&test_struct.value_entries[0] as *const _ as usize) - base_ptr) as u32;
        test_struct.additional_entries[0].name_offset =
            ((&test_struct.virtual_name_2 as *const _ as usize) - base_ptr) as u32;
        test_struct.additional_entries[0].data_offset =
            ((&test_struct.value_entries[0] as *const _ as usize) - base_ptr) as u32;
        test_struct.additional_entries[1].name_offset =
            ((&test_struct.virtual_name_3 as *const _ as usize) - base_ptr) as u32;
        test_struct.additional_entries[1].data_offset =
            ((&test_struct.value_entries[0] as *const _ as usize) - base_ptr) as u32;
        test_struct.additional_entries[2].name_offset =
            ((&test_struct.virtual_name_4 as *const _ as usize) - base_ptr) as u32;
        test_struct.additional_entries[2].data_offset =
            ((&test_struct.value_entries[1] as *const _ as usize) - base_ptr) as u32;
        test_struct.additional_entries[3].name_offset =
            ((&test_struct.virtual_name_5 as *const _ as usize) - base_ptr) as u32;
        test_struct.additional_entries[3].data_offset =
            ((&test_struct.value_entries[0] as *const _ as usize) - base_ptr) as u32;
        test_struct.value_entries[0].value_offset =
            ((&test_struct.correct_dll as *const _ as usize) - base_ptr) as u32;
        test_struct.value_entries[1].value_offset =
            ((&test_struct.wrong_dll as *const _ as usize) - base_ptr) as u32;
        test_struct.value_entries[2].value_offset =
            ((&test_struct.correct_dll as *const _ as usize) - base_ptr) as u32;
        test_struct.value_entries[2].origin_offset =
            ((&test_struct.specific_dll as *const _ as usize) - base_ptr) as u32;

        test_struct
    }
}
