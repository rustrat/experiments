mod v2;
mod v4;
mod v6;

#[repr(C)]
pub struct ApiSetMap(*const u32);

impl ApiSetMap {
    pub fn get_actual_name(&self, virtual_library: &str, importing_module: &str) -> Option<String> {
        // We do not care about anything after the last hyphen (including the hypen).
        // It is a build number which should not have anything to say and .dll.
        let (lookup_name, _) = virtual_library.rsplit_once("-")?;
        unsafe {
            match *self.0 {
                6 => v6::get_actual_name(
                    self.0 as *const v6::NamespaceArray,
                    lookup_name,
                    importing_module,
                ),
                4 => v4::get_actual_name(
                    self.0 as *const v4::NamespaceArray,
                    lookup_name,
                    importing_module,
                ),
                2 => v2::get_actual_name(
                    self.0 as *const v2::NamespaceArray,
                    lookup_name,
                    importing_module,
                ),
                _ => None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    // Maybe these tests should be moved out to integration tests? Maybe not that much of a big deal?
    #[test]
    fn test_get_actual_name() {
        let actual_name = unsafe {
            (*crate::peb::Peb::get_ptr())
                .api_set_map
                .get_actual_name("api-ms-win-core-io-l1-1-0.dll", "dontcare")
        };

        assert_eq!(actual_name, Some("kernel32.dll".into()))
    }

    #[test]
    fn test_get_actual_name_2() {
        let actual_name = unsafe {
            (*crate::peb::Peb::get_ptr())
                .api_set_map
                .get_actual_name("api-ms-win-core-io-l1-1-0.dll", "kernel32.dll")
        };

        assert_eq!(actual_name, Some("kernelbase.dll".into()))
    }

    #[test]
    fn test_return_none_on_invalid() {
        let actual_name = unsafe {
            (*crate::peb::Peb::get_ptr())
                .api_set_map
                .get_actual_name("api-this-does-not-exists-l1-0-0.dll", "dontcare.dll")
        };

        assert_eq!(actual_name, None)
    }
}
