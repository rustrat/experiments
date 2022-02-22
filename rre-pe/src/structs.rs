// Derived from https://sourceforge.net/p/mingw-w64/mingw-w64/ci/3fb0b9bd05b99762c12492e92e359e69281a0938/tree/mingw-w64-headers/include/winternl.h#l37
#[repr(C)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *const u16,
}

impl UnicodeString {
    pub fn try_to_string(&self) -> Result<String, std::string::FromUtf16Error> {
        let utf16_slice =
            unsafe { std::slice::from_raw_parts(self.buffer, (self.length / 2).into()) };

        String::from_utf16(utf16_slice)
    }
}
