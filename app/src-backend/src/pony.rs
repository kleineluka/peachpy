mod structures {

    // file headers
    pub mod header {
        #[derive(Debug, Clone)]
        pub struct Header {
            pub file_count: u32,
            pub metadata_offset: u32,
            pub ark_version: u32,
        }

        impl Header {
            pub fn new(file_count: u32, metadata_offset: u32, ark_version: u32) -> Self {
                Self {
                    file_count,
                    metadata_offset,
                    ark_version,
                }
            }
        }
    }

    // file decryption key
    pub mod key {
        pub struct Key;

        impl Key {
            pub fn get_key() -> &'static [u32; 4] {
                &[0x3d5b2a34, 0x923fff10, 0x00e346a4, 0x0c74902b]
            }
        }
    }

    // file metadata
    pub mod metadata {
        use std::convert::TryInto;

        pub const SIZE: usize = 296;

        #[derive(Debug, Clone)]
        pub struct Metadata {
            pub filename: [u8; 128],
            pub pathname: [u8; 128],
            pub file_location: u32,
            pub original_filesize: u32,
            pub compressed_size: u32,
            pub encrypted_nbytes: u32,
            pub timestamp: u32,
            pub md5sum: [u32; 4],
            pub priority: u32,
        }

        impl Metadata {
            pub fn new(data: &[u8]) -> Result<Self, String> {
                if data.len() != SIZE {
                    return Err("Invalid metadata byte array size.".to_string());
                }

                let filename = data[0..128].try_into().map_err(|_| "Failed to parse filename")?;
                let pathname = data[128..256].try_into().map_err(|_| "Failed to parse pathname")?;
                let file_location = u32::from_le_bytes(data[256..260].try_into().unwrap());
                let original_filesize = u32::from_le_bytes(data[260..264].try_into().unwrap());
                let compressed_size = u32::from_le_bytes(data[264..268].try_into().unwrap());
                let encrypted_nbytes = u32::from_le_bytes(data[268..272].try_into().unwrap());
                let timestamp = u32::from_le_bytes(data[272..276].try_into().unwrap());

                let md5sum = [
                    u32::from_le_bytes(data[276..280].try_into().unwrap()),
                    u32::from_le_bytes(data[280..284].try_into().unwrap()),
                    u32::from_le_bytes(data[284..288].try_into().unwrap()),
                    u32::from_le_bytes(data[288..292].try_into().unwrap()),
                ];

                let priority = u32::from_le_bytes(data[292..296].try_into().unwrap());

                Ok(Self {
                    filename,
                    pathname,
                    file_location,
                    original_filesize,
                    compressed_size,
                    encrypted_nbytes,
                    timestamp,
                    md5sum,
                    priority,
                })
            }
        }
    }
}
