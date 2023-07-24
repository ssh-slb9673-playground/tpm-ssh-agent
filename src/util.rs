pub fn u16le(arr: &[u8]) -> u16 {
    arr[0] as u16 + ((arr[1] as u16) << 8)
}

pub fn u16be(arr: &[u8]) -> u16 {
    arr[1] as u16 + ((arr[0] as u16) << 8)
}

pub fn p16le(x: u16) -> [u8; 2] {
    [(x & 255) as u8, ((x >> 8) & 255) as u8]
}

pub fn p16be(x: u16) -> [u8; 2] {
    [((x >> 8) & 255) as u8, (x & 255) as u8]
}

pub fn u32le(arr: &[u8]) -> u32 {
    arr[0] as u32 + ((arr[1] as u32) << 8) + ((arr[2] as u32) << 16) + ((arr[3] as u32) << 24)
}

pub fn u32be(arr: &[u8]) -> u32 {
    arr[3] as u32 + ((arr[2] as u32) << 8) + ((arr[1] as u32) << 16) + ((arr[0] as u32) << 24)
}

pub fn p32le(x: u32) -> [u8; 4] {
    [
        (x & 255) as u8,
        ((x >> 8) & 255) as u8,
        ((x >> 16) & 255) as u8,
        ((x >> 24) & 255) as u8,
    ]
}

pub fn p32be(x: u32) -> [u8; 4] {
    [
        ((x >> 24) & 255) as u8,
        ((x >> 16) & 255) as u8,
        ((x >> 8) & 255) as u8,
        (x & 255) as u8,
    ]
}
