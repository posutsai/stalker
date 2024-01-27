pub const MAX_BUF_SIZE: usize = 256;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SQLExecution {
    pub statement: [u8; MAX_BUF_SIZE],
    pub len: i64,
}

#[cfg(feature = "user")]
impl std::fmt::Display for SQLExecution {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let statement = String::from_utf8_lossy(&self.statement[..self.len as usize]);
        write!(f, "Length: {}, SQL: {}", self.len, statement)
    }
}
