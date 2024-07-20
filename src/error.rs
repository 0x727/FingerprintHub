use std::io::ErrorKind;

// 临时错误处理
pub type Result<T> = std::result::Result<T, std::io::Error>;

pub(crate) fn new_io_error(msg: &str) -> std::io::Error {
  std::io::Error::new(ErrorKind::InvalidData, msg)
}
