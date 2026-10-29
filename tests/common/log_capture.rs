use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use tracing_subscriber::fmt::writer::MakeWriter;

#[derive(Clone, Default)]
pub struct Logs(Arc<Mutex<Vec<u8>>>);

impl Write for Logs {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .expect("log buffer poisoned")
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Logs {
    type Writer = Self;
    fn make_writer(&'a self) -> Self {
        self.clone()
    }
}

impl Logs {
    pub fn read(&self) -> String {
        String::from_utf8(self.0.lock().expect("log buffer poisoned").clone()).expect("UTF-8 logs")
    }
}
