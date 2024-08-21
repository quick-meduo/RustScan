use rmbuf::MBuf;
use serde_derive::{Deserialize, Serialize};
use std::sync::mpsc::channel;

#[derive(Debug, Clone,Serialize,Deserialize)]
pub struct Event {
    pub ty: u32,
    pub data: Vec<u8>
}

impl Event {
    pub fn new(ty: u32, data: Vec<u8>) -> Self {
        Event {
            ty,
            data
        }
    }
}

impl From<&MBuf> for Event {
    fn from(buf: &MBuf) -> Self {
        Event {
            ty: 0,
            data: buf.data().to_vec()
        }
    }
}

impl From<MBuf> for Event {
    fn from(buf: MBuf) -> Self {
        Event {
            ty: 0,
            data: buf.data().to_vec()
        }
    }
}

impl From<Event> for MBuf {
    fn from(event: Event) -> Self {
        let mut buf = MBuf::new(event.data.len());
        buf.append(&event.data).unwrap();
        buf
    }
}

impl From<&Event> for MBuf {
    fn from(event: &Event) -> Self {
        let mut buf = MBuf::new(event.data.len());
        buf.append(&event.data).unwrap();
        buf
    }
}

pub fn new_channel() -> (std::sync::mpsc::Sender<Event>, std::sync::mpsc::Receiver<Event>){
    channel::<Event>()
}