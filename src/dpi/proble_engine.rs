#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use rmbuf::MBuf;
use snafu::{whatever, Whatever};
use crate::dpi::proble_rule::{ProblePattern};
use crate::dpi::rule_load::RuleLoad;

pub struct PacketInjector {
    pub load: RuleLoad
}

impl PacketInjector {
    pub fn new() -> Self {
        let load = RuleLoad::new();
        PacketInjector {
            load
        }
    }

    pub fn load(&mut self,paths: Vec<PathBuf>) {
        self.load.load_rules_with_folders(paths);
    }

    pub fn inject(&self, ip: &str, port: u16, protocol: &str) {
        let rule = self.load.get_rules();
        for rule in rule {
            let rule = rule.1;
            if rule.check_ports(port) && rule.check_protocols(protocol) {
                let proble_pattern = rule.get_proble_pattern();
                for pattern in proble_pattern {
                   let ret = self.inject_with_pattern(ip, port, protocol, &pattern);
                   match ret {
                       Ok(ret) => {
                           println!("inject success,message,{:x?}",ret.as_slice());
                       }
                       Err(e) => {
                           println!("inject failed,message,{:?}",e);
                       }
                   }
                }
            }
        }
    }

    pub fn inject_with_pattern(&self, ip: &str, port: u16, protocol: &str, rule: &ProblePattern) -> Result<Vec<u8>,Whatever> {
        match protocol {
            "tcp" => {
                self.inject_tcp(ip, port, &rule.to_bytes())
            }
            _ => {
                whatever!("not support protocol")
            }
        }
    }

    #[allow(unreachable_code)]
    fn inject_tcp(&self,ip: &str, port: u16,data: &[u8]) -> Result<Vec<u8>,Whatever> {
        let mut stream = std::net::TcpStream::connect(SocketAddr::new(ip.parse().unwrap(), port));
        match stream {
            Ok(mut stream) => {
               stream.set_read_timeout(Some(std::time::Duration::from_secs(2))).expect("failed to set timer");
               let time_ret = stream.set_nonblocking(false);
               match time_ret {
                   Ok(_) => {
                   }
                   Err(e) => {
                       return whatever!("failed to set nonblocking");
                   }
               }

               if data.len() > 0 {
                   if let Ok(_n) =stream.write(data) {
                   }
               }

               let mut mbuf = MBuf::new(8192);
               let mut packet = [0u8; 4096];
               while let response = stream.read(&mut packet){
                   match response {
                       Ok(size) => {
                           if size == 0 {
                               break;
                           }
                           let _ret = mbuf.append(&packet[..size]);
                       }
                       Err(e) => {
                           whatever!("Error: {}", e)
                       }
                   }
               };
               Ok(mbuf.data().to_vec())
            }
            Err(e) => {
               whatever!("Error: {}", e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_definition() {
        let mut injector = PacketInjector::new();
        injector.load(vec![PathBuf::from("src/tests/sniffp")]);

        injector.inject("127.0.0.1", 3000, "tcp");
    }

    #[test]
    fn test_bit_transform() {
        let a: f32 = 42.42;
        let frankentype: u32 = unsafe {
            std::mem::transmute::<f32, u32>(a)
        };
        println!("{}", frankentype);
        println!("{:032b}", frankentype);

        let b: f32 = unsafe {
            std::mem::transmute::<u32, f32>(frankentype)
        };

        println!("{}", b);
        assert_eq!(a, b);
    }
}