#![allow(dead_code)]

use std::option::Option;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::mpsc::{Sender};
use std::thread;
use rmbuf::MBuf;
use snafu::{whatever, Whatever};
use crate::dpi::proble_rule::{ProblePattern};
use crate::dpi::rule_load::RuleLoad;
use crate::dpi::{match_jsonify, Scanner, YaraXCompiler};
use yara_x as yrx;
use yara_x::{Rule, Rules};
use crate::dpi::lmax::{new_channel, Event};

pub struct PacketInjector {
    pub load: RuleLoad,
    pub yrx_rules: Option<yrx::Rules>,
}

impl PacketInjector {
    pub fn new() -> Self {
        let load = RuleLoad::new();
        PacketInjector {
            load,
            yrx_rules: None,
        }
    }

    pub fn load(&mut self,paths: Vec<PathBuf>) {
        self.load.load_rules_with_folders(paths);

        //initial scanner
        let rules = self.load.get_rules();
        let mut compiler = YaraXCompiler::new(false,false);
        for rule in rules {
           let rule_definition = rule.1.get_rule_definition();
           if let Ok(_) = compiler.add_source(&rule_definition){
           }
        }

        if let Ok(rules) = compiler.build(){
            self.yrx_rules = Some(rules);
        }
    }

    pub fn create_disruptor(&mut self) -> Sender<Event> {
        let rules = self.yrx_rules.take().unwrap();
        let (sender, receiver) = new_channel();

        thread::spawn(move || {
            let mut scanner = Scanner::new(&rules);
            loop{
                let event = receiver.recv();
                match event {
                    Ok(e) => {
                        let ret = scanner.scan(&e.data);
                        if let Ok(scan_results) = ret{
                            let matching_rules = scan_results
                                .matching_rules()
                                .map(|rule| rule )
                                .collect::<Vec<Rule>>();
                            for rule in matching_rules {
                                println!("recv {}", rule.identifier());
                                rule.patterns().for_each(|pattern| {
                                    println!("pattern {}", pattern.identifier());
                                    pattern.matches().for_each(|mat| {
                                        let mat = match_jsonify(mat);
                                        println!("    match: {} -> {}", mat.offset, mat.length);
                                    });
                                })
                            }
                        }
                    }
                    Err(_) => {
                    }
                }
            }
        });

        sender
    }

    pub fn inject(&self, mut sender: Sender<Event>, ip: &str, port: u16, protocol: &str) {
        let rule_map = self.load.get_rules();
        for rule in rule_map {
            let rule = rule.1;
            if rule.check_ports(port) && rule.check_protocols(protocol) {
                let proble_pattern = rule.get_proble_pattern();
                for pattern in proble_pattern {
                   let ret = self.inject_with_pattern(ip, port, protocol, &pattern);
                   match ret {
                       Ok(ret) => {
                           let ret = sender.send(Event::new(1, ret));
                           if let Err(e) = ret {
                               println!("send failed,message,{:?}",e);
                           }
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
        let stream = std::net::TcpStream::connect(SocketAddr::new(ip.parse().unwrap(), port));
        match stream {
            Ok(mut stream) => {
               stream.set_read_timeout(Some(std::time::Duration::from_secs(2))).expect("failed to set timer");
               let time_ret = stream.set_nonblocking(false);
               match time_ret {
                   Ok(_) => {
                   }
                   Err(_e) => {
                       return whatever!("failed to set nonblocking");
                   }
               }

               if data.len() > 0 {
                   if let Ok(_n) =stream.write(data) {
                   }
               }

               let mut mbuf = MBuf::new(8192);
               let mut packet = [0u8; 4096];
               while let Ok(size) = stream.read(&mut packet){
                   if size == 0 {
                       break;
                   }
                   let _ret = mbuf.append(&packet[..size]);
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
        let mut disruptor = injector.create_disruptor();
        injector.inject(disruptor,"127.0.0.1", 3000, "tcp");
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