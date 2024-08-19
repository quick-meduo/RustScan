#![allow(dead_code)]
#![warn(unreachable_code)]

use std::fs::File;
use std::io::BufReader;
use async_std::path::Path;
use serde_derive::{Deserialize, Serialize};
use snafu::{prelude::*, Whatever};
#[derive(Deserialize,Serialize,Clone)]
pub enum ProblePattern {
    HexSequence(Vec<u8>),
    HexString(String),
    String(String),
}

impl ProblePattern {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            ProblePattern::HexSequence(bytes) => bytes.clone(),
            ProblePattern::HexString(hex_string) => {
                hex::decode(hex_string).unwrap()
            }
            ProblePattern::String(string) => {
                string.as_bytes().to_vec()
            }
        }
    }
}

#[derive(Deserialize,Serialize,Clone)]
pub struct MetaInfo {
    pub name: String,
    pub enabled: bool,
    pub description: String,
}

#[derive(Deserialize,Serialize,Clone)]
pub struct ProbleRule{
    pub meta: MetaInfo,
    pub trigger_ports : Vec<String>,
    pub trigger_protocols : Vec<String>,
    pub packet_patterns : Vec<ProblePattern>,
    pub rule_definition: String,
}

impl ProbleRule {
    #![allow(unreachable_code)]
    pub fn new(path: &str) -> Result<ProbleRule,Whatever> {
        let path = Path::new(path);
        let file = File::open(path);
        if file.is_err() {
            return whatever!("Failed to load packet definition from {}", path.to_str().unwrap());
        }

        let file = file.unwrap();
        let reader = BufReader::new(file);
        let yaml = serde_yaml::from_reader::<BufReader<File>, ProbleRule>(reader);
        if yaml.is_err() {
            return whatever!("Invalid packet definition in {}", path.to_str().unwrap());
        }

        Ok(yaml.unwrap())
    }

    pub fn new_empty() -> ProbleRule {
        ProbleRule {
            meta: MetaInfo {
                name: "".to_string(),
                enabled: true,
                description: "".to_string(),
            },
            trigger_ports: Vec::new(),
            trigger_protocols: Vec::new(),
            packet_patterns: Vec::new(),
            rule_definition: "".to_string(),
        }
    }

    pub fn set_trigger_ports(&mut self, ports: Vec<String>) {
        self.trigger_ports = ports;
    }

    pub fn set_trigger_protocols(&mut self, protocols: Vec<String>) {
        self.trigger_protocols = protocols;
    }

    pub fn set_rule_definition(&mut self, rule_definition: String) {
        self.rule_definition = rule_definition;
    }
    pub fn set_proble_pattern(&mut self, patterns: Vec<ProblePattern>) {
        self.packet_patterns = patterns;
    }

    pub fn get_rule_definition(&self) -> String {
        self.rule_definition.clone()
    }

    pub fn check_ports(&self, port : u16) -> bool {
        for port_str in &self.trigger_ports {
            if port_str == "*" {
                return true;
            }
            if port_str == &port.to_string() {
                return true;
            }
            if port_str.contains('-') {
                let parts: Vec<&str> = port_str.split('-').collect();
                if parts.len() != 2 {
                    continue;
                }
                let start = parts[0].parse::<u16>();
                if start.is_err() {
                    continue;
                }

                let end = parts[1].parse::<u16>();
                if end.is_err() {
                    continue;
                }

                if port >= start.unwrap() && port <= end.unwrap() {
                    return true;
                }
            }
        }
        false
    }

    pub fn check_protocols(&self, protocol : &str) -> bool {
        for protocol_str in &self.trigger_protocols {
            if protocol_str == "*" {
                return true;
            }
            if protocol_str.to_lowercase() == protocol.to_lowercase() {
                return true;
            }
        }
        false
    }
    
    pub fn get_proble_pattern(&self) -> Vec<ProblePattern> {
        self.packet_patterns.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_packet_definition() {
        let packet = ProbleRule::new("src/tests/sniffp/a.yaml");
        assert!(packet.is_ok());
    }

    #[test]
    fn dump_yaml() {
        let mut packet = ProbleRule::new_empty();

        let trigger_ports = vec!["1".to_string(), "2".to_string()];
        packet.set_trigger_ports(trigger_ports);

        let trigger_protocols = vec!["tcp".to_string(), "udp".to_string()];
        packet.set_trigger_protocols(trigger_protocols);

        let packet_patterns = vec![
            ProblePattern::HexSequence(vec![0x01, 0x02, 0x03]),
            ProblePattern::HexString("04 05 06".to_string()),
        ];
        packet.set_proble_pattern(packet_patterns);

        println!("{}", serde_yaml::to_string(&packet).unwrap());
    }

    #[test]
    fn test_pattern_bytes() {
        let hexstring = ProblePattern::HexSequence(vec![0x01, 0x02, 0x03]);
        assert_eq!(hexstring.to_bytes(), vec![0x01, 0x02, 0x03]);

        let hexstring = ProblePattern::HexString("010203DDFF".to_string());
        assert_eq!(hexstring.to_bytes(), vec![0x01, 0x02, 0x03, 0xDD, 0xFF]);

        let xstring = ProblePattern::String("hello world".to_string());
        assert_eq!(xstring.to_bytes(), "hello world".as_bytes())
    }
}