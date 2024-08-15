use std::fs::File;
use std::io::BufReader;
use async_std::path::Path;
use serde_derive::{Deserialize, Serialize};
use snafu::{prelude::*, Whatever};
#[derive(Deserialize,Serialize)]
pub enum SniffPacketPattern {
    HexSequence(Vec<u8>),
    HexString(String),
}

#[derive(Deserialize,Serialize)]
pub struct MetaInfo {
    pub name: String,
    pub enabled: bool,
    pub description: String,
}

#[derive(Deserialize,Serialize)]
pub struct SniffPacket {
    pub meta: MetaInfo,
    pub trigger_ports : Vec<String>,
    pub trigger_protocols : Vec<String>,
    pub packet_patterns : Vec<SniffPacketPattern>,
    pub rule_definition: String,
}

impl SniffPacket {
    pub fn new(path: &str) -> Result<SniffPacket,Whatever> {
        let path = Path::new(path);
        let file = File::open(path);
        if file.is_err() {
            return whatever!("Failed to load packet definition from {}", path.to_str().unwrap());
        }

        let file = file.unwrap();
        let reader = BufReader::new(file);
        let yaml = serde_yaml::from_reader::<BufReader<File>, SniffPacket>(reader);
        if yaml.is_err() {
            return return whatever!("Invalid packet definition in {}", path.to_str().unwrap());;
        }

        Ok(yaml.unwrap())
    }

    pub fn new_empty() -> SniffPacket {
        SniffPacket {
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
    pub fn set_packet_patterns(&mut self, patterns: Vec<SniffPacketPattern>) {
        self.packet_patterns = patterns;
    }

    pub fn get_rule_definition(&self) -> String {
        self.rule_definition.clone()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_packet_definition() {
        let packet = SniffPacket::new("src/tests/sniffp/a.yaml");
        assert!(packet.is_ok());
    }

    #[test]
    fn dump_yaml() {
        let mut packet = SniffPacket::new_empty();

        let trigger_ports = vec!["1".to_string(), "2".to_string()];
        packet.set_trigger_ports(trigger_ports);

        let trigger_protocols = vec!["tcp".to_string(), "udp".to_string()];
        packet.set_trigger_protocols(trigger_protocols);

        let packet_patterns = vec![
            SniffPacketPattern::HexSequence(vec![0x01, 0x02, 0x03]),
            SniffPacketPattern::HexString("04 05 06".to_string()),
        ];
        packet.set_packet_patterns(packet_patterns);

        println!("{}", serde_yaml::to_string(&packet).unwrap());
    }
}