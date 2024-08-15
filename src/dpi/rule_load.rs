use std::collections::HashMap;
use std::path::{Path, PathBuf};
use snafu::{whatever, Whatever};
use yara_x::Rules;
use crate::dpi::sniff_packet::SniffPacket;
use crate::dpi::{Scanner, YaraXCompiler};

pub struct RuleLoad {
    rules: HashMap<String, SniffPacket>
}

impl RuleLoad {
    pub fn new() -> Self {
        Self {
            rules: HashMap::new()
        }
    }

    pub fn load_rules_with_folders(&mut self, paths: Vec<PathBuf>) {
        //walk folder to load all yaml and yml
        for path in paths {
            for entry in walkdir::WalkDir::new::<&Path>(path.as_ref()).into_iter().filter_map(|e|{
                match e {
                    Err(err) => {
                        println!("{}", err);
                        None
                    }
                    Ok(entry) => {
                        if entry.file_type().is_file() {
                            let ext =  entry.path().extension();
                            match ext {
                                Some(ext) => {
                                    if ext == "yaml" || ext == "yml"{
                                        Some(entry)
                                    } else {
                                        None
                                    }
                                },
                                None => {
                                    None
                                }
                            }
                        }else{
                            None
                        }
                    }
                }
            }) {
                self.load_rule_with_file(entry.path().to_string_lossy().to_string());
            }
        }
    }

    pub fn create_yara_rules(&self) -> Result<Rules, Whatever> {
        let mut compiler = YaraXCompiler::new(true, false);

        for (_, rule) in self.rules.iter() {
            let result = compiler.add_source(rule.get_rule_definition().as_str());
            if result.is_err() {
            }
        }

        let rules = compiler.build();
        match rules {
            Err(err) => {
                whatever!("{}", err)
            },
            Ok(rules) => {
                Ok(rules)
            }
        }
    }

    pub fn load_rule_with_file(&mut self, file_path: String) {
        let packet = SniffPacket::new(file_path.as_str());
        match packet {
            Ok(packet) => {
                self.add_rule(file_path, packet);
            },
            Err(_) => {}
        }
    }

    pub fn add_rule(&mut self,key: String, rule: SniffPacket) {
        if rule.meta.enabled {
            self.rules.insert(key, rule);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::any::Any;
    use super::*;

    #[test]
    fn test_rule_load() {
        let mut rule_load = RuleLoad::new();
        let paths = vec![PathBuf::from("src/tests/sniffp")];
        rule_load.load_rules_with_folders(paths);
        assert_eq!(rule_load.rules.len(), 1);
    }

    #[test]
    fn test_create_yara_rules() {
        let mut rule_load = RuleLoad::new();
        let paths = vec![PathBuf::from("src/tests/sniffp")];
        rule_load.load_rules_with_folders(paths);
        let rules = rule_load.create_yara_rules();
        assert!(rules.is_ok());

        let binding = rules.unwrap();
        let scanner = Scanner::new(&binding);
        println!("done");
    }
}