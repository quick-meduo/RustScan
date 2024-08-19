#![allow(dead_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use snafu::{whatever, Whatever};
use yara_x::Rules;
use crate::dpi::proble_rule::ProbleRule;
use crate::dpi::{YaraXCompiler};

#[cfg(test)]
use crate::dpi::Scanner;

pub struct RuleLoad {
    rules: HashMap<String, ProbleRule>
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
        let packet = ProbleRule::new(file_path.as_str());
        match packet {
            Ok(packet) => {
                self.add_rule(file_path, packet);
            },
            Err(_) => {}
        }
    }

    pub fn add_rule(&mut self,key: String, rule: ProbleRule) {
        if rule.meta.enabled {
            self.rules.insert(key, rule);
        }
    }

    pub fn get_rules(&self) -> &HashMap<String, ProbleRule> {
        &self.rules
    }
}


#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;
    use disruptor::Sequence;
    use super::*;
    use disruptor::*;

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
        let _scanner = Scanner::new(&binding);
        println!("done");
    }

    #[test]
    fn test_ref_cell() {
        #[derive(Debug)]
        struct GroundStation{
            radio_freq: f64
        }

        let base = Rc::new(RefCell::new(GroundStation{
            radio_freq: 87.65
        }));
        println!("base {:?}", base);

        {
            let mut base_ref = base.borrow_mut();
            base_ref.radio_freq = 123.456;
            println!("base_ref {:?}", base_ref);
        }

        println!("base {:?}", base);

        let mut base_ref = base.borrow_mut();
        base_ref.radio_freq = 98.76;

        println!("base {:?}", base);
        println!("base_ref {:?}", base_ref);
    }

    #[test]
    fn test_disruptor() {
        struct Event {
            price: f64
        }

        let factory = || { Event { price: 0.0 }};

        let processor = |e: &Event, _sequence: Sequence, _end_of_batch: bool| {
            println!("price: {}", e.price);
        };

        let size = 64;
        let mut producer = disruptor::build_single_producer(size, factory, BusySpin)
            .handle_events_with(processor)
            .build();

        for i in 0..10 {
            producer.publish(|e| {
                e.price = i as f64;
            });
        }

        // Publish a batch of events into the Disruptor.
        producer.batch_publish(5, |iter| {
            let mut delta = 0.1;
            for e in iter { // `iter` is guaranteed to yield 5 events.
                e.price = 42.0 + delta;
                delta += 0.1;
            }
        });
    }
}