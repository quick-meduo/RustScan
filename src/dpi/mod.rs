#![allow(dead_code)]
#![warn(non_camel_case_types)]

mod proble_rule;
mod rule_load;
mod proble_engine;

use core::mem;
use std::convert::TryInto;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Error, Result};
use protobuf_json_mapping::print_to_string;
use yara_x as yrx;
use yara_x::{Variable};
use yara_x::SourceCode;

use serde_json::{Map, Value};

pub struct YaraXCompiler<'a> {
    inner: yrx::Compiler<'a>,
    relaxed_re_syntax: bool,
    error_on_slow_pattern: bool,
}

impl<'a> YaraXCompiler<'a>{
    pub fn new(
        relaxed_re_syntax: bool,
        error_on_slow_pattern: bool,
    ) -> Self {
        Self {
            inner: Self::new_inner(relaxed_re_syntax, error_on_slow_pattern),
            relaxed_re_syntax,
            error_on_slow_pattern,
        }
    }

    pub fn new_inner(
        relaxed_re_syntax: bool,
        error_on_slow_pattern: bool,
    ) -> yrx::Compiler<'static> {
        let mut compiler = yrx::Compiler::new();
        if relaxed_re_syntax {
            compiler.relaxed_re_syntax(true);
        }
        if error_on_slow_pattern {
            compiler.error_on_slow_pattern(true);
        }
        compiler
    }

    pub fn add_source(&mut self, src: &str) -> Result<()> {
        let result = self.inner.add_source(src);
        if let Err(err) = result {
            return Err(err.into());
        }

        Ok(())
    }

    pub fn add_paths(&mut self, paths: Vec<PathBuf>, path_as_namespace: bool) -> Result<()> {
        for path in paths {
            for entry in walkdir::WalkDir::new::<&Path>(path.as_ref()).into_iter().filter_map(|e|{
                match e {
                    Err(err) => {
                        println!("{}", err);
                        None
                    }
                    Ok(entry) => {
                        if entry.file_type().is_file() {
                           //check extension if yara,yar,yr
                           let ext =  entry.path().extension();
                           match ext {
                               Some(ext) => {
                                   if ext == "yara" || ext == "yar" || ext == "yr" {
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
                let src = fs::read::<&Path>(entry.path().as_ref()).with_context(|| {
                    format!("can not read `{}`", entry.path().display())
                });

                match src {
                    Ok(src) => {
                        let src = SourceCode::from(src.as_slice())
                            .with_origin(entry.path().to_str().unwrap());
                        if path_as_namespace {
                            self.inner.new_namespace(entry.path().to_string_lossy().as_ref());
                        }
                        let result = self.inner.add_source(src);
                        match result {
                            Ok(_) => {}
                            Err(_) => {
                            }
                        }
                    }
                    Err(_) => {
                    }
                }
            }
        }
        Ok(())
    }

    pub fn ignore_module(&mut self, module_name: &str) -> Result<()> {
        let _ = self.inner.ignore_module(module_name);
        Ok(())
    }
    pub fn new_namespace(&mut self, namespace_name: &str) -> Result<()> {
        let _ = self.inner.new_namespace(namespace_name);
        Ok(())
    }

    pub fn define_global<T: TryInto<Variable>>(
        &mut self,
        ident: &str,
        value: T,
    ) -> Result<(),Error>
    where
        yara_x::Error: From<<T as TryInto<Variable>>::Error> {
        let result = self.inner.define_global(ident, value);
        match result {
            Ok(_) => { Ok(())}
            Err(_) => {
                Err(anyhow!("Failed to define global variable"))
            }
        }
    }

    pub fn build(&mut self) -> Result<yrx::Rules> {
        // let result = self.inner.take().build();
        let compiler = mem::replace(
            &mut self.inner,
            Self::new_inner(
                self.relaxed_re_syntax,
                self.error_on_slow_pattern,
            )
        );
        let result = compiler.build();
        Ok(result)
    }
}


pub struct Scanner<'r> {
    inner: yrx::Scanner<'r>,
}

impl<'r>  Scanner<'r>{
    pub fn new(rules: &'r yrx::Rules) -> Self {
        Scanner {
            inner: yrx::Scanner::new(rules),
        }
    }

    pub fn scan<'a>(&'a mut self, data: &'a [u8]) -> Result<yrx::ScanResults<'a, 'r>, yrx::ScanError> {
        self.inner.scan(data)
    }

    pub fn scan_file<'a>(&'a mut self, path: &str) -> Result<yrx::ScanResults<'a, 'r>, yrx::ScanError> {
        let result = self.inner.scan_file(path);
        result
    }
}

trait ToJson {
    fn to_json(&self) -> Value;
}

pub struct Pattern {
    identifier: String,
    matches: Vec<Match>,
}

impl ToJson for Pattern {
    fn to_json(&self) -> Value {
        let mut result: Map<String, Value> = Map::new();
        result.insert("identifier".to_string(), Value::String(self.identifier.to_string()));

        let mut match_vec: Vec<Value> = vec![];
        for m in &self.matches {
            match_vec.push(m.to_json());
        }
        result.insert("matches".to_string(), Value::Array(match_vec));
        Value::from(result)
    }
}

pub struct Match {
    /// Offset within the scanned data where the match occurred.
    offset: usize,
    /// Length of the match.
    length: usize,
    /// For patterns that have the `xor` modifier, contains the XOR key that
    /// applied to matching data. For any other pattern will be `None`.
    xor_key: Option<u8>,
}

impl ToJson for Match {
    fn to_json(&self) -> Value {
        let mut result: Map<String, Value> = Map::new();
        result.insert("offset".to_string(), Value::from(self.offset));
        result.insert("length".to_string(), Value::from(self.length));
        if self.xor_key.is_none() {
            result.insert("xor_key".to_string(), Value::from(false));
        } else {
            result.insert("xor_key".to_string(), Value::from(true));
        }
        Value::from(result)
    }
}

pub struct MetaData {
    ident: String,
    value: String,
}

impl ToJson for MetaData {
    fn to_json(&self) -> Value {
        let mut result:Map<String, Value> = Map::new();
        result.insert("ident".to_string(), Value::from(self.ident.to_string()));
        result.insert("value".to_string(), Value::from(self.value.to_string()));
        Value::from(result)
    }
}

pub struct Rule {
    identifier: String,
    namespace: String,
    metadata: Vec<MetaData>,
    patterns: Vec<Pattern>,
}

impl ToJson for Rule {
    fn to_json(&self) -> Value {
        let mut result: Map<String, Value> = Map::new();
        result.insert("identifier".to_string(), Value::String(self.identifier.to_string()));
        result.insert("namespace".to_string(), Value::String(self.namespace.to_string()));
        let mut metadata_vec:Vec<Value> = vec![];
        for m in &self.metadata {
            metadata_vec.push(Value::from(m.to_json()));
        }
        result.insert("metadata".to_string(), Value::from(metadata_vec));

        let mut pattern_vec: Vec<Value> = vec![];
        for p in &self.patterns {
            pattern_vec.push(Value::from(p.to_json()));
        }
        result.insert("patterns".to_string(), Value::from(pattern_vec));
        Value::from(result)
    }
}

pub struct ScanResults {
    /// Vector that contains all the rules that matched during the scan.
    matching_rules: Vec<Rule>,
    /// Dictionary where keys are module names and values are other
    /// dictionaries with the information produced by the corresponding module.
    module_outputs: Vec<(String,String)>,
}

impl ToJson for ScanResults{
    fn to_json(&self) -> Value {
        let mut result: Map<String, Value> = Map::new();
        let mut rule_vec:Vec<Value> = vec![];
        for r in &self.matching_rules {
            rule_vec.push(Value::from(r.to_json()));
        }
        result.insert("matching_rules".to_string(), Value::from(rule_vec));

        let mut module_map: Map<String, Value> = Map::new();
        for (k, v) in &self.module_outputs {
            module_map.insert(k.to_string(), Value::from(v.to_string()));
        }
        result.insert("module_outputs".to_string(), Value::Object(module_map));
        Value::from(result)
    }
}

pub fn metadata_jsonify(
    ident: &str,
    metadata: yrx::MetaValue,
) -> MetaData {
    let value = match metadata {
        yrx::MetaValue::Integer(v) => v.to_string(),
        yrx::MetaValue::Float(v) => v.to_string(),
        yrx::MetaValue::Bool(v) => v.to_string(),
        yrx::MetaValue::String(v) => v.to_string(),
        yrx::MetaValue::Bytes(v) => v.to_string(),
    };
    MetaData {
        ident: ident.to_string(),
        value,
    }
}

pub fn match_jsonify(match_: yrx::Match) -> Match {
    Match {
        offset: match_.range().start,
        length: match_.range().len(),
        xor_key: match_.xor_key(),
    }
}
pub fn pattern_jsonify(pattern: yrx::Pattern) -> Pattern {
    Pattern {
        identifier: pattern.identifier().to_string(),
        matches: pattern.matches().map(|match_| {
            match_jsonify(match_)
        }).collect(),
    }
}
pub fn rule_jsonify( rule: &yrx::Rule) -> Rule {
    Rule {
        identifier: rule.identifier().to_string(),
        namespace: rule.namespace().to_string(),
        metadata: rule.metadata().map(|(ident, value)| metadata_jsonify(ident, value)).collect(),
        patterns: rule.patterns().map(|pattern| pattern_jsonify(pattern)).collect()
    }
}

pub fn scan_results_jsonify(scan_results: yrx::ScanResults) -> ScanResults {
    let matching_rules = scan_results
        .matching_rules()
        .map(|rule| rule_jsonify(&rule))
        .collect::<Vec<Rule>>();

    let mut module_outputs:  Vec::<(String, String)> = Vec::new();
    for (module, output) in scan_results.module_outputs() {
        let byteout = output.write_to_bytes_dyn();
        if let Ok(bb) = byteout {
            let str = std::str::from_utf8(bb.as_slice());
            if let Ok(s) = str {
                module_outputs.push((module.to_string(),s.to_string()));
                continue;
            }
        }
        let module_output_json = print_to_string(output).unwrap();
        module_outputs.push((module.to_string(),module_output_json));
    }

    ScanResults {
        matching_rules,
        module_outputs,
    }
}



#[cfg(test)]
mod tests {
    use yara_x::Rule;
    use super::*;

    #[test]
    fn test_scanner() {
        let mut compiler = YaraXCompiler::new(false, false);
        compiler.add_source(
            r#"
            rule lorem_ipsum: test te t {
                meta:
                    author = "John Doe"
                    description = "Lorem ipsum dolor sit amet"
                    version = 1
                strings:
                    $a = "lorem ipsum"
                    $b = "dolor sit amet"
                condition:
                    $a or $b
            }
            "#,
        ).unwrap();

        let rules = compiler.build().unwrap();
        let mut scanner = Scanner::new(&rules);
        let scan_results = scanner.scan(b"lorem ipsum").unwrap();
        let matching_rules = scan_results
            .matching_rules()
            .map(|rule| rule )
            .collect::<Vec<Rule>>();
        for rule in matching_rules {
            println!("{}", rule.identifier());
        }
    }

    #[test]
    fn test_compiler() {
        let mut compiler = YaraXCompiler::new(true, false);
        let result = compiler.add_source(r#"
        rule test {
            strings:
                $a = "lorem ipsum"
                $b = "dolor sit amet"
            condition:
                $a or $b
        }
        "#
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_compiler_with_paths() {
        let mut compiler = YaraXCompiler::new(true, false);

        let result = compiler.add_paths(vec![PathBuf::from("src/tests/rules")], true);
        assert!(result.is_ok());

        let rules =  compiler.build().unwrap();

        let mut scanner = Scanner::new(&rules);
        let scan_results =scanner.scan(b"_1234UVODFRYSIHLNWPEJXQZAKCBGMT_").unwrap();
        let matching_rules = scan_results
            .matching_rules()
            .map(|rule| rule )
            .collect::<Vec<Rule>>();
        for rule in matching_rules {
            println!("{}", rule.identifier());
            rule.tags().for_each(|tag| {
                println!("  tag: {}", tag.identifier());
            });

            rule.metadata().for_each(|meta| {
                let m = metadata_jsonify(meta.0, meta.1);
                println!("  meta: {} -> {}", m.ident, m.value);
            });

            rule.patterns().for_each(|pattern| {
                println!("  pattern: {}", pattern.identifier());
                pattern.matches().for_each(|mat| {
                    let mat = match_jsonify(mat);
                    println!("    match: {} -> {}", mat.offset, mat.length);
                });
            });
        }
        assert!(result.is_ok());
    }
}