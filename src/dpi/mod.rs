use core::mem;
use std::any::Any;
use std::convert::TryInto;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Error, Result};

use yara_x as yrx;
use yara_x::{Rule, Variable};
use yara_x::SourceCode;

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

#[cfg(test)]
mod tests {
    use yara_x::MetaValue::String;
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
        let scan_results =scanner.scan(b"UVODFRYSIHLNWPEJXQZAKCBGMT").unwrap();
        let matching_rules = scan_results
            .matching_rules()
            .map(|rule| rule )
            .collect::<Vec<Rule>>();
        for rule in matching_rules {
            println!("{}", rule.identifier());
            rule.tags().for_each(|tag| {
                println!("  {}", tag.identifier());
            });

            rule.metadata().for_each(|meta| {
                println!("  {}", meta.0, meta.1);
            });
        }
        assert!(result.is_ok());
    }
}