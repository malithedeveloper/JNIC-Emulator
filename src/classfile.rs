use std::borrow::Cow;

use anyhow::{Context, Result, bail, ensure};

use crate::descriptor::{dotted, parse_method_descriptor};
use crate::limits::MAX_CONSTANT_POOL_ENTRIES;

const CLASS_MAGIC: u32 = 0xCAFE_BABE;
const ACC_PUBLIC: u16 = 0x0001;
const ACC_PRIVATE: u16 = 0x0002;
const ACC_PROTECTED: u16 = 0x0004;
const ACC_STATIC: u16 = 0x0008;
const ACC_FINAL: u16 = 0x0010;
const ACC_SYNCHRONIZED: u16 = 0x0020;
const ACC_NATIVE: u16 = 0x0100;
const ACC_ABSTRACT: u16 = 0x0400;
const ACC_STRICT: u16 = 0x0800;

#[derive(Debug, Clone, Default)]
pub enum Constant {
    #[default]
    Unusable,
    Utf8(String),
    Integer(i32),
    Float(u32),
    Long(u64),
    Double(u64),
    Class(u16),
    String(u16),
    Member {
        tag: u8,
        class_index: u16,
        name_type_index: u16,
    },
    NameAndType {
        name_index: u16,
        descriptor_index: u16,
    },
    MethodHandle {
        kind: u8,
        reference_index: u16,
    },
    MethodType(u16),
    Dynamic {
        tag: u8,
        bootstrap_index: u16,
        name_type_index: u16,
    },
    Module(u16),
    Package(u16),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExceptionHandler {
    pub start_pc: u16,
    pub end_pc: u16,
    pub handler_pc: u16,
    pub catch_type: Option<String>,
}

#[derive(Debug, Clone)]
pub struct JavaMethod {
    pub access: u16,
    pub name: String,
    pub descriptor: String,
    pub exceptions: Vec<String>,
    pub code: Vec<u8>,
    pub exception_handlers: Vec<ExceptionHandler>,
}

impl JavaMethod {
    #[must_use]
    pub fn is_native(&self) -> bool {
        self.access & ACC_NATIVE != 0
    }

    pub fn declaration(&self) -> Result<String> {
        let descriptor = parse_method_descriptor(&self.descriptor)
            .with_context(|| format!("invalid descriptor for {}", self.name))?;
        let mut parts = Vec::new();
        if self.access & ACC_PUBLIC != 0 {
            parts.push("public");
        } else if self.access & ACC_PROTECTED != 0 {
            parts.push("protected");
        } else if self.access & ACC_PRIVATE != 0 {
            parts.push("private");
        }
        if self.access & ACC_STATIC != 0 {
            parts.push("static");
        }
        if self.access & ACC_FINAL != 0 {
            parts.push("final");
        }
        if self.access & ACC_SYNCHRONIZED != 0 {
            parts.push("synchronized");
        }
        if self.access & ACC_ABSTRACT != 0 {
            parts.push("abstract");
        }
        if self.access & ACC_STRICT != 0 {
            parts.push("strictfp");
        }

        let mut declaration = String::new();
        if !parts.is_empty() {
            declaration.push_str(&parts.join(" "));
            declaration.push(' ');
        }
        declaration.push_str(&descriptor.result);
        declaration.push(' ');
        declaration.push_str(&self.name);
        declaration.push('(');
        for (index, parameter) in descriptor.parameters.iter().enumerate() {
            if index != 0 {
                declaration.push_str(", ");
            }
            declaration.push_str(parameter);
            declaration.push_str(" arg");
            declaration.push_str(&index.to_string());
        }
        declaration.push(')');
        if !self.exceptions.is_empty() {
            declaration.push_str(" throws ");
            declaration.push_str(
                &self
                    .exceptions
                    .iter()
                    .map(|name| dotted(name))
                    .collect::<Vec<_>>()
                    .join(", "),
            );
        }
        Ok(declaration)
    }
}

#[derive(Debug, Clone)]
pub struct JavaClass {
    pub entry_name: String,
    pub internal_name: String,
    pub super_name: Option<String>,
    pub interfaces: Vec<String>,
    pub pool: Vec<Constant>,
    pub methods: Vec<JavaMethod>,
    pub dat_resources: Vec<String>,
}

impl JavaClass {
    #[must_use]
    pub fn protected_methods(&self) -> Vec<&JavaMethod> {
        self.methods
            .iter()
            .filter(|method| method.is_native() && method.name != "$jnicLoader")
            .collect()
    }

    #[must_use]
    pub fn has_loader_method(&self) -> bool {
        self.methods
            .iter()
            .any(|method| method.is_native() && method.name == "$jnicLoader")
    }

    #[must_use]
    pub fn utf8(&self, index: u16) -> Option<&str> {
        match self.pool.get(usize::from(index))? {
            Constant::Utf8(value) => Some(value),
            _ => None,
        }
    }

    #[must_use]
    pub fn class_name(&self, index: u16) -> Option<&str> {
        match self.pool.get(usize::from(index))? {
            Constant::Class(name_index) => self.utf8(*name_index),
            _ => None,
        }
    }

    #[must_use]
    pub fn resolve_member(&self, index: u16) -> Option<ResolvedMember<'_>> {
        let Constant::Member {
            tag,
            class_index,
            name_type_index,
        } = self.pool.get(usize::from(index))?
        else {
            return None;
        };
        let Constant::NameAndType {
            name_index,
            descriptor_index,
        } = self.pool.get(usize::from(*name_type_index))?
        else {
            return None;
        };
        Some(ResolvedMember {
            tag: *tag,
            owner: self.class_name(*class_index)?,
            name: self.utf8(*name_index)?,
            descriptor: self.utf8(*descriptor_index)?,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ResolvedMember<'a> {
    pub tag: u8,
    pub owner: &'a str,
    pub name: &'a str,
    pub descriptor: &'a str,
}

pub fn parse_class(bytes: &[u8], entry_name: impl Into<String>) -> Result<JavaClass> {
    let mut reader = Reader::new(bytes);
    ensure!(reader.u4()? == CLASS_MAGIC, "invalid class-file magic");
    let _minor = reader.u2()?;
    let _major = reader.u2()?;
    let pool_count = usize::from(reader.u2()?);
    ensure!(
        (1..=MAX_CONSTANT_POOL_ENTRIES).contains(&pool_count),
        "invalid constant-pool size"
    );

    let mut pool = vec![Constant::Unusable; pool_count];
    let mut index = 1;
    while index < pool_count {
        let tag = reader.u1()?;
        let item = match tag {
            1 => {
                let length = usize::from(reader.u2()?);
                let raw = reader.bytes(length)?;
                let decoded: Cow<'_, str> = cesu8::from_java_cesu8(raw)
                    .map_err(|error| anyhow::anyhow!("invalid modified UTF-8: {error}"))?;
                Constant::Utf8(decoded.into_owned())
            }
            3 => Constant::Integer(reader.u4()? as i32),
            4 => Constant::Float(reader.u4()?),
            5 => {
                let value = reader.u8()?;
                pool[index] = Constant::Long(value);
                index += 1;
                ensure!(index < pool_count, "wide constant at end of pool");
                index += 1;
                continue;
            }
            6 => {
                let value = reader.u8()?;
                pool[index] = Constant::Double(value);
                index += 1;
                ensure!(index < pool_count, "wide constant at end of pool");
                index += 1;
                continue;
            }
            7 => Constant::Class(reader.u2()?),
            8 => Constant::String(reader.u2()?),
            9..=11 => Constant::Member {
                tag,
                class_index: reader.u2()?,
                name_type_index: reader.u2()?,
            },
            12 => Constant::NameAndType {
                name_index: reader.u2()?,
                descriptor_index: reader.u2()?,
            },
            15 => Constant::MethodHandle {
                kind: reader.u1()?,
                reference_index: reader.u2()?,
            },
            16 => Constant::MethodType(reader.u2()?),
            17 | 18 => Constant::Dynamic {
                tag,
                bootstrap_index: reader.u2()?,
                name_type_index: reader.u2()?,
            },
            19 => Constant::Module(reader.u2()?),
            20 => Constant::Package(reader.u2()?),
            _ => bail!("unsupported constant-pool tag {tag}"),
        };
        pool[index] = item;
        index += 1;
    }

    let _access = reader.u2()?;
    let this_class = reader.u2()?;
    let super_class = reader.u2()?;
    let internal_name = class_name(&pool, this_class)
        .context("class file has an invalid this_class entry")?
        .to_owned();
    let super_name = (super_class != 0)
        .then(|| class_name(&pool, super_class).map(ToOwned::to_owned))
        .flatten();

    let interface_count = usize::from(reader.u2()?);
    let mut interfaces = Vec::with_capacity(interface_count);
    for _ in 0..interface_count {
        let class_index = reader.u2()?;
        if let Some(name) = class_name(&pool, class_index) {
            interfaces.push(name.to_owned());
        }
    }

    let field_count = usize::from(reader.u2()?);
    for _ in 0..field_count {
        skip_member(&mut reader)?;
    }

    let method_count = usize::from(reader.u2()?);
    let mut methods = Vec::with_capacity(method_count);
    for _ in 0..method_count {
        let access = reader.u2()?;
        let name = utf8(&pool, reader.u2()?)
            .context("method has an invalid name index")?
            .to_owned();
        let descriptor = utf8(&pool, reader.u2()?)
            .context("method has an invalid descriptor index")?
            .to_owned();
        let attribute_count = usize::from(reader.u2()?);
        let mut code = Vec::new();
        let mut exception_handlers = Vec::new();
        let mut exceptions = Vec::new();

        for _ in 0..attribute_count {
            let attribute_name = utf8(&pool, reader.u2()?)
                .context("method has an invalid attribute name")?
                .to_owned();
            let attribute_length = usize::try_from(reader.u4()?)?;
            let raw_attribute = reader.bytes(attribute_length)?;
            match attribute_name.as_str() {
                "Code" => {
                    let parsed = parse_code_attribute(raw_attribute, &pool)?;
                    code = parsed.0;
                    exception_handlers = parsed.1;
                }
                "Exceptions" => {
                    let mut attribute = Reader::new(raw_attribute);
                    let count = usize::from(attribute.u2()?);
                    for _ in 0..count {
                        if let Some(name) = class_name(&pool, attribute.u2()?) {
                            exceptions.push(name.to_owned());
                        }
                    }
                    attribute.finish("Exceptions attribute")?;
                }
                _ => {}
            }
        }
        methods.push(JavaMethod {
            access,
            name,
            descriptor,
            exceptions,
            code,
            exception_handlers,
        });
    }

    let class_attribute_count = usize::from(reader.u2()?);
    for _ in 0..class_attribute_count {
        let _name = reader.u2()?;
        let length = usize::try_from(reader.u4()?)?;
        let _content = reader.bytes(length)?;
    }
    reader.finish("class file")?;

    let mut dat_resources = pool
        .iter()
        .filter_map(|constant| match constant {
            Constant::String(index) => utf8(&pool, *index),
            Constant::Utf8(value) => Some(value.as_str()),
            _ => None,
        })
        .filter(|value| value.to_ascii_lowercase().ends_with(".dat"))
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    dat_resources.sort();
    dat_resources.dedup();

    Ok(JavaClass {
        entry_name: entry_name.into(),
        internal_name,
        super_name,
        interfaces,
        pool,
        methods,
        dat_resources,
    })
}

fn parse_code_attribute(
    bytes: &[u8],
    pool: &[Constant],
) -> Result<(Vec<u8>, Vec<ExceptionHandler>)> {
    let mut reader = Reader::new(bytes);
    let _max_stack = reader.u2()?;
    let _max_locals = reader.u2()?;
    let code_length = usize::try_from(reader.u4()?)?;
    let code = reader.bytes(code_length)?.to_vec();
    let exception_count = usize::from(reader.u2()?);
    let mut handlers = Vec::with_capacity(exception_count);
    for _ in 0..exception_count {
        let start_pc = reader.u2()?;
        let end_pc = reader.u2()?;
        let handler_pc = reader.u2()?;
        let catch_index = reader.u2()?;
        handlers.push(ExceptionHandler {
            start_pc,
            end_pc,
            handler_pc,
            catch_type: (catch_index != 0)
                .then(|| class_name(pool, catch_index).map(ToOwned::to_owned))
                .flatten(),
        });
    }
    let nested_count = usize::from(reader.u2()?);
    for _ in 0..nested_count {
        let _name = reader.u2()?;
        let length = usize::try_from(reader.u4()?)?;
        let _content = reader.bytes(length)?;
    }
    reader.finish("Code attribute")?;
    Ok((code, handlers))
}

fn skip_member(reader: &mut Reader<'_>) -> Result<()> {
    let _access = reader.u2()?;
    let _name = reader.u2()?;
    let _descriptor = reader.u2()?;
    let attribute_count = usize::from(reader.u2()?);
    for _ in 0..attribute_count {
        let _name = reader.u2()?;
        let length = usize::try_from(reader.u4()?)?;
        let _content = reader.bytes(length)?;
    }
    Ok(())
}

fn utf8(pool: &[Constant], index: u16) -> Option<&str> {
    match pool.get(usize::from(index))? {
        Constant::Utf8(value) => Some(value),
        _ => None,
    }
}

fn class_name(pool: &[Constant], index: u16) -> Option<&str> {
    let Constant::Class(name_index) = pool.get(usize::from(index))? else {
        return None;
    };
    utf8(pool, *name_index)
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .context("class-file offset overflow")?;
        let value = self
            .bytes
            .get(self.offset..end)
            .context("truncated class file")?;
        self.offset = end;
        Ok(value)
    }

    fn u1(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }

    fn u2(&mut self) -> Result<u16> {
        let raw: [u8; 2] = self.bytes(2)?.try_into()?;
        Ok(u16::from_be_bytes(raw))
    }

    fn u4(&mut self) -> Result<u32> {
        let raw: [u8; 4] = self.bytes(4)?.try_into()?;
        Ok(u32::from_be_bytes(raw))
    }

    fn u8(&mut self) -> Result<u64> {
        let raw: [u8; 8] = self.bytes(8)?.try_into()?;
        Ok(u64::from_be_bytes(raw))
    }

    fn finish(&self, what: &str) -> Result<()> {
        ensure!(
            self.offset == self.bytes.len(),
            "trailing data in {what}: {} bytes",
            self.bytes.len() - self.offset
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_rejects_truncation() {
        let mut reader = Reader::new(&[0xCA, 0xFE]);
        assert!(reader.u4().is_err());
    }

    #[test]
    fn decodes_modified_utf8() {
        let bytes = [0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80];
        assert_eq!(cesu8::from_java_cesu8(&bytes).unwrap(), "😀");
    }
}
