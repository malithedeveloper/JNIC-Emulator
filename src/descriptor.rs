use anyhow::{Result, bail};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodDescriptor {
    pub parameters: Vec<String>,
    pub result: String,
}

pub fn dotted(internal_name: &str) -> String {
    internal_name.replace('/', ".")
}

fn parse_type(descriptor: &str, offset: usize, allow_void: bool) -> Result<(String, usize)> {
    let bytes = descriptor.as_bytes();
    let Some(&kind) = bytes.get(offset) else {
        bail!("truncated Java descriptor");
    };

    let primitive = match kind {
        b'V' if allow_void => Some("void"),
        b'Z' => Some("boolean"),
        b'B' => Some("byte"),
        b'C' => Some("char"),
        b'S' => Some("short"),
        b'I' => Some("int"),
        b'J' => Some("long"),
        b'F' => Some("float"),
        b'D' => Some("double"),
        _ => None,
    };
    if let Some(name) = primitive {
        return Ok((name.to_owned(), offset + 1));
    }

    match kind {
        b'L' => {
            let tail = &descriptor[offset + 1..];
            let Some(relative_end) = tail.find(';') else {
                bail!("unterminated object descriptor");
            };
            if relative_end == 0 {
                bail!("empty object descriptor");
            }
            let end = offset + 1 + relative_end;
            Ok((dotted(&descriptor[offset + 1..end]), end + 1))
        }
        b'[' => {
            let (component, next) = parse_type(descriptor, offset + 1, false)?;
            Ok((format!("{component}[]"), next))
        }
        _ => bail!("invalid Java descriptor type at byte {offset}"),
    }
}

pub fn parse_method_descriptor(descriptor: &str) -> Result<MethodDescriptor> {
    if !descriptor.starts_with('(') {
        bail!("invalid method descriptor: {descriptor}");
    }
    let mut offset = 1;
    let mut parameters = Vec::new();
    while descriptor.as_bytes().get(offset) != Some(&b')') {
        if offset >= descriptor.len() {
            bail!("unterminated method descriptor: {descriptor}");
        }
        let (parameter, next) = parse_type(descriptor, offset, false)?;
        parameters.push(parameter);
        offset = next;
    }
    let (result, next) = parse_type(descriptor, offset + 1, true)?;
    if next != descriptor.len() {
        bail!("trailing data in method descriptor: {descriptor}");
    }
    Ok(MethodDescriptor { parameters, result })
}

pub fn parse_field_descriptor(descriptor: &str) -> Result<String> {
    let (field, next) = parse_type(descriptor, 0, false)?;
    if next != descriptor.len() {
        bail!("trailing data in field descriptor: {descriptor}");
    }
    Ok(field)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_method_descriptor() {
        let parsed = parse_method_descriptor("(ILjava/lang/String;[[B)Ljava/util/List;").unwrap();
        assert_eq!(parsed.parameters, ["int", "java.lang.String", "byte[][]"]);
        assert_eq!(parsed.result, "java.util.List");
    }

    #[test]
    fn rejects_truncated_descriptors() {
        assert!(parse_method_descriptor("(Ljava/lang/String;)Ljava/lang/").is_err());
        assert!(parse_field_descriptor("[Lbroken").is_err());
        assert!(parse_method_descriptor("(V)V").is_err());
    }
}
