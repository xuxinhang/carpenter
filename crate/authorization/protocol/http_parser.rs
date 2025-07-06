
#[derive(Debug)]
pub enum ParseError {
    InvalidAuthScheme,
    InvalidToken,
    InvalidToken68,
    InvalidAuthParam,
    InvalidQuotedString,
    UnexpectedEnd,
}


fn is_token_char(c: char) -> bool {
    match c {
        _ if c.is_ascii() => {
            !c.is_ascii_control() &&
                !matches!(c, ' ' | '\t' | '!' | '#' | '$' | '%' | '&' | '\'' | '(' | ')' | '*' | '+' | ',' | '-' | '.' | '/' | ':' | ';' | '<' | '=' | '>' | '?' | '@' | '[' | '\\' | ']' | '^' | '`' | '{' | '|' | '}' | '~')
        },
        _ => false,
    }
}

fn parse_token(input: &str) -> Option<String> {
    let end = input
        .char_indices()
        .position(|(_, c)| !is_token_char(c))
        .map_or(input.len(), |i| i);
    if end == 0 {
        None
    } else {
        Some(input[..end].to_string())
    }
}

fn parse_token68(input: &str) -> Option<String> {
    let mut end = 0;
    for c in input.chars() {
        if matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '-'| '.'| '_'| '~'| '+'| '/') {
            end += c.len_utf8();
        } else {
            break;
        }
    }
    let base_part = &input[..end];
    if base_part.is_empty() {
        return None;
    }
    let mut equal_count = 0;
    let mut i = end;
    while i < input.len() {
        let c = input.chars().nth(i).unwrap();
        if c == '=' {
            equal_count += 1;
            i += c.len_utf8();
            if equal_count > 2 {
                break;
            }
        } else {
            break;
        }
    }
    Some(input[..i].to_string())
}

fn skip_ows(input: &str) -> &str {
    input.trim_start_matches(|c| c == ' ' || c == '\t')
}

fn parse_quoted_string(input: &str) -> Option<(String, &str)> {
    if input.starts_with('"') {
        let mut chars = input.chars();
        chars.next(); // Skip first quote
        let mut result = String::new();
        let mut escaped = false;
        let mut i = 1;
        loop {
            let c = chars.next()?;
            i += c.len_utf8();
            if escaped {
                result.push(c);
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                return Some((result, &input[i..]));
            } else {
                result.push(c);
            }
        }
    } else {
        None
    }
}

fn parse_auth_param(input: &str) -> Option<(String, String, &str)> {
    let name = parse_token(input)?;
    let rest = &input[name.len()..];
    let rest = skip_ows(rest);
    if rest.starts_with('=') {
        let rest = &rest[1..];
        let rest = skip_ows(rest);
        if rest.starts_with('"') {
            if let Some((value, new_rest)) = parse_quoted_string(rest) {
                return Some((name, value, new_rest));
            }
        } else {
            if let Some(value) = parse_token(rest) {
                return Some((name, value.clone(), &rest[value.len()..]));
            }
        }
    }
    None
}

fn parse_auth_params(input: &str) -> Option<Vec<(String, String)>> {
    let mut params = Vec::new();
    let mut rest = input;
    loop {
        if let Some((name, value, new_rest)) = parse_auth_param(rest) {
            params.push((name, value));
            rest = new_rest;
            rest = skip_ows(rest);
            if rest.starts_with(',') {
                rest = &rest[1..];
                rest = skip_ows(rest);
            } else {
                break;
            }
        } else {
            break;
        }
    }
    if params.is_empty() {
        None
    } else {
        Some(params)
    }
}

pub fn parse_credentials(input: &str) -> Result<(String, Option<CredentialsPart>), ParseError> {
    let scheme = parse_token(input).ok_or(ParseError::InvalidAuthScheme)?;
    let rest = &input[scheme.len()..];
    let trimmed_rest = rest.trim_start();
    if rest.len() != trimmed_rest.len() {
        let after_sp = trimmed_rest;
        if let Some(token68) = parse_token68(after_sp) {
            return Ok((scheme, Some(CredentialsPart::Token68(token68))));
        } else {
            let params = parse_auth_params(after_sp).ok_or(ParseError::InvalidAuthParam)?;
            return Ok((scheme, Some(CredentialsPart::Params(params))));
        }
    } else {
        Ok((scheme, None))
    }
}


pub enum CredentialsPart {
    Token68(String),
    Params(Vec<(String, String)>),
}


