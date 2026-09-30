use std::{
    borrow::Cow,
    iter::Peekable,
    mem::take,
    path::{Path, PathBuf},
    str::CharIndices,
};

use thiserror::Error;

const UUID_FIXTURE: &str = "00000000-0000-4000-8000-000000000001";

#[derive(Debug, PartialEq)]
enum Lang {
    Shell,
    Json,
    Yaml,
    Mermaid,
    Plain,
    Unknown(String),
}

impl Lang {
    fn parse(info: &str) -> Self {
        match info {
            "sh" | "bash" => Self::Shell,
            "json" => Self::Json,
            "yaml" | "yml" => Self::Yaml,
            "mermaid" => Self::Mermaid,
            "" => Self::Plain,
            other => Self::Unknown(other.to_owned()),
        }
    }
}

struct Fence {
    lang: Lang,
    body: String,
    start_line: usize,
    comments: Vec<String>,
}

struct InlineSpan {
    line: usize,
    text: String,
}

struct Document {
    fences: Vec<Fence>,
    spans: Vec<InlineSpan>,
}

fn document(markdown: &str) -> Document {
    let mut fences = Vec::new();
    let mut spans = Vec::new();
    let mut open: Option<(usize, Fence)> = None;
    let mut comments = Vec::new();
    for (index, line) in markdown.lines().enumerate() {
        let indent = line.len() - line.trim_start().len();
        let trimmed = line.trim();
        match &mut open {
            Some((_, fence)) if trimmed == "```" => {
                fence.body.pop();
                fences.extend(open.take().map(|(_, fence)| fence));
            }
            Some((open_indent, fence)) => {
                let strip = (*open_indent).min(indent);
                fence.body.push_str(&line[strip..]);
                fence.body.push('\n');
            }
            None => {
                if let Some(info) = trimmed.strip_prefix("```") {
                    open = Some((
                        indent,
                        Fence {
                            lang: Lang::parse(info.trim()),
                            body: String::new(),
                            start_line: index + 2,
                            comments: take(&mut comments),
                        },
                    ));
                    continue;
                }
                if trimmed.starts_with("<!--") && trimmed.ends_with("-->") {
                    comments.push(
                        trimmed
                            .trim_start_matches("<!--")
                            .trim_end_matches("-->")
                            .trim()
                            .to_owned(),
                    );
                } else {
                    comments.clear();
                }
                let mut rest = line;
                while let Some(start) = rest.find('`') {
                    let after = &rest[start + 1..];
                    let Some(end) = after.find('`') else { break };
                    let span = &after[..end];
                    if span.starts_with("tk ") && span.contains(" --") {
                        spans.push(InlineSpan {
                            line: index + 1,
                            text: span.to_owned(),
                        });
                    }
                    rest = &after[end + 1..];
                }
            }
        }
    }
    Document { fences, spans }
}

#[derive(Debug, Error)]
#[error("{}:{line}: {message}", path.display())]
struct Unsupported {
    path: PathBuf,
    line: usize,
    message: String,
}

enum Part {
    Bare(String),
    Quoted(String),
    Var(String),
    Subst(String),
}

enum Token {
    Word(Vec<Part>),
    Separator,
    Redirect,
    Heredoc { strip_tabs: bool },
}

enum Word<'a> {
    Literal,
    Fixture(Cow<'a, str>),
    Unknown,
}

fn classify<'a>(name: &str, public_key: &'a str) -> Word<'a> {
    let placeholder = name == "02…"
        || (name.len() > 1
            && name
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
            && name.starts_with(|c: char| c.is_ascii_uppercase()));
    if !placeholder {
        return Word::Literal;
    }
    let value = match name {
        "02…" | "PK" | "PUBLIC_KEY" => Cow::Borrowed(public_key),
        "BODY" => Cow::Owned(format!(r#"{{"organizationId": "{UUID_FIXTURE}"}}"#)),
        "API_TOKEN" | "NEW_API_TOKEN" | "TOKEN" => Cow::Borrowed("fixture-value"),
        _ if name.starts_with("ACTIVITY_TYPE_") => return Word::Unknown,
        _ if name.ends_with("_PUBLIC_KEY") => Cow::Borrowed(public_key),
        _ if name.ends_with("DIR") => Cow::Borrowed("fixture-dir"),
        _ if name.ends_with("_ID") || name.ends_with("_UUID") || name.ends_with("_TAG") => {
            Cow::Borrowed(UUID_FIXTURE)
        }
        _ if name.contains("SSH") && name.ends_with("FINGERPRINT") => {
            Cow::Borrowed("SHA256:fixture")
        }
        _ if name.ends_with("FINGERPRINT") => {
            Cow::Borrowed("0123456789ABCDEF0123456789ABCDEF01234567")
        }
        _ => return Word::Unknown,
    };
    Word::Fixture(value)
}

#[derive(Debug, Error)]
enum TokenizeError {
    #[error("unterminated single quote")]
    UnterminatedSingleQuote,
    #[error("unterminated double quote")]
    UnterminatedDoubleQuote,
    #[error("trailing backslash")]
    TrailingBackslash,
    #[error("{0}")]
    Other(String),
}

impl From<String> for TokenizeError {
    fn from(message: String) -> Self {
        Self::Other(message)
    }
}

struct Tokenizer<'a> {
    source: &'a str,
    chars: Peekable<CharIndices<'a>>,
}

impl<'a> Tokenizer<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source,
            chars: source.char_indices().peekable(),
        }
    }

    fn take_until_balanced(&mut self) -> Result<String, TokenizeError> {
        let mut depth = 1usize;
        let mut inner = String::new();
        let mut quote: Option<char> = None;
        while let Some((_, c)) = self.chars.next() {
            match (quote, c) {
                (None | Some('"'), '\\') => match self.chars.next() {
                    Some((_, escaped)) => {
                        inner.push(c);
                        inner.push(escaped);
                    }
                    None => return Err(TokenizeError::TrailingBackslash),
                },
                (Some(q), c) if c == q => {
                    quote = None;
                    inner.push(c);
                }
                (Some(_), c) => inner.push(c),
                (None, '\'' | '"') => {
                    quote = Some(c);
                    inner.push(c);
                }
                (None, '(') => {
                    depth += 1;
                    inner.push(c);
                }
                (None, ')') => {
                    depth -= 1;
                    if depth == 0 {
                        return Ok(inner);
                    }
                    inner.push(c);
                }
                (None, c) => inner.push(c),
            }
        }
        Err("unterminated $( substitution".to_owned().into())
    }

    fn dollar(&mut self) -> Result<Part, TokenizeError> {
        if self.chars.peek().is_some_and(|(_, c)| *c == '(') {
            self.chars.next();
            return Ok(Part::Subst(self.take_until_balanced()?));
        }
        let mut name = String::new();
        while let Some((_, c)) = self
            .chars
            .next_if(|(_, c)| c.is_ascii_alphanumeric() || *c == '_')
        {
            name.push(c);
        }
        if name.is_empty() {
            return Err("bare $ is not a supported construct".to_owned().into());
        }
        Ok(Part::Var(name))
    }

    fn tokens(mut self) -> Result<Vec<Token>, TokenizeError> {
        let mut tokens = Vec::new();
        let mut parts: Vec<Part> = Vec::new();
        let mut literal = String::new();
        let mut angle: Option<usize> = None;
        let flush_literal = |parts: &mut Vec<Part>, literal: &mut String| {
            if !literal.is_empty() {
                parts.push(Part::Bare(take(literal)));
            }
        };
        let flush_word = |tokens: &mut Vec<Token>, parts: &mut Vec<Part>, literal: &mut String| {
            flush_literal(parts, literal);
            if !parts.is_empty() {
                tokens.push(Token::Word(take(parts)));
            }
        };
        while let Some((index, c)) = self.chars.next() {
            match c {
                ' ' | '\t' => flush_word(&mut tokens, &mut parts, &mut literal),
                '#' if parts.is_empty() && literal.is_empty() => break,
                '\'' => {
                    flush_literal(&mut parts, &mut literal);
                    let mut text = String::new();
                    loop {
                        match self.chars.next() {
                            Some((_, '\'')) => break,
                            Some((_, c)) => text.push(c),
                            None => return Err(TokenizeError::UnterminatedSingleQuote),
                        }
                    }
                    parts.push(Part::Quoted(text));
                }
                '"' => {
                    flush_literal(&mut parts, &mut literal);
                    let mut text = String::new();
                    loop {
                        match self.chars.next() {
                            Some((_, '"')) => break,
                            Some((_, '\\')) => match self.chars.next() {
                                Some((_, c @ ('"' | '\\' | '$' | '`'))) => text.push(c),
                                Some((_, '\n')) => {}
                                Some((_, c)) => {
                                    text.push('\\');
                                    text.push(c);
                                }
                                None => return Err(TokenizeError::UnterminatedDoubleQuote),
                            },
                            Some((_, '$')) => {
                                if !text.is_empty() {
                                    parts.push(Part::Quoted(take(&mut text)));
                                }
                                parts.push(self.dollar()?);
                            }
                            Some((index, '`')) => {
                                return Err(format!(
                                    "backtick substitution at column {index} is not supported; use $(...)"
                                )
                                .into());
                            }
                            Some((_, c)) => text.push(c),
                            None => return Err(TokenizeError::UnterminatedDoubleQuote),
                        }
                    }
                    parts.push(Part::Quoted(text));
                }
                '\\' => match self.chars.next() {
                    Some((_, c)) => literal.push(c),
                    None => return Err(TokenizeError::TrailingBackslash),
                },
                '$' => {
                    flush_literal(&mut parts, &mut literal);
                    parts.push(self.dollar()?);
                }
                '|' | ';' | '&' => {
                    flush_word(&mut tokens, &mut parts, &mut literal);
                    if self.chars.peek().is_some_and(|(_, n)| *n == c) {
                        self.chars.next();
                    }
                    angle = None;
                    tokens.push(Token::Separator);
                }
                '>' | '<' => {
                    if let Some(start) = angle.take()
                        && c == '>'
                        && !literal.is_empty()
                        && !literal.chars().all(|c| c.is_ascii_digit())
                    {
                        let text = &self.source[start..index];
                        return Err(
                            format!("angle-bracket placeholder <{text}> is not supported").into(),
                        );
                    }
                    if literal.chars().all(|c| c.is_ascii_digit()) && parts.is_empty() {
                        literal.clear();
                    }
                    flush_word(&mut tokens, &mut parts, &mut literal);
                    if c == '<' && self.chars.next_if(|(_, n)| *n == '<').is_some() {
                        if self.chars.next_if(|(_, n)| *n == '<').is_some() {
                            return Err("here-string <<< is not supported".to_owned().into());
                        }
                        let strip_tabs = self.chars.next_if(|(_, n)| *n == '-').is_some();
                        tokens.push(Token::Heredoc { strip_tabs });
                        continue;
                    }
                    let mut ampersand = false;
                    while let Some((_, n)) = self
                        .chars
                        .next_if(|(_, n)| matches!(n, '>' | '<' | '&' | '|'))
                    {
                        ampersand |= n == '&';
                    }
                    if self.chars.next_if(|(_, n)| *n == '(').is_some() {
                        return Err("process substitution is not supported".to_owned().into());
                    }
                    if ampersand && self.chars.next_if(|(_, n)| n.is_ascii_digit()).is_some() {
                        while self.chars.next_if(|(_, n)| n.is_ascii_digit()).is_some() {}
                    } else {
                        tokens.push(Token::Redirect);
                        angle = (c == '<').then_some(index + 1);
                    }
                }
                '`' => {
                    return Err(format!(
                        "backtick substitution at column {index} is not supported; use $(...)"
                    )
                    .into());
                }
                '(' | ')' | '{' | '}' => {
                    return Err(format!("bare `{c}` at column {index} is not supported").into());
                }
                _ => literal.push(c),
            }
        }
        flush_word(&mut tokens, &mut parts, &mut literal);
        Ok(tokens)
    }
}

#[derive(Debug)]
struct Script {
    invocations: Vec<Vec<String>>,
    literals: Vec<String>,
}

struct LogicalLine {
    offset: usize,
    tokens: Vec<Token>,
    heredocs: Vec<String>,
}

fn logical_lines(body: &str) -> Result<Vec<LogicalLine>, (usize, String)> {
    let lines: Vec<&str> = body.lines().collect();
    let mut result = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let start = index;
        let mut logical = String::new();
        let tokens = loop {
            let line = lines[index];
            index += 1;
            logical.push_str(line);
            let more = index < lines.len();
            match Tokenizer::new(&logical).tokens() {
                Err(TokenizeError::TrailingBackslash) if more => {
                    if lines[index].trim_start().starts_with('#') {
                        return Err((start, "line continuation followed by a comment".to_owned()));
                    }
                    logical.pop();
                }
                Err(
                    TokenizeError::UnterminatedSingleQuote | TokenizeError::UnterminatedDoubleQuote,
                ) if more => {
                    logical.push('\n');
                }
                Ok(_) if more && line.ends_with('\\') => {
                    return Err((start, "line continuation inside a comment".to_owned()));
                }
                Err(error) => return Err((start, error.to_string())),
                Ok(tokens) => break tokens,
            }
        };
        let mut heredocs = Vec::new();
        for (position, token) in tokens.iter().enumerate() {
            let Token::Heredoc { strip_tabs } = token else {
                continue;
            };
            let Some(Token::Word(parts)) = tokens.get(position + 1) else {
                return Err((start, "heredoc has no terminator".to_owned()));
            };
            let terminator: String = parts
                .iter()
                .filter_map(|part| match part {
                    Part::Bare(text) | Part::Quoted(text) => Some(text.as_str()),
                    Part::Var(_) | Part::Subst(_) => None,
                })
                .collect();
            let mut heredoc = Vec::new();
            loop {
                let Some(line) = lines.get(index) else {
                    return Err((start, format!("heredoc terminator {terminator} not found")));
                };
                index += 1;
                let candidate = if *strip_tabs {
                    line.trim_start_matches('\t')
                } else {
                    line
                };
                if candidate == terminator {
                    break;
                }
                heredoc.push(*line);
            }
            heredocs.push(heredoc.join("\n"));
        }
        result.push(LogicalLine {
            offset: start,
            tokens,
            heredocs,
        });
    }
    Ok(result)
}

fn commands(tokens: Vec<Token>) -> Vec<Vec<Vec<Part>>> {
    let mut commands = Vec::new();
    let mut current = Vec::new();
    let mut skip_next = false;
    for token in tokens {
        match token {
            Token::Separator => {
                skip_next = false;
                if !current.is_empty() {
                    commands.push(take(&mut current));
                }
            }
            Token::Redirect | Token::Heredoc { .. } => skip_next = true,
            Token::Word(_) if skip_next => skip_next = false,
            Token::Word(parts) => current.push(parts),
        }
    }
    if !current.is_empty() {
        commands.push(current);
    }
    commands
}

fn is_assignment(parts: &[Part]) -> bool {
    match parts.first() {
        Some(Part::Bare(text)) => text
            .split_once('=')
            .is_some_and(|(name, _)| !name.is_empty() && !name.contains('-')),
        _ => false,
    }
}

fn substitute(parts: &[Part], public_key: &str) -> Result<String, String> {
    let mut out = String::new();
    for part in parts {
        match part {
            Part::Bare(text) => {
                let (prefix, name) = match text.split_once('=') {
                    Some((flag, value)) if text.starts_with('-') => (&text[..=flag.len()], value),
                    _ => ("", text.as_str()),
                };
                match classify(name, public_key) {
                    Word::Literal => out.push_str(text),
                    Word::Fixture(value) => {
                        out.push_str(prefix);
                        out.push_str(&value);
                    }
                    Word::Unknown => return Err(format!("unknown placeholder {name}")),
                }
            }
            Part::Quoted(text) => out.push_str(text),
            Part::Var(name) => match classify(name, public_key) {
                Word::Fixture(value) => out.push_str(&value),
                Word::Literal | Word::Unknown => {
                    return Err(format!("unknown shell variable ${name}"));
                }
            },
            Part::Subst(_) => out.push_str("substituted"),
        }
    }
    Ok(out)
}

fn collect(
    tokens: Vec<Token>,
    public_key: &str,
    invocations: &mut Vec<Vec<String>>,
    literals: &mut Vec<String>,
) -> Result<(), String> {
    for command in commands(tokens) {
        let argv = {
            let mut words = command.iter().skip_while(|parts| {
                is_assignment(parts)
                    || matches!(
                        parts.as_slice(),
                        [Part::Bare(word)]
                            if matches!(
                                word.as_str(),
                                "if" | "then" | "else" | "elif" | "while" | "until" | "do" | "!"
                                    | "time" | "exec" | "nohup" | "sudo" | "env"
                            )
                    )
            });
            match words.next() {
                Some(first) if matches!(first.as_slice(), [Part::Bare(head)] if head == "tk") => {
                    let mut argv = vec!["tk".to_owned()];
                    for parts in words {
                        argv.push(substitute(parts, public_key)?);
                    }
                    Some(argv)
                }
                _ => None,
            }
        };
        for part in command.into_iter().flatten() {
            match part {
                Part::Subst(inner) => collect(
                    Tokenizer::new(&inner)
                        .tokens()
                        .map_err(|error| error.to_string())?,
                    public_key,
                    invocations,
                    literals,
                )?,
                Part::Quoted(text) if text.trim_start().starts_with(['{', '[']) => {
                    literals.push(text);
                }
                Part::Bare(_) | Part::Quoted(_) | Part::Var(_) => {}
            }
        }
        invocations.extend(argv);
    }
    Ok(())
}

fn script(
    path: &Path,
    start_line: usize,
    body: &str,
    public_key: &str,
) -> Result<Script, Unsupported> {
    let unsupported = |(offset, message): (usize, String)| Unsupported {
        path: path.to_path_buf(),
        line: start_line + offset,
        message,
    };
    let mut invocations = Vec::new();
    let mut literals = Vec::new();
    for LogicalLine {
        offset,
        tokens,
        heredocs,
    } in logical_lines(body).map_err(unsupported)?
    {
        literals.extend(
            heredocs
                .into_iter()
                .filter(|text| text.trim_start().starts_with(['{', '['])),
        );
        collect(tokens, public_key, &mut invocations, &mut literals)
            .map_err(|message| unsupported((offset, message)))?;
    }
    Ok(Script {
        invocations,
        literals,
    })
}

mod tests;
