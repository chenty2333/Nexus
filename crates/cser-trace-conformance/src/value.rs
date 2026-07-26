//! The TLA+ value subset that occurs in the replayed families' traces.
//!
//! The specifications this lane replays assign only integers, booleans,
//! strings, model values, sets, and functions. TLC renders a function in
//! `:>`/`@@` form when its domain is model values and in `[field |-> value]`
//! record form when its domain is strings; both parse to the same
//! [`TlaValue::Function`]. Every other TLA+ constructor is rejected rather
//! than approximated, so a spec change that introduces tuples or nested
//! structures fails this lane loudly instead of being silently misread.

use core::fmt;

/// A parsed TLA+ value from one TLC trace conjunct.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TlaValue {
    /// A TLA+ integer literal, possibly negative (`NoEpoch` is `-1`).
    Int(i64),
    /// `TRUE` or `FALSE`.
    Bool(bool),
    /// A quoted string such as `"Active"`.
    Str(String),
    /// A bare identifier, which in these configurations is a CONSTANT model
    /// value such as `e0`.
    Model(String),
    /// A set literal such as `{}` or `{e0, e1}`. Elements are deduplicated and
    /// ordered, matching TLA+ set equality.
    Set(Vec<TlaValue>),
    /// A function literal such as `(e0 :> 0 @@ e1 :> 1)`, kept sorted by key.
    Function(Vec<(TlaValue, TlaValue)>),
}

impl TlaValue {
    /// Builds a set, normalizing element order and removing duplicates.
    #[must_use]
    pub fn set(mut elements: Vec<Self>) -> Self {
        elements.sort();
        elements.dedup();
        Self::Set(elements)
    }

    /// Builds a function, normalizing key order.
    ///
    /// Duplicate keys are a malformed TLC rendering and are reported by
    /// [`parse`] rather than silently collapsed here.
    #[must_use]
    pub fn function(mut entries: Vec<(Self, Self)>) -> Self {
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        Self::Function(entries)
    }

    /// Returns the value bound to `key` when this value is a function.
    #[must_use]
    pub fn apply(&self, key: &Self) -> Option<&Self> {
        match self {
            Self::Function(entries) => entries
                .iter()
                .find(|(entry_key, _)| entry_key == key)
                .map(|(_, value)| value),
            _ => None,
        }
    }

    /// Returns the domain of a function value in key order.
    #[must_use]
    pub fn domain(&self) -> Option<Vec<&Self>> {
        match self {
            Self::Function(entries) => Some(entries.iter().map(|(key, _)| key).collect()),
            _ => None,
        }
    }

    /// Returns the integer payload of an [`TlaValue::Int`].
    #[must_use]
    pub const fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(value) => Some(*value),
            _ => None,
        }
    }
}

impl fmt::Display for TlaValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Int(value) => write!(formatter, "{value}"),
            Self::Bool(value) => formatter.write_str(if *value { "TRUE" } else { "FALSE" }),
            Self::Str(value) => write!(formatter, "\"{value}\""),
            Self::Model(name) => formatter.write_str(name),
            Self::Set(elements) => {
                formatter.write_str("{")?;
                for (index, element) in elements.iter().enumerate() {
                    if index > 0 {
                        formatter.write_str(", ")?;
                    }
                    write!(formatter, "{element}")?;
                }
                formatter.write_str("}")
            }
            Self::Function(entries) => {
                formatter.write_str("(")?;
                for (index, (key, value)) in entries.iter().enumerate() {
                    if index > 0 {
                        formatter.write_str(" @@ ")?;
                    }
                    write!(formatter, "{key} :> {value}")?;
                }
                formatter.write_str(")")
            }
        }
    }
}

/// Rejected TLA+ value text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValueError {
    /// The input ended while a construct was still open.
    UnexpectedEnd {
        /// What the parser required next.
        expected: &'static str,
    },
    /// A character outside the supported subset was found.
    UnexpectedCharacter {
        /// Byte offset of the character.
        offset: usize,
        /// The character itself.
        found: char,
    },
    /// Text remained after a complete value was parsed.
    TrailingInput {
        /// Byte offset of the first unconsumed character.
        offset: usize,
    },
    /// An integer literal did not fit in `i64`.
    IntegerOverflow {
        /// The rejected literal.
        literal: String,
    },
    /// A function literal bound the same key twice.
    DuplicateKey {
        /// The repeated key, rendered.
        key: String,
    },
    /// A `@@` chain mixed function entries with a non-function operand.
    MalformedFunction,
}

impl fmt::Display for ValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEnd { expected } => {
                write!(formatter, "value text ended while expecting {expected}")
            }
            Self::UnexpectedCharacter { offset, found } => {
                write!(
                    formatter,
                    "unsupported character {found:?} at offset {offset}"
                )
            }
            Self::TrailingInput { offset } => {
                write!(formatter, "unparsed value text at offset {offset}")
            }
            Self::IntegerOverflow { literal } => {
                write!(formatter, "integer literal {literal} does not fit in i64")
            }
            Self::DuplicateKey { key } => write!(formatter, "function binds key {key} twice"),
            Self::MalformedFunction => {
                formatter.write_str("`@@` combined operands that are not all function entries")
            }
        }
    }
}

impl std::error::Error for ValueError {}

/// Parses one complete TLA+ value from `text`.
///
/// # Errors
///
/// Returns [`ValueError`] when `text` is not a value in the supported subset.
pub fn parse(text: &str) -> Result<TlaValue, ValueError> {
    let mut parser = Parser {
        input: text.as_bytes(),
        offset: 0,
    };
    let value = parser.value()?;
    parser.skip_space();
    if parser.offset < parser.input.len() {
        return Err(ValueError::TrailingInput {
            offset: parser.offset,
        });
    }
    Ok(value)
}

struct Parser<'a> {
    input: &'a [u8],
    offset: usize,
}

impl Parser<'_> {
    fn skip_space(&mut self) {
        while self
            .input
            .get(self.offset)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.offset += 1;
        }
    }

    fn eat(&mut self, token: &str) -> bool {
        self.skip_space();
        if self.input[self.offset..].starts_with(token.as_bytes()) {
            self.offset += token.len();
            return true;
        }
        false
    }

    fn peek(&mut self) -> Option<u8> {
        self.skip_space();
        self.input.get(self.offset).copied()
    }

    /// Parses `maplet ("@@" maplet)*`, the only infix level TLC emits here.
    fn value(&mut self) -> Result<TlaValue, ValueError> {
        let first = self.maplet()?;
        if !self.eat("@@") {
            return Ok(match first {
                Maplet::Value(value) => value,
                Maplet::Entry(key, value) => TlaValue::function(vec![(key, value)]),
            });
        }
        let mut entries = vec![first.into_entry()?];
        loop {
            entries.push(self.maplet()?.into_entry()?);
            if !self.eat("@@") {
                break;
            }
        }
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        if let Some(pair) = entries.windows(2).find(|pair| pair[0].0 == pair[1].0) {
            return Err(ValueError::DuplicateKey {
                key: pair[0].0.to_string(),
            });
        }
        Ok(TlaValue::function(entries))
    }

    fn maplet(&mut self) -> Result<Maplet, ValueError> {
        let left = self.atom()?;
        if self.eat(":>") {
            let right = self.atom()?;
            return Ok(Maplet::Entry(left, right));
        }
        Ok(Maplet::Value(left))
    }

    fn atom(&mut self) -> Result<TlaValue, ValueError> {
        let Some(byte) = self.peek() else {
            return Err(ValueError::UnexpectedEnd {
                expected: "a value",
            });
        };
        match byte {
            b'(' => {
                self.offset += 1;
                let inner = self.value()?;
                if !self.eat(")") {
                    return Err(ValueError::UnexpectedEnd {
                        expected: "a closing `)`",
                    });
                }
                Ok(inner)
            }
            b'{' => self.set(),
            b'[' => self.record(),
            b'"' => self.string(),
            b'-' | b'0'..=b'9' => self.integer(),
            b'A'..=b'Z' | b'a'..=b'z' | b'_' => Ok(self.identifier()),
            found => Err(ValueError::UnexpectedCharacter {
                offset: self.offset,
                found: char::from(found),
            }),
        }
    }

    /// Parses `[ field |-> value, ... ]`.
    ///
    /// TLC renders a function whose domain is a set of strings in record
    /// syntax with the field names unquoted. A TLA+ record *is* such a
    /// function, so both become [`TlaValue::Function`] with string keys and
    /// compare equal to the same value written either way.
    fn record(&mut self) -> Result<TlaValue, ValueError> {
        self.offset += 1;
        let mut entries: Vec<(TlaValue, TlaValue)> = Vec::new();
        loop {
            let Some(b'A'..=b'Z' | b'a'..=b'z' | b'_') = self.peek() else {
                return Err(ValueError::UnexpectedEnd {
                    expected: "a record field name",
                });
            };
            let TlaValue::Model(field) = self.identifier() else {
                return Err(ValueError::UnexpectedEnd {
                    expected: "a record field name",
                });
            };
            if !self.eat("|->") {
                return Err(ValueError::UnexpectedEnd {
                    expected: "`|->` after a record field name",
                });
            }
            entries.push((TlaValue::Str(field), self.value()?));
            if self.eat(",") {
                continue;
            }
            if self.eat("]") {
                break;
            }
            return Err(ValueError::UnexpectedEnd {
                expected: "`,` or `]`",
            });
        }
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        if let Some(pair) = entries.windows(2).find(|pair| pair[0].0 == pair[1].0) {
            return Err(ValueError::DuplicateKey {
                key: pair[0].0.to_string(),
            });
        }
        Ok(TlaValue::function(entries))
    }

    fn set(&mut self) -> Result<TlaValue, ValueError> {
        self.offset += 1;
        let mut elements = Vec::new();
        if self.eat("}") {
            return Ok(TlaValue::set(elements));
        }
        loop {
            elements.push(self.value()?);
            if self.eat(",") {
                continue;
            }
            if self.eat("}") {
                break;
            }
            return Err(ValueError::UnexpectedEnd {
                expected: "`,` or `}`",
            });
        }
        Ok(TlaValue::set(elements))
    }

    fn string(&mut self) -> Result<TlaValue, ValueError> {
        self.offset += 1;
        let start = self.offset;
        while let Some(byte) = self.input.get(self.offset) {
            if *byte == b'"' {
                let text = String::from_utf8_lossy(&self.input[start..self.offset]).into_owned();
                self.offset += 1;
                return Ok(TlaValue::Str(text));
            }
            // `Cser.tla` uses only plain alphanumeric state names; a backslash
            // would need TLA+ escape handling this parser does not implement.
            if *byte == b'\\' {
                return Err(ValueError::UnexpectedCharacter {
                    offset: self.offset,
                    found: '\\',
                });
            }
            self.offset += 1;
        }
        Err(ValueError::UnexpectedEnd {
            expected: "a closing quote",
        })
    }

    fn integer(&mut self) -> Result<TlaValue, ValueError> {
        let start = self.offset;
        if self.input[self.offset] == b'-' {
            self.offset += 1;
        }
        while self.input.get(self.offset).is_some_and(u8::is_ascii_digit) {
            self.offset += 1;
        }
        let literal = String::from_utf8_lossy(&self.input[start..self.offset]).into_owned();
        literal
            .parse::<i64>()
            .map(TlaValue::Int)
            .map_err(|_| ValueError::IntegerOverflow { literal })
    }

    fn identifier(&mut self) -> TlaValue {
        let start = self.offset;
        while self
            .input
            .get(self.offset)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            self.offset += 1;
        }
        let name = String::from_utf8_lossy(&self.input[start..self.offset]).into_owned();
        match name.as_str() {
            "TRUE" => TlaValue::Bool(true),
            "FALSE" => TlaValue::Bool(false),
            _ => TlaValue::Model(name),
        }
    }
}

enum Maplet {
    Value(TlaValue),
    Entry(TlaValue, TlaValue),
}

impl Maplet {
    fn into_entry(self) -> Result<(TlaValue, TlaValue), ValueError> {
        match self {
            Self::Entry(key, value) => Ok((key, value)),
            Self::Value(_) => Err(ValueError::MalformedFunction),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{TlaValue, ValueError, parse};

    #[test]
    fn parses_scalars() {
        assert_eq!(parse("0"), Ok(TlaValue::Int(0)));
        assert_eq!(parse("-1"), Ok(TlaValue::Int(-1)));
        assert_eq!(parse("TRUE"), Ok(TlaValue::Bool(true)));
        assert_eq!(parse("FALSE"), Ok(TlaValue::Bool(false)));
        assert_eq!(
            parse("\"Active\""),
            Ok(TlaValue::Str(String::from("Active")))
        );
        assert_eq!(parse("e0"), Ok(TlaValue::Model(String::from("e0"))));
    }

    #[test]
    fn parses_sets_in_canonical_order() {
        assert_eq!(parse("{}"), Ok(TlaValue::Set(Vec::new())));
        assert_eq!(
            parse("{e1, e0, e1}"),
            Ok(TlaValue::set(vec![
                TlaValue::Model(String::from("e0")),
                TlaValue::Model(String::from("e1")),
            ]))
        );
    }

    #[test]
    fn parses_functions_and_applies_them() {
        let value = parse("(e0 :> \"Registered\" @@ e1 :> \"Unregistered\")")
            .expect("function literal parses");
        assert_eq!(
            value.apply(&TlaValue::Model(String::from("e0"))),
            Some(&TlaValue::Str(String::from("Registered")))
        );
        assert_eq!(value.domain().map(|keys| keys.len()), Some(2));
    }

    #[test]
    fn parses_single_entry_function() {
        let value = parse("(e0 :> 0)").expect("single-entry function parses");
        assert_eq!(
            value.apply(&TlaValue::Model(String::from("e0"))),
            Some(&TlaValue::Int(0))
        );
    }

    #[test]
    fn parses_records_as_string_keyed_functions() {
        let record = parse("[Personality |-> \"Bound\", VirtIo |-> \"Closed\"]")
            .expect("record literal parses");
        assert_eq!(
            record.apply(&TlaValue::Str(String::from("Personality"))),
            Some(&TlaValue::Str(String::from("Bound")))
        );
        // A record and the same function written with `:>` are one value.
        let function = parse("(\"Personality\" :> \"Bound\" @@ \"VirtIo\" :> \"Closed\")")
            .expect("function literal parses");
        assert_eq!(record, function);
    }

    #[test]
    fn parses_multiline_records() {
        let record =
            parse("[ PersonalitySyscall |-> \"Registered\", BlockRequest |-> \"Unused\" ]")
                .expect("wide record parses");
        assert_eq!(record.domain().map(|keys| keys.len()), Some(2));
    }

    #[test]
    fn rejects_malformed_records() {
        assert!(matches!(
            parse("[Personality = \"Bound\"]"),
            Err(ValueError::UnexpectedEnd { .. })
        ));
        assert!(matches!(
            parse("[Personality |-> 1, Personality |-> 2]"),
            Err(ValueError::DuplicateKey { .. })
        ));
    }

    #[test]
    fn rejects_unsupported_syntax() {
        assert!(matches!(
            parse("<<1, 2>>"),
            Err(ValueError::UnexpectedCharacter { .. })
        ));
        assert!(matches!(
            parse("e0 :> 1 @@ 2"),
            Err(ValueError::MalformedFunction)
        ));
        assert!(matches!(
            parse("(e0 :> 1 @@ e0 :> 2)"),
            Err(ValueError::DuplicateKey { .. })
        ));
        assert!(matches!(
            parse("0 1"),
            Err(ValueError::TrailingInput { .. })
        ));
    }
}
