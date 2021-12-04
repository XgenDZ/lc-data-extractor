#[derive(Debug)]
pub struct Error {
    pub kind: self::ErrorKind,
}

#[derive(Debug)]
pub enum ErrorKind {
    UnknownCommand(String),
    ExtrUnknownObject(String),
    UnknownOption(String),
    ArgsExpectOption(String),
    ArgsExpectParameter(String),
    SerdeJson(serde_json::Error),
    Httpc(attohttpc::Error),
    JsonValueType(&'static str),
    JsonNotFound(&'static str),
}

impl Error {
    pub fn wrong_value_type(elem: &'static str) -> Self {
        Self {
            kind: ErrorKind::JsonValueType(elem),
        }
    }
    pub fn value_not_found(elem: &'static str) -> Self {
        Self {
            kind: ErrorKind::JsonNotFound(elem),
        }
    }
}

impl std::fmt::Display for self::Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match &self.kind {
            ErrorKind::UnknownCommand(v) =>
                write!(f, "unknown command '{}'", v),
            ErrorKind::ExtrUnknownObject(v) =>
                write!( f, "unknown object '{}'\n\
                    You can use `--objects` option to see all \
                    available names for the extraction presets.", v),
            ErrorKind::UnknownOption(v) =>
                write!(f, "unknown option '{}'", v),
            ErrorKind::ArgsExpectOption(v) =>
                write!(f, "expecting an option, found '{}'", v),
            ErrorKind::ArgsExpectParameter(v) =>
                write!(f, "expecting a parameter, found '{}'", v),
            ErrorKind::SerdeJson(e) =>
                write!(f, "[serde_json] {}", e),
            ErrorKind::Httpc(e) =>
                write!(f, "[http_client] {}", e),
            ErrorKind::JsonNotFound(v) =>
                write!(f, "JSON parsing error: element not found ({})", v),
            ErrorKind::JsonValueType(v) =>
                write!(f, "JSON parsing error: unexpected value type ({})", v),
        }
    }
}

impl std::error::Error for self::Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.kind {
            ErrorKind::SerdeJson(e) => Some(e),
            _ => None,
        }
    }
}

impl std::convert::From<serde_json::Error> for self::Error {
    fn from(src: serde_json::Error) -> Self {
        Self {
            kind: self::ErrorKind::SerdeJson(src),
        }
    }
}

impl std::convert::From<attohttpc::Error> for self::Error {
    fn from(src: attohttpc::Error) -> Self {
        Self {
            kind: self::ErrorKind::Httpc(src),
        }
    }
}
