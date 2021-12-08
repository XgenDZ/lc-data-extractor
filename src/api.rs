use crate::data;
use crate::error::Error;
use crate::Verbose;
use crate::cfg::Config;

const ENTRY_POINT_BASE: &str = "https://127.0.0.1";

macro_rules! log {
    ( $x:expr , $($arg:tt)* ) => {
        if $x != false { print!($($arg)*); }
    }
}

pub struct Context {
    verbose: Verbose,
    config: Config,
    base: &'static str,
    token: String,
    port: u32,
}

impl Context {
    pub fn new(lcu_port: u32, auth_token: String, config: Config) -> Self {
        let verbose = Verbose::default();
        Self {
            verbose, config,
            base: ENTRY_POINT_BASE,
            token: auth_token,
            port: lcu_port,
        }
    }

    pub fn verbose(mut self, verbose: Verbose) -> Self {
        self.verbose = verbose;
        return self;
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum Method { Get, Post, Delete }

#[derive(Copy, Clone, PartialEq, Eq)]
enum Path {
    Simple(&'static str),
    Complex(&'static str),
}

pub struct EndPoint {
    path: self::Path,
    method: self::Method,
    params: &'static [&'static str],
}

impl EndPoint {
    pub fn compute(&self, params: &[String]) -> String {
        use std::str::FromStr;
        match self.path {
            Path::Simple(raw) => raw.to_string(),
            Path::Complex(raw) => {
                assert!(self.params.len() == params.len());
                let mut url = String::from_str(raw).unwrap();
                let mut i: usize = 0;
                while i < self.params.len() {
                    url = url.replace(self.params[i], &params[i]);
                    i += 1;
                }
                url
            }
        }
    }
}

impl Context {
    fn entry_point(&self) -> String {
        format!("{}:{}", self.base, self.port.to_string())
    }

    fn auth_token_base64(&self) -> String {
        let srcstr = format!("riot:{}", self.token);
        base64::encode(srcstr)
    }
}

impl Context {
    pub fn get_friends(&self) -> Result<data::FriendList, Error> {
        let resp_bytes = self.request(&end_points::GET_FRIENDS, &[])?;
        //let s = String::from_utf8(resp_bytes.clone()).unwrap();
        //log!(self.verbose.1, "RAW RESPONSE: {}\n", s);
        return Ok(data::FriendList::fron_json_bytes(resp_bytes)?);
    }

    fn request(&self, ep: &EndPoint, params: &[String])
        -> Result<Vec<u8>, attohttpc::Error>
    {
        log!(self.verbose.0 || self.verbose.1, "\n");
        log!(self.verbose.0, "Performing HTTP/1.1 request...\n");
        let url = format!("{}:{}/{}", self.base, self.port, ep.compute(params));
        log!(self.verbose.1, ".url={}\n", &url);
        log!(self.verbose.1, ".auth={}\n", self.auth_token_base64());

        match self.config.general.http_client.as_str() {
            "attohttpc" => {
                let req = match ep.method {
                    Method::Get => attohttpc::get(url),
                    Method::Post => panic!("not implemented yet"),
                    Method::Delete => panic!("not implemented yet"),
                };
                log!(self.verbose.1, "cert file path: {}\n",
                     self.config.general.cert_file_path);
                let pem = std::fs::read(&self.config.general.cert_file_path)
                    .expect("cannot read TLS certificate");
                let cert = native_tls::Certificate::from_pem(&pem).unwrap();
                let req = req.header("Authorization",
                                     format!("Basic {}", self.auth_token_base64()))
                    .add_root_certificate(cert);
                let resp = req.send()?;
                log!(self.verbose.0, "SUCCESS\n");
                if self.verbose.1 {
                    for h in resp.headers() {
                        log!(self.verbose.1, ".header {}: {}\n",
                             h.0, h.1.to_str().unwrap());
                    }
                }
                log!(self.verbose.1, ".status {}\n", resp.status().as_str());
                return Ok(resp.bytes()?)
            },
            "libcurl" => {
                log!(self.verbose.0, "WARNING: insecure connection (curl)\n");
                match ep.method {
                    Method::Post => panic!("not implemented"),
                    Method::Delete => panic!("not implemented"),
                    Method::Get => {}
                }
                let handler = CurlRespHandler(Vec::new());
                let mut hcurl = curl::easy::Easy2::new(handler);
                let mut headers = curl::easy::List::new();
                let auth_header = format!("Authorization: Basic {}",
                                          self.auth_token_base64());
                headers.append(&auth_header).unwrap();
                hcurl.http_headers(headers).unwrap();
                { hcurl.certinfo(false).unwrap();
                  hcurl.ssl_verify_peer(false).unwrap();
                  hcurl.ssl_verify_host(false).unwrap(); }
                hcurl.url(&url).unwrap();
                hcurl.perform().unwrap(); // TODO: error handling
                log!(self.verbose.1, ".status {}\n", hcurl.response_code().unwrap());
                let resp = hcurl.get_ref();
                return Ok(resp.0.clone());
            },
            _ => panic!("config: unknown http client")
        }
    }
}

mod end_points {
    use super::EndPoint;
    use super::Method;
    use super::Path;

    pub const VOID: EndPoint = EndPoint {
        path: Path::Simple("void"),
        method: Method::Get,
        params: &["param"],
    };

    pub const GET_FRIENDS: EndPoint = EndPoint {
        path: Path::Simple("lol-chat/v1/friends"),
        method: Method::Get,
        params: &[],
    };
}

struct CurlRespHandler ( Vec<u8> );

impl curl::easy::Handler for CurlRespHandler {
    fn write(&mut self, data: &[u8]) -> Result<usize, curl::easy::WriteError> {
        self.0.extend_from_slice(data);
        Ok(data.len())
    }
}
