use serde::Serialize;
use serde::Deserialize;

const CONFIG_FILE_PATH: &str = "%appdata%\\lc-data-extractor\\config.toml";

pub const TARGET_PROCESS: &str = "LeagueClientUx.exe";

pub const MEMORY_PAGE_SIZE: usize = 4096;
pub const USTR_SWAP_BUFFER_SIZE: usize = 255; // in symbols

#[derive(Clone)]
#[derive(Debug)]
#[derive(Serialize, Deserialize)]
pub struct SectionGeneral {
    pub work_folder: String,
    pub game_folder: String,
    pub cert_file_path: String,
    pub http_client: String,
    //pub trg_process: String,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Serialize, Deserialize)]
pub struct SectionWinAPI {
    pub memory_page_size: usize, // in bytes           /* NOT IN USE */
    pub ustr_swap_buffer_size: usize, // in symbols    /* NOT IN USE */
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Serialize, Deserialize)]
pub struct SectionDebug {
    pub rfsuspv: [u32; 5]
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Serialize, Deserialize)]
pub struct Config {
    pub general: SectionGeneral,
    pub winapi: SectionWinAPI,
    pub debug: SectionDebug
}

fn resolve_path(raw: &str) -> String {
    let appdata = std::env::vars().find(|v| { v.0 == "APPDATA" }).unwrap();
    let path = raw.replace("%appdata%", &appdata.1);
    path
}

impl Config {
    pub fn load() -> Option<Self> {
        use std::io::Read;
        let path = resolve_path(CONFIG_FILE_PATH);
        let mut f = match std::fs::File::open(path) {
            Err(e) => return None,
            Ok(v) => v,
        };
        let mut source = String::new();
        f.read_to_string(&mut source).unwrap();
        let toml: Config = toml::from_str(&source).unwrap();
        Some(toml)
    }

    pub fn write(&self) -> () {
        use std::io::Write;
        let path = resolve_path(CONFIG_FILE_PATH);
        let mut f = std::fs::File::create(path).unwrap();
        let toml_str = toml::to_string(&self).unwrap();
        write!(f, "{}", toml_str).unwrap();
    }

    pub fn init(mut self) -> Self {
        self.general.work_folder = resolve_path(&self.general.work_folder);
        self.general.game_folder = resolve_path(&self.general.game_folder);
        self.general.cert_file_path = resolve_path(&self.general.cert_file_path);
        self
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            general: SectionGeneral {
                work_folder: "%appdata%\\lc-data-extractor".to_owned(),
                game_folder: "C:\\Riot Games\\League of Legends".to_owned(),
                cert_file_path: "%appdata%\\lc-data-extractor\\riotgames.pem".to_owned(),
                http_client: "libcurl".to_owned(),
            },
            winapi: SectionWinAPI {
                memory_page_size: MEMORY_PAGE_SIZE,
                ustr_swap_buffer_size: USTR_SWAP_BUFFER_SIZE,
            },
            debug: SectionDebug {
                rfsuspv: [
                    2000, // 0: general
                    10,   // 1: process list iteration delay
                    10,   // 2: region list iteration delay
                    1000, // 3: dumping region: general msg in case of verbose-0
                    0     // 4: dumping region: iteration delay in case of verbose-1
                ],
            }
        }
    }
}
