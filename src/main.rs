mod api;
mod auth_hack;
mod data;
mod error;

const _APP_NAME: &str = "lc-data-extractor";
const _APP_VERSION: &str = "0.2.7";

fn main() {
    let launch_params = match parse_arguments(std::env::args()) {
        Err(err) => {
            println!("error: {}", err);
            return;
        }
        Ok(v) => v,
    };
    let verbose: Verbose; {
        let s = launch_params.contains(CmdOption::Silent);
        let v = launch_params.contains(CmdOption::Verbose);
        verbose = Verbose::default().set_general(!s)
                                    .set_debug1(!s & v);
    }
    if verbose.0 | verbose.1 {
        println!(
            "Action: {}",
            match &launch_params.act {
                Some(action) => match action {
                    Action::Extract(v) => format!("extract, object={}", v),
                    Action::DumpMemory => "memdump".to_owned(),
                },
                None => format!("none"),
            }
        );
    }
    if let Some(ref action) = launch_params.act {
        match action {
            Action::Extract(_) => {
                let extracted_data = auth_hack::get_auth_data(verbose);
                let mut port: Option<u32> = None;
                let mut token: Option<String> = None;
                for opt in &launch_params.ops {
                    if let CmdOption::Port(v) = opt {
                        port = Some(*v);
                    }
                    if let CmdOption::Token(v) = opt {
                        token = Some(v.clone());
                    }
                }
                let api = api::Context::new(
                    match port {
                        Some(_port) => _port,
                        None => extracted_data.0,
                    },
                    match token {
                        Some(_token) => _token,
                        None => extracted_data.1,
                    },
                ).verbose(verbose);
                let friend_list = match api.get_friends() {
                    Err(err) => {
                        println!("error: {}", err);
                        return;
                    }
                    Ok(v) => v,
                };
                let mut find_friend: Option<String> = None;
                for opt in &launch_params.ops {
                    if let CmdOption::Find(v) = opt {
                        find_friend = Some(v.to_owned());
                        break;
                    }
                }
                println!();
                if let Some(pattern) = find_friend {
                    let mut found = false;
                    for friend in friend_list.0 {
                        if friend.name == pattern {
                            println!("{}", friend);
                            found = true;
                            break;
                        }
                    }
                    if !found {
                        println!("Cannot find a friend with name '{}'.\n", pattern);
                    }
                } else {
                    println!("{}", friend_list);
                }
            }
            Action::DumpMemory => {
                let t = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH).unwrap();
                let file_name = format!("memdump_{}.bin", t.as_secs());
                let appdata = std::env::vars().find(|v| { v.0 == "APPDATA" });
                let filepath = format!("{}\\lc-data-extractor\\{}",
                                       appdata.unwrap().1, file_name);
                unsafe {
                    let target = auth_hack::TARGET_PROCESS;
                    let handle = auth_hack::__find_process(verbose, target);
                    let memory = auth_hack::__get_proc_memory_regions(verbose, handle);
                    let fn_dump_all = || {
                        let mut file = std::fs::File::create(&filepath).unwrap();
                        let meminfo = auth_hack::__get_memory_defaults(verbose);
                        let mut fsz = 0;
                        for mbi in &memory {
                            fsz += auth_hack::__dump_memory_region(
                                verbose, handle, &mut file, meminfo, mbi);
                        }
                        println!("The process memory was successfully dumped.");
                        println!("  dump file: {}", &filepath);
                        println!("  bytes written: {}", fsz);
                    };
                    let fn_dump_specified = || {
                        let mut file = std::fs::File::create(&filepath).unwrap();
                        let meminfo = auth_hack::__get_memory_defaults(verbose);
                        for arg in &launch_params.prs {
                            let addr = usize::from_str_radix(arg, 16)
                                .expect("hex number parse error");
                            for mbi in &memory {
                                if mbi.BaseAddress as usize == addr {
                                    let fsz = auth_hack::__dump_memory_region(
                                        verbose, handle, &mut file, meminfo, mbi);
                                    println!("The process memory was successfully dumped.");
                                    println!("  dump file: {}", &filepath);
                                    println!("  bytes written: {}", fsz);
                                    return;
                                }
                            }
                            println!("(!) Can't find memory region {:#016X}", addr);
                        }
                    };
                    if launch_params.contains(CmdOption::All) {
                        fn_dump_all();
                    } else if launch_params.prs.len() > 0 {
                        fn_dump_specified();
                    }
                }
            }
        }
    } else {
        for opt in launch_params.ops {
            match opt {
                CmdOption::Version => {
                    println!("v{}", _APP_VERSION);
                    return;
                },
                _ => { }
            }
        }
    }
    println!("EXIT_OK");
}

// -----------------------------------------------------------------------------

#[derive(Copy, Clone)]
pub struct Verbose(bool, bool);

impl Default for Verbose {
    fn default() -> Verbose { Verbose(true, false) }
}

impl Verbose {
    pub fn set_general(mut self, v: bool) -> Self { self.0 = v; self }
    pub fn set_debug1(mut self, v: bool) -> Self { self.1 = v; self }
    pub fn general(&self) -> bool { self.0 }
    pub fn debug1(&self) -> bool { self.1 }
}

enum Action {
    Extract(&'static str),
    DumpMemory,
}

#[derive(PartialEq)]
enum CmdOption {
    _Nop,
    Help,
    Version,
    Silent,
    Verbose,
    Find(String),
    Port(u32),
    Token(String),
    Objects,
    All,
}

struct LaunchParams {
    act: Option<Action>,
    ops: Vec<CmdOption>,
    prs: Vec<String>,
}

impl LaunchParams {
    // TODO: variants with value cause problems
    pub fn contains(&self, opt: CmdOption) -> bool {
        for _opt in &self.ops {
            if *_opt == opt { return true; }
        } return false;
    }
}

use crate::error::Error;
use crate::error::ErrorKind;
fn parse_arguments(args: std::env::Args) -> Result<LaunchParams, Error> {
    let args: Vec<String> = args.collect::<Vec<String>>();
    let mut act: Option<Action> = None;
    let mut ops = Vec::<CmdOption>::new();
    let mut prs = Vec::<String>::new();
    let max = args.len();
    if max == 1 {
        return Ok(LaunchParams { act, ops, prs });
    }
    let mut i: usize = 1;
    if args[i].starts_with('-') == false {
        if args[i].starts_with('!') == true {
            match args[i].as_ref() {
                "!extract" => {
                    i += 1;
                    match args[i].as_ref() {
                        "chat.friends" => {
                            act = Some(Action::Extract("chat.friends"));
                        }
                        _ => {
                            return Err(Error {
                                kind: ErrorKind::ExtrUnknownObject(args[i].to_owned()),
                            })
                        }
                    }
                }
                "!memdump" => {
                    act = Some(Action::DumpMemory);
                }
                _ => {
                    return Err(Error {
                        kind: ErrorKind::UnknownCommand(args[i].to_owned()),
                    })
                }
            }
            i += 1;
        } else {
            // the default command is Action::Extract
            // reading command agrument (object)
            // TODO: move to func (duplicates)
            match args[i].as_ref() {
                "chat.friends" => {
                    act = Some(Action::Extract("chat.friends"));
                }
                _ => {
                    return Err(Error {
                        kind: ErrorKind::ExtrUnknownObject(args[i].to_owned()),
                    })
                }
            }
            i += 1;
        }
    }
    while i < max {
        if args[i].starts_with('-') == true {
            ops.push(parse_option(&args, &mut i)?);
        } else {
            prs.push(args[i].to_owned());
        }
        i += 1;
    }
    Ok(LaunchParams { act, ops, prs })
}

fn parse_option(args: &Vec<String>, i: &mut usize) -> Result<CmdOption, Error> {
    match args[*i].as_ref() {
        "--help" => Ok(CmdOption::Help),
        "--objects" => { panic!("not implemented yet") },
        "--silent" => Ok(CmdOption::Silent),
        "--verbose" => Ok(CmdOption::Verbose),
        "--version" => Ok(CmdOption::Version),
        "--find" => {
            *i = *i + 1;
            let arg = &args[*i];
            if args[*i].starts_with('-') {
                Err(Error {
                    kind: ErrorKind::ArgsExpectParameter(arg.to_owned()),
                })
            } else {
                Ok(CmdOption::Find(arg.to_owned()))
            }
        }
        "--port" => {
            *i = *i + 1;
            if args[*i].starts_with('-') {
                Err(Error {
                    kind: ErrorKind::ArgsExpectParameter(args[*i].to_owned()),
                })
            } else {
                let v = args[*i].parse::<u32>()
                    .expect("port value parse error"); // TODO
                Ok(CmdOption::Port(v))
            }
        }
        "--token" => {
            *i = *i + 1;
            if args[*i].starts_with('-') {
                Err(Error {
                    kind: ErrorKind::ArgsExpectParameter(args[*i].to_owned()),
                })
            } else {
                Ok(CmdOption::Token(args[*i].to_owned()))
            }
        }
        "--all" => Ok(CmdOption::All),
        "--nop" => Ok(CmdOption::_Nop),
        &_ => Err(Error {
            kind: ErrorKind::UnknownOption(args[*i].to_owned()),
        }),
    }
}
