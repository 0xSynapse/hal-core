use hal_bridge::{
    pair_from_bundle, run_self_test, update_paired_token, BridgeConfig, BridgeSession,
    McpBridgeServer, TriNodeDemoCluster, TriNodeDemoConfig,
};
use serde_json::Value;
use std::io::{self, BufReader};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

fn print_usage() {
    println!(
        "Usage:\n  hal-bridge pair --bundle <path> --out-dir <dir> [--gateway-addr <ip:port>] [--episode <id>] [--json]\n  hal-bridge pair --token <path> --out-dir <dir> [--agent-id <id>] [--json]\n  hal-bridge --config <path> --check\n  hal-bridge --config <path> ping\n  hal-bridge --config <path> propose --target <path> --action <op> --reason <text> [--args <json>] [--episode <id>]\n  hal-bridge --config <path> mcp\n  hal-bridge demo [--oob-bind <addr>] [--gateway-bind <addr>] [--state-dir <dir>] [--token <secret>] [--seed-l2] [--self-test] [--duration-ms <ms>]"
    );
}

fn take_opt(args: &[String], i: &mut usize) -> Result<String, String> {
    if *i + 1 >= args.len() {
        return Err(format!("missing value after '{}'", args[*i]));
    }
    let val = args[*i + 1].clone();
    *i += 2;
    Ok(val)
}

fn load_cfg_or_err(cfg_path: Option<PathBuf>) -> Result<BridgeConfig, i32> {
    let Some(path) = cfg_path else {
        eprintln!("hal-bridge requires --config <path>");
        return Err(2);
    };
    BridgeConfig::from_file(&path).map_err(|err| {
        eprintln!("hal-bridge config error ({}): {err}", path.display());
        1
    })
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() <= 1 || matches!(args[1].as_str(), "--help" | "-h" | "help") {
        print_usage();
        return ExitCode::SUCCESS;
    }

    if args[1] == "demo" {
        return run_demo_cli(&args[2..]);
    }
    if args[1] == "pair" {
        return run_pair_cli(&args[2..]);
    }

    let mut cfg_path: Option<PathBuf> = None;
    let mut check_only = false;
    let mut subcmd: Option<String> = None;
    let mut target_path: Option<String> = None;
    let mut action: Option<String> = None;
    let mut reason: Option<String> = None;
    let mut prop_args_raw: Option<String> = None;
    let mut episode_id: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => match take_opt(&args, &mut i) {
                Ok(v) => cfg_path = Some(PathBuf::from(v)),
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            },
            "--check" => {
                check_only = true;
                i += 1;
            }
            "--target" => match take_opt(&args, &mut i) {
                Ok(v) => target_path = Some(v),
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            },
            "--action" => match take_opt(&args, &mut i) {
                Ok(v) => action = Some(v),
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            },
            "--reason" => match take_opt(&args, &mut i) {
                Ok(v) => reason = Some(v),
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            },
            "--args" => match take_opt(&args, &mut i) {
                Ok(v) => prop_args_raw = Some(v),
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            },
            "--episode" => match take_opt(&args, &mut i) {
                Ok(v) => episode_id = Some(v),
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            },
            "--help" | "-h" => {
                print_usage();
                return ExitCode::SUCCESS;
            }
            cmd if !cmd.starts_with('-') && subcmd.is_none() => {
                subcmd = Some(cmd.to_string());
                i += 1;
            }
            other => {
                eprintln!("Unknown argument: {other}");
                return ExitCode::from(2);
            }
        }
    }

    let cfg = match load_cfg_or_err(cfg_path) {
        Ok(c) => c,
        Err(code) => return ExitCode::from(code as u8),
    };

    if check_only && subcmd.is_none() {
        println!(
            "HAL_BRIDGE_READY agent={} gateway={}",
            cfg.agent_id, cfg.gateway_addr
        );
        return ExitCode::SUCCESS;
    }

    let mut session = match BridgeSession::connect(cfg) {
        Ok(s) => s,
        Err(err) => {
            eprintln!("hal-bridge connect failed: {err}");
            return ExitCode::from(1);
        }
    };

    match subcmd.as_deref() {
        Some("ping") => match session.ping() {
            Ok(resp) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".to_string())
                );
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("hal-bridge ping failed: {err}");
                ExitCode::from(1)
            }
        },
        Some("propose") => {
            let (Some(tgt), Some(act), Some(rsn)) = (target_path, action, reason) else {
                eprintln!("propose requires --target <path> --action <op> --reason <text>");
                return ExitCode::from(2);
            };
            let args_json: Value = match prop_args_raw {
                Some(raw) => match serde_json::from_str(&raw) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("invalid --args JSON: {e}");
                        return ExitCode::from(2);
                    }
                },
                None => Value::Object(Default::default()),
            };
            match session.submit_proposal(
                episode_id.as_deref(),
                &tgt,
                &act,
                args_json,
                &rsn,
                Vec::new(),
            ) {
                Ok(resp) => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".to_string())
                    );
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("hal-bridge propose failed: {err}");
                    ExitCode::from(1)
                }
            }
        }
        Some("mcp") => {
            let mut server = McpBridgeServer::new(session);
            let stdin = io::stdin();
            let stdout = io::stdout();
            if let Err(err) = server.run_stdio(BufReader::new(stdin.lock()), stdout.lock()) {
                eprintln!("hal-bridge mcp I/O error: {err}");
                return ExitCode::from(1);
            }
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("Unknown subcommand '{other}'");
            ExitCode::from(2)
        }
        None => {
            println!(
                "HAL_BRIDGE_CONNECTED agent={} session={}",
                session.principal().agent_id,
                session.session_id()
            );
            ExitCode::SUCCESS
        }
    }
}

fn run_demo_cli(args: &[String]) -> ExitCode {
    let mut state_dir = PathBuf::from("/tmp/hal-trinode-demo");
    let mut oob_bind: SocketAddr = "127.0.0.1:8443".parse().expect("valid loopback addr");
    let mut gateway_bind: SocketAddr = "127.0.0.1:9443".parse().expect("valid loopback addr");
    let mut token: Option<String> = None;
    let mut seed_l2 = false;
    let mut self_test = false;
    let mut duration_ms: Option<u64> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--state-dir" => match take_opt(args, &mut i) {
                Ok(v) => state_dir = PathBuf::from(v),
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            },
            "--oob-bind" => match take_opt(args, &mut i) {
                Ok(v) => match v.parse() {
                    Ok(a) => oob_bind = a,
                    Err(e) => {
                        eprintln!("invalid --oob-bind '{v}': {e}");
                        return ExitCode::from(2);
                    }
                },
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            },
            "--gateway-bind" => match take_opt(args, &mut i) {
                Ok(v) => match v.parse() {
                    Ok(a) => gateway_bind = a,
                    Err(e) => {
                        eprintln!("invalid --gateway-bind '{v}': {e}");
                        return ExitCode::from(2);
                    }
                },
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            },
            "--token" => match take_opt(args, &mut i) {
                Ok(v) => token = Some(v),
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            },
            "--duration-ms" => match take_opt(args, &mut i) {
                Ok(v) => match v.parse() {
                    Ok(ms) => duration_ms = Some(ms),
                    Err(e) => {
                        eprintln!("invalid --duration-ms '{v}': {e}");
                        return ExitCode::from(2);
                    }
                },
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            },
            "--seed-l2" => {
                seed_l2 = true;
                i += 1;
            }
            "--self-test" => {
                self_test = true;
                i += 1;
            }
            "--help" | "-h" => {
                print_usage();
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("Unknown demo argument: {other}");
                return ExitCode::from(2);
            }
        }
    }

    if self_test {
        return match run_self_test() {
            Ok(()) => {
                println!("TRINODE_SELF_TEST_OK");
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("TRINODE_SELF_TEST_FAILED: {err}");
                ExitCode::from(1)
            }
        };
    }

    let mut cfg = TriNodeDemoConfig::ephemeral(state_dir);
    cfg.oob_bind = oob_bind;
    cfg.gateway_bind = gateway_bind;
    if let Some(tok) = token {
        cfg.oob_token = tok;
    }
    cfg.seed_sample_l2 = seed_l2;

    let mut cluster = match TriNodeDemoCluster::start(cfg) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("failed to start tri-node demo cluster: {err}");
            return ExitCode::from(1);
        }
    };

    println!("HAL Core + HAL Key Tri-Node Demo Running");
    println!("  HAL Key PWA URL : http://{}/", cluster.oob_addr());
    println!("  X-Hal-Oob-Token : {}", cluster.oob_token());
    println!("  hal-gateway TCP : {}", cluster.gateway_addr());
    println!(
        "  Laptop MCP cmd  : hal-bridge --config {} mcp",
        cluster.bridge_config_path().display()
    );
    println!(
        "  Sample L2 cmd   : hal-bridge --config {} propose --target /habitat/entry/lock --action lock --reason \"test L2\"",
        cluster.bridge_config_path().display()
    );

    let started = Instant::now();
    loop {
        if let Some(limit) = duration_ms {
            if started.elapsed() >= Duration::from_millis(limit) {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    cluster.shutdown();
    ExitCode::SUCCESS
}

fn run_pair_cli(args: &[String]) -> ExitCode {
    let mut bundle_path: Option<PathBuf> = None;
    let mut token_path: Option<PathBuf> = None;
    let mut out_dir: Option<PathBuf> = None;
    let mut gateway_override: Option<String> = None;
    let mut episode_override: Option<String> = None;
    let mut agent_id: Option<String> = None;
    let mut json_out = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--bundle" => match take_opt(args, &mut i) {
                Ok(v) => bundle_path = Some(PathBuf::from(v)),
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            },
            "--token" => match take_opt(args, &mut i) {
                Ok(v) => token_path = Some(PathBuf::from(v)),
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            },
            "--out-dir" => match take_opt(args, &mut i) {
                Ok(v) => out_dir = Some(PathBuf::from(v)),
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            },
            "--gateway-addr" => match take_opt(args, &mut i) {
                Ok(v) => gateway_override = Some(v),
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            },
            "--episode" => match take_opt(args, &mut i) {
                Ok(v) => episode_override = Some(v),
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            },
            "--agent-id" => match take_opt(args, &mut i) {
                Ok(v) => agent_id = Some(v),
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            },
            "--json" => {
                json_out = true;
                i += 1;
            }
            "--help" | "-h" => {
                print_usage();
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("Unknown flag in 'hal-bridge pair': {other}");
                return ExitCode::from(2);
            }
        }
    }

    let Some(out_dir) = out_dir else {
        eprintln!("hal-bridge pair requires --out-dir <dir>");
        return ExitCode::from(2);
    };

    let res = match (bundle_path, token_path) {
        (Some(bundle), None) => pair_from_bundle(
            &bundle,
            &out_dir,
            gateway_override.as_deref(),
            episode_override.as_deref(),
        ),
        (None, Some(token)) => update_paired_token(&token, &out_dir, agent_id.as_deref()),
        (Some(_), Some(_)) => {
            eprintln!("hal-bridge pair accepts either --bundle or --token, not both");
            return ExitCode::from(2);
        }
        (None, None) => {
            eprintln!("hal-bridge pair requires --bundle <path> or --token <path>");
            return ExitCode::from(2);
        }
    };

    match res {
        Ok(paired) => {
            if json_out {
                match serde_json::to_string_pretty(&paired) {
                    Ok(s) => println!("{s}"),
                    Err(e) => {
                        eprintln!("hal-bridge JSON error: {e}");
                        return ExitCode::from(1);
                    }
                }
            } else {
                println!(
                    "BRIDGE_PAIRED agent_id={} gateway={} config={} token={} token_id={} expires_at_ms={}",
                    paired.agent_id,
                    paired.gateway_addr,
                    paired.config_path.display(),
                    paired.token_path.display(),
                    paired.token_id,
                    paired.token_expires_at_ms
                );
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("hal-bridge pair error: {err}");
            ExitCode::from(1)
        }
    }
}
