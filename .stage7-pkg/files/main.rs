use std::ffi::{OsStr, OsString};
#[cfg(any(feature = "production", feature = "simulation"))]
use std::path::PathBuf;
use std::process::ExitCode;

#[cfg(feature = "production")]
const PRODUCTION_USAGE_V1: &str = "usage: dom-interopd self-check [--json]\n       dom-interopd run --state-dir PATH [--create]\n              nine secrets are read from standard input, one pass, no trailing newline:\n              <bearer token>\n<upstream Relay signing secret: 64 lowercase hex>\n<downstream Relay signing secret: 64 lowercase hex>\n<Contracts identity passphrase>\n<DOM wallet passphrase>\n<Bitcoin participant secret: 64 lowercase hex>\n<route-secret seal key: 64 lowercase hex>\n<refund-arming credential: 64 lowercase hex>\n<local EVM signing secret: 64 lowercase hex>";

fn main() -> ExitCode {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    match arguments.as_slice() {
        [command] if command == OsStr::new("self-check") => print_self_check(),
        [command, format]
            if command == OsStr::new("self-check") && format == OsStr::new("--json") =>
        {
            print_self_check()
        }
        #[cfg(feature = "production")]
        [command, rest @ ..] if command == OsStr::new("run") => run_production(rest),
        #[cfg(feature = "simulation")]
        [command, rest @ ..] if command == OsStr::new("simulate") => run_simulation(rest),
        _ => {
            print_usage();
            ExitCode::from(2)
        }
    }
}

fn print_self_check() -> ExitCode {
    match dom_interopd::self_check_json_v1() {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

/// Prints the commands this binary accepts.
///
/// Under `production` there is now a `run` command. It does not yet drive a
/// route: it authenticates everything it can and then refuses, naming the
/// parts that have no production implementation. That is deliberate and the
/// refusal prints the list; see `production_run` for why a refusal is a result
/// and a loop on test doubles would not be.
fn print_usage() {
    #[cfg(feature = "production")]
    eprintln!("{PRODUCTION_USAGE_V1}");
    #[cfg(feature = "simulation")]
    eprintln!(
        "usage: dom-interopd self-check [--json]\n       dom-interopd simulate --state-dir PATH --scenario claim|refund [--crash-after authority-persist|timer-event-commit]"
    );
    #[cfg(not(any(feature = "production", feature = "simulation")))]
    eprintln!("usage: dom-interopd self-check [--json]");
}

#[cfg(all(test, feature = "production"))]
mod production_usage_tests {
    use super::PRODUCTION_USAGE_V1;

    #[test]
    fn usage_pins_all_nine_secret_lines() {
        assert!(PRODUCTION_USAGE_V1.contains("nine secrets"));
        assert_eq!(PRODUCTION_USAGE_V1.matches('<').count(), 9);
        assert!(PRODUCTION_USAGE_V1.contains("upstream Relay signing secret"));
        assert!(PRODUCTION_USAGE_V1.contains("downstream Relay signing secret"));
        assert!(PRODUCTION_USAGE_V1.contains("DOM wallet passphrase"));
        assert!(PRODUCTION_USAGE_V1.contains("Bitcoin participant secret"));
        assert!(PRODUCTION_USAGE_V1.contains("refund-arming credential"));
        assert!(PRODUCTION_USAGE_V1.contains("local EVM signing secret"));
    }
}

/// Parses `run` and hands off to the composition root.
///
/// The fail-closed limits of this build are printed one per line at startup,
/// from `PRODUCTION_KNOWN_LIMITS_V1`, so an operator knows which paths refuse
/// by policy before the route is driven.
#[cfg(feature = "production")]
fn run_production(arguments: &[OsString]) -> ExitCode {
    use dom_interopd::{
        require_operational_artifact_v1, run_production_v1, ProductionRunModeV1,
        ProductionRunOptionsV1, PRODUCTION_KNOWN_LIMITS_V1,
    };

    // Refuse a debug-profile or otherwise incomplete artifact before parsing
    // a state path, reading the nine secrets, opening a store or reaching a
    // network boundary. Merely selecting the `production` Cargo feature does
    // not make an artifact operational.
    if let Err(error) = require_operational_artifact_v1() {
        eprintln!("{error}");
        return ExitCode::FAILURE;
    }

    let mut state_dir: Option<PathBuf> = None;
    let mut mode = ProductionRunModeV1::ReopenExisting;
    let mut index = 0;
    while index < arguments.len() {
        let flag = &arguments[index];
        index += 1;
        if flag == OsStr::new("--create") {
            if mode == ProductionRunModeV1::Create {
                print_usage();
                return ExitCode::from(2);
            }
            mode = ProductionRunModeV1::Create;
            continue;
        }
        let Some(value) = arguments.get(index) else {
            print_usage();
            return ExitCode::from(2);
        };
        index += 1;
        if flag == OsStr::new("--state-dir") && state_dir.is_none() {
            let path = PathBuf::from(value);
            if path.as_os_str().is_empty() {
                print_usage();
                return ExitCode::from(2);
            }
            state_dir = Some(path);
        } else {
            print_usage();
            return ExitCode::from(2);
        }
    }
    let Some(state_dir) = state_dir else {
        print_usage();
        return ExitCode::from(2);
    };

    for limit in PRODUCTION_KNOWN_LIMITS_V1 {
        eprintln!("  known limit: {limit}");
    }
    match run_production_v1(&ProductionRunOptionsV1 { state_dir, mode }) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(feature = "simulation")]
fn run_simulation(arguments: &[OsString]) -> ExitCode {
    use dom_interopd::{
        run_simulation_v1, SimulationCrashPointV1, SimulationOptionsV1, SimulationScenarioV1,
    };

    let mut state_dir: Option<PathBuf> = None;
    let mut scenario = None;
    let mut crash_after = None;
    let mut index = 0;
    while index < arguments.len() {
        let flag = &arguments[index];
        index += 1;
        let Some(value) = arguments.get(index) else {
            print_usage();
            return ExitCode::from(2);
        };
        index += 1;
        if flag == OsStr::new("--state-dir") && state_dir.is_none() {
            let path = PathBuf::from(value);
            if path.as_os_str().is_empty() {
                print_usage();
                return ExitCode::from(2);
            }
            state_dir = Some(path);
        } else if flag == OsStr::new("--scenario") && scenario.is_none() {
            scenario = match value.to_str() {
                Some("claim") => Some(SimulationScenarioV1::Claim),
                Some("refund") => Some(SimulationScenarioV1::Refund),
                _ => {
                    print_usage();
                    return ExitCode::from(2);
                }
            };
        } else if flag == OsStr::new("--crash-after") && crash_after.is_none() {
            crash_after = match value.to_str() {
                Some("authority-persist") => Some(SimulationCrashPointV1::AfterAuthorityPersist),
                Some("timer-event-commit") => Some(SimulationCrashPointV1::AfterTimerEventCommit),
                _ => {
                    print_usage();
                    return ExitCode::from(2);
                }
            };
        } else {
            print_usage();
            return ExitCode::from(2);
        }
    }
    let (Some(state_dir), Some(scenario)) = (state_dir, scenario) else {
        print_usage();
        return ExitCode::from(2);
    };
    let options = SimulationOptionsV1 {
        state_dir,
        scenario,
        crash_after,
    };
    match run_simulation_v1(options) {
        Ok(report) => match serde_json::to_string_pretty(&report) {
            Ok(json) => {
                println!("{json}");
                ExitCode::SUCCESS
            }
            Err(_) => {
                eprintln!("simulation report encoding failed");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
