use std::ffi::{OsStr, OsString};
#[cfg(any(feature = "production", feature = "simulation"))]
use std::path::PathBuf;
use std::process::ExitCode;

#[cfg(feature = "production")]
const PRODUCTION_USAGE_V1: &str = "usage: dom-interopd self-check [--json]\n       dom-interopd run --state-dir PATH [--create]\n              eight secrets are read from standard input, one pass, no trailing newline:\n              <bearer token>\n<upstream Relay signing secret: 64 lowercase hex>\n<downstream Relay signing secret: 64 lowercase hex>\n<Contracts identity passphrase>\n<DOM wallet passphrase>\n<Bitcoin participant secret: 64 lowercase hex>\n<route-secret seal key: 64 lowercase hex>\n<refund-arming credential: 64 lowercase hex>";

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
    fn usage_pins_all_eight_secret_lines() {
        assert!(PRODUCTION_USAGE_V1.contains("eight secrets"));
        assert_eq!(PRODUCTION_USAGE_V1.matches('<').count(), 8);
        assert!(PRODUCTION_USAGE_V1.contains("upstream Relay signing secret"));
        assert!(PRODUCTION_USAGE_V1.contains("downstream Relay signing secret"));
        assert!(PRODUCTION_USAGE_V1.contains("DOM wallet passphrase"));
        assert!(PRODUCTION_USAGE_V1.contains("Bitcoin participant secret"));
        assert!(PRODUCTION_USAGE_V1.contains("refund-arming credential"));
    }
}

/// Parses `run` and hands off to the composition root.
///
/// On refusal the missing parts are printed one per line, because an operator
/// who runs this needs to know what is absent rather than that something
/// failed. The parts come from `MISSING_PRODUCTION_PARTS_V1`, which is the
/// measured list and not a guess.
#[cfg(feature = "production")]
fn run_production(arguments: &[OsString]) -> ExitCode {
    use dom_interopd::{
        run_production_v1, ProductionRunErrorV1, ProductionRunModeV1, ProductionRunOptionsV1,
        MISSING_PRODUCTION_PARTS_V1,
    };

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

    match run_production_v1(&ProductionRunOptionsV1 { state_dir, mode }) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            if error == ProductionRunErrorV1::NotComposable {
                for part in MISSING_PRODUCTION_PARTS_V1 {
                    eprintln!("  missing: {part}");
                }
            }
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
