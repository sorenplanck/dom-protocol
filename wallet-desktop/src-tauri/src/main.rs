// Prevents an extra console window on Windows in release. Keep this line.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    dom_wallet_desktop_lib::run();
}
