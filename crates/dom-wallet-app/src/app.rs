use crate::runtime::{AppRuntime, Screen};
use crate::storage;
use dom_wallet::Network;
use eframe::egui;
use std::path::PathBuf;

pub struct WalletApp {
    runtime: AppRuntime,
    bootstrap_complete: bool,
    create_wallet_dir: String,
    create_password: String,
    create_network: Network,
    created_phrase: Option<String>,
    restore_wallet_dir: String,
    restore_password: String,
    restore_network: Network,
    restore_phrase: String,
    unlock_password: String,
    receive_amount: String,
    send_request_text: String,
    send_fee: String,
    send_result: Option<String>,
}

impl WalletApp {
    pub fn new(data_dir: PathBuf) -> anyhow::Result<Self> {
        let runtime = AppRuntime::load(data_dir)?;
        Ok(Self {
            runtime,
            bootstrap_complete: false,
            create_wallet_dir: String::new(),
            create_password: String::new(),
            create_network: Network::Regtest,
            created_phrase: None,
            restore_wallet_dir: String::new(),
            restore_password: String::new(),
            restore_network: Network::Regtest,
            restore_phrase: String::new(),
            unlock_password: String::new(),
            receive_amount: String::new(),
            send_request_text: String::new(),
            send_fee: "1000".to_string(),
            send_result: None,
        })
    }
}

impl eframe::App for WalletApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if !self.bootstrap_complete {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.heading("Loading");
                ui.label("Resolving local wallet application state.");
            });
            self.runtime.complete_bootstrap();
            self.bootstrap_complete = true;
            ctx.request_repaint();
            return;
        }

        egui::TopBottomPanel::top("top_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("DOM Wallet");
                ui.separator();
                ui.label("Conservative deterministic desktop wallet");
                if self.runtime.session.is_some() {
                    ui.separator();
                    if ui.button("Dashboard").clicked() {
                        self.runtime.screen = Screen::Dashboard;
                    }
                    if ui.button("Receive").clicked() {
                        self.runtime.screen = Screen::Receive;
                    }
                    if ui.button("Send").clicked() {
                        self.runtime.screen = Screen::Send;
                    }
                    if ui.button("History").clicked() {
                        self.runtime.screen = Screen::History;
                    }
                    if ui.button("Diagnostics").clicked() {
                        self.runtime.screen = Screen::Diagnostics;
                    }
                    if ui.button("Settings").clicked() {
                        self.runtime.screen = Screen::Settings;
                    }
                    if ui.button("Lock").clicked() {
                        self.runtime.lock_wallet();
                        self.unlock_password.clear();
                    }
                }
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            if let Some(error) = &self.runtime.last_error {
                ui.colored_label(egui::Color32::from_rgb(180, 50, 50), error);
                if ui.button("Clear Error").clicked() {
                    self.runtime.clear_error();
                }
                ui.separator();
            }

            match self.runtime.screen {
                Screen::Splash => {
                    ui.heading("Loading");
                    ui.label("Resolving local application state.");
                }
                Screen::Welcome => self.render_welcome(ui),
                Screen::Create => self.render_create(ui),
                Screen::Restore => self.render_restore(ui),
                Screen::Unlock => self.render_unlock(ui),
                Screen::Dashboard => self.render_dashboard(ui),
                Screen::Receive => self.render_receive(ui),
                Screen::Send => self.render_send(ui),
                Screen::History => self.render_history(ui),
                Screen::Diagnostics => self.render_diagnostics(ui),
                Screen::Settings => self.render_settings(ui),
            }
        });
    }
}

impl WalletApp {
    fn render_welcome(&mut self, ui: &mut egui::Ui) {
        ui.heading("Wallet Setup");
        ui.label("No wallet is currently configured for this desktop application.");
        if ui.button("Create Wallet").clicked() {
            self.runtime.screen = Screen::Create;
        }
        if ui.button("Restore Wallet").clicked() {
            self.runtime.screen = Screen::Restore;
        }
    }

    fn render_create(&mut self, ui: &mut egui::Ui) {
        ui.heading("Create Wallet");
        ui.label("Creates a deterministic V2 wallet directory and displays the seed phrase once.");
        ui.horizontal(|ui| {
            ui.label("Wallet directory");
            ui.text_edit_singleline(&mut self.create_wallet_dir);
        });
        ui.horizontal(|ui| {
            ui.label("Password");
            ui.add(egui::TextEdit::singleline(&mut self.create_password).password(true));
        });
        ui.horizontal(|ui| {
            ui.label("Network");
            network_selector(ui, &mut self.create_network);
        });

        if ui.button("Create Deterministic Wallet").clicked() {
            match self.runtime.create_wallet(
                PathBuf::from(self.create_wallet_dir.trim()),
                &self.create_password,
                self.create_network,
            ) {
                Ok(phrase) => self.created_phrase = Some(phrase),
                Err(e) => self.runtime.set_error(format!("create wallet: {e}")),
            }
        }

        if let Some(phrase) = &self.created_phrase {
            ui.separator();
            ui.label("Seed phrase. Record offline before proceeding.");
            ui.code(phrase);
        }
    }

    fn render_restore(&mut self, ui: &mut egui::Ui) {
        ui.heading("Restore Wallet");
        ui.label("Phase 1 app restore recreates the deterministic wallet from the phrase without node scanning.");
        ui.horizontal(|ui| {
            ui.label("Wallet directory");
            ui.text_edit_singleline(&mut self.restore_wallet_dir);
        });
        ui.horizontal(|ui| {
            ui.label("Password");
            ui.add(egui::TextEdit::singleline(&mut self.restore_password).password(true));
        });
        ui.horizontal(|ui| {
            ui.label("Network");
            network_selector(ui, &mut self.restore_network);
        });
        ui.label("24-word phrase");
        ui.add(
            egui::TextEdit::multiline(&mut self.restore_phrase)
                .desired_rows(4)
                .desired_width(f32::INFINITY),
        );

        if ui.button("Restore Deterministic Wallet").clicked() {
            match self.runtime.restore_wallet(
                PathBuf::from(self.restore_wallet_dir.trim()),
                &self.restore_password,
                self.restore_network,
                &self.restore_phrase,
            ) {
                Ok(()) => {
                    self.restore_phrase.clear();
                    self.runtime.screen = Screen::Unlock;
                }
                Err(e) => self.runtime.set_error(format!("restore wallet: {e}")),
            }
        }
    }

    fn render_unlock(&mut self, ui: &mut egui::Ui) {
        ui.heading("Unlock Wallet");
        if let Some(wallet_dir) = &self.runtime.persisted.wallet_dir {
            ui.label(format!("Wallet directory: {}", wallet_dir.display()));
        }
        ui.horizontal(|ui| {
            ui.label("Password");
            ui.add(egui::TextEdit::singleline(&mut self.unlock_password).password(true));
        });
        if ui.button("Unlock").clicked() {
            match self.runtime.unlock_wallet(&self.unlock_password) {
                Ok(()) => self.unlock_password.clear(),
                Err(e) => self.runtime.set_error(format!("unlock wallet: {e}")),
            }
        }
    }

    fn render_dashboard(&mut self, ui: &mut egui::Ui) {
        ui.heading("Dashboard");
        ui.label("Explicit wallet and node state. No background mutation occurs here.");

        if ui.button("Refresh Node Status").clicked() {
            if let Err(e) = self.runtime.refresh_node_status() {
                self.runtime.set_error(format!("refresh node status: {e}"));
            }
        }

        if let Some(balance) = self.runtime.wallet_balance {
            ui.separator();
            ui.label(format!("Confirmed: {} noms", balance.confirmed));
            ui.label(format!("Immature: {} noms", balance.immature));
            ui.label(format!("Reserved: {} noms", balance.reserved));
            ui.label(format!("Spendable: {} noms", balance.spendable()));
        } else {
            ui.label("Wallet balance unavailable until the wallet is unlocked.");
        }

        if let Some(status) = &self.runtime.node_status {
            ui.separator();
            ui.label(format!("Node network: {}", status.network));
            ui.label(format!("Chain height: {}", status.chain_height));
            ui.label(format!("Mempool size: {}", status.mempool_size));
        } else {
            ui.separator();
            ui.label("Node status unavailable.");
        }

        ui.separator();
        ui.heading("Recent Transactions");
        for row in self.runtime.history.iter().take(5) {
            ui.label(format!(
                "{}  {}  {}",
                row.timestamp, row.status, row.tx_hash_hex
            ));
        }
        if self.runtime.history.is_empty() {
            ui.label("No journaled wallet transactions yet.");
        }
    }

    fn render_receive(&mut self, ui: &mut egui::Ui) {
        ui.heading("Receive");
        ui.label("Conservative receive in DOM Wallet V1 is an exact-amount payment request.");
        ui.label("This is not a generic open-ended address. The sender must use the exact amount, commitment, and blinding shown below.");
        ui.label("No hidden state mutation occurs here. Requests are persisted inside the encrypted wallet and re-derived deterministically on reopen.");

        ui.separator();
        ui.horizontal(|ui| {
            ui.label("Amount (noms)");
            ui.text_edit_singleline(&mut self.receive_amount);
            if ui.button("Create Request").clicked() {
                match self.receive_amount.trim().parse::<u64>() {
                    Ok(amount) => {
                        if let Err(e) = self.runtime.create_receive_request(amount) {
                            self.runtime
                                .set_error(format!("create receive request: {e}"));
                        } else {
                            self.receive_amount.clear();
                        }
                    }
                    Err(e) => self.runtime.set_error(format!("parse receive amount: {e}")),
                }
            }
            if ui.button("Refresh Detection").clicked() {
                if let Err(e) = self.runtime.refresh_receive_statuses() {
                    self.runtime
                        .set_error(format!("refresh receive detection: {e}"));
                }
            }
        });

        ui.separator();
        if self.runtime.receive_requests.is_empty() {
            ui.label("No receive requests have been created yet.");
            return;
        }

        for row in &self.runtime.receive_requests {
            ui.group(|ui| {
                ui.label(format!("Index: {}", row.index));
                ui.label(format!("Amount: {} noms", row.amount));
                ui.label(format!("Created: {}", row.created_at));
                ui.label(format!("Status: {}", row.status));
                ui.label("Address payload");
                ui.code(&row.address);
                ui.label("Commitment");
                ui.code(&row.commitment_hex);
                ui.label("Recipient blinding");
                ui.code(&row.blinding_hex);
                ui.label("Payment request");
                ui.code(&row.request_text);
            });
        }
    }

    fn render_send(&mut self, ui: &mut egui::Ui) {
        ui.heading("Send");
        ui.label("Send consumes the exact payment request produced by the Receive screen.");
        ui.label("The wallet validates network, address, commitment, amount, and blinding before constructing the transaction.");
        ui.horizontal(|ui| {
            ui.label("Fee (noms)");
            ui.text_edit_singleline(&mut self.send_fee);
        });
        ui.label("Payment request");
        ui.add(
            egui::TextEdit::multiline(&mut self.send_request_text)
                .desired_rows(8)
                .desired_width(f32::INFINITY),
        );
        if ui.button("Build And Submit").clicked() {
            match self.send_fee.trim().parse::<u64>() {
                Ok(fee) => match self
                    .runtime
                    .submit_payment_request(&self.send_request_text, fee)
                {
                    Ok(tx_hash) => {
                        self.send_result =
                            Some(format!("submitted transaction {}", hex::encode(tx_hash)));
                        self.send_request_text.clear();
                    }
                    Err(e) => self
                        .runtime
                        .set_error(format!("submit payment request: {e}")),
                },
                Err(e) => self.runtime.set_error(format!("parse fee: {e}")),
            }
        }
        if let Some(result) = &self.send_result {
            ui.separator();
            ui.label(result);
        }
    }

    fn render_history(&mut self, ui: &mut egui::Ui) {
        ui.heading("Transaction History");
        if ui.button("Refresh Transaction States").clicked() {
            self.runtime.refresh_wallet_view();
        }
        if self.runtime.history.is_empty() {
            ui.label("No wallet transaction journal entries available.");
            return;
        }
        let mut cancel_tx = None;
        let mut rebroadcast_tx = None;
        for row in &self.runtime.history {
            ui.group(|ui| {
                ui.label(format!("Timestamp: {}", row.timestamp));
                ui.label(format!("Status: {}", row.status));
                ui.code(&row.tx_hash_hex);
                if let Some(warning) = &row.warning {
                    ui.label(format!("Warning: {warning}"));
                }
                ui.horizontal(|ui| {
                    if row.can_cancel && ui.button("Cancel").clicked() {
                        cancel_tx = Some(row.tx_hash_hex.clone());
                    }
                    if row.can_rebroadcast && ui.button("Rebroadcast").clicked() {
                        rebroadcast_tx = Some(row.tx_hash_hex.clone());
                    }
                });
            });
        }
        if let Some(tx_hash) = cancel_tx {
            if let Err(e) = self.runtime.cancel_transaction(&tx_hash) {
                self.runtime
                    .set_error(format!("cancel transaction {tx_hash}: {e}"));
            }
        }
        if let Some(tx_hash) = rebroadcast_tx {
            if let Err(e) = self.runtime.rebroadcast_transaction(&tx_hash) {
                self.runtime
                    .set_error(format!("rebroadcast transaction {tx_hash}: {e}"));
            }
        }
    }

    fn render_diagnostics(&mut self, ui: &mut egui::Ui) {
        ui.heading("Node Diagnostics");
        ui.horizontal(|ui| {
            ui.label("Node URL");
            ui.text_edit_singleline(&mut self.runtime.persisted.node_url);
            if ui.button("Save").clicked() {
                if let Err(e) = self.runtime.save_persisted() {
                    self.runtime
                        .set_error(format!("persist node diagnostics config: {e}"));
                }
            }
            if ui.button("Refresh").clicked() {
                if let Err(e) = self.runtime.refresh_node_status() {
                    self.runtime.set_error(format!("refresh diagnostics: {e}"));
                }
            }
        });

        if let Some(status) = &self.runtime.node_status {
            ui.separator();
            ui.label("Connectivity: online");
            ui.label(format!("Protocol version: {}", status.version));
            ui.label(format!("Height: {}", status.chain_height));
            ui.label(format!("Mempool: {}", status.mempool_size));
            ui.label(format!("Network: {}", status.network));
        } else {
            ui.separator();
            ui.label("Connectivity: offline or unverified");
        }
    }

    fn render_settings(&mut self, ui: &mut egui::Ui) {
        ui.heading("Settings");
        ui.label(format!(
            "Application data directory: {}",
            self.runtime.data_dir.display()
        ));
        if let Some(wallet_dir) = &self.runtime.persisted.wallet_dir {
            ui.label(format!("Wallet directory: {}", wallet_dir.display()));
        } else {
            ui.label("Wallet directory: not configured");
        }
        ui.label(format!("Node URL: {}", self.runtime.persisted.node_url));
        if ui.button("Persist Settings").clicked() {
            if let Err(e) = self.runtime.save_persisted() {
                self.runtime.set_error(format!("persist settings: {e}"));
            }
        }
    }
}

fn network_selector(ui: &mut egui::Ui, network: &mut Network) {
    egui::ComboBox::from_id_salt(ui.next_auto_id())
        .selected_text(match network {
            Network::Mainnet => "Mainnet",
            Network::Testnet => "Testnet",
            Network::Regtest => "Regtest",
        })
        .show_ui(ui, |ui| {
            ui.selectable_value(network, Network::Mainnet, "Mainnet");
            ui.selectable_value(network, Network::Testnet, "Testnet");
            ui.selectable_value(network, Network::Regtest, "Regtest");
        });
}

pub fn run() -> anyhow::Result<()> {
    let data_dir = storage::default_data_dir();
    let app = WalletApp::new(data_dir)?;
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([980.0, 720.0])
            .with_min_inner_size([820.0, 620.0])
            .with_title("DOM Wallet"),
        ..Default::default()
    };

    eframe::run_native(
        "DOM Wallet",
        native_options,
        Box::new(move |_cc| Ok(Box::new(app))),
    )
    .map_err(|e| anyhow::anyhow!("eframe: {e}"))
}
