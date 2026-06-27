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
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        apply_theme(&ctx);

        if !self.bootstrap_complete {
            egui::CentralPanel::default().show(ui, |ui| {
                centered_stage(ui, "Loading", "Resolving local wallet application state.");
            });
            self.runtime.complete_bootstrap();
            self.bootstrap_complete = true;
            ctx.request_repaint();
            return;
        }
        self.runtime.poll_node_reconnect();
        self.runtime.poll_pending_resubmit();

        egui::Panel::top("top_bar")
            .frame(panel_frame())
            .show(ui, |ui| {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.heading("DOM Wallet");
                        ui.label(
                            egui::RichText::new("Deterministic monetary workstation")
                                .color(palette().muted_text),
                        );
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if self.runtime.session.is_some() {
                            if ui.button("Lock").clicked() {
                                self.runtime.lock_wallet();
                                self.unlock_password.clear();
                            }
                            ui.add_space(10.0);
                            nav_button(ui, &mut self.runtime.screen, Screen::Settings, "Settings");
                            nav_button(
                                ui,
                                &mut self.runtime.screen,
                                Screen::Diagnostics,
                                "Diagnostics",
                            );
                            nav_button(ui, &mut self.runtime.screen, Screen::History, "History");
                            nav_button(ui, &mut self.runtime.screen, Screen::Send, "Send");
                            nav_button(ui, &mut self.runtime.screen, Screen::Receive, "Receive");
                            nav_button(
                                ui,
                                &mut self.runtime.screen,
                                Screen::Dashboard,
                                "Dashboard",
                            );
                        }
                    });
                });
                if self.runtime.session.is_some() {
                    ui.add_space(8.0);
                    ui.separator();
                    ui.add_space(4.0);
                    ui.horizontal_wrapped(|ui| {
                        runtime_status_strip(ui, &self.runtime);
                    });
                }
                ui.add_space(4.0);
            });

        egui::CentralPanel::default()
            .frame(egui::Frame::default().inner_margin(18))
            .show(ui, |ui| {
                if let Some(error) = &self.runtime.last_error {
                    warning_banner(ui, "Runtime Error", error, palette().danger);
                    ui.add_space(8.0);
                    if ui.button("Clear Error").clicked() {
                        self.runtime.clear_error();
                    }
                    ui.add_space(12.0);
                }

                egui::ScrollArea::vertical()
                    .auto_shrink([false; 2])
                    .show(ui, |ui| match self.runtime.screen {
                        Screen::Splash => {
                            centered_stage(ui, "Loading", "Resolving local application state.");
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
                    });
            });
    }
}

impl WalletApp {
    fn render_welcome(&mut self, ui: &mut egui::Ui) {
        section_header(
            ui,
            "Wallet Setup",
            "Create a new deterministic wallet or reopen an existing seed.",
        );
        card(ui, |ui| {
            ui.label("No wallet is currently configured for this desktop application.");
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if ui.button("Create Wallet").clicked() {
                    self.runtime.screen = Screen::Create;
                }
                if ui.button("Restore Wallet").clicked() {
                    self.runtime.screen = Screen::Restore;
                }
            });
        });
    }

    fn render_create(&mut self, ui: &mut egui::Ui) {
        section_header(
            ui,
            "Create Wallet",
            "Creates a deterministic V2 wallet directory and shows the seed phrase once.",
        );
        card(ui, |ui| {
            labeled_text_edit(ui, "Wallet directory", &mut self.create_wallet_dir, false);
            labeled_text_edit(ui, "Password", &mut self.create_password, true);
            labeled_row(ui, "Network", |ui| {
                network_selector(ui, &mut self.create_network)
            });
            ui.add_space(8.0);
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
        });

        if let Some(phrase) = &self.created_phrase {
            ui.add_space(14.0);
            card(ui, |ui| {
                mini_header(ui, "Seed Phrase");
                ui.label("Record offline before proceeding.");
                code_block(ui, phrase);
            });
        }
    }

    fn render_restore(&mut self, ui: &mut egui::Ui) {
        section_header(
            ui,
            "Restore Wallet",
            "Recreates the deterministic wallet from the phrase without node scanning.",
        );
        card(ui, |ui| {
            labeled_text_edit(ui, "Wallet directory", &mut self.restore_wallet_dir, false);
            labeled_text_edit(ui, "Password", &mut self.restore_password, true);
            labeled_row(ui, "Network", |ui| {
                network_selector(ui, &mut self.restore_network)
            });
            mini_header(ui, "24-word Phrase");
            ui.add(
                egui::TextEdit::multiline(&mut self.restore_phrase)
                    .desired_rows(4)
                    .desired_width(f32::INFINITY),
            );
            ui.add_space(8.0);
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
        });
    }

    fn render_unlock(&mut self, ui: &mut egui::Ui) {
        section_header(
            ui,
            "Unlock Wallet",
            "Unlock is explicit. No credentials are cached beyond the active session.",
        );
        card(ui, |ui| {
            if let Some(wallet_dir) = &self.runtime.persisted.wallet_dir {
                labeled_value(ui, "Wallet directory", &wallet_dir.display().to_string());
            }
            labeled_text_edit(ui, "Password", &mut self.unlock_password, true);
            ui.add_space(8.0);
            if ui.button("Unlock").clicked() {
                match self.runtime.unlock_wallet(&self.unlock_password) {
                    Ok(()) => self.unlock_password.clear(),
                    Err(e) => self.runtime.set_error(format!("unlock wallet: {e}")),
                }
            }
        });
    }

    fn render_dashboard(&mut self, ui: &mut egui::Ui) {
        section_header(
            ui,
            "Dashboard",
            "Explicit wallet and node state. No background mutation occurs here.",
        );
        ui.horizontal(|ui| {
            status_badge(
                ui,
                if self.runtime.node_status.is_some() {
                    "Node Online"
                } else {
                    "Node Unverified"
                },
                if self.runtime.node_status.is_some() {
                    palette().success
                } else {
                    palette().warning
                },
            );
            if ui.button("Refresh Node Status").clicked() {
                if let Err(e) = self.runtime.refresh_node_status() {
                    self.runtime.set_error(format!("refresh node status: {e}"));
                }
            }
        });
        ui.add_space(10.0);

        ui.columns(2, |columns| {
            card(&mut columns[0], |ui| {
                mini_header(ui, "Balances");
                if let Some(balance) = self.runtime.wallet_balance {
                    balance_stat(ui, "Spendable", balance.spendable(), true);
                    balance_stat(ui, "Confirmed", balance.confirmed, false);
                    balance_stat(ui, "Reserved", balance.reserved, false);
                    balance_stat(ui, "Immature", balance.immature, false);
                } else {
                    ui.label("Wallet balance unavailable until the wallet is unlocked.");
                }
            });

            card(&mut columns[1], |ui| {
                mini_header(ui, "Node State");
                let network_rows = self.runtime.node_connection.status.diagnostics_rows();
                status_badge(
                    ui,
                    &network_rows.state,
                    network_state_color(self.runtime.node_connection.status.state),
                );
                labeled_value(ui, "Connected peer", &network_rows.connected_peer);
                labeled_value(ui, "Peer count", &network_rows.peer_count);
                labeled_value(ui, "Last Pong", &network_rows.last_pong);
                if let Some(status) = &self.runtime.node_status {
                    labeled_value(ui, "Network", &status.network);
                    labeled_value(ui, "Chain height", &status.chain_height.to_string());
                    labeled_value(ui, "Mempool size", &status.mempool_size.to_string());
                    labeled_value(ui, "Protocol", &status.version.to_string());
                } else {
                    ui.label("Node status unavailable.");
                }
            });
        });

        ui.add_space(14.0);
        card(ui, |ui| {
            mini_header(ui, "Recent Transactions");
            if self.runtime.history.is_empty() {
                ui.label("No journaled wallet transactions yet.");
                return;
            }
            for row in self.runtime.history.iter().take(5) {
                transaction_summary(ui, row);
                ui.add_space(6.0);
            }
        });
    }

    fn render_receive(&mut self, ui: &mut egui::Ui) {
        section_header(
            ui,
            "Receive",
            "Exact-amount payment requests only. No generic open-ended address model is fabricated here.",
        );
        card(ui, |ui| {
            labeled_text_edit(ui, "Amount (noms)", &mut self.receive_amount, false);
            ui.horizontal(|ui| {
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
        });

        ui.add_space(14.0);
        if self.runtime.receive_requests.is_empty() {
            ui.label("No receive requests have been created yet.");
            return;
        }

        for row in &self.runtime.receive_requests {
            card(ui, |ui| {
                ui.horizontal(|ui| {
                    mini_header(ui, &format!("Request #{}", row.index));
                    ui.add_space(8.0);
                    status_badge(ui, &row.status, palette().info);
                });
                labeled_value(ui, "Amount", &format!("{} noms", row.amount));
                labeled_value(ui, "Created", &row.created_at.to_string());
                mini_header(ui, "Address Payload");
                code_block(ui, &row.address);
                mini_header(ui, "Commitment");
                code_block(ui, &row.commitment_hex);
                mini_header(ui, "Recipient Blinding");
                code_block(ui, &row.blinding_hex);
                mini_header(ui, "Payment Request");
                code_block(ui, &row.request_text);
            });
            ui.add_space(10.0);
        }
    }

    fn render_send(&mut self, ui: &mut egui::Ui) {
        section_header(
            ui,
            "Send",
            "Consumes the exact payment request emitted by Receive and validates it before transaction construction.",
        );
        card(ui, |ui| {
            labeled_text_edit(ui, "Fee (noms)", &mut self.send_fee, false);
            mini_header(ui, "Payment Request");
            ui.add(
                egui::TextEdit::multiline(&mut self.send_request_text)
                    .desired_rows(8)
                    .desired_width(f32::INFINITY),
            );
            ui.add_space(8.0);
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
        });
        if let Some(result) = &self.send_result {
            ui.add_space(12.0);
            warning_banner(ui, "Submission Result", result, palette().success);
        }
    }

    fn render_history(&mut self, ui: &mut egui::Ui) {
        section_header(
            ui,
            "Transaction History",
            "Operator-facing lifecycle view derived from journal state and current mempool visibility.",
        );
        ui.horizontal(|ui| {
            if ui.button("Refresh Transaction States").clicked() {
                self.runtime.refresh_wallet_view();
            }
            ui.label(
                egui::RichText::new("No hidden retries. Recovery remains explicit.")
                    .color(palette().muted_text),
            );
        });
        ui.add_space(10.0);
        if self.runtime.history.is_empty() {
            ui.label("No wallet transaction journal entries available.");
            return;
        }
        let mut cancel_tx = None;
        let mut rebroadcast_tx = None;
        for row in &self.runtime.history {
            card(ui, |ui| {
                ui.horizontal(|ui| {
                    mini_header(ui, "Transaction");
                    ui.add_space(8.0);
                    status_badge(ui, &row.status, status_color(&row.status));
                });
                labeled_value(ui, "Timestamp", &row.timestamp.to_string());
                mini_header(ui, "Transaction Hash");
                code_block(ui, &row.tx_hash_hex);
                if let Some(warning) = &row.warning {
                    ui.add_space(6.0);
                    warning_banner(ui, "Warning", warning, palette().warning);
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
            ui.add_space(10.0);
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
        section_header(
            ui,
            "Diagnostics",
            "Infrastructure-facing view of RPC connectivity and current node metadata.",
        );
        card(ui, |ui| {
            labeled_text_edit(ui, "Node URL", &mut self.runtime.persisted.node_url, false);
            ui.horizontal(|ui| {
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
                if ui.button("Export Logs").clicked() {
                    match self.runtime.export_diagnostics() {
                        Ok(path) => self
                            .runtime
                            .set_error(format!("diagnostics exported to {}", path.display())),
                        Err(e) => self.runtime.set_error(format!("export diagnostics: {e}")),
                    }
                }
            });
        });

        ui.add_space(12.0);
        ui.columns(2, |columns| {
            card(&mut columns[0], |ui| {
                mini_header(ui, "Node Connectivity");
                let network_rows = self.runtime.node_connection.status.diagnostics_rows();
                status_badge(
                    ui,
                    &network_rows.state,
                    network_state_color(self.runtime.node_connection.status.state),
                );
                labeled_value(ui, "Connected peer", &network_rows.connected_peer);
                labeled_value(ui, "Last error", &network_rows.last_error);
                labeled_value(ui, "Last TCP connect", &network_rows.last_tcp_connect);
                labeled_value(ui, "Last handshake", &network_rows.last_handshake);
                labeled_value(ui, "Last Pong", &network_rows.last_pong);
                labeled_value(ui, "Reconnect delay", &network_rows.reconnect_delay);
                labeled_value(ui, "Peer count", &network_rows.peer_count);
                if let Some(next) = self.runtime.node_connection.next_reconnect_at() {
                    labeled_value(ui, "Next attempt", &next.to_string());
                }
                if let Some(status) = &self.runtime.node_status {
                    labeled_value(ui, "Protocol version", &status.version.to_string());
                    labeled_value(ui, "Height", &status.chain_height.to_string());
                    labeled_value(ui, "Mempool", &status.mempool_size.to_string());
                    labeled_value(ui, "Network", &status.network);
                } else {
                    ui.label("Node status unavailable.");
                }
            });
            card(&mut columns[1], |ui| {
                mini_header(ui, "Wallet Runtime");
                status_badge(
                    ui,
                    if self.runtime.session.is_some() {
                        "Unlocked Session"
                    } else {
                        "Locked Session"
                    },
                    if self.runtime.session.is_some() {
                        palette().info
                    } else {
                        palette().warning
                    },
                );
                labeled_value(ui, "Screen", &format!("{:?}", self.runtime.screen));
                labeled_value(
                    ui,
                    "Receive requests",
                    &self.runtime.receive_requests.len().to_string(),
                );
                labeled_value(ui, "History rows", &self.runtime.history.len().to_string());
                labeled_value(
                    ui,
                    "Diagnostic log rows",
                    &self.runtime.diagnostic_log.len().to_string(),
                );
            });
        });
    }

    fn render_settings(&mut self, ui: &mut egui::Ui) {
        section_header(
            ui,
            "Settings",
            "Local operator configuration and persistent application paths.",
        );
        card(ui, |ui| {
            labeled_value(
                ui,
                "Application data directory",
                &self.runtime.data_dir.display().to_string(),
            );
            if let Some(wallet_dir) = &self.runtime.persisted.wallet_dir {
                labeled_value(ui, "Wallet directory", &wallet_dir.display().to_string());
            } else {
                labeled_value(ui, "Wallet directory", "not configured");
            }
            labeled_value(ui, "Node URL", &self.runtime.persisted.node_url);
            ui.add_space(8.0);
            if ui.button("Persist Settings").clicked() {
                if let Err(e) = self.runtime.save_persisted() {
                    self.runtime.set_error(format!("persist settings: {e}"));
                }
            }
        });
        ui.add_space(12.0);
        card(ui, |ui| {
            mini_header(ui, "Operator Notes");
            ui.label(
                egui::RichText::new(
                    "Refresh, send recovery, and receive detection remain explicit operator actions.",
                )
                .color(palette().muted_text),
            );
            ui.label(
                egui::RichText::new(
                    "This UI does not imply continuous background synchronization or hidden retries.",
                )
                .color(palette().muted_text),
            );
        });
    }
}

#[derive(Clone, Copy)]
struct Palette {
    bg: egui::Color32,
    panel: egui::Color32,
    panel_alt: egui::Color32,
    border: egui::Color32,
    text: egui::Color32,
    muted_text: egui::Color32,
    accent: egui::Color32,
    success: egui::Color32,
    warning: egui::Color32,
    danger: egui::Color32,
    info: egui::Color32,
}

fn palette() -> Palette {
    Palette {
        bg: egui::Color32::from_rgb(18, 21, 26),
        panel: egui::Color32::from_rgb(28, 33, 40),
        panel_alt: egui::Color32::from_rgb(35, 41, 50),
        border: egui::Color32::from_rgb(64, 72, 84),
        text: egui::Color32::from_rgb(222, 226, 232),
        muted_text: egui::Color32::from_rgb(151, 159, 171),
        accent: egui::Color32::from_rgb(183, 150, 84),
        success: egui::Color32::from_rgb(104, 155, 115),
        warning: egui::Color32::from_rgb(184, 148, 86),
        danger: egui::Color32::from_rgb(166, 92, 92),
        info: egui::Color32::from_rgb(103, 125, 156),
    }
}

fn apply_theme(ctx: &egui::Context) {
    let palette = palette();
    let mut visuals = egui::Visuals::dark();
    visuals.override_text_color = Some(palette.text);
    visuals.panel_fill = palette.bg;
    visuals.window_fill = palette.panel;
    visuals.faint_bg_color = palette.panel_alt;
    visuals.extreme_bg_color = egui::Color32::from_rgb(22, 26, 32);
    visuals.code_bg_color = egui::Color32::from_rgb(20, 24, 30);
    visuals.selection.bg_fill = palette.accent;
    visuals.selection.stroke = egui::Stroke::new(1.0, palette.bg);
    visuals.widgets.inactive.bg_fill = palette.panel;
    visuals.widgets.inactive.weak_bg_fill = palette.panel;
    visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, palette.border);
    visuals.widgets.hovered.bg_fill = palette.panel_alt;
    visuals.widgets.hovered.weak_bg_fill = palette.panel_alt;
    visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, palette.accent);
    visuals.widgets.active.bg_fill = palette.panel_alt;
    visuals.widgets.active.bg_stroke = egui::Stroke::new(1.0, palette.accent);
    visuals.widgets.open.bg_fill = palette.panel_alt;
    ctx.set_visuals(visuals);

    let mut style = (*ctx.style_of(egui::Theme::Dark)).clone();
    style.spacing.item_spacing = egui::vec2(10.0, 10.0);
    style.spacing.button_padding = egui::vec2(10.0, 6.0);
    style.spacing.indent = 16.0;
    style.text_styles.insert(
        egui::TextStyle::Heading,
        egui::FontId::new(24.0, egui::FontFamily::Proportional),
    );
    style.text_styles.insert(
        egui::TextStyle::Body,
        egui::FontId::new(15.0, egui::FontFamily::Proportional),
    );
    style.text_styles.insert(
        egui::TextStyle::Monospace,
        egui::FontId::new(14.0, egui::FontFamily::Monospace),
    );
    style.text_styles.insert(
        egui::TextStyle::Button,
        egui::FontId::new(14.0, egui::FontFamily::Proportional),
    );
    ctx.set_style_of(egui::Theme::Dark, style);
}

fn panel_frame() -> egui::Frame {
    egui::Frame::default()
        .fill(palette().panel)
        .stroke(egui::Stroke::new(1.0, palette().border))
        .inner_margin(12)
}

fn card(ui: &mut egui::Ui, add_contents: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::default()
        .fill(palette().panel)
        .stroke(egui::Stroke::new(1.0, palette().border))
        .corner_radius(8)
        .inner_margin(14)
        .show(ui, add_contents);
}

fn section_header(ui: &mut egui::Ui, title: &str, subtitle: &str) {
    ui.heading(title);
    ui.label(egui::RichText::new(subtitle).color(palette().muted_text));
    ui.add_space(12.0);
}

fn mini_header(ui: &mut egui::Ui, title: &str) {
    ui.label(
        egui::RichText::new(title)
            .strong()
            .color(palette().accent)
            .size(15.0),
    );
    ui.add_space(4.0);
}

fn labeled_row(ui: &mut egui::Ui, label: &str, add_contents: impl FnOnce(&mut egui::Ui)) {
    ui.horizontal(|ui| {
        ui.add_sized(
            [160.0, 20.0],
            egui::Label::new(egui::RichText::new(label).color(palette().muted_text)),
        );
        add_contents(ui);
    });
}

fn labeled_text_edit(ui: &mut egui::Ui, label: &str, value: &mut String, secret: bool) {
    labeled_row(ui, label, |ui| {
        let mut edit = egui::TextEdit::singleline(value).desired_width(f32::INFINITY);
        if secret {
            edit = edit.password(true);
        }
        ui.add(edit);
    });
}

fn labeled_value(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.add_sized(
            [160.0, 20.0],
            egui::Label::new(egui::RichText::new(label).color(palette().muted_text)),
        );
        ui.label(egui::RichText::new(value).monospace());
    });
}

fn status_badge(ui: &mut egui::Ui, text: &str, color: egui::Color32) {
    let fill = egui::Color32::from_rgba_premultiplied(color.r(), color.g(), color.b(), 40);
    egui::Frame::default()
        .fill(fill)
        .stroke(egui::Stroke::new(1.0, color))
        .corner_radius(6)
        .inner_margin(egui::Margin::symmetric(8, 4))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(text).color(color).strong());
        });
}

fn warning_banner(ui: &mut egui::Ui, title: &str, body: &str, color: egui::Color32) {
    let fill = egui::Color32::from_rgba_premultiplied(color.r(), color.g(), color.b(), 32);
    egui::Frame::default()
        .fill(fill)
        .stroke(egui::Stroke::new(1.0, color))
        .corner_radius(6)
        .inner_margin(10)
        .show(ui, |ui| {
            ui.label(egui::RichText::new(title).strong().color(color));
            ui.label(body);
        });
}

fn code_block(ui: &mut egui::Ui, text: &str) {
    egui::Frame::default()
        .fill(egui::Color32::from_rgb(20, 24, 30))
        .stroke(egui::Stroke::new(1.0, palette().border))
        .corner_radius(6)
        .inner_margin(8)
        .show(ui, |ui| {
            ui.label(egui::RichText::new(text).monospace());
        });
}

fn nav_button(ui: &mut egui::Ui, screen: &mut Screen, target: Screen, label: &str) {
    let selected = *screen == target;
    if ui.selectable_label(selected, label).clicked() {
        *screen = target;
    }
}

fn centered_stage(ui: &mut egui::Ui, title: &str, body: &str) {
    ui.vertical_centered(|ui| {
        ui.add_space(120.0);
        ui.heading(title);
        ui.label(egui::RichText::new(body).color(palette().muted_text));
    });
}

fn balance_stat(ui: &mut egui::Ui, label: &str, value: u64, primary: bool) {
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(label).color(palette().muted_text));
        let text = if primary {
            egui::RichText::new(format!("{value} noms"))
                .strong()
                .size(22.0)
                .monospace()
        } else {
            egui::RichText::new(format!("{value} noms")).monospace()
        };
        ui.label(text);
    });
}

fn transaction_summary(ui: &mut egui::Ui, row: &crate::runtime::HistoryRow) {
    ui.horizontal_wrapped(|ui| {
        status_badge(ui, &row.status, status_color(&row.status));
        ui.label(egui::RichText::new(format!("ts {}", row.timestamp)).monospace());
        ui.label(egui::RichText::new(&row.tx_hash_hex).monospace());
    });
    if let Some(warning) = &row.warning {
        ui.label(egui::RichText::new(warning).color(palette().warning));
    }
}

fn status_color(status: &str) -> egui::Color32 {
    let lower = status.to_ascii_lowercase();
    if lower.contains("confirmed") || lower.contains("received") {
        palette().success
    } else if lower.contains("failed") || lower.contains("rejected") {
        palette().danger
    } else if lower.contains("building")
        || lower.contains("submitted")
        || lower.contains("observed")
    {
        palette().info
    } else if lower.contains("reorg") || lower.contains("rolled") {
        palette().warning
    } else {
        palette().muted_text
    }
}

fn network_state_color(state: crate::runtime::NetworkStatusState) -> egui::Color32 {
    match state {
        crate::runtime::NetworkStatusState::Connected => palette().success,
        crate::runtime::NetworkStatusState::TcpConnecting
        | crate::runtime::NetworkStatusState::TcpConnected
        | crate::runtime::NetworkStatusState::Handshaking
        | crate::runtime::NetworkStatusState::Reconnecting => palette().warning,
        crate::runtime::NetworkStatusState::Disconnected
        | crate::runtime::NetworkStatusState::Failed => palette().danger,
    }
}

fn runtime_status_strip(ui: &mut egui::Ui, runtime: &AppRuntime) {
    status_badge(
        ui,
        runtime.node_connection.state_label(),
        network_state_color(runtime.node_connection.status.state),
    );
    if let Some(balance) = runtime.wallet_balance {
        status_badge(
            ui,
            &format!("Spendable {} noms", balance.spendable()),
            palette().accent,
        );
    }
    if let Some(status) = &runtime.node_status {
        status_badge(
            ui,
            &format!("Height {}", status.chain_height),
            palette().info,
        );
        status_badge(
            ui,
            &format!("Mempool {}", status.mempool_size),
            palette().info,
        );
    }
    status_badge(
        ui,
        &format!("Tx rows {}", runtime.history.len()),
        palette().muted_text,
    );
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
