//! Interface graphique avec egui/eframe pour la démonstration Diffie-Hellman
//! 
//! Ce module crée une interface utilisateur graphique moderne et interactive
//! pour rendre la démonstration encore plus accessible et visuelle

use eframe::egui;
use num_bigint::BigUint;
use std::str::FromStr;
use std::time::Instant;
use rand::Rng;

// Modules internes
use crate::dh::{is_prime, compute_public_key, compute_shared_key};
use crate::attack::{brute_force_attack, smart_attack, AttackResult};
use crate::classify::{classify_prime_size, SecurityLevel, get_security_description, get_security_explanation};

// État de l'application
#[derive(Debug, Default)]
pub struct DiffieHellmanApp {
    // Paramètres
    pub p_input: String,
    pub g_input: String,
    pub a_input: String,
    pub b_input: String,
    
    // Valeurs calculées
    pub p: Option<BigUint>,
    pub g: Option<BigUint>,
    pub a: Option<BigUint>,
    pub b: Option<BigUint>,
    pub A: Option<BigUint>,
    pub B: Option<BigUint>,
    pub shared_key: Option<BigUint>,
    
    // État de sécurité
    pub security_level: Option<SecurityLevel>,
    
    // Résultat d'attaque
    pub attack_result: Option<AttackResult>,
    
    // État de l'interface
    pub show_error: Option<String>,
    pub show_success: Option<String>,
    pub attack_running: bool,
    pub attack_progress: f32,
    
    // Messages
    pub protocol_steps: Vec<String>,
    pub security_message: String,
    
    // Nouvelles fonctionnalités
    pub dark_mode: bool,
    pub selected_preset: usize,
    pub show_advanced: bool,
    pub animation_time: f32,
    pub last_update: Option<Instant>,
    pub auto_generate: bool,
    pub copy_buffer: String,
}

impl DiffieHellmanApp {
    // Crée une nouvelle instance de l'application
    pub fn new() -> Self {
        let mut app = Self::default();
        app.dark_mode = true;
        app.last_update = Some(Instant::now());
        app.selected_preset = 0;
        app
    }
    
    /// Retourne les presets prédéfinis
    fn get_presets() -> Vec<(&'static str, &'static str, &'static str, &'static str, &'static str)> {
        vec![
            ("Pédagogique (petit)", "23", "5", "6", "15"),
            ("Sécurité moyenne", "104729", "2", "12345", "67890"),
            ("Haute sécurité", "1000000007", "2", "987654321", "123456789"),
            ("Personnalisé", "", "", "", ""),
        ]
    }
    
    /// Applique un preset
    fn apply_preset(&mut self, preset_index: usize) {
        let presets = Self::get_presets();
        if preset_index < presets.len() {
            let (_name, p, g, a, b) = presets[preset_index];
            self.p_input = p.to_string();
            self.g_input = g.to_string();
            self.a_input = a.to_string();
            self.b_input = b.to_string();
            self.selected_preset = preset_index;
        }
    }
    
    /// Génère des paramètres aléatoires sécurisés
    fn generate_secure_parameters(&mut self) {
        use rand::thread_rng;
        
        let mut rng = thread_rng();
        
        // Générer un nombre premier de taille moyenne (1024 bits serait trop lent)
        let primes = vec![
            "104729", "1299709", "15485863", "32452843", "49979687"
        ];
        let p_str = primes[rng.gen_range(0..primes.len())];
        self.p_input = p_str.to_string();
        
        // g = 2 est souvent un bon choix
        self.g_input = "2".to_string();
        
        // Secrets aléatoires (simplifié)
        self.a_input = rng.gen_range(1000..99999).to_string();
        self.b_input = rng.gen_range(1000..99999).to_string();
    }
    
    /// Copie une valeur dans le presse-papiers
    fn copy_to_clipboard(&mut self, value: &str) {
        self.copy_buffer = value.to_string();
        self.show_success = Some(format!("Copié : {}", value));
    }
    
    // Valide et parse les paramètres
    fn validate_parameters(&mut self) -> bool {
        // Parse p
        match BigUint::from_str(&self.p_input) {
            Ok(p_val) => {
                if !is_prime(&p_val) {
                    self.show_error = Some("p n'est pas un nombre premier".to_string());
                    return false;
                }
                self.p = Some(p_val);
            }
            Err(_) => {
                self.show_error = Some("p n'est pas un nombre valide".to_string());
                return false;
            }
        }
        
        // Parse g
        match BigUint::from_str(&self.g_input) {
            Ok(g_val) => {
                if let Some(ref p_val) = self.p {
                    if g_val >= *p_val || g_val <= BigUint::from(1u32) {
                        self.show_error = Some("g doit être compris entre 1 et p".to_string());
                        return false;
                    }
                }
                self.g = Some(g_val);
            }
            Err(_) => {
                self.show_error = Some("g n'est pas un nombre valide".to_string());
                return false;
            }
        }
        
        // Parse a
        match BigUint::from_str(&self.a_input) {
            Ok(a_val) => {
                self.a = Some(a_val);
            }
            Err(_) => {
                self.show_error = Some("a n'est pas un nombre valide".to_string());
                return false;
            }
        }
        
        // Parse b
        match BigUint::from_str(&self.b_input) {
            Ok(b_val) => {
                self.b = Some(b_val);
            }
            Err(_) => {
                self.show_error = Some("b n'est pas un nombre valide".to_string());
                return false;
            }
        }
        
        self.show_error = None;
        true
    }
    
    // Calcule les clés publiques et partagées
    fn calculate_keys(&mut self) {
        if let (Some(ref p), Some(ref g), Some(ref a), Some(ref b)) = (&self.p, &self.g, &self.a, &self.b) {
            // Calculer les clés publiques
            let A_val = compute_public_key(g, a, p);
            let B_val = compute_public_key(g, b, p);
            
            // Calculer la clé partagée
            let shared_key_val = compute_shared_key(&A_val, b, p);
            
            self.A = Some(A_val.clone());
            self.B = Some(B_val.clone());
            self.shared_key = Some(shared_key_val.clone());
            
            // Classifier la sécurité
            self.security_level = Some(classify_prime_size(p));
            
            // Générer les étapes du protocole
            self.generate_protocol_steps();
            
            // Générer le message de sécurité
            self.generate_security_message();
            
            self.show_success = Some("Clés calculées avec succès !".to_string());
        }
    }
    
    // Génère les étapes du protocole pour l'affichage
    fn generate_protocol_steps(&mut self) {
        self.protocol_steps.clear();
        
        if let (Some(ref p), Some(ref g), Some(ref a), Some(ref b), Some(ref A), Some(ref B), Some(ref shared_key)) = 
            (&self.p, &self.g, &self.a, &self.b, &self.A, &self.B, &self.shared_key) {
            
            self.protocol_steps.push(format!("Paramètres publics : p = {}, g = {}", p, g));
            self.protocol_steps.push(format!("Secrets : a = {}, b = {}", a, b));
            self.protocol_steps.push(format!("Alice calcule : A = {}^{} mod {} = {}", g, a, p, A));
            self.protocol_steps.push(format!("Bob calcule : B = {}^{} mod {} = {}", g, b, p, B));
            self.protocol_steps.push(format!("Alice calcule la clé partagée : K = {}^{} mod {} = {}", B, a, p, shared_key));
            self.protocol_steps.push(format!("Bob calcule la clé partagée : K = {}^{} mod {} = {}", A, b, p, shared_key));
            self.protocol_steps.push(format!("Clé partagée finale : K = {}", shared_key));
        }
    }
    
    // Génère le message de sécurité
    fn generate_security_message(&mut self) {
        if let Some(ref level) = self.security_level {
            self.security_message = format!(
                "Niveau de sécurité : {}\n\n{}",
                get_security_description(level),
                get_security_explanation(level)
            );
        }
    }
    
    // Lance une attaque brute-force
    fn launch_brute_force_attack(&mut self) {
        if let (Some(ref p), Some(ref g), Some(ref A), Some(ref B)) = (&self.p, &self.g, &self.A, &self.B) {
            self.attack_running = true;
            self.attack_progress = 0.0;
            
            // Pour l'instant, on simule une attaque simple
            // Dans une vraie application, on lancerait cette attaque dans un thread séparé
            let max_attempts = 10000;
            let result = brute_force_attack(p, g, A, B, max_attempts, false);
            
            self.attack_result = Some(result);
            self.attack_running = false;
            self.attack_progress = 1.0;
        }
    }
    
    // Lance une attaque intelligente
    fn launch_smart_attack(&mut self) {
        if let (Some(ref p), Some(ref g), Some(ref A), Some(ref B)) = (&self.p, &self.g, &self.A, &self.B) {
            self.attack_running = true;
            self.attack_progress = 0.0;
            
            let result = smart_attack(p, g, A, B);
            
            self.attack_result = Some(result);
            self.attack_running = false;
            self.attack_progress = 1.0;
        }
    }
}

impl eframe::App for DiffieHellmanApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Mettre à jour le temps d'animation
        if let Some(last_update) = self.last_update {
            let now = Instant::now();
            self.animation_time += (now - last_update).as_secs_f32();
            self.last_update = Some(now);
        } else {
            self.last_update = Some(Instant::now());
        }
        
        // Appliquer le thème
        if self.dark_mode {
            ctx.set_visuals(egui::Visuals::dark());
        } else {
            ctx.set_visuals(egui::Visuals::light());
        }
        
        egui::CentralPanel::default().show(ctx, |ui| {
            // En-tête avec titre et contrôles
            ui.horizontal(|ui| {
                ui.heading("🔐 Démonstration Diffie-Hellman");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button(if self.dark_mode { "☀️" } else { "🌙" }).clicked() {
                        self.dark_mode = !self.dark_mode;
                    }
                    if ui.button("📊").clicked() {
                        self.show_advanced = !self.show_advanced;
                    }
                });
            });
            
            ui.separator();
            
            // Section des presets
            ui.horizontal(|ui| {
                ui.label("Preset:");
                let presets = Self::get_presets();
                let selected_text = presets[self.selected_preset].0;
                
                egui::ComboBox::from_label("")
                    .selected_text(&*selected_text)
                    .show_ui(ui, |ui| {
                        for (i, (name, _, _, _, _)) in presets.iter().enumerate() {
                            if ui.selectable_label(self.selected_preset == i, *name).clicked() {
                                self.apply_preset(i);
                            }
                        }
                    });
                
                if ui.button("🎲 Aléatoire").clicked() {
                    self.generate_secure_parameters();
                }
                
                if ui.button("🔄").clicked() {
                    *self = Self::new();
                }
            });
            
            ui.separator();
            
            // Section des paramètres avec style amélioré
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.heading("📋 Paramètres du protocole");
                
                // Paramètres publics
                ui.horizontal(|ui| {
                    ui.label("🔢 Nombre premier p:");
                    ui.add_sized([200.0, 20.0], egui::TextEdit::singleline(&mut self.p_input));
                    if !self.p_input.is_empty() && ui.button("📋").clicked() {
                        let value = self.p_input.clone();
                        self.copy_to_clipboard(&value);
                    }
                });
                ui.horizontal(|ui| {
                    ui.label("⚡ Générateur g:");
                    ui.add_sized([200.0, 20.0], egui::TextEdit::singleline(&mut self.g_input));
                    if !self.g_input.is_empty() && ui.button("📋").clicked() {
                        let value = self.g_input.clone();
                        self.copy_to_clipboard(&value);
                    }
                });
                
                ui.separator();
                
                ui.heading("🔐 Secrets d'Alice et Bob");
                ui.horizontal(|ui| {
                    ui.label("👩 Secret d'Alice (a):");
                    ui.add_sized([200.0, 20.0], egui::TextEdit::singleline(&mut self.a_input));
                    if !self.a_input.is_empty() && ui.button("📋").clicked() {
                        let value = self.a_input.clone();
                        self.copy_to_clipboard(&value);
                    }
                });
                ui.horizontal(|ui| {
                    ui.label("👨 Secret de Bob (b):");
                    ui.add_sized([200.0, 20.0], egui::TextEdit::singleline(&mut self.b_input));
                    if !self.b_input.is_empty() && ui.button("📋").clicked() {
                        let value = self.b_input.clone();
                        self.copy_to_clipboard(&value);
                    }
                });
            });
            
            // Messages avec style amélioré
            if let Some(ref error) = self.show_error {
                egui::Frame::none()
                    .fill(egui::Color32::from_rgb(255, 240, 240))
                    .stroke(egui::Stroke::new(1.0, egui::Color32::RED))
                    .rounding(4.0)
                    .show(ui, |ui| {
                        ui.colored_label(egui::Color32::RED, format!("❌ {}", error));
                    });
            }
            if let Some(ref success) = self.show_success {
                egui::Frame::none()
                    .fill(egui::Color32::from_rgb(240, 255, 240))
                    .stroke(egui::Stroke::new(1.0, egui::Color32::GREEN))
                    .rounding(4.0)
                    .show(ui, |ui| {
                        ui.colored_label(egui::Color32::GREEN, format!("✅ {}", success));
                    });
            }
            
            // Boutons d'action avec style
            ui.horizontal(|ui| {
                if ui.add_sized([150.0, 30.0], egui::Button::new("🔍 Valider").fill(egui::Color32::from_rgb(0, 120, 215))).clicked() {
                    if self.validate_parameters() {
                        self.calculate_keys();
                    }
                }
                if ui.add_sized([100.0, 30.0], egui::Button::new("🔄 Reset").fill(egui::Color32::from_rgb(108, 117, 125))).clicked() {
                    *self = Self::new();
                }
                ui.checkbox(&mut self.auto_generate, "Génération auto");
            });
            
            ui.separator();
            
            // Section de sécurité avec indicateur visuel
            if !self.security_message.is_empty() {
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.heading("🛡️ Analyse de sécurité");
                    
                    // Indicateur de sécurité visuel
                    if let Some(ref level) = self.security_level {
                        let (color, icon, text) = match level {
                            SecurityLevel::Small => (egui::Color32::RED, "🔴", "Non sécurisé"),
                            SecurityLevel::Medium => (egui::Color32::from_rgb(255, 165, 0), "🟡", "Faible"),
                            SecurityLevel::Large => (egui::Color32::from_rgb(0, 255, 0), "🟢", "Fort"),
                        };
                        
                        ui.horizontal(|ui| {
                            ui.colored_label(color, format!("{} {}", icon, text));
                            ui.add(egui::ProgressBar::new(0.5).fill(color));
                        });
                    }
                    
                    ui.label(&self.security_message);
                });
                ui.separator();
            }
            
            // Section du protocole avec mise en forme
            if !self.protocol_steps.is_empty() {
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.heading("🔄 Étapes du protocole");
                    
                    egui::Grid::new("protocol_grid")
                        .num_columns(2)
                        .spacing([10.0, 4.0])
                        .show(ui, |ui| {
                            for (i, step) in self.protocol_steps.iter().enumerate() {
                                ui.label(format!("{}.", i + 1));
                                ui.label(step);
                                ui.end_row();
                            }
                        });
                });
                ui.separator();
            }
            
            // Section d'attaque avec design amélioré
            if self.A.is_some() && self.B.is_some() {
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.heading("⚔️ Simulation d'attaque");
                    
                    ui.horizontal(|ui| {
                        let brute_force_btn = ui.add_sized(
                            [150.0, 30.0],
                            egui::Button::new("💥 Brute-Force")
                                .fill(if self.attack_running { egui::Color32::GRAY } else { egui::Color32::from_rgb(220, 53, 69) })
                        );
                        
                        let smart_btn = ui.add_sized(
                            [150.0, 30.0],
                            egui::Button::new("🧠 Intelligente")
                                .fill(if self.attack_running { egui::Color32::GRAY } else { egui::Color32::from_rgb(23, 162, 184) })
                        );
                        
                        if brute_force_btn.clicked() && !self.attack_running {
                            self.launch_brute_force_attack();
                        }
                        if smart_btn.clicked() && !self.attack_running {
                            self.launch_smart_attack();
                        }
                    });
                    
                    // Progression animée
                    if self.attack_running {
                        ui.add(
                            egui::ProgressBar::new(self.attack_progress)
                                .show_percentage()
                                .fill(egui::Color32::from_rgb(255, 193, 7))
                        );
                        ui.label("🔍 Recherche en cours...");
                    }
                    
                    // Résultat détaillé
                    if let Some(ref result) = self.attack_result {
                        ui.separator();
                        ui.heading("📊 Résultat de l'attaque");
                        
                        // Carte de résultat
                        egui::Frame::none()
                            .fill(if result.secret.is_some() { 
                                egui::Color32::from_rgb(255, 240, 240) 
                            } else { 
                                egui::Color32::from_rgb(240, 255, 240) 
                            })
                            .rounding(8.0)
                            .show(ui, |ui| {
                                ui.label(&result.message);
                                
                                ui.horizontal(|ui| {
                                    ui.label("⏱️ Temps:");
                                    ui.label(format!("{:.2}s", result.duration.as_secs_f64()));
                                });
                                
                                ui.horizontal(|ui| {
                                    ui.label("🔄 Tentatives:");
                                    ui.label(format!("{}", result.attempts));
                                });
                                
                                if let (Some(ref secret), Some(ref shared_key)) = (&result.secret, &result.shared_key) {
                                    ui.separator();
                                    ui.colored_label(egui::Color32::RED, format!("🚨 Secret découvert : {}", secret));
                                    ui.colored_label(egui::Color32::RED, format!("🔓 Clé partagée : {}", shared_key));
                                } else {
                                    ui.colored_label(egui::Color32::GREEN, "✅ La communication reste sécurisée !");
                                }
                            });
                    }
                });
            }
        });
    }
}

// Lance l'interface graphique
pub fn run_gui() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1000.0, 800.0])
            .with_min_inner_size([800.0, 600.0])
            .with_title("🔐 Démonstration Diffie-Hellman - Interface Améliorée"),
        ..Default::default()
    };
    
    eframe::run_native(
        "Démonstration Diffie-Hellman",
        options,
        Box::new(|cc| {
            // Configure le renderer pour de meilleures performances
            cc.egui_ctx.set_pixels_per_point(1.0);
            Box::new(DiffieHellmanApp::new())
        }),
    )
}
