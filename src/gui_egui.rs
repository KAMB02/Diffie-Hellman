//! Interface graphique avec egui/eframe pour la démonstration Diffie-Hellman
//! 
//! Ce module crée une interface utilisateur graphique moderne et interactive
//! pour rendre la démonstration encore plus accessible et visuelle

use eframe::egui;
use num_bigint::BigUint;
use std::str::FromStr;

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
}

impl DiffieHellmanApp {
    // Crée une nouvelle instance de l'application
    pub fn new() -> Self {
        Self::default()
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
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Démonstration Diffie-Hellman");
            ui.separator();
            
            // Section des paramètres
            ui.heading("Paramètres du protocole");
            ui.horizontal(|ui| {
                ui.label("Nombre premier p:");
                ui.text_edit_singleline(&mut self.p_input);
            });
            ui.horizontal(|ui| {
                ui.label("Générateur g:");
                ui.text_edit_singleline(&mut self.g_input);
            });
            
            ui.separator();
            
            ui.heading("Secrets d'Alice et Bob");
            ui.horizontal(|ui| {
                ui.label("Secret d'Alice (a):");
                ui.text_edit_singleline(&mut self.a_input);
            });
            ui.horizontal(|ui| {
                ui.label("Secret de Bob (b):");
                ui.text_edit_singleline(&mut self.b_input);
            });
            
            // Messages d'erreur et de succès
            if let Some(ref error) = self.show_error {
                ui.colored_label(egui::Color32::RED, error);
            }
            if let Some(ref success) = self.show_success {
                ui.colored_label(egui::Color32::GREEN, success);
            }
            
            // Boutons d'action
            ui.horizontal(|ui| {
                if ui.button("Valider les paramètres").clicked() {
                    if self.validate_parameters() {
                        self.calculate_keys();
                    }
                }
                if ui.button("Réinitialiser").clicked() {
                    *self = Self::default();
                }
            });
            
            ui.separator();
            
            // Section de sécurité
            if !self.security_message.is_empty() {
                ui.heading("Analyse de sécurité");
                ui.label(&self.security_message);
                ui.separator();
            }
            
            // Section du protocole
            if !self.protocol_steps.is_empty() {
                ui.heading("Étapes du protocole");
                for step in &self.protocol_steps {
                    ui.label(step);
                }
                ui.separator();
            }
            
            // Section d'attaque
            if self.A.is_some() && self.B.is_some() {
                ui.heading("Simulation d'attaque");
                ui.horizontal(|ui| {
                    if ui.button("Attaque Brute-Force").clicked() && !self.attack_running {
                        self.launch_brute_force_attack();
                    }
                    if ui.button("Attaque Intelligente").clicked() && !self.attack_running {
                        self.launch_smart_attack();
                    }
                });
                
                // Progression de l'attaque
                if self.attack_running {
                    ui.add(egui::ProgressBar::new(self.attack_progress).show_percentage());
                }
                
                // Résultat de l'attaque
                if let Some(ref result) = self.attack_result {
                    ui.separator();
                    ui.heading("Résultat de l'attaque");
                    ui.label(&result.message);
                    ui.label(format!("Temps d'attaque : {:.2} secondes", result.duration.as_secs_f64()));
                    ui.label(format!("Nombre de tentatives : {}", result.attempts));
                    
                    if let (Some(ref secret), Some(ref shared_key)) = (&result.secret, &result.shared_key) {
                        ui.colored_label(egui::Color32::RED, format!("Secret trouvé : {}", secret));
                        ui.colored_label(egui::Color32::RED, format!("Clé partagée : {}", shared_key));
                    } else {
                        ui.colored_label(egui::Color32::GREEN, "La communication reste sécurisée !");
                    }
                }
            }
        });
    }
}

// Lance l'interface graphique
pub fn run_gui() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([800.0, 600.0]),
        ..Default::default()
    };
    
    eframe::run_native(
        "Démonstration Diffie-Hellman",
        options,
        Box::new(|_cc| Box::new(DiffieHellmanApp::new())),
    )
}
