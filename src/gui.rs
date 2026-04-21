//! Interface graphique avec Flet pour la démonstration Diffie-Hellman
//! 
//! Ce module crée une interface utilisateur graphique moderne et interactive
//! pour rendre la démonstration encore plus accessible et visuelle

use flet::{colors, theme, App, Control, CrossAxisAlignment, MainAxisAlignment, Page, Row, Column, Container, Card, ElevatedButton, OutlinedButton, Text, TextField, Icon, icons, MainAxisAlignment as MainAxisAlignment2, CrossAxisAlignment as CrossAxisAlignment2, Border, BorderRadius, Margin, Padding, Alignment, BoxShadow, TextTheme, TextStyle, FontWeight, ScrollMode, ScrollbarMode};
use num_bigint::BigUint;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use tokio::sync::RwLock;

// Modules internes
use dh::{is_prime, compute_public_key, compute_shared_key};
use attack::{brute_force_attack, smart_attack, AttackResult};
use classify::{classify_prime_size, SecurityLevel, get_security_description, get_security_explanation};

/// État de l'application partagé entre les callbacks
#[derive(Debug, Clone)]
pub struct AppState {
    pub p: Option<BigUint>,
    pub g: Option<BigUint>,
    pub a: Option<BigUint>,
    pub b: Option<BigUint>,
    pub A: Option<BigUint>,
    pub B: Option<BigUint>,
    pub shared_key: Option<BigUint>,
    pub security_level: Option<SecurityLevel>,
    pub attack_result: Option<AttackResult>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            p: None,
            g: None,
            a: None,
            b: None,
            A: None,
            B: None,
            shared_key: None,
            security_level: None,
            attack_result: None,
        }
    }
}

/// Crée l'interface graphique principale
pub async fn create_gui_app() -> Result<Page, Box<dyn std::error::Error>> {
    let state = Arc::new(RwLock::new(AppState::default()));
    
    // Page principale
    let mut page = Page::new();
    page.title = "Démonstration Diffie-Hellman";
    page.theme = theme::Theme::LIGHT;
    page.scroll = ScrollMode::AUTO;
    page.vertical_scroll = ScrollbarMode::ALWAYS;
    
    // En-tête
    let header = create_header();
    
    // Section des paramètres
    let params_section = create_parameters_section(state.clone()).await?;
    
    // Section de sécurité
    let security_section = create_security_section(state.clone()).await?;
    
    // Section du protocole
    let protocol_section = create_protocol_section(state.clone()).await?;
    
    // Section d'attaque
    let attack_section = create_attack_section(state.clone()).await?;
    
    // Section de conclusion
    let conclusion_section = create_conclusion_section(state.clone()).await?;
    
    // Assemblage de la page
    page.content = Column::new()
        .extend(header)
        .extend(params_section)
        .extend(security_section)
        .extend(protocol_section)
        .extend(attack_section)
        .extend(conclusion_section)
        .horizontal_alignment(CrossAxisAlignment2::CENTER)
        .spacing(20)
        .padding(Padding::all(20));
    
    Ok(page)
}

/// Crée l'en-tête de l'application
fn create_header() -> Column {
    Column::new()
        .push(
            Container::new(
                Text::new("Démonstration Diffie-Hellman")
                    .size(32)
                    .weight(FontWeight::BOLD)
                    .color(colors::BLUE)
            )
            .alignment(Alignment::CENTER)
            .margin(Margin::only(20, 10, 20, 10))
        )
        .push(
            Container::new(
                Text::new("Explorez comment Alice et Bob peuvent communiquer secrètement, et comment Ismaël peut attaquer !")
                    .size(16)
                    .color(colors::GREY_700)
                    .text_align(flet::TextAlign::CENTER)
            )
            .alignment(Alignment::CENTER)
            .margin(Margin::only(20, 0, 20, 20))
        )
        .push(
            Container::new(
                Row::new()
                    .push(
                        Icon::new(icons::Icons::SECURITY)
                            .size(40)
                            .color(colors::GREEN)
                    )
                    .push(
                        Icon::new(icons::Icons::LOCK)
                            .size(40)
                            .color(colors::ORANGE)
                    )
                    .push(
                        Icon::new(icons::Icons::HACKER)
                            .size(40)
                            .color(colors::RED)
                    )
                    .alignment(MainAxisAlignment2::SPACE_AROUND)
            )
            .margin(Margin::only(20, 0, 20, 30))
        )
}

/// Crée la section des paramètres
async fn create_parameters_section(state: Arc<RwLock<AppState>>) -> Result<Column, Box<dyn std::error::Error>> {
    let section = Column::new()
        .push(
            Card::new(
                Container::new(
                    Column::new()
                        .push(
                            Row::new()
                                .push(
                                    Icon::new(icons::Icons::SETTINGS)
                                        .size(24)
                                        .color(colors::BLUE)
                                )
                                .push(
                                    Text::new("Paramètres du protocole")
                                        .size(20)
                                        .weight(FontWeight::BOLD)
                                        .color(colors::BLUE)
                                )
                                .spacing(10)
                        )
                        .push(
                            Container::new(
                                Text::new("Choisissez les paramètres publics p (nombre premier) et g (générateur)")
                                    .size(14)
                                    .color(colors::GREY_600)
                            )
                            .margin(Margin::only(0, 5, 0, 15))
                        )
                        .push(
                            Row::new()
                                .push(
                                    Column::new()
                                        .push(
                                            Text::new("Nombre premier p")
                                                .size(14)
                                                .weight(FontWeight::BOLD)
                                        )
                                        .push(
                                            TextField::new("p_field")
                                                .label("Ex: 23, 101, 10007")
                                                .width(200)
                                        )
                                        .spacing(5)
                                )
                                .push(
                                    Column::new()
                                        .push(
                                            Text::new("Générateur g")
                                                .size(14)
                                                .weight(FontWeight::BOLD)
                                        )
                                        .push(
                                            TextField::new("g_field")
                                                .label("Ex: 5, 2, 3")
                                                .width(200)
                                        )
                                        .spacing(5)
                                )
                                .spacing(30)
                        )
                        .push(
                            Container::new(
                                ElevatedButton::new("Valider les paramètres")
                                    .on_click(|_| {
                                        // TODO: Implémenter la validation
                                        Box::pin(async { Ok(()) })
                                    })
                                    .bgcolor(colors::BLUE)
                                    .color(colors::WHITE)
                            )
                            .margin(Margin::only(0, 15, 0, 0))
                            .alignment(Alignment::CENTER)
                        )
                )
                .padding(Padding::all(20))
                .margin(Margin::all(10))
            )
            .elevation(4)
        )
        .push(
            Card::new(
                Container::new(
                    Column::new()
                        .push(
                            Row::new()
                                .push(
                                    Icon::new(icons::Icons::KEY)
                                        .size(24)
                                        .color(colors::GREEN)
                                )
                                .push(
                                    Text::new("Secrets d'Alice et Bob")
                                        .size(20)
                                        .weight(FontWeight::BOLD)
                                        .color(colors::GREEN)
                                )
                                .spacing(10)
                        )
                        .push(
                            Container::new(
                                Text::new("Choisissez les nombres secrets (seuls Alice et Bob les connaissent)")
                                    .size(14)
                                    .color(colors::GREY_600)
                            )
                            .margin(Margin::only(0, 5, 0, 15))
                        )
                        .push(
                            Row::new()
                                .push(
                                    Column::new()
                                        .push(
                                            Row::new()
                                                .push(
                                                    Icon::new(icons::Icons::PERSON)
                                                        .size(20)
                                                        .color(colors::PURPLE)
                                                )
                                                .push(
                                                    Text::new("Secret d'Alice (a)")
                                                        .size(14)
                                                        .weight(FontWeight::BOLD)
                                                )
                                                .spacing(5)
                                        )
                                        .push(
                                            TextField::new("a_field")
                                                .label("Ex: 6, 15, 123")
                                                .width(200)
                                        )
                                        .spacing(5)
                                )
                                .push(
                                    Column::new()
                                        .push(
                                            Row::new()
                                                .push(
                                                    Icon::new(icons::Icons::PERSON)
                                                        .size(20)
                                                        .color(colors::INDIGO)
                                                )
                                                .push(
                                                    Text::new("Secret de Bob (b)")
                                                        .size(14)
                                                        .weight(FontWeight::BOLD)
                                                )
                                                .spacing(5)
                                        )
                                        .push(
                                            TextField::new("b_field")
                                                .label("Ex: 15, 8, 456")
                                                .width(200)
                                        )
                                        .spacing(5)
                                )
                                .spacing(30)
                        )
                        .push(
                            Container::new(
                                ElevatedButton::new("Calculer les clés")
                                    .on_click(|_| {
                                        // TODO: Implémenter le calcul
                                        Box::pin(async { Ok(()) })
                                    })
                                    .bgcolor(colors::GREEN)
                                    .color(colors::WHITE)
                            )
                            .margin(Margin::only(0, 15, 0, 0))
                            .alignment(Alignment::CENTER)
                        )
                )
                .padding(Padding::all(20))
                .margin(Margin::all(10))
            )
            .elevation(4)
        );
    
    Ok(section)
}

/// Crée la section de sécurité
async fn create_security_section(state: Arc<RwLock<AppState>>) -> Result<Column, Box<dyn std::error::Error>> {
    let section = Column::new()
        .push(
            Card::new(
                Container::new(
                    Column::new()
                        .push(
                            Row::new()
                                .push(
                                    Icon::new(icons::Icons::SECURITY)
                                        .size(24)
                                        .color(colors::ORANGE)
                                )
                                .push(
                                    Text::new("Analyse de sécurité")
                                        .size(20)
                                        .weight(FontWeight::BOLD)
                                        .color(colors::ORANGE)
                                )
                                .spacing(10)
                        )
                        .push(
                            Container::new(
                                Text::new("Classification du niveau de sécurité selon la taille de p")
                                    .size(14)
                                    .color(colors::GREY_600)
                            )
                            .margin(Margin::only(0, 5, 0, 15))
                        )
                        .push(
                            Container::new(
                                Text::new("Veuillez d'abord saisir les paramètres...")
                                    .size(16)
                                    .color(colors::GREY_500)
                                    .text_align(flet::TextAlign::CENTER)
                            )
                            .alignment(Alignment::CENTER)
                            .padding(Padding::all(20))
                        )
                )
                .padding(Padding::all(20))
                .margin(Margin::all(10))
            )
            .elevation(4)
        );
    
    Ok(section)
}

/// Crée la section du protocole
async fn create_protocol_section(state: Arc<RwLock<AppState>>) -> Result<Column, Box<dyn std::error::Error>> {
    let section = Column::new()
        .push(
            Card::new(
                Container::new(
                    Column::new()
                        .push(
                            Row::new()
                                .push(
                                    Icon::new(icons::Icons::SYNC)
                                        .size(24)
                                        .color(colors::BLUE)
                                )
                                .push(
                                    Text::new("Étapes du protocole")
                                        .size(20)
                                        .weight(FontWeight::BOLD)
                                        .color(colors::BLUE)
                                )
                                .spacing(10)
                        )
                        .push(
                            Container::new(
                                Text::new("Visualisation des étapes d'échange des clés")
                                    .size(14)
                                    .color(colors::GREY_600)
                            )
                            .margin(Margin::only(0, 5, 0, 15))
                        )
                        .push(
                            Container::new(
                                Text::new("Veuillez d'abord calculer les clés...")
                                    .size(16)
                                    .color(colors::GREY_500)
                                    .text_align(flet::TextAlign::CENTER)
                            )
                            .alignment(Alignment::CENTER)
                            .padding(Padding::all(20))
                        )
                )
                .padding(Padding::all(20))
                .margin(Margin::all(10))
            )
            .elevation(4)
        );
    
    Ok(section)
}

/// Crée la section d'attaque
async fn create_attack_section(state: Arc<RwLock<AppState>>) -> Result<Column, Box<dyn std::error::Error>> {
    let section = Column::new()
        .push(
            Card::new(
                Container::new(
                    Column::new()
                        .push(
                            Row::new()
                                .push(
                                    Icon::new(icons::Icons::HACKER)
                                        .size(24)
                                        .color(colors::RED)
                                )
                                .push(
                                    Text::new("Simulation d'attaque")
                                        .size(20)
                                        .weight(FontWeight::BOLD)
                                        .color(colors::RED)
                                )
                                .spacing(10)
                        )
                        .push(
                            Container::new(
                                Text::new("Ismaël essaie de casser la clé partagée")
                                    .size(14)
                                    .color(colors::GREY_600)
                            )
                            .margin(Margin::only(0, 5, 0, 15))
                        )
                        .push(
                            Row::new()
                                .push(
                                    OutlinedButton::new("Attaque Brute-Force")
                                        .on_click(|_| {
                                            // TODO: Implémenter l'attaque brute-force
                                            Box::pin(async { Ok(()) })
                                        })
                                        .icon(icons::Icons::BOLT)
                                        .color(colors::ORANGE)
                                )
                                .push(
                                    OutlinedButton::new("Attaque Intelligente")
                                        .on_click(|_| {
                                            // TODO: Implémenter l'attaque intelligente
                                            Box::pin(async { Ok(()) })
                                        })
                                        .icon(icons::Icons::PSYCHOLOGY)
                                        .color(colors::PURPLE)
                                )
                                .spacing(10)
                                .alignment(MainAxisAlignment2::CENTER)
                        )
                        .push(
                            Container::new(
                                Text::new("Veuillez d'abord calculer les clés...")
                                    .size(16)
                                    .color(colors::GREY_500)
                                    .text_align(flet::TextAlign::CENTER)
                            )
                            .alignment(Alignment::CENTER)
                            .padding(Padding::all(20))
                        )
                )
                .padding(Padding::all(20))
                .margin(Margin::all(10))
            )
            .elevation(4)
        );
    
    Ok(section)
}

/// Crée la section de conclusion
async fn create_conclusion_section(state: Arc<RwLock<AppState>>) -> Result<Column, Box<dyn std::error::Error>> {
    let section = Column::new()
        .push(
            Card::new(
                Container::new(
                    Column::new()
                        .push(
                            Row::new()
                                .push(
                                    Icon::new(icons::Icons::SCHOOL)
                                        .size(24)
                                        .color(colors::GREEN)
                                )
                                .push(
                                    Text::new("Conclusion")
                                        .size(20)
                                        .weight(FontWeight::BOLD)
                                        .color(colors::GREEN)
                                )
                                .spacing(10)
                        )
                        .push(
                            Container::new(
                                Text::new("Ce que nous avons appris sur la cryptographie")
                                    .size(14)
                                    .color(colors::GREY_600)
                            )
                            .margin(Margin::only(0, 5, 0, 15))
                        )
                        .push(
                            Container::new(
                                Text::new("Effectuez une démonstration complète pour voir la conclusion...")
                                    .size(16)
                                    .color(colors::GREY_500)
                                    .text_align(flet::TextAlign::CENTER)
                            )
                            .alignment(Alignment::CENTER)
                            .padding(Padding::all(20))
                        )
                )
                .padding(Padding::all(20))
                .margin(Margin::all(10))
            )
            .elevation(4)
        );
    
    Ok(section)
}
