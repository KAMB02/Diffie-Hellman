//! Programme principal de démonstration du protocole Diffie-Hellman
//! 
//! Ce programme offre une démonstration interactive et pédagogique du protocole
//! Diffie-Hellman, montrant comment la taille du nombre premier p affecte la sécurité.
//! 
//! Auteur : Démo pédagogique pour lycéens
//! Objectif : Comprendre les bases de la cryptographie moderne

use std::io::{self, Write};
use std::str::FromStr;
use num_bigint::BigUint;

// Modules internes
mod dh;
mod attack;
mod classify;
mod display;

use dh::{is_prime, compute_public_key, compute_shared_key};
use attack::{brute_force_attack, smart_attack, display_attack_result};
use classify::{classify_prime_size, SecurityLevel};
use display::{
    display_title, display_section, explain_parameters, display_classification,
    display_protocol_steps, display_attack_menu, display_brute_force_options,
    display_conclusion, display_error, display_success, display_info
};

/// Point d'entrée du programme
fn main() {
    display_title("DÉMONSTRATION DU PROTOCOLE DIFFIE-HELLMAN");
    
    println!("🎓 BIENVENUE DANS CETTE DÉMONSTRATION PÉDAGOGIQUE !");
    println!("Nous allons explorer comment le protocole Diffie-Hellman permet à");
    println!("Alice et Bob de communiquer secrètement, et comment Ismaël peut attaquer...");
    
    // Boucle principale du programme
    loop {
        match main_menu() {
            MenuResult::Quit => break,
            MenuResult::Continue => continue,
            MenuResult::NewDemo => {
                if let Err(e) = run_demonstration() {
                    display_error(&format!("Erreur lors de la démonstration : {}", e));
                }
            }
        }
    }
    
    display_title("AU REVOIR !");
    println!("Merci d'avoir exploré la cryptographie avec nous !");
    println!("N'oubliez pas : en sécurité, la taille des nombres compte ! 🔐");
}

/// Résultat du menu principal
enum MenuResult {
    NewDemo,
    Continue,
    Quit,
}

/// Affiche le menu principal et gère le choix de l'utilisateur
fn main_menu() -> MenuResult {
    println!("\n{}", "=".repeat(70));
    println!("📋 MENU PRINCIPAL");
    println!("{}", "=".repeat(70));
    println!("1. 🚀 Lancer une nouvelle démonstration Diffie-Hellman");
    println!("2. ❓ Afficher l'aide sur les paramètres p et g");
    println!("3. 🚪 Quitter le programme");
    println!("{}", "-".repeat(70));
    
    print!("💭 Votre choix (1-3) : ");
    io::stdout().flush().unwrap();
    
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    
    match input.trim() {
        "1" => MenuResult::NewDemo,
        "2" => {
            explain_parameters();
            MenuResult::Continue
        }
        "3" => MenuResult::Quit,
        _ => {
            display_error("Choix invalide. Veuillez entrer 1, 2 ou 3.");
            MenuResult::Continue
        }
    }
}

/// Fonction principale de la démonstration
fn run_demonstration() -> Result<(), Box<dyn std::error::Error>> {
    display_title("NOUVELLE DÉMONSTRATION DIFFIE-HELLMAN");
    
    // Étape 1 : Saisie des paramètres publics p et g
    let (p, g) = get_public_parameters()?;
    
    // Étape 2 : Classification et explication de la sécurité
    let security_level = classify_prime_size(&p);
    display_classification(&p, &security_level);
    
    // Étape 3 : Saisie des secrets a et b
    let (a, b) = get_secret_parameters()?;
    
    // Étape 4 : Calcul des clés publiques
    let A = compute_public_key(&g, &a, &p);
    let B = compute_public_key(&g, &b, &p);
    
    // Étape 5 : Calcul de la clé partagée
    let shared_key = compute_shared_key(&A, &b, &p);
    
    // Étape 6 : Affichage des étapes du protocole
    display_protocol_steps(&p, &g, &a, &b, &A, &B, &shared_key);
    
    // Étape 7 : Proposer l'attaque
    if want_to_attack()? {
        run_attack_simulation(&p, &g, &A, &B, &shared_key, &security_level);
    }
    
    // Étape 8 : Conclusion
    display_conclusion(&shared_key, &security_level);
    
    Ok(())
}

/// Demande à l'utilisateur de saisir les paramètres publics p et g
fn get_public_parameters() -> Result<(BigUint, BigUint), Box<dyn std::error::Error>> {
    display_section("Saisie des paramètres publics");
    
    // Saisie de p
    let p = loop {
        println!("📌 Saisissez le nombre premier p (ex: 23, 101, 10007) :");
        print!("   p = ");
        io::stdout().flush().unwrap();
        
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        
        match BigUint::from_str(input.trim()) {
            Ok(num) => {
                if is_prime(&num) {
                    display_success(&format!("{} est bien un nombre premier !", num));
                    break num;
                } else {
                    display_error("Ce nombre n'est pas premier. Veuillez en choisir un autre.");
                }
            }
            Err(_) => {
                display_error("Nombre invalide. Veuillez entrer un entier positif.");
            }
        }
    };
    
    // Saisie de g
    let g = loop {
        println!("\n📌 Saisissez le générateur g (doit être < p) :");
        print!("   g = ");
        io::stdout().flush().unwrap();
        
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        
        match BigUint::from_str(input.trim()) {
            Ok(num) => {
                if num < p && num > BigUint::from(1u32) {
                    display_success(&format!("g = {} est valide (1 < g < p)", num));
                    break num;
                } else {
                    display_error(&format!("g doit être compris entre 1 et {}", p));
                }
            }
            Err(_) => {
                display_error("Nombre invalide. Veuillez entrer un entier positif.");
            }
        }
    };
    
    Ok((p, g))
}

/// Demande à l'utilisateur de saisir les secrets a et b
fn get_secret_parameters() -> Result<(BigUint, BigUint), Box<dyn std::error::Error>> {
    display_section("Saisie des secrets d'Alice et Bob");
    
    println!("🤫 Ces nombres sont SECRETS ! Personne ne doit les connaître...");
    
    // Saisie de a (secret d'Alice)
    let a = loop {
        println!("\n👩 Alice choisit son secret a :");
        print!("   a = ");
        io::stdout().flush().unwrap();
        
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        
        match BigUint::from_str(input.trim()) {
            Ok(num) => {
                if num > BigUint::from(0u32) {
                    display_success("Alice a choisi son secret en toute sécurité !");
                    break num;
                } else {
                    display_error("Le secret doit être un entier positif.");
                }
            }
            Err(_) => {
                display_error("Nombre invalide. Veuillez entrer un entier positif.");
            }
        }
    };
    
    // Saisie de b (secret de Bob)
    let b = loop {
        println!("\n👨 Bob choisit son secret b :");
        print!("   b = ");
        io::stdout().flush().unwrap();
        
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        
        match BigUint::from_str(input.trim()) {
            Ok(num) => {
                if num > BigUint::from(0u32) {
                    display_success("Bob a choisi son secret en toute sécurité !");
                    break num;
                } else {
                    display_error("Le secret doit être un entier positif.");
                }
            }
            Err(_) => {
                display_error("Nombre invalide. Veuillez entrer un entier positif.");
            }
        }
    };
    
    Ok((a, b))
}

/// Demande à l'utilisateur s'il veut lancer une attaque
fn want_to_attack() -> Result<bool, Box<dyn std::error::Error>> {
    display_attack_menu();
    
    loop {
        print!("💭 Votre choix (1-3) : ");
        io::stdout().flush().unwrap();
        
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        
        match input.trim() {
            "1" => return Ok(true),
            "2" => return Ok(true),
            "3" => {
                display_info("Vous respectez la vie privée d'Alice et Bob !");
                return Ok(false);
            }
            _ => {
                display_error("Choix invalide. Veuillez entrer 1, 2 ou 3.");
            }
        }
    }
}

/// Lance la simulation d'attaque
fn run_attack_simulation(
    p: &BigUint,
    g: &BigUint,
    A: &BigUint,
    B: &BigUint,
    shared_key: &BigUint,
    _security_level: &SecurityLevel,
) {
    display_section("Simulation d'attaque d'Ismaël");
    
    println!("🎯 Ismaël connaît : p = {}, g = {}, A = {}, B = {}", p, g, A, B);
    println!("🔍 Il cherche à retrouver la clé partagée : {}", shared_key);
    
    loop {
        println!("\n⚔️  CHOISISSEZ LA MÉTHODE D'ATTAQUE :");
        println!("   1. 🤖 Attaque brute-force (tester toutes les possibilités)");
        println!("   2. 🧠 Attaque intelligente (algorithmes avancés)");
        println!("   3. 🚪 Retour au menu principal");
        print!("💭 Votre choix (1-3) : ");
        io::stdout().flush().unwrap();
        
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        
        match input.trim() {
            "1" => {
                run_brute_force_attack(p, g, A, B);
                break;
            }
            "2" => {
                let result = smart_attack(p, g, A, B);
                display_attack_result(&result);
                break;
            }
            "3" => {
                display_info("Ismaël abandonne son attaque.");
                break;
            }
            _ => {
                display_error("Choix invalide. Veuillez entrer 1, 2 ou 3.");
            }
        }
    }
}

/// Lance une attaque brute-force avec paramètres personnalisés
fn run_brute_force_attack(p: &BigUint, g: &BigUint, A: &BigUint, B: &BigUint) {
    display_brute_force_options();
    
    let max_attempts = loop {
        print!("💭 Nombre maximum de tentatives (ex: 1000, 100000) : ");
        io::stdout().flush().unwrap();
        
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        
        match input.trim().parse::<u64>() {
            Ok(num) if num > 0 => break num,
            Ok(_) => display_error("Le nombre doit être positif."),
            Err(_) => display_error("Nombre invalide. Veuillez entrer un entier."),
        }
    };
    
    let show_progress = loop {
        print!("💭 Afficher la progression ? (o/n) : ");
        io::stdout().flush().unwrap();
        
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        
        match input.trim().to_lowercase().as_str() {
            "o" | "oui" | "yes" | "y" => break true,
            "n" | "non" | "no" => break false,
            _ => display_error("Réponse invalide. Veuillez entrer 'o' ou 'n'."),
        }
    };
    
    let result = brute_force_attack(p, g, A, B, max_attempts, show_progress);
    display_attack_result(&result);
}
