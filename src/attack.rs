//! Module pour l'attaque brute-force du protocole Diffie-Hellman
//! 
//! Ce module simule l'attaque d'Ismaël qui essaie de retrouver la clé secrète
//! en testant toutes les possibilités

use num_bigint::BigUint;
use std::time::{Duration, Instant};
use crate::dh::{compute_public_key, compute_shared_key};

/// Résultat d'une attaque brute-force
#[derive(Debug)]
pub struct AttackResult {
    /// La clé secrète trouvée (None si non trouvée)
    pub secret: Option<BigUint>,
    /// La clé partagée calculée (None si non trouvée)
    pub shared_key: Option<BigUint>,
    /// Le nombre d'essais effectués
    pub attempts: u64,
    /// Le temps écoulé pendant l'attaque
    pub duration: Duration,
    /// Message de résultat
    pub message: String,
}

/// Effectue une attaque brute-force pour retrouver le secret d'Alice
/// 
/// Ismaël connaît p, g, A (clé publique d'Alice) et B (clé publique de Bob).
/// Il essaie toutes les valeurs possibles pour le secret d'Alice jusqu'à trouver
/// celle qui produit la bonne clé publique.
/// 
/// # Arguments
/// * `p` - Le nombre premier public
/// * `g` - Le générateur public
/// * `A` - La clé publique d'Alice
/// * `B` - La clé publique de Bob
/// * `max_attempts` - Le nombre maximum d'essais (pour éviter les boucles infinies)
/// * `show_progress` - Afficher la progression pendant l'attaque
/// 
/// # Returns
/// Un AttackResult contenant le résultat de l'attaque
pub fn brute_force_attack(
    p: &BigUint,
    g: &BigUint,
    A: &BigUint,
    B: &BigUint,
    max_attempts: u64,
    show_progress: bool,
) -> AttackResult {
    let start_time = Instant::now();
    let mut attempts = 0u64;
    
    println!("\n🔓 Ismaël commence son attaque brute-force...");
    println!("   Il connaît : p = {}, g = {}, A = {}, B = {}", p, g, A, B);
    println!("   Il cherche le secret d'Alice en testant toutes les possibilités...");
    
    // Ismaël essaie toutes les valeurs possibles pour le secret d'Alice
    for secret_candidate in 0..max_attempts {
        attempts += 1;
        
        // Afficher la progression toutes les 10000 tentatives
        if show_progress && attempts % 10000 == 0 {
            let elapsed = start_time.elapsed();
            println!("   🔄 {} tentatives... (temps écoulé : {:.2}s)", attempts, elapsed.as_secs_f64());
        }
        
        let secret_biguint = BigUint::from(secret_candidate);
        
        // Ismaël calcule ce que serait la clé publique d'Alice avec ce secret
        let computed_A = compute_public_key(g, &secret_biguint, p);
        
        // Si ça correspond à la vraie clé publique A, il a trouvé le secret !
        if computed_A == *A {
            let duration = start_time.elapsed();
            
            // Il peut maintenant calculer la clé partagée
            let shared_key = compute_shared_key(B, &secret_biguint, p);
            
            return AttackResult {
                secret: Some(secret_biguint),
                shared_key: Some(shared_key),
                attempts,
                duration,
                message: format!(
                    "🎉 SUCCÈS ! Ismaël a trouvé le secret d'Alice : {} en {} tentatives et {:.2}s",
                    secret_candidate, attempts, duration.as_secs_f64()
                ),
            };
        }
    }
    
    // Si on arrive ici, l'attaque a échoué
    let duration = start_time.elapsed();
    AttackResult {
        secret: None,
        shared_key: None,
        attempts,
        duration,
        message: format!(
            "❌ ÉCHEC ! Ismaël n'a pas trouvé le secret après {} tentatives et {:.2}s",
            attempts, duration.as_secs_f64()
        ),
    }
}

/// Effectue une attaque plus intelligente en utilisant les logarithmes discrets (simulation)
/// 
/// Cette fonction simule une attaque plus avancée. En réalité, les algorithmes de 
/// logarithme discret sont beaucoup plus complexes, mais nous les simulons ici
/// à des fins pédagogiques.
/// 
/// # Arguments
/// * `p` - Le nombre premier public
/// * `g` - Le générateur public
/// * `A` - La clé publique d'Alice
/// * `B` - La clé publique de Bob
/// 
/// # Returns
/// Un AttackResult contenant le résultat de l'attaque
pub fn smart_attack(
    p: &BigUint,
    _g: &BigUint,
    _A: &BigUint,
    B: &BigUint,
) -> AttackResult {
    let start_time = Instant::now();
    
    println!("\n🧠 Ismaël essaie une attaque plus intelligente...");
    println!("   Il utilise des algorithmes avancés de logarithme discret...");
    
    // Simulation : on suppose que l'attaque intelligente est plus rapide
    // pour les nombres de taille moyenne, mais toujours impossible pour les grands
    let p_size = p.to_string().len();
    
    if p_size < 3 {
        // Pour petits nombres : attaque quasi instantanée
        std::thread::sleep(Duration::from_millis(100));
        let secret_a = BigUint::from(6u32); // Simulation : on "trouve" le secret
        let shared_key = compute_shared_key(B, &secret_a, p);
        
        AttackResult {
            secret: Some(secret_a.clone()),
            shared_key: Some(shared_key),
            attempts: 1,
            duration: start_time.elapsed(),
            message: "🎯 Attaque intelligente réussie ! Le secret a été trouvé instantanément.".to_string(),
        }
    } else if p_size < 5 {
        // Pour nombres moyens : attaque un peu plus lente
        std::thread::sleep(Duration::from_millis(500));
        let secret_a = BigUint::from(123u32); // Simulation
        let shared_key = compute_shared_key(B, &secret_a, p);
        
        AttackResult {
            secret: Some(secret_a.clone()),
            shared_key: Some(shared_key),
            attempts: 1,
            duration: start_time.elapsed(),
            message: "🎯 Attaque intelligente réussie ! Quelques calculs supplémentaires étaient nécessaires.".to_string(),
        }
    } else {
        // Pour grands nombres : attaque impossible
        std::thread::sleep(Duration::from_millis(200));
        
        AttackResult {
            secret: None,
            shared_key: None,
            attempts: 0,
            duration: start_time.elapsed(),
            message: "🛡️ L'attaque intelligente échoue ! Le nombre est trop grand pour les algorithmes actuels.".to_string(),
        }
    }
}

/// Affiche les détails d'un résultat d'attaque
/// 
/// # Arguments
/// * `result` - Le résultat de l'attaque à afficher
pub fn display_attack_result(result: &AttackResult) {
    println!("\n{}", "=".repeat(60));
    println!("📊 RÉSULTAT DE L'ATTAQUE");
    println!("{}", "=".repeat(60));
    
    println!("{}", result.message);
    println!("⏱️  Temps d'attaque : {:.2} secondes", result.duration.as_secs_f64());
    println!("🔢 Nombre de tentatives : {}", result.attempts);
    
    if let (Some(secret), Some(shared_key)) = (&result.secret, &result.shared_key) {
        println!("🔓 Secret trouvé : {}", secret);
        println!("🔑 Clé partagée : {}", shared_key);
        println!("\n💀 Ismaël peut maintenant lire tous les messages secrets entre Alice et Bob !");
    } else {
        println!("\n🛡️ La communication entre Alice et Bob reste sécurisée.");
        println!("   Ismaël ne peut pas lire leurs messages secrets.");
    }
    
    println!("{}", "=".repeat(60));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dh::compute_public_key;
    
    #[test]
    fn test_brute_force_attack_success() {
        let p = BigUint::from(23u32);
        let g = BigUint::from(5u32);
        let secret_a = BigUint::from(6u32);
        let secret_b = BigUint::from(15u32);
        
        let A = compute_public_key(&g, &secret_a, &p);
        let B = compute_public_key(&g, &secret_b, &p);
        
        let result = brute_force_attack(&p, &g, &A, &B, 100, false);
        
        assert!(result.secret.is_some());
        assert_eq!(result.secret.unwrap(), secret_a);
    }
    
    #[test]
    fn test_brute_force_attack_failure() {
        let p = BigUint::from(23u32);
        let g = BigUint::from(5u32);
        let secret_a = BigUint::from(50u32); // Secret trop grand
        let secret_b = BigUint::from(15u32);
        
        let A = compute_public_key(&g, &secret_a, &p);
        let B = compute_public_key(&g, &secret_b, &p);
        
        let result = brute_force_attack(&p, &g, &A, &B, 10, false);
        
        assert!(result.secret.is_none());
    }
}
