//! Module pour la classification des tailles de nombres premiers
//! 
//! Ce module permet de classer le nombre premier p selon sa taille
//! pour donner une indication sur le niveau de sécurité

use num_bigint::BigUint;

// Catégorie de sécurité pour un nombre premier
#[derive(Debug, Clone, PartialEq)]
pub enum SecurityLevel {
    // Petit nombre premier (< 100) - Très dangereux, attaque facile
    Small,
    // Nombre premier moyen (100 ≤ p < 10 000) - Attaquable avec effort
    Medium, 
    // Grand nombre premier (≥ 10 000) - Sécurisé pour cette démo
    Large,
}

// Classifie un nombre premier selon sa taille
// 
// # Arguments
// * `p` - Le nombre premier à classifier
// 
// # Returns
// La catégorie de sécurité correspondante
// 
// # Classification
// - Small : p < 100 (dangereux, attaque en quelques secondes)
// - Medium : 100 ≤ p < 10 000 (attaquable avec effort)
// - Large : p ≥ 10 000 (sécurisé pour cette démo)
pub fn classify_prime_size(p: &BigUint) -> SecurityLevel {
    let small_threshold = BigUint::from(100u32);
    let medium_threshold = BigUint::from(10000u32);
    
    if p < &small_threshold {
        SecurityLevel::Small
    } else if p < &medium_threshold {
        SecurityLevel::Medium
    } else {
        SecurityLevel::Large
    }
}

// Retourne une description textuelle du niveau de sécurité
// 
// # Arguments
// * `level` - Le niveau de sécurité
// 
// # Returns
// Une chaîne de caractères décrivant le niveau
pub fn get_security_description(level: &SecurityLevel) -> &'static str {
    match level {
        SecurityLevel::Small => "petit (très dangereux !)",
        SecurityLevel::Medium => "moyen (attaquable avec effort)",
        SecurityLevel::Large => "grand (sécurisé pour cette démo)",
    }
}

// Retourne une explication pédagogique sur la sécurité
// 
// # Arguments
// * `level` - Le niveau de sécurité
// 
// # Returns
// Une explication détaillée pour les lycéens
pub fn get_security_explanation(level: &SecurityLevel) -> &'static str {
    match level {
        SecurityLevel::Small => {
            "⚠️  DANGER ! Avec un petit nombre premier, Ismaël peut tester toutes les possibilités \
             très rapidement (en quelques secondes). La clé secrète n'est plus secrète !"
        }
        SecurityLevel::Medium => {
            "⚡ ATTENTION ! Avec un nombre premier moyen, Ismaël peut quand même casser la clé, \
             mais cela prendra plus de temps. Il faut être patient et tester beaucoup de possibilités."
        }
        SecurityLevel::Large => {
            "✅ SÉCURISÉ ! Avec un grand nombre premier, Ismaël devrait tester des milliards de \
             possibilités. Même avec un ordinateur très puissant, cela prendrait des années ! \
             La clé est bien protégée."
        }
    }
}

// Retourne une estimation du temps d'attaque pour information
// 
// # Arguments
// * `level` - Le niveau de sécurité
// 
// # Returns
// Une estimation du temps nécessaire pour une attaque brute-force
pub fn get_attack_time_estimate(level: &SecurityLevel) -> &'static str {
    match level {
        SecurityLevel::Small => "quelques secondes",
        SecurityLevel::Medium => "plusieurs minutes à heures",
        SecurityLevel::Large => "plusieurs années (impossible en pratique)",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_classify_small() {
        let p = BigUint::from(23u32);
        assert_eq!(classify_prime_size(&p), SecurityLevel::Small);
    }
    
    #[test]
    fn test_classify_medium() {
        let p = BigUint::from(1009u32);
        assert_eq!(classify_prime_size(&p), SecurityLevel::Medium);
    }
    
    #[test]
    fn test_classify_large() {
        let p = BigUint::from(50021u32);
        assert_eq!(classify_prime_size(&p), SecurityLevel::Large);
    }
    
    #[test]
    fn test_security_descriptions() {
        assert!(!get_security_description(&SecurityLevel::Small).is_empty());
        assert!(!get_security_description(&SecurityLevel::Medium).is_empty());
        assert!(!get_security_description(&SecurityLevel::Large).is_empty());
    }
}
