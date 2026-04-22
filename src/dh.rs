//! Module contenant les fonctions mathématiques du protocole Diffie-Hellman
//! 
//! Ce module implémente les opérations de base nécessaires au protocole :
//! - Exponentiation modulaire
//! - Calcul des clés publiques
//! - Calcul de la clé partagée

use num_bigint::BigUint;
use num_traits::{Zero, One};

// let result = mod_exp(2, 3, 5); // Calcule (2^3) % 5 = 8 % 5 = 3
// ```
pub fn mod_exp(base: &BigUint, exposant: &BigUint, modulus: &BigUint) -> BigUint {
    if modulus.is_one() {
        return BigUint::zero();
    }
    
    let mut result = BigUint::one();
    let mut base = base.clone() % modulus;
    let mut exposant = exposant.clone();
    
    while exposant > BigUint::zero() {
        if &exposant % 2u32 == BigUint::one() {
            result = (result * &base) % modulus;
        }
        exposant >>= 1;
        base = (&base * &base) % modulus;
    }
    
    result
}

// Calcule la clé publique à partir du générateur g, du secret et du nombre premier p

// Formule : clé_publique = g^secret mod p

// La clé publique correspondante
pub fn compute_public_key(g: &BigUint, secret: &BigUint, p: &BigUint) -> BigUint {
    mod_exp(g, secret, p)
}

// La clé partagée (identique pour Alice et Bob)
pub fn compute_shared_key(public_key_received: &BigUint, own_secret: &BigUint, p: &BigUint) -> BigUint {
    mod_exp(public_key_received, own_secret, p)
}

pub fn is_prime(n: &BigUint) -> bool {
    if n < &BigUint::from(2u32) {
        return false;
    }
    if n == &BigUint::from(2u32) {
        return true;
    }
    if n % &BigUint::from(2u32) == BigUint::zero() {
        return false;
    }
    
    let _limit = (n - &BigUint::one()) / &BigUint::from(2u32);
    let mut i = BigUint::from(3u32);
    
    while &i * &i <= *n {
        if n % &i == BigUint::zero() {
            return false;
        }
        i += &BigUint::from(2u32);
    }
    
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_mod_exp() {
        let base = BigUint::from(2u32);
        let exposant = BigUint::from(3u32);
        let modulus = BigUint::from(5u32);
        
        let result = mod_exp(&base, &exposant, &modulus);
        assert_eq!(result, BigUint::from(3u32)); // (2^3) % 5 = 8 % 5 = 3
    }
    
    #[test]
    fn test_public_key() {
        let g = BigUint::from(5u32);
        let secret = BigUint::from(7u32);
        let p = BigUint::from(23u32);
        
        let public_key = compute_public_key(&g, &secret, &p);
        // 5^7 % 23 = 78125 % 23 = 17
        assert_eq!(public_key, BigUint::from(17u32));
    }
    
    #[test]
    fn test_shared_key() {
        let g = BigUint::from(5u32);
        let a = BigUint::from(6u32); // secret d'Alice
        let b = BigUint::from(15u32); // secret de Bob
        let p = BigUint::from(23u32);
        
        let A = compute_public_key(&g, &a, &p); // 5^6 % 23 = 8
        let B = compute_public_key(&g, &b, &p); // 5^15 % 23 = 19
        
        // Alice calcule la clé partagée
        let shared_key_alice = compute_shared_key(&B, &a, &p);
        // Bob calcule la clé partagée
        let shared_key_bob = compute_shared_key(&A, &b, &p);
        
        // Les deux clés doivent être identiques
        assert_eq!(shared_key_alice, shared_key_bob);
        assert_eq!(shared_key_alice, BigUint::from(2u32)); // 19^6 % 23 = 8^15 % 23 = 2
    }
}
