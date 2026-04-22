//! Module pour les affichages pédagogiques
//! 
//! Ce module contient toutes les fonctions d'affichage interactives
//! et explicatives pour les lycéens

use num_bigint::BigUint;
use crate::classify::{SecurityLevel, get_security_description, get_security_explanation, get_attack_time_estimate};

// Affiche un titre stylisé
pub fn display_title(title: &str) {
    println!("\n{}", "=".repeat(70));
    println!("🔐 {}", title);
    println!("{}", "=".repeat(70));
}

// Affiche une section avec sous-titre
pub fn display_section(title: &str) {
    println!("\n{}", "-".repeat(50));
    println!("📚 {}", title);
    println!("{}", "-".repeat(50));
}

// Affiche une explication sur ce que sont p et g
pub fn explain_parameters() {
    display_section("Comprendre les paramètres p et g");
    
    println!("🤓 EXPLICATION POUR LES LYCÉENS :");
    println!();
    
    println!("📌 p : Le NOMBRE PREMIER PUBLIC");
    println!("   • C'est comme un grand nombre que tout le monde connaît");
    println!("   • Il doit être premier (divisible seulement par 1 et lui-même)");
    println!("   • Plus p est GRAND, plus la communication est SÉCURISÉE");
    println!("   • Exemples : 23, 101, 10007, 99991...");
    println!();
    
    println!("📌 g : Le GÉNÉRATEUR PUBLIC");
    println!("   • C'est un nombre plus petit que p");
    println!("   • Il sert à 'générer' les clés publiques");
    println!("   • Tout le monde connaît g aussi");
    println!("   • Exemples courants : 2, 3, 5...");
    println!();
    
    println!("🔍 POURQUOI CES NOMBRES SONT IMPORTANTS ?");
    println!("   • Alice et Bob choisissent p et g ensemble (tout le monde peut les voir)");
    println!("   • Chacun choisit ensuite un NOMBRE SECRET que personne ne connaît");
    println!("   • La magie : même si tout le monde voit p et g, personne ne peut deviner");
    println!("     les nombres secrets s'ils sont bien choisis !");
    println!();
    
    println!("⚠️  ATTENTION : Si p est trop petit, Ismaël peut attaquer !");
    println!("   • Petit p (< 100) = DANGER ! Attaque facile");
    println!("   • Moyen p (100-9999) = RISQUE ! Attaque possible");
    println!("   • Grand p (≥ 10000) = SÉCURITÉ ! Attaque impossible");
}

// Affiche la classification du nombre premier
pub fn display_classification(p: &BigUint, level: &SecurityLevel) {
    display_section("Classification du nombre premier");
    
    println!("📊 Analyse de p = {}", p);
    println!("🏷️  Niveau : {}", get_security_description(level));
    println!();
    
    println!("💡 Explication :");
    println!("{}", get_security_explanation(level));
    println!();
    
    println!("⏱️  Temps d'attaque estimé pour Ismaël : {}", get_attack_time_estimate(level));
    println!();
    
    match level {
        SecurityLevel::Small => {
            println!("🚨 RECOMMANDATION : N'utilisez JAMAIS un si petit nombre premier !");
            println!("   C'est comme utiliser un cadenas à 3 chiffres... n'importe qui peut l'ouvrir !");
        }
        SecurityLevel::Medium => {
            println!("⚡ RECOMMANDATION : Méfiez-vous, c'est encore risqué !");
            println!("   C'est comme un cadenas à 6 chiffres... possible mais difficile !");
        }
        SecurityLevel::Large => {
            println!("✅ RECOMMANDATION : Bon choix pour cette démo !");
            println!("   C'est comme un cadenas à 20 chiffres... pratiquement incassable !");
        }
    }
}

// Affiche les étapes du protocole Diffie-Hellman
pub fn display_protocol_steps(
    p: &BigUint,
    g: &BigUint,
    a: &BigUint,
    b: &BigUint,
    A: &BigUint,
    B: &BigUint,
    shared_key: &BigUint,
) {
    display_section("Étapes du protocole Diffie-Hellman");
    
    println!("👥 PERSONNAGES :");
    println!("   • Alice : veut communiquer secrètement");
    println!("   • Bob : veut communiquer secrètement");
    println!("   • Ismaël : l'attaquant qui espionne");
    println!();
    
    println!("🌐 INFORMATIONS PUBLIQUES (tout le monde voit ça) :");
    println!("   • p = {} (le nombre premier)", p);
    println!("   • g = {} (le générateur)", g);
    println!();
    
    println!("🔐 INFORMATIONS SECRÈTES (seul le propriétaire connaît) :");
    println!("   • a = {} (secret d'Alice)", a);
    println!("   • b = {} (secret de Bob)", b);
    println!();
    
    println!("📤 ÉTAPE 1 : Alice envoie sa clé publique");
    println!("   Alice calcule : A = g^a mod p = {}^{} mod {} = {}", g, a, p, A);
    println!("   📡 Alice envoie A = {} à Bob (Ismaël peut voir !)", A);
    println!();
    
    println!("📤 ÉTAPE 2 : Bob envoie sa clé publique");
    println!("   Bob calcule : B = g^b mod p = {}^{} mod {} = {}", g, b, p, B);
    println!("   📡 Bob envoie B = {} à Alice (Ismaël peut voir !)", B);
    println!();
    
    println!("🔑 ÉTAPE 3 : Alice calcule la clé partagée");
    println!("   Alice calcule : K = B^a mod p = {}^{} mod {} = {}", B, a, p, shared_key);
    println!("   🔐 Alice a maintenant la clé secrète : {}", shared_key);
    println!();
    
    println!("🔑 ÉTAPE 4 : Bob calcule la clé partagée");
    println!("   Bob calcule : K = A^b mod p = {}^{} mod {} = {}", A, b, p, shared_key);
    println!("   🔐 Bob a maintenant la clé secrète : {}", shared_key);
    println!();
    
    println!("✅ MAGIE ! Alice et Bob ont la même clé sans jamais l'échanger !");
    println!("   Ils peuvent maintenant communiquer secrètement...");
    println!();
    
    println!("👁️  CE QU'ISMAËL VOIT :");
    println!("   • p = {}", p);
    println!("   • g = {}", g);
    println!("   • A = {}", A);
    println!("   • B = {}", B);
    println!("   ❌ Mais il NE voit PAS : a, b, ni la clé partagée K = {}", shared_key);
}

// Affiche le menu d'attaque
pub fn display_attack_menu() {
    display_section("Menu d'attaque d'Ismaël");
    
    println!("🎯 Ismaël veut casser la clé partagée !");
    println!("   Il connaît : p, g, A, B");
    println!("   Il cherche : le secret d'Alice (a) ou de Bob (b)");
    println!();
    
    println!("⚔️  CHOISISSEZ VOTRE MÉTHODE D'ATTAQUE :");
    println!("   1. 🤖 Attaque brute-force (tester toutes les possibilités)");
    println!("   2. 🧠 Attaque intelligente (algorithmes avancés)");
    println!("   3. 🚪 Ne pas attaquer (respecter la vie privée)");
    println!();
}

// Affiche les options pour l'attaque brute-force
pub fn display_brute_force_options() {
    println!("🔧 OPTIONS DE L'ATTAQUE BRUTE-FORCE :");
    println!("   • Ismaël va tester tous les nombres possibles un par un");
    println!("   • Plus le nombre est grand, plus ça prend de temps");
    println!();
    println!("📊 PLAGES SUGGÉRÉES :");
    println!("   • Pour p petit : 0..1000 (rapide)");
    println!("   • Pour p moyen : 0..100000 (plus lent)");
    println!("   • Pour p grand : 0..1000000 (très lent !)");
    println!();
}

// Affiche un message de conclusion
pub fn display_conclusion(shared_key: &BigUint, level: &SecurityLevel) {
    display_section("Conclusion de la démonstration");
    
    println!("🎓 CE QUE NOUS AVONS APPRIS :");
    println!();
    
    println!("✅ Le protocole Diffie-Hellman fonctionne !");
    println!("   • Alice et Bob ont obtenu la même clé : {}", shared_key);
    println!("   • Ils n'ont jamais échangé cette clé directement");
    println!();
    
    println!("🔓 La sécurité dépend de la taille de p :");
    println!("   • Petit p = ❌ Insecure (attaque facile)");
    println!("   • Moyen p = ⚠️  Risqué (attaque possible)");
    println!("   • Grand p = ✅ Secure (attaque impossible)");
    println!();
    
    match level {
        SecurityLevel::Small => {
            println!("🚨 POURQUOI c'est dangereux avec un petit p :");
            println!("   • Ismaël peut tester toutes les possibilités rapidement");
            println!("   • Il retrouve le secret et peut lire tous les messages");
            println!("   • C'est comme utiliser un mot de passe '1234' !");
        }
        SecurityLevel::Medium => {
            println!("⚡ POURQUOI c'est risqué avec un p moyen :");
            println!("   • Ismaël peut quand même réussir avec de la patience");
            println!("   • Il faut des ordinateurs puissants et beaucoup de temps");
            println!("   • C'est comme un mot de passe de 8 caractères...");
        }
        SecurityLevel::Large => {
            println!("🛡️ POURQUOI c'est sécurisé avec un grand p :");
            println!("   • Ismaël devrait tester des milliards de possibilités");
            println!("   • Même avec tous les ordinateurs du monde, ça prendrait des années");
            println!("   • C'est comme un mot de passe de 20 caractères aléatoires !");
        }
    }
    println!();
    
    println!("💡 LEÇON IMPORTANTE :");
    println!("   En cryptographie, la taille des nombres PRIMORDIALE !");
    println!("   Toujours choisir des nombres premiers très grands en pratique.");
    println!("   Les vrais protocoles utilisent des nombres avec des centaines de chiffres !");
    println!();
}

// Affiche un message d'erreur
pub fn display_error(message: &str) {
    println!("\n❌ ERREUR : {}", message);
    println!("Veuillez réessayer.");
}

// Affiche un message de succès
pub fn display_success(message: &str) {
    println!("\n✅ SUCCÈS : {}", message);
}

// Affiche une information
pub fn display_info(message: &str) {
    println!("\n💡 INFORMATION : {}", message);
}
