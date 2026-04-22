from sympy import randprime
import math

def generer_nombre_premier():
    print("=== Générateur de nombres premiers ===")
    print("Ce programme génère un nombre premier de la taille que vous spécifiez.")
    print()
    
    try:
        # Demander à l'utilisateur le nombre de bits souhaité
        bits = int(input("Entrez le nombre de bits souhaité (entre 8 et 2048): "))
        
        if bits < 8:
            print("⚠️  Le nombre de bits doit être d'au moins 8.")
            return
        elif bits > 2048:
            print("⚠️  Le nombre de bits ne doit pas dépasser 2048.")
            return
        elif bits > 1024:
            print("⚠️  ATTENTION : La génération de nombres premiers de plus de 1024 bits peut prendre")
            print("   beaucoup de temps et l'interface peut ne pas répondre pendant le calcul.")
            print("   Pour les très grands nombres (>1536 bits), le programme peut sembler bloqué.")
            confirm = input("   Voulez-vous continuer malgré cet avertissement ? (o/n): ").lower()
            if confirm not in ['o', 'oui']:
                print("   Annulation. Veuillez choisir un nombre de bits plus petit.")
                return
        
        # Calculer les bornes pour la génération
        min_val = 2**(bits-1)  # Le plus petit nombre avec 'bits' bits
        max_val = 2**bits - 1   # Le plus grand nombre avec 'bits' bits
        
        print(f"\n🔄 Génération d'un nombre premier de {bits} bits...")
        
        # Générer le nombre premier
        premier = randprime(min_val, max_val)
        
        # Calculer le nombre de bits réel du nombre généré
        bits_reels = premier.bit_length()
        
        # Afficher les résultats
        print("\n✅ Nombre premier généré avec succès !")
        print(f"   Nombre premier : {premier}")
        print(f"   Bits demandés : {bits}")
        print(f"   Bits réels   : {bits_reels}")
        print(f"   Chiffres      : {len(str(premier))}")
        
    except ValueError:
        print("❌ Erreur : Veuillez entrer un nombre entier valide.")
    except KeyboardInterrupt:
        print("\n\n👋 Programme interrompu. Au revoir !")
    except Exception as e:
        print(f"❌ Une erreur est survenue : {e}")

# Lancer le programme
if __name__ == "__main__":
    generer_nombre_premier()