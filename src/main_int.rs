//! Point d'entrée principal pour l'interface graphique egui
//! 
//! Ce fichier lance l'application avec l'interface graphique moderne

use std::error::Error;

mod interface;
mod dh;
mod attack;
mod classifi;

fn main() -> Result<(), Box<dyn Error>> {
    // Lancer l'interface graphique egui
    interface::run_gui()?;
    
    Ok(())
}
