//! Point d'entrée principal pour l'interface graphique egui
//! 
//! Ce fichier lance l'application avec l'interface graphique moderne

use std::error::Error;

mod gui_egui;
mod dh;
mod attack;
mod classify;

fn main() -> Result<(), Box<dyn Error>> {
    // Lancer l'interface graphique egui
    gui_egui::run_gui()?;
    
    Ok(())
}
