
pub mod analysis;
pub mod archive;
mod commands;
pub mod decompile;
pub mod java;
pub mod metadata;
pub mod model;
pub mod pe;

use commands::AppState;
use std::sync::Arc;
use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_store::Builder::default().build())
        .setup(|app| {
            let (vineflower_jar, cfr_jar) = commands::resolve_jars(app.handle());
            let ilspy_dir = commands::resolve_ilspy(app.handle());
            app.manage(Arc::new(AppState::new(vineflower_jar, cfr_jar, ilspy_dir)));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::detect_java,
            commands::open_archive,
            commands::close_archive,
            commands::decompile_class,
            commands::decompile_all,
            commands::get_strings,
            commands::get_metadata,
            commands::read_resource,
            commands::analyze_archive,
            commands::search_all,
            commands::export_report,
            commands::export_sources,
            commands::analyze_dll,
            commands::get_dll_strings,
            commands::disassemble_dll,
            commands::decompile_dotnet,
            commands::read_image_data_url,
            commands::write_file,
        ])
        .run(tauri::generate_context!())
        .expect("error while running End Decompiler");
}
