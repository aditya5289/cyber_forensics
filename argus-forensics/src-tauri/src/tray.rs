//! System tray for ARGUS Forensics desktop shell.

use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Manager,
};

pub fn install_tray(app: &AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    let show = MenuItem::with_id(app, "show", "Show ARGUS", true, None::<&str>)?;
    let workspace = MenuItem::with_id(app, "workspace", "Open workspace folder", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &workspace, &quit])?;

    let icon = app.default_window_icon().cloned().ok_or("No default icon")?;

    let _tray = TrayIconBuilder::new()
        .icon(icon)
        .menu(&menu)
        .tooltip("ARGUS Forensics")
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => show_main(app),
            "workspace" => open_workspace(),
            "quit" => {
                let state = app.state::<crate::sidecar::SidecarState>();
                crate::sidecar::stop_sidecar(&state);
                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main(tray.app_handle());
            }
        })
        .build(app)?;

    Ok(())
}

fn show_main(app: &AppHandle) {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.show();
        let _ = win.set_focus();
        let _ = win.unminimize();
    }
}

fn open_workspace() {
    let home = std::env::var("USERPROFILE").unwrap_or_else(|_| ".".into());
    let path = format!("{home}\\ARGUS");
    let _ = std::process::Command::new("explorer")
        .arg(path)
        .spawn();
}
