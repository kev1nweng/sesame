// SPDX-License-Identifier: AGPL-3.0-or-later
//! Load a dynamic library into another process (macOS).
//!
//! Uses `frida_session_attach` plus a small script calling `dlopen`, rather than
//! Frida's `inject_library_file`: that path goes through frida-helper, which fails on
//! recent macOS because `/usr/lib/libiconv.2.dylib` no longer exists on disk.
//!
//! Equivalent to 'attach then dlopen' from Python; validated against WeChat.

use anyhow::{anyhow, Result};
use frida::{DeviceManager, Frida, Message, ScriptHandler, ScriptOption};
use std::path::Path;
use std::time::Duration;

struct Printer;

impl ScriptHandler for Printer {
    fn on_message(&mut self, message: &Message, _data: Option<Vec<u8>>) {
        // The script sends 'ok' on success. Frida wraps it in a struct this crate cannot
        // deserialize, so the only useful thing here is the error text; stay quiet
        // otherwise instead of dumping raw debug output at the user.
        let text = format!("{message:?}");
        if text.contains("err:") {
            println!("  loader: {text}");
        }
    }
}

/// Load `lib_path` into `pid`.
///
/// Success only means `dlopen` did not fail. Whether the library finished initialising
/// is for the caller to confirm (for example by reading the hook log).
pub fn inject_library(pid: u32, lib_path: &Path) -> Result<()> {
    let path_str = lib_path
        .to_str()
        .ok_or_else(|| anyhow!("library path is not valid UTF-8"))?;
    let path = serde_json::to_string(path_str)?;

    let frida = unsafe { Frida::obtain() };
    let manager = DeviceManager::obtain(&frida);
    let device = manager.get_local_device()?;
    let session = device.attach(pid)?;

    let js = format!(
        r#"(function () {{
            try {{
                const p = Memory.allocUtf8String({path});
                const dl = new NativeFunction(Module.getExportByName(null, 'dlopen'), 'pointer', ['pointer', 'int']);
                const h = dl(p, 2);
                if (!h.isNull()) {{ send('ok'); return; }}
                const de = new NativeFunction(Module.getExportByName(null, 'dlerror'), 'pointer', []);
                const e = de();
                send('err: ' + (e.isNull() ? 'unknown' : e.readUtf8String()));
            }} catch (e) {{ send('err: ' + String(e)); }}
        }})();"#
    );

    let mut opt = ScriptOption::new().set_name("wxkit-loader");
    let mut script = session.create_script(&js, &mut opt)?;
    script.handle_message(Printer)?;
    script.load()?;
    std::thread::sleep(Duration::from_millis(1200));
    let _ = script.unload();
    Ok(())
}

/// frida-core version, for diagnostics.
pub fn version() -> &'static str {
    Frida::version()
}