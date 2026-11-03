//! Session logging, mimikatz `log`-style.
//!
//! `log` starts logging to `<TIMESTAMP>-adshell-rs.log`, `log <file>` to a
//! chosen file, `log stop` ends it. Once active, the file receives:
//!   * a timestamped header for every command executed (`[ts] $ <command>`),
//!   * every `log`-facade record (mirrored by the `env_logger` format hook in
//!     `main`, via [`append`]),
//!   * every line the shell prints through [`echo`] / the `shlog!` macro.
//!
//! ANSI color codes are stripped on the way to the file.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::Mutex;

use chrono::Local;

struct State {
    path: String,
    file: File,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);

/// `YYYY-MM-DD HH:MM:SS` in the machine's local time, for log entries.
fn ts() -> String {
    Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

/// `YYYYMMDD-HHMMSS` (local time) for the default file name.
fn ts_compact() -> String {
    Local::now().format("%Y%m%d-%H%M%S").to_string()
}

/// Start logging. `arg` is an optional file name; the default is
/// `<TIMESTAMP>-adshell-rs.log` in the current directory. Appends if the file
/// exists. Returns the path in use.
pub fn start(arg: Option<&str>) -> std::io::Result<String> {
    let path = match arg {
        Some(p) if !p.trim().is_empty() => p.trim().to_string(),
        _ => format!("{}-adshell-rs.log", ts_compact()),
    };
    let file = OpenOptions::new().create(true).append(true).open(&path)?;
    let mut guard = STATE.lock().unwrap();
    *guard = Some(State { path: path.clone(), file });
    if let Some(st) = guard.as_mut() {
        let _ = writeln!(st.file, "\n==== adshell-rs log opened {} ====", ts());
        let _ = st.file.flush();
    }
    Ok(path)
}

/// Stop logging. Returns the path that was in use, if any.
pub fn stop() -> Option<String> {
    let mut guard = STATE.lock().unwrap();
    if let Some(st) = guard.as_mut() {
        let _ = writeln!(st.file, "==== adshell-rs log closed {} ====\n", ts());
        let _ = st.file.flush();
    }
    guard.take().map(|s| s.path)
}

/// The active log path, if any.
pub fn path() -> Option<String> {
    STATE.lock().unwrap().as_ref().map(|s| s.path.clone())
}

/// Record a command execution header: a blank line then `[ts] $ <command>`.
pub fn command(cmdline: &str) {
    let mut guard = STATE.lock().unwrap();
    if let Some(st) = guard.as_mut() {
        let _ = writeln!(st.file, "\n[{}] $ {}", ts(), cmdline);
        let _ = st.file.flush();
    }
}

/// Append raw text (ANSI-stripped) to the log, verbatim, under the current
/// command header. No-op when no file is open. Used by the shell (`echo`) and
/// by the `env_logger` format hook to mirror `log`-facade records.
pub fn append(text: &str) {
    let mut guard = STATE.lock().unwrap();
    if let Some(st) = guard.as_mut() {
        let _ = writeln!(st.file, "{}", strip_ansi(text));
        let _ = st.file.flush();
    }
}

/// Print `text` to stdout (unchanged, colors kept) and mirror it to the log
/// file (ANSI stripped). Use via the [`shlog!`](crate::shlog) macro.
pub fn echo(text: &str) {
    println!("{text}");
    append(text);
}

/// Remove ANSI SGR escape sequences (`\x1b[...m` and friends) from a string.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if chars.peek() == Some(&'[') {
                chars.next();
            }
            // Consume until the final byte (an ASCII letter, e.g. 'm').
            while let Some(&n) = chars.peek() {
                chars.next();
                if n.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Print `format!`-style to stdout and mirror it to the active log file.
/// Drop-in for `println!`: `shlog!()` prints a blank line, `shlog!("{x}")` etc.
#[macro_export]
macro_rules! shlog {
    () => {
        $crate::actions::common::logfile::echo("")
    };
    ($($arg:tt)*) => {
        $crate::actions::common::logfile::echo(&format!($($arg)*))
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn echo_command_and_append_land_in_file() {
        let path = std::env::temp_dir().join(format!("adshell-test-{}.log", std::process::id()));
        let p = path.to_str().unwrap();
        start(Some(p)).unwrap();
        command("whoami");
        echo("ECHOVALUE123");
        append("[INFO  adws::client] APPENDVALUE123");
        stop();

        let mut s = String::new();
        File::open(p).unwrap().read_to_string(&mut s).unwrap();
        let _ = std::fs::remove_file(p);
        assert!(s.contains("$ whoami"), "command header missing:\n{s}");
        assert!(s.contains("ECHOVALUE123"), "echo missing:\n{s}");
        assert!(s.contains("APPENDVALUE123"), "append missing:\n{s}");
    }

    #[test]
    fn strip_ansi_removes_color() {
        assert_eq!(strip_ansi("\x1b[1;32mgreen\x1b[0m"), "green");
    }
}