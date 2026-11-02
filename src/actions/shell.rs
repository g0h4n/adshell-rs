//! Interactive shell, shared across transports.
//!
//! Each command dispatches to the matching `actions::ldap` or `actions::adws`
//! module depending on the active [`Session`], so the same shell drives LDAP
//! and ADWS. Actions not yet available over ADWS print a notice instead of
//! failing.

use anyhow::Result;
use log::warn;
use rustyline::error::ReadlineError;
use rustyline::history::MemHistory;
use rustyline::{Config, Editor};

use crate::actions::shell_completer::ShellHelper;
use crate::actions::{adws, ldap};
use crate::args::Options;
use crate::transport::Session;

type ShellEditor = Editor<ShellHelper, MemHistory>;

fn build_editor() -> Result<ShellEditor> {
    let config = Config::builder()
        .auto_add_history(true)
        .completion_type(rustyline::CompletionType::List)
        .build();
    let mut editor = Editor::with_history(config, MemHistory::new())?;
    editor.set_helper(Some(ShellHelper));
    Ok(editor)
}

fn transport_name(session: &Session) -> &'static str {
    match session {
        Session::Ldap(_) => "LDAP",
        Session::Adws(_) => "ADWS",
    }
}

pub async fn run(session: &mut Session, base_opts: &Options) -> Result<()> {
    println!(
        "adshell-rs shell ({} transport). type 'help' or '?' for commands, 'exit' to quit.",
        transport_name(session)
    );
    println!("(Tab completes commands, up/down browse history, Ctrl-C cancels a line, Ctrl-D quits)");

    let mut editor = build_editor()?;

    loop {
        let (line_result, ed) = tokio::task::spawn_blocking(move || {
            let res = editor.readline("# ");
            (res, editor)
        })
        .await
        .expect("readline task panicked");
        editor = ed;

        let line = match line_result {
            Ok(l) => l,
            Err(ReadlineError::Interrupted) => continue,
            Err(ReadlineError::Eof) => break,
            Err(e) => {
                warn!("readline error: {e}");
                break;
            }
        };

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let args: Vec<&str> = line.split_whitespace().collect();
        let cmd = args[0];
        let rest = &args[1..];

        let result: Result<()> = match cmd {
            "exit" | "quit" | "q" => break,
            "help" | "?" | "h" => {
                print_help();
                Ok(())
            }

            "whoami" => do_whoami(session, base_opts).await,
            "search" => {
                do_search(session, rest).await;
                Ok(())
            }
            "dn" => {
                if rest.is_empty() {
                    println!("usage: dn <baseDN>");
                    Ok(())
                } else {
                    do_search(session, &[rest[0], "(objectClass=*)"]).await;
                    Ok(())
                }
            }

            "add_member" => run_group(session, base_opts, rest, true).await,
            "del_member" | "remove_member" => run_group(session, base_opts, rest, false).await,

            "enable" | "enable_account" => run_account(session, base_opts, rest, true).await,
            "disable" | "disable_account" => run_account(session, base_opts, rest, false).await,

            "passwd" | "reset_password" => run_passwd(session, base_opts, rest).await,
            "elevate" | "dcsync" => run_elevate(session, base_opts, rest).await,

            "add_computer" => run_add_computer(session, base_opts, rest).await,
            "del_computer" => run_del_computer(session, base_opts, rest).await,

            "read_rbcd" => run_rbcd(session, base_opts, rest, "read").await,
            "write_rbcd" => run_rbcd(session, base_opts, rest, "write").await,
            "remove_rbcd" => run_rbcd(session, base_opts, rest, "remove").await,
            "flush_rbcd" => run_rbcd(session, base_opts, rest, "flush").await,

            "read_object" | "read" | "dump" | "get_object" => run_read_object(session, base_opts, rest).await,

            "add_shadow_cred" | "shadow_add" => run_shadow(session, base_opts, rest, "add").await,
            "list_shadow_cred" | "shadow_list" => run_shadow(session, base_opts, rest, "list").await,
            "remove_shadow_cred" | "shadow_remove" => run_shadow(session, base_opts, rest, "remove").await,
            "flush_shadow_cred" | "shadow_flush" => run_shadow(session, base_opts, rest, "flush").await,

            other => {
                println!("unknown command '{other}' (try 'help')");
                Ok(())
            }
        };

        if let Err(e) = result {
            warn!("{e}");
        }
    }
    Ok(())
}

/// ADWS-not-yet notice helper.
fn adws_todo(cmd: &str) {
    println!("{cmd}: not available over ADWS yet (use the LDAP transport)");
}

async fn do_whoami(session: &mut Session, base: &Options) -> Result<()> {
    match session {
        Session::Ldap(l) => ldap::whoami::run(l).await.map(|_| ()),
        Session::Adws(c) => adws::whoami::run(c, base).await,
    }
}

async fn do_search(session: &mut Session, a: &[&str]) {
    if a.is_empty() {
        println!("usage: search <baseDN> [filter]");
        return;
    }
    let base = a[0];
    let filter = if a.len() > 1 { a[1] } else { "(objectClass=*)" };
    match session {
        Session::Ldap(l) => {
            use ldap3::{Scope, SearchEntry};
            match l.search(base, Scope::Subtree, filter, vec!["dn"]).await {
                Ok(res) => match res.success() {
                    Ok((entries, _)) => {
                        println!("{} entrie(s):", entries.len());
                        for e in entries {
                            println!("  {}", SearchEntry::construct(e).dn);
                        }
                    }
                    Err(e) => warn!("search error: {e}"),
                },
                Err(e) => warn!("search failed: {e}"),
            }
        }
        Session::Adws(c) => {
            use adws_rs::Scope;
            match c.search(base, Scope::Subtree, filter, &["distinguishedName"], None, false).await {
                Ok(entries) => {
                    println!("{} entrie(s):", entries.len());
                    for e in entries {
                        println!("  {}", e.dn);
                    }
                }
                Err(e) => warn!("search failed: {e}"),
            }
        }
    }
}

async fn run_group(session: &mut Session, base: &Options, a: &[&str], add: bool) -> Result<()> {
    if a.len() < 2 {
        println!("usage: {} <user> <group>", if add { "add_member" } else { "del_member" });
        return Ok(());
    }
    let mut o = base.clone();
    o.target = Some(a[0].to_string());
    o.group = Some(a[1..].join(" "));
    match session {
        Session::Ldap(l) => if add { ldap::group::add_member(l, &o).await } else { ldap::group::remove_member(l, &o).await },
        Session::Adws(c) => if add { adws::group::add_member(c, &o).await } else { adws::group::remove_member(c, &o).await },
    }
}

async fn run_account(session: &mut Session, base: &Options, a: &[&str], enable: bool) -> Result<()> {
    if a.is_empty() {
        println!("usage: {} <user>", if enable { "enable" } else { "disable" });
        return Ok(());
    }
    let mut o = base.clone();
    o.target = Some(a[0].to_string());
    match session {
        Session::Ldap(l) => if enable { ldap::account::enable(l, &o).await } else { ldap::account::disable(l, &o).await },
        Session::Adws(c) => if enable { adws::account::enable(c, &o).await } else { adws::account::disable(c, &o).await },
    }
}

async fn run_passwd(session: &mut Session, base: &Options, a: &[&str]) -> Result<()> {
    if a.is_empty() {
        println!("usage: passwd <user> [newpassword]");
        return Ok(());
    }
    let mut o = base.clone();
    o.target = Some(a[0].to_string());
    o.new_pass = a.get(1).map(|s| s.to_string());
    match session {
        Session::Ldap(l) => ldap::modify_user::change_password(l, &o).await,
        Session::Adws(c) => adws::modify_user::change_password(c, &o).await,
    }
}

async fn run_elevate(session: &mut Session, base: &Options, a: &[&str]) -> Result<()> {
    if a.is_empty() {
        println!("usage: elevate <user>   (grant DCSync)");
        return Ok(());
    }
    let mut o = base.clone();
    o.target = Some(a[0].to_string());
    o.elevate = true;
    match session {
        Session::Ldap(l) => ldap::modify_user::elevate(l, &o).await,
        Session::Adws(c) => adws::modify_user::elevate(c, &o).await,
    }
}

async fn run_add_computer(session: &mut Session, base: &Options, a: &[&str]) -> Result<()> {
    let mut o = base.clone();
    o.computer_name = a.first().map(|s| s.to_string());
    o.computer_pass = a.get(1).map(|s| s.to_string());
    match session {
        Session::Ldap(l) => ldap::computer::run(l, &o).await,
        Session::Adws(c) => adws::computer::run(c, &o).await,
    }
}

async fn run_del_computer(session: &mut Session, base: &Options, a: &[&str]) -> Result<()> {
    if a.is_empty() {
        println!("usage: del_computer <name$>");
        return Ok(());
    }
    let mut o = base.clone();
    o.computer_name = Some(a[0].to_string());
    match session {
        Session::Ldap(l) => ldap::computer::del_computer(l, &o).await,
        Session::Adws(c) => adws::computer::del_computer(c, &o).await,
    }
}

async fn run_read_object(session: &mut Session, base: &Options, a: &[&str]) -> Result<()> {
    if a.is_empty() {
        println!("usage: read_object <sAMAccountName | CN | DN>");
        return Ok(());
    }
    let mut o = base.clone();
    o.target = Some(a.join(" "));
    match session {
        Session::Ldap(l) => ldap::read_object::run(l, &o).await,
        Session::Adws(c) => adws::read_object::run(c, &o).await,
    }
}

async fn run_rbcd(session: &mut Session, base: &Options, a: &[&str], op: &str) -> Result<()> {
    if a.is_empty() {
        println!("usage: {op}_rbcd <target$> [from$]");
        return Ok(());
    }
    let mut o = base.clone();
    o.delegate_to = Some(a[0].to_string());
    o.delegate_from = a.get(1).map(|s| s.to_string());
    match session {
        Session::Ldap(l) => match op {
            "read" => ldap::rbcd::read(l, &o).await,
            "write" => ldap::rbcd::write(l, &o).await,
            "remove" => ldap::rbcd::remove(l, &o).await,
            "flush" => ldap::rbcd::flush(l, &o).await,
            _ => Ok(()),
        },
        Session::Adws(c) => match op {
            "read" => adws::rbcd::read(c, &o).await,
            "write" => adws::rbcd::write(c, &o).await,
            "remove" => adws::rbcd::remove(c, &o).await,
            "flush" => adws::rbcd::flush(c, &o).await,
            _ => Ok(()),
        },
    }
}

async fn run_shadow(session: &mut Session, base: &Options, a: &[&str], op: &str) -> Result<()> {
    match session {
        Session::Adws(_) => {
            adws_todo(&format!("{op}_shadow_cred"));
            Ok(())
        }
        Session::Ldap(l) => {
            if a.is_empty() {
                println!("usage: {op}_shadow_cred <target> [key_id_hex (remove)]");
                return Ok(());
            }
            let mut o = base.clone();
            o.shadow_target = Some(a[0].to_string());
            o.shadow_key_id = a.get(1).map(|s| s.to_string());
            match op {
                "add" => ldap::shadow_cred::add(l, &o).await,
                "list" => ldap::shadow_cred::list(l, &o).await,
                "remove" => ldap::shadow_cred::remove(l, &o).await,
                "flush" => ldap::shadow_cred::flush(l, &o).await,
                _ => Ok(()),
            }
        }
    }
}

fn print_help() {
    println!(
        "commands:\n\
         \x20 whoami                               show the authenticated identity\n\
         \x20 search <baseDN> [filter]             subtree search, prints DNs\n\
         \x20 dn <baseDN>                          search <baseDN> (objectClass=*)\n\
         \x20 add_member <user> <group>            add user/computer to a group\n\
         \x20 del_member <user> <group>            remove user/computer from a group\n\
         \x20 enable <user>                        enable an account (clear ACCOUNTDISABLE)\n\
         \x20 disable <user>                       disable an account (set ACCOUNTDISABLE)\n\
         \x20 passwd <user> [newpass]              reset a user's password\n\
         \x20 elevate <user>                       grant the user DCSync rights\n\
         \x20 add_computer [name$] [pass]          create a machine account (LDAP)\n\
         \x20 del_computer <name$>                 delete a machine account\n\
         \x20 read_rbcd <target$>                  list RBCD entries on target\n\
         \x20 write_rbcd <target$> <from$>         allow from$ to impersonate on target$\n\
         \x20 remove_rbcd <target$> <from$>        remove one RBCD entry\n\
         \x20 flush_rbcd <target$>                 clear all RBCD entries\n\
         \x20 add_shadow_cred <target>            add Key Credential (LDAP)\n\
         \x20 list_shadow_cred <target>           list shadow credentials (LDAP)\n\
         \x20 remove_shadow_cred <target> <keyid> remove one shadow credential (LDAP)\n\
         \x20 flush_shadow_cred <target>          clear all shadow credentials (LDAP)\n\
         \x20 read_object <name|DN>                dump every attribute of an object\n\
         \x20 help                                 this help\n\
         \x20 exit | quit                          leave\n\
         \n\
         Commands run over the active transport (LDAP or ADWS); a few are\n\
         LDAP-only for now and say so when run over ADWS."
    );
}
