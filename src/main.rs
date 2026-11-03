//! adshell-rs - interactive LDAP/ADWS shell and AD attack actions, over
//! LDAP(S) or ADWS (SOAP). Transport model from RustHound-CE; ADWS via adws.

use anyhow::{anyhow, Result};

mod actions;
mod args;
mod transport;

use transport::Session;

#[tokio::main]
async fn main() -> Result<()> {
    let mut opts = args::extract_args();
    // env_logger with its native console format; a `.format` hook also mirrors
    // each record into the session log file (when `log` is active in the
    // shell). The rustyline backend is capped at warn to avoid key-event spam.
    env_logger::Builder::new()
        .filter_level(opts.verbose)
        .filter_module("rustyline", log::LevelFilter::Warn)
        .format(|buf, record| {
            use std::io::Write;
            let level = record.level();
            let style = buf.default_level_style(level);
            let ts = buf.timestamp();
            // Console: env_logger-native look, only the level colored.
            writeln!(
                buf,
                "[{ts} {style}{level:<5}{style:#} {target}] {args}",
                target = record.target(),
                args = record.args(),
            )?;
            // Mirror into the log file (plain, ANSI stripped by `append`).
            actions::common::logfile::append(&format!(
                "[{level:<5} {target}] {args}",
                target = record.target(),
                args = record.args(),
            ));
            Ok(())
        })
        .init();

    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow!("failed to install rustls crypto provider"))?;

    // Prompt for the password when -u is given without -p (and no hash /
    // Kerberos / certificate), like RustHound-CE. Applies to LDAP and ADWS.
    args::prompt_password_if_missing(&mut opts);

    // Connect + authenticate over the selected transport.
    let mut session = transport::connect(&opts).await?;

    // The interactive shell drives whichever transport authenticated.
    if opts.action == "ldapshell" {
        actions::shell::run(&mut session, &opts).await?;
        if let Session::Ldap(l) = &mut session {
            let _ = l.unbind().await;
        }
        return Ok(());
    }

    match (opts.action.as_str(), &mut session) {
        // whoami
        ("whoami", Session::Ldap(l)) => { actions::ldap::whoami::run(l).await?; }
        ("whoami", Session::Adws(a)) => actions::adws::whoami::run(a, &opts).await?,

        // Computer accounts
        ("add_computer", Session::Ldap(l)) => actions::ldap::computer::run(l, &opts).await?,
        ("del_computer", Session::Ldap(l)) => actions::ldap::computer::del_computer(l, &opts).await?,
        ("add_computer", Session::Adws(a)) => actions::adws::computer::run(a, &opts).await?,
        ("del_computer", Session::Adws(a)) => actions::adws::computer::del_computer(a, &opts).await?,

        // Users
        ("modify_user", Session::Ldap(l)) => {
            if opts.elevate {
                actions::ldap::modify_user::elevate(l, &opts).await?;
            } else {
                actions::ldap::modify_user::change_password(l, &opts).await?;
            }
        }
        ("modify_user", Session::Adws(a)) => {
            if opts.elevate {
                actions::adws::modify_user::elevate(a, &opts).await?;
            } else {
                actions::adws::modify_user::change_password(a, &opts).await?;
            }
        }

        // Group membership
        ("add_member", Session::Ldap(l)) => actions::ldap::group::add_member(l, &opts).await?,
        ("remove_member", Session::Ldap(l)) => actions::ldap::group::remove_member(l, &opts).await?,
        ("add_member", Session::Adws(a)) => actions::adws::group::add_member(a, &opts).await?,
        ("remove_member", Session::Adws(a)) => actions::adws::group::remove_member(a, &opts).await?,

        // Account status
        ("enable_account", Session::Ldap(l)) => actions::ldap::account::enable(l, &opts).await?,
        ("disable_account", Session::Ldap(l)) => actions::ldap::account::disable(l, &opts).await?,
        ("enable_account", Session::Adws(a)) => actions::adws::account::enable(a, &opts).await?,
        ("disable_account", Session::Adws(a)) => actions::adws::account::disable(a, &opts).await?,

        // RBCD (both transports)
        ("read_rbcd", Session::Ldap(l)) => actions::ldap::rbcd::read(l, &opts).await?,
        ("write_rbcd", Session::Ldap(l)) => actions::ldap::rbcd::write(l, &opts).await?,
        ("remove_rbcd", Session::Ldap(l)) => actions::ldap::rbcd::remove(l, &opts).await?,
        ("flush_rbcd", Session::Ldap(l)) => actions::ldap::rbcd::flush(l, &opts).await?,
        ("read_rbcd", Session::Adws(a)) => actions::adws::rbcd::read(a, &opts).await?,
        ("write_rbcd", Session::Adws(a)) => actions::adws::rbcd::write(a, &opts).await?,
        ("remove_rbcd", Session::Adws(a)) => actions::adws::rbcd::remove(a, &opts).await?,
        ("flush_rbcd", Session::Adws(a)) => actions::adws::rbcd::flush(a, &opts).await?,

        // Shadow Credentials
        ("add_shadow_cred", Session::Ldap(l)) => actions::ldap::shadow_cred::add(l, &opts).await?,
        ("list_shadow_cred", Session::Ldap(l)) => actions::ldap::shadow_cred::list(l, &opts).await?,
        ("remove_shadow_cred", Session::Ldap(l)) => actions::ldap::shadow_cred::remove(l, &opts).await?,
        ("flush_shadow_cred", Session::Ldap(l)) => actions::ldap::shadow_cred::flush(l, &opts).await?,
        ("add_shadow_cred", Session::Adws(a)) => actions::adws::shadow_cred::add(a, &opts).await?,
        ("list_shadow_cred", Session::Adws(a)) => actions::adws::shadow_cred::list(a, &opts).await?,
        ("remove_shadow_cred", Session::Adws(a)) => actions::adws::shadow_cred::remove(a, &opts).await?,
        ("flush_shadow_cred", Session::Adws(a)) => actions::adws::shadow_cred::flush(a, &opts).await?,

        // Read object
        ("read_object", Session::Ldap(l)) => actions::ldap::read_object::run(l, &opts).await?,
        ("read_object", Session::Adws(a)) => actions::adws::read_object::run(a, &opts).await?,

        (other, _) => return Err(anyhow!("unknown action: {other}")),
    }

    // Close the LDAP session cleanly (ADWS closes on drop).
    if let Session::Ldap(l) = &mut session {
        let _ = l.unbind().await;
    }
    Ok(())
}