//! Argument parsing (RustHound-CE / PassTheCert-rs style).
//!
//! Connection + all authentication methods, a `--transport ldap|soap` switch,
//! and the per-action parameters. LDAP is the default transport.

use clap::{value_parser, Arg, ArgAction, Command};

/// Directory transport. `soap`/`adws` select ADWS; anything else is LDAP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Ldap,
    Soap,
}

#[derive(Clone, Debug)]
pub struct Options {
    // Transport
    pub transport: Transport,
    // Connection
    pub domain: String,
    pub ldapfqdn: Option<String>,
    pub ip: Option<String>,
    pub port: Option<u16>,
    pub ldaps: bool,
    // Credential auth
    pub username: Option<String>,
    pub password: Option<String>,
    pub hashes: Option<String>,
    pub kerberos: bool,
    // Certificate auth (LDAP only)
    pub pfx: Option<String>,
    pub pfx_pass: Option<String>,
    pub crt: Option<String>,
    pub key: Option<String>,
    // Action
    pub action: String,
    // Manage user (modify_user)
    pub target: Option<String>,
    pub new_pass: Option<String>,
    pub elevate: bool,
    // Manage computer (add_computer / del_computer)
    pub computer_name: Option<String>,
    pub computer_pass: Option<String>,
    pub computer_group: Option<String>,
    // Group membership (add_member / remove_member)
    pub group: Option<String>,
    // RBCD (read/write/remove/flush)
    pub delegate_to: Option<String>,
    pub delegate_from: Option<String>,
    // Shadow Credentials
    pub shadow_target: Option<String>,
    pub shadow_key_id: Option<String>,
    // Verbosity
    pub verbose: log::LevelFilter,
}

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

fn cli() -> Command {
    Command::new("adshell-rs")
        .version(VERSION)
        .about("Interactive LDAP/ADWS shell and AD attack actions over LDAP(S) or ADWS (SOAP)")
        .arg(Arg::new("v").short('v').help("Verbosity (-v debug, -vv trace)").action(ArgAction::Count))
        .next_help_heading("REQUIRED VALUES")
        .arg(Arg::new("domain").short('d').long("domain").help("Domain name like: DOMAIN.LOCAL").required(true).value_parser(value_parser!(String)))
        .next_help_heading("TRANSPORT")
        .arg(Arg::new("transport").short('t').long("transport")
            .help("Directory transport: ldap (LDAP/LDAPS, default) or soap/adws (ADWS, tcp/9389). Case-insensitive")
            .required(false).value_parser(["ldap", "LDAP", "soap", "SOAP", "adws", "ADWS"]))
        .next_help_heading("CONNECTION")
        .arg(Arg::new("ldapfqdn").short('f').long("ldapfqdn").help("Domain Controller FQDN like: DC01.DOMAIN.LOCAL").required(false).value_parser(value_parser!(String)))
        .arg(Arg::new("ldapip").short('i').long("ldapip").help("Domain Controller IP address").required(false).value_parser(value_parser!(String)))
        .arg(Arg::new("ldapport").short('P').long("ldapport").help("LDAP port [default: 389 / 636 with --ldaps]; for -t soap, the ADWS port [default: 9389]").required(false).value_parser(value_parser!(String)))
        .arg(Arg::new("ldaps").long("ldaps").help("Use LDAPS instead of LDAP/StartTLS").required(false).action(ArgAction::SetTrue))
        .next_help_heading("AUTHENTICATION")
        .arg(Arg::new("username").short('u').long("ldapusername").help("Username, like: user or user@domain.local").required(false).value_parser(value_parser!(String)))
        .arg(Arg::new("password").short('p').long("ldappassword").help("Password").required(false).value_parser(value_parser!(String)))
        .arg(Arg::new("hashes").short('H').long("hashes").help("NT hash for pass-the-hash (NTLM): [NTHASH, :NTHASH, LMHASH:NTHASH]").required(false).value_parser(value_parser!(String)))
        .arg(Arg::new("kerberos").short('k').long("kerberos").help("Kerberos auth from ccache (KRB5CCNAME). LDAP only").required(false).action(ArgAction::SetTrue))
        .next_help_heading("CERTIFICATE AUTH (LDAP only, Pass-the-Certificate)")
        .arg(Arg::new("pfx").long("pfx").help("PFX/PKCS#12 client certificate").required(false).value_parser(value_parser!(String)))
        .arg(Arg::new("pfx-pass").long("pfx-pass").help("Password protecting the PFX").required(false).value_parser(value_parser!(String)))
        .arg(Arg::new("crt").long("crt").help("PEM client certificate (use with --key)").required(false).value_parser(value_parser!(String)))
        .arg(Arg::new("key").long("key").help("PEM private key (use with --crt)").required(false).value_parser(value_parser!(String)))
        .next_help_heading("ACTION")
        .arg(Arg::new("action").long("action")
            .help("whoami | ldapshell | add_computer | del_computer | modify_user | \
                   add_member | remove_member | enable_account | disable_account | \
                   read_rbcd | write_rbcd | remove_rbcd | flush_rbcd | \
                   add_shadow_cred | list_shadow_cred | remove_shadow_cred | flush_shadow_cred | \
                   read_object  [default: ldapshell]")
            .required(false)
            .value_parser([
                "whoami", "ldapshell",
                "add_computer", "del_computer",
                "modify_user",
                "add_member", "remove_member",
                "enable_account", "disable_account",
                "read_rbcd", "write_rbcd", "remove_rbcd", "flush_rbcd",
                "add_shadow_cred", "list_shadow_cred", "remove_shadow_cred", "flush_shadow_cred",
                "read_object",
            ]))
        .next_help_heading("MANAGE USER (modify_user)")
        .arg(Arg::new("target").long("target").help("sAMAccountName of the target").required(false).value_parser(value_parser!(String)))
        .arg(Arg::new("new-pass").long("new-pass").help("New password for the target").required(false).value_parser(value_parser!(String)))
        .arg(Arg::new("elevate").long("elevate").help("Grant the target DCSync rights").required(false).action(ArgAction::SetTrue))
        .next_help_heading("MANAGE COMPUTER (add_computer / del_computer)")
        .arg(Arg::new("computer-name").long("computer-name").help("Machine account sAMAccountName (COMPUTERNAME$)").required(false).value_parser(value_parser!(String)))
        .arg(Arg::new("computer-pass").long("computer-pass").help("Password for the new machine account").required(false).value_parser(value_parser!(String)))
        .arg(Arg::new("computer-group").long("computer-group").help("Container [default: CN=Computers,<baseDN>]").required(false).value_parser(value_parser!(String)))
        .next_help_heading("GROUP MEMBERSHIP (add_member / remove_member)")
        .arg(Arg::new("group").long("group").help("Target group: sAMAccountName or full DN").required(false).value_parser(value_parser!(String)))
        .next_help_heading("RBCD (read/write/flush_rbcd)")
        .arg(Arg::new("delegate-to").long("delegate-to").help("Target computer sAMAccountName (victim, append $)").required(false).value_parser(value_parser!(String)))
        .arg(Arg::new("delegate-from").long("delegate-from").help("Source computer sAMAccountName (attacker, append $)").required(false).value_parser(value_parser!(String)))
        .next_help_heading("SHADOW CREDENTIALS")
        .arg(Arg::new("shadow-target").long("shadow-target").help("Target account sAMAccountName (user or machine$)").required(false).value_parser(value_parser!(String)))
        .arg(Arg::new("shadow-key-id").long("shadow-key-id").help("KeyID (lowercase hex) to remove").required(false).value_parser(value_parser!(String)))
}

/// Extract all arguments into the `Options` structure.
/// Prompt interactively for the password when credential auth is selected
/// (a username is given) but no password, NT hash, Kerberos ticket or
/// certificate was provided - same behaviour as RustHound-CE. Applies to both
/// LDAP and ADWS. No-op otherwise.
pub fn prompt_password_if_missing(opts: &mut Options) {
    let credential_auth =
        opts.hashes.is_none() && !opts.kerberos && opts.pfx.is_none() && opts.crt.is_none();
    if credential_auth && opts.username.is_some() && opts.password.is_none() {
        match rpassword::prompt_password("Password: ") {
            Ok(p) => opts.password = Some(p),
            Err(e) => log::warn!("could not read password from prompt: {e}"),
        }
    }
}

pub fn extract_args() -> Options {
    let m = cli().get_matches();

    let transport = match m.get_one::<String>("transport").map(|s| s.to_ascii_lowercase()).as_deref() {
        Some("soap") | Some("adws") => Transport::Soap,
        _ => Transport::Ldap,
    };

    let action = m.get_one::<String>("action").cloned().unwrap_or_else(|| "ldapshell".to_string());

    let verbose = match m.get_count("v") {
        0 => log::LevelFilter::Info,
        1 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };

    Options {
        transport,
        domain:         m.get_one::<String>("domain").cloned().unwrap_or_default(),
        ldapfqdn:       m.get_one::<String>("ldapfqdn").cloned(),
        ip:             m.get_one::<String>("ldapip").cloned(),
        port:           m.get_one::<String>("ldapport").and_then(|p| p.parse::<u16>().ok()),
        ldaps:          m.get_flag("ldaps"),
        username:       m.get_one::<String>("username").cloned(),
        password:       m.get_one::<String>("password").cloned(),
        hashes:         m.get_one::<String>("hashes").cloned(),
        kerberos:       m.get_flag("kerberos"),
        pfx:            m.get_one::<String>("pfx").cloned(),
        pfx_pass:       m.get_one::<String>("pfx-pass").cloned(),
        crt:            m.get_one::<String>("crt").cloned(),
        key:            m.get_one::<String>("key").cloned(),
        action,
        target:         m.get_one::<String>("target").cloned(),
        new_pass:       m.get_one::<String>("new-pass").cloned(),
        elevate:        m.get_flag("elevate"),
        computer_name:  m.get_one::<String>("computer-name").cloned(),
        computer_pass:  m.get_one::<String>("computer-pass").cloned(),
        computer_group: m.get_one::<String>("computer-group").cloned(),
        group:          m.get_one::<String>("group").cloned(),
        delegate_to:    m.get_one::<String>("delegate-to").cloned(),
        delegate_from:  m.get_one::<String>("delegate-from").cloned(),
        shadow_target:  m.get_one::<String>("shadow-target").cloned(),
        shadow_key_id:  m.get_one::<String>("shadow-key-id").cloned(),
        verbose,
    }
}
