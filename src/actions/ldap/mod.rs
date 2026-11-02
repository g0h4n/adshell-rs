//! Actions over an `ldap3::Ldap` session (LDAP/LDAPS transport).

pub mod account;
pub mod computer;
pub mod group;
pub mod modify_user;
pub mod rbcd;
pub mod read_object;
pub mod shadow_cred;
pub mod whoami;
