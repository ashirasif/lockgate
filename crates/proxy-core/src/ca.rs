use hudsucker::{
    certificate_authority::RcgenAuthority,
    rcgen::{Issuer, KeyPair},
    rustls::crypto::aws_lc_rs,
};

/// Build the certificate authority used to sign leaf certs for MITM'd hosts.
///
/// The CA is embedded at compile time. `ca.key` is gitignored, so a fresh clone
/// won't build until you generate your own — which is intentional: a CA private
/// key is a per-machine secret.
pub fn authority() -> RcgenAuthority {
    let key_pem = include_str!("ca/ca.key");
    let cert_pem = include_str!("ca/ca.cer");

    let key_pair = KeyPair::from_pem(key_pem).expect("Failed to parse CA private key");
    let issuer =
        Issuer::from_ca_cert_pem(cert_pem, key_pair).expect("Failed to parse CA certificate");

    // 1_000 = how many generated leaf certs to keep cached.
    RcgenAuthority::new(issuer, 1_000, aws_lc_rs::default_provider())
}
