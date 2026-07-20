//! Command-line arguments.
//!
//! Hand-rolled rather than `clap`. There are six of them, they are all either a
//! port, a path or a flag, and the parser plus its tests is smaller than the
//! dependency would be — the same trade this codebase makes for base64, globs
//! and JSON formatting.
//!
//! Unknown arguments are an **error**, never ignored. Silently skipping a
//! misspelled `--porb 8080` would leave the proxy listening somewhere other
//! than where you asked, which you would discover only by wondering why nothing
//! is being captured.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

pub const USAGE: &str = "\
proxy — an intercepting HTTP proxy for security testing

USAGE:
    proxy [OPTIONS]

OPTIONS:
    -p, --port <PORT>        Port to proxy on (default 3000)
        --mcp-port <PORT>    Port for the MCP server (default 3001; 0 disables)
        --listen <ADDR>      Address to bind both listeners to (default 127.0.0.1)
        --project <NAME>     Project to open (default \"default\")
        --data-dir <PATH>    Where projects live (default ~/.proxy)
        --export-ca <PATH>   Write the CA certificate here and exit
    -h, --help               Print this
    -V, --version            Print the version

The CA is also downloadable through the proxy itself, at http://proxy/ — which
is the only practical way to install it on a phone.
";

#[derive(Debug, PartialEq, Eq)]
pub struct Args {
    pub listen: IpAddr,
    pub port: u16,
    /// `0` means "do not start it". Useful when running two instances, where
    /// the second would otherwise fail to bind and log a confusing error.
    pub mcp_port: u16,
    pub project: String,
    /// `None` means the default location, resolved later — the parser does not
    /// touch the filesystem, which is what makes it testable.
    pub data_dir: Option<PathBuf>,
    pub export_ca: Option<PathBuf>,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            listen: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 3000,
            mcp_port: 3001,
            project: "default".to_string(),
            data_dir: None,
            export_ca: None,
        }
    }
}

impl Args {
    pub fn proxy_addr(&self) -> SocketAddr {
        SocketAddr::new(self.listen, self.port)
    }

    pub fn mcp_addr(&self) -> SocketAddr {
        SocketAddr::new(self.listen, self.mcp_port)
    }
}

/// What to do after parsing.
#[derive(Debug, PartialEq, Eq)]
pub enum Parsed {
    Run(Box<Args>),
    /// Print this and exit successfully.
    Print(String),
    /// Print this to stderr and exit non-zero.
    Error(String),
}

pub fn parse<I, S>(argv: I) -> Parsed
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut args = Args::default();
    let mut it = argv.into_iter().map(|s| s.as_ref().to_string());

    while let Some(arg) = it.next() {
        // `--key=value` and `--key value` both work; people type both.
        let (key, inline) = match arg.split_once('=') {
            Some((key, value)) => (key.to_string(), Some(value.to_string())),
            None => (arg.clone(), None),
        };

        let mut value = || match inline.clone() {
            Some(v) => Ok(v),
            None => it.next().ok_or(format!("{key} needs a value")),
        };

        match key.as_str() {
            "-h" | "--help" => return Parsed::Print(USAGE.to_string()),
            "-V" | "--version" => {
                return Parsed::Print(format!("proxy {}\n", env!("CARGO_PKG_VERSION")));
            }
            "-p" | "--port" => match value().and_then(parse_port) {
                Ok(port) => args.port = port,
                Err(e) => return Parsed::Error(e),
            },
            "--mcp-port" => match value().and_then(parse_port) {
                Ok(port) => args.mcp_port = port,
                Err(e) => return Parsed::Error(e),
            },
            "--listen" => match value().and_then(|v| {
                v.parse::<IpAddr>()
                    .map_err(|_| format!("not an IP address: {v}"))
            }) {
                Ok(addr) => args.listen = addr,
                Err(e) => return Parsed::Error(e),
            },
            "--project" => match value() {
                Ok(name) if !name.trim().is_empty() => args.project = name,
                Ok(_) => return Parsed::Error("--project needs a name".into()),
                Err(e) => return Parsed::Error(e),
            },
            "--data-dir" => match value() {
                Ok(path) => args.data_dir = Some(PathBuf::from(path)),
                Err(e) => return Parsed::Error(e),
            },
            "--export-ca" => match value() {
                Ok(path) => args.export_ca = Some(PathBuf::from(path)),
                Err(e) => return Parsed::Error(e),
            },
            other => {
                return Parsed::Error(format!("unknown argument: {other}\n\nTry --help."));
            }
        }
    }

    Parsed::Run(Box::new(args))
}

/// Ports are `u16`, and `0` is meaningful only for the MCP server. Rejecting
/// out-of-range here beats a confusing bind failure later.
fn parse_port(value: String) -> Result<u16, String> {
    value
        .parse::<u16>()
        .map_err(|_| format!("not a port: {value}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(argv: &[&str]) -> Args {
        match parse(argv) {
            Parsed::Run(args) => *args,
            other => panic!("expected a run, got {other:?}"),
        }
    }

    fn error(argv: &[&str]) -> String {
        match parse(argv) {
            Parsed::Error(e) => e,
            other => panic!("expected an error, got {other:?}"),
        }
    }

    #[test]
    fn no_arguments_is_the_documented_default() {
        let args = run(&[]);
        assert_eq!(args.proxy_addr().to_string(), "127.0.0.1:3000");
        assert_eq!(args.mcp_addr().to_string(), "127.0.0.1:3001");
        assert_eq!(args.project, "default");
        assert_eq!(args.data_dir, None);
    }

    #[test]
    fn ports_and_project_are_settable() {
        let args = run(&["--port", "8080", "--mcp-port", "8081", "--project", "acme"]);
        assert_eq!(args.port, 8080);
        assert_eq!(args.mcp_port, 8081);
        assert_eq!(args.project, "acme");
    }

    /// People type both forms without thinking about it.
    #[test]
    fn equals_and_space_forms_agree() {
        assert_eq!(run(&["--port=8080"]).port, run(&["--port", "8080"]).port);
        assert_eq!(
            run(&["--project=acme"]).project,
            run(&["--project", "acme"]).project
        );
    }

    #[test]
    fn short_flags_work() {
        assert_eq!(run(&["-p", "9000"]).port, 9000);
        assert!(matches!(parse(["-h"]), Parsed::Print(_)));
        assert!(matches!(parse(["-V"]), Parsed::Print(_)));
    }

    #[test]
    fn listening_elsewhere_is_allowed_but_not_the_default() {
        let args = run(&["--listen", "0.0.0.0", "--port", "8080"]);
        assert_eq!(args.proxy_addr().to_string(), "0.0.0.0:8080");
        assert_eq!(
            Args::default().listen.to_string(),
            "127.0.0.1",
            "binding beyond loopback must be a deliberate choice"
        );
    }

    /// The whole reason unknown arguments are an error: a typo that is ignored
    /// leaves the proxy listening somewhere other than where you asked.
    #[test]
    fn a_typo_is_refused_rather_than_ignored() {
        let e = error(&["--porb", "8080"]);
        assert!(e.contains("unknown argument"), "{e}");
        assert!(e.contains("--help"), "{e}");
    }

    #[test]
    fn bad_values_say_what_was_wrong() {
        assert!(error(&["--port", "notanumber"]).contains("not a port"));
        assert!(error(&["--port", "99999"]).contains("not a port"));
        assert!(error(&["--listen", "nope"]).contains("not an IP address"));
        assert!(error(&["--port"]).contains("needs a value"));
        assert!(error(&["--project", "  "]).contains("needs a name"));
    }

    /// Zero disables the MCP server, which is how you run two instances
    /// without the second logging a confusing bind failure.
    #[test]
    fn mcp_can_be_switched_off() {
        assert_eq!(run(&["--mcp-port", "0"]).mcp_port, 0);
    }

    #[test]
    fn export_ca_is_a_path() {
        let args = run(&["--export-ca", "/tmp/ca.cer"]);
        assert_eq!(args.export_ca, Some(PathBuf::from("/tmp/ca.cer")));
    }

    #[test]
    fn help_mentions_every_option() {
        for flag in [
            "--port",
            "--mcp-port",
            "--listen",
            "--project",
            "--data-dir",
            "--export-ca",
        ] {
            assert!(USAGE.contains(flag), "{flag} missing from --help");
        }
    }
}
