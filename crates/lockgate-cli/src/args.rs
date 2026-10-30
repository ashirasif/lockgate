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
lockgate — an intercepting HTTP proxy for security testing

USAGE:
    lockgate [OPTIONS]

OPTIONS:
    -p, --port <PORT>        Port to proxy on (default 3000)
        --mcp-port <PORT>    Port for the MCP server (default 3001; 0 disables)
        --listen <ADDR>      Address to bind both listeners to (default 127.0.0.1)
        --project <NAME>     Open this project directly, skipping the picker
        --data-dir <PATH>    Where projects live (default ~/.lockgate)
        --export-ca <PATH>   Write the CA certificate here and exit
        --cdp-chrome         Ensure a CDP Chrome (persistent profile, port
                             --cdp-port) is running at startup, so an agent's
                             browser client can attach without a launch script
        --cdp-port <PORT>    Port for CDP Chrome (default 9222)
        --ntfy <URL>         Push headline events (findings, settled leads) to
                             an ntfy-compatible topic, e.g.
                             https://ntfy.sh/my-secret-topic
        --status-token <T>   Require ?token=<T> on the /status dashboard —
                             set it before exposing the port beyond loopback
        --no-tui             Run without the terminal UI (proxy + MCP only;
                             needs --project, since the picker needs a terminal)
        --no-mcp             Run without the MCP server (TUI + proxy only)
    -h, --help               Print this
    -V, --version            Print the version

The CA is also downloadable through the proxy itself, at http://lockgate/ — which
is the only practical way to install it on a phone.
";

#[derive(Debug, PartialEq, Eq)]
pub struct Args {
    pub listen: IpAddr,
    pub port: u16,
    /// `0` means "do not start it". Useful when running two instances, where
    /// the second would otherwise fail to bind and log a confusing error.
    pub mcp_port: u16,
    /// `None` shows the startup picker; `Some(name)` opens that project directly
    /// and skips it — the scriptable path, and what every non-interactive test
    /// wants so it lands on a known project without a menu waiting on input.
    pub project: Option<String>,
    /// `None` means the default location, resolved later — the parser does not
    /// touch the filesystem, which is what makes it testable.
    pub data_dir: Option<PathBuf>,
    pub export_ca: Option<PathBuf>,
    /// Ensure a CDP Chrome is up before anything else starts — the agent's
    /// identity-bearing browser, attachable at `--cdp-port`.
    pub cdp_chrome: bool,
    pub cdp_port: u16,
    /// ntfy-compatible topic URL for push notifications, when asked for.
    pub ntfy: Option<String>,
    /// Required `?token=` on the /status dashboard, when asked for.
    pub status_token: Option<String>,
    /// Run the proxy and MCP server without taking over the terminal — the
    /// headless shape a server or container wants, where an agent drives
    /// everything through the MCP.
    pub no_tui: bool,
    /// Skip the MCP server: the TUI and proxy only. Same effect as
    /// `--mcp-port 0`, spelled as its own flag so it is discoverable.
    pub no_mcp: bool,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            listen: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 3000,
            mcp_port: 3001,
            project: None,
            data_dir: None,
            export_ca: None,
            cdp_chrome: false,
            cdp_port: lockgate_core::browser::CdpConfig::default().port,
            ntfy: None,
            status_token: None,
            no_tui: false,
            no_mcp: false,
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
                return Parsed::Print(format!("lockgate {}\n", env!("CARGO_PKG_VERSION")));
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
                Ok(name) if !name.trim().is_empty() => args.project = Some(name),
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
            "--cdp-chrome" => args.cdp_chrome = true,
            "--cdp-port" => match value().and_then(parse_port) {
                Ok(port) => args.cdp_port = port,
                Err(e) => return Parsed::Error(e),
            },
            "--ntfy" => match value() {
                Ok(url) if url.starts_with("http://") || url.starts_with("https://") => {
                    args.ntfy = Some(url)
                }
                Ok(_) => return Parsed::Error("--ntfy needs an http(s) topic URL".into()),
                Err(e) => return Parsed::Error(e),
            },
            "--status-token" => match value() {
                Ok(t) if !t.trim().is_empty() => args.status_token = Some(t),
                Ok(_) => return Parsed::Error("--status-token needs a value".into()),
                Err(e) => return Parsed::Error(e),
            },
            "--no-tui" => args.no_tui = true,
            "--no-mcp" => args.no_mcp = true,
            other => {
                return Parsed::Error(format!("unknown argument: {other}\n\nTry --help."));
            }
        }
    }

    // The picker is a TUI, so headless mode has no way to choose a project:
    // refusing here beats starting a process that blocks forever on a menu
    // nobody can see.
    if args.no_tui && args.project.is_none() {
        return Parsed::Error("--no-tui needs --project: the picker needs a terminal".into());
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
        assert_eq!(args.project, None, "no --project means the picker");
        assert_eq!(args.data_dir, None);
    }

    #[test]
    fn ports_and_project_are_settable() {
        let args = run(&["--port", "8080", "--mcp-port", "8081", "--project", "acme"]);
        assert_eq!(args.port, 8080);
        assert_eq!(args.mcp_port, 8081);
        assert_eq!(args.project.as_deref(), Some("acme"));
    }

    #[test]
    fn ntfy_and_status_token_parse() {
        let args = run(&[
            "--ntfy",
            "https://ntfy.sh/my-topic",
            "--status-token",
            "sekrit",
        ]);
        assert_eq!(args.ntfy.as_deref(), Some("https://ntfy.sh/my-topic"));
        assert_eq!(args.status_token.as_deref(), Some("sekrit"));

        // A non-http topic is a typo, not a silently dead push.
        let e = error(&["--ntfy", "my-topic"]);
        assert!(e.contains("http"), "{e}");
        let e = error(&["--status-token", ""]);
        assert!(!e.is_empty());
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

    /// Each front-end can run on its own: `--no-tui` for a headless proxy
    /// driven through the MCP, `--no-mcp` for a purely interactive session.
    #[test]
    fn either_frontend_can_be_switched_off() {
        let args = run(&["--no-tui", "--project", "acme"]);
        assert!(args.no_tui);
        assert!(!args.no_mcp);
        let args = run(&["--no-mcp"]);
        assert!(args.no_mcp);
        assert!(!args.no_tui);
    }

    /// The startup picker needs a terminal, so headless mode has to name its
    /// project — otherwise the process would wait on a menu nobody can see.
    #[test]
    fn headless_needs_a_project() {
        let e = error(&["--no-tui"]);
        assert!(e.contains("--no-tui needs --project"), "{e}");
        // And naming one is enough.
        assert!(matches!(
            parse(["--no-tui", "--project", "acme"]),
            Parsed::Run(_)
        ));
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
            "--no-tui",
            "--no-mcp",
        ] {
            assert!(USAGE.contains(flag), "{flag} missing from --help");
        }
    }
}
