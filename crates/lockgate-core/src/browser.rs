//! A CDP-capable Chrome with a persistent profile, ensured rather than launched.
//!
//! The operator's browser-with-identity story used to be a hand-run script:
//! start Chrome with a separate user-data-dir and a remote-debugging port, then
//! point an agent's browser tool at it. This module makes lockgate own that —
//! same profile directory (so an identity you logged in once keeps its
//! sessions), same port — so `ensure` is something an agent can simply call and
//! find done, whether nobody has started it yet or it is already running.
//!
//! The spawned Chrome is deliberately left running after lockgate exits: it
//! holds the identity's live sessions, and killing it would log those out from
//! under the next run.

use std::path::PathBuf;

/// Defaults match the hand-run script this replaces: the profile is where the
/// operator's sessions already live, and 9222 is what every CDP client assumes.
const DEFAULT_PORT: u16 = 9222;
const DEFAULT_PROFILE_SUBDIR: &str = ".chrome-mcp-profile";

#[derive(Clone, Debug)]
pub struct CdpConfig {
    pub port: u16,
    pub profile: PathBuf,
    /// Overrides binary discovery. `None` walks the usual suspects (see
    /// [`find_binary`]).
    pub binary: Option<PathBuf>,
    /// `None` means auto: headless when there is no display to show a window
    /// in (a VPS), headed otherwise. Explicit `Some` wins — see
    /// `LOCKGATE_CDP_HEADLESS`.
    pub headless: Option<bool>,
}

impl Default for CdpConfig {
    fn default() -> Self {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        Self {
            port: DEFAULT_PORT,
            profile: home.join(DEFAULT_PROFILE_SUBDIR),
            binary: None,
            headless: None,
        }
    }
}

impl CdpConfig {
    /// Defaults with `LOCKGATE_CHROME` (binary), `LOCKGATE_CDP_PORT` /
    /// `LOCKGATE_CDP_PROFILE` (path) and `LOCKGATE_CDP_HEADLESS` (0/1)
    /// respected — the overrides a headless VPS needs, where the macOS Chrome
    /// path does not exist and there is no display to open a window on.
    pub fn from_env() -> Self {
        let mut cfg = Self::default();
        if let Some(path) = std::env::var_os("LOCKGATE_CHROME") {
            cfg.binary = Some(PathBuf::from(path));
        }
        if let Ok(port) = std::env::var("LOCKGATE_CDP_PORT")
            && let Ok(port) = port.parse()
        {
            cfg.port = port;
        }
        if let Some(dir) = std::env::var_os("LOCKGATE_CDP_PROFILE") {
            cfg.profile = PathBuf::from(dir);
        }
        if let Ok(v) = std::env::var("LOCKGATE_CDP_HEADLESS") {
            cfg.headless = Some(v == "1" || v.eq_ignore_ascii_case("true"));
        }
        cfg
    }

    /// Auto-detection: no display means headless is the only mode that works.
    /// macOS and desktop Linux have a display; a VPS has neither X nor Wayland.
    fn resolves_headless(&self) -> bool {
        if let Some(explicit) = self.headless {
            return explicit;
        }
        std::env::var_os("DISPLAY").is_none()
            && std::env::var_os("WAYLAND_DISPLAY").is_none()
            && !cfg!(target_os = "macos")
    }
}

/// What an ensure found or did.
#[derive(Clone, Debug)]
pub struct CdpStatus {
    /// True when something was already listening and we started nothing.
    pub already_running: bool,
    /// The endpoint a browser client attaches to.
    pub cdp_url: String,
    pub profile: PathBuf,
    pub binary: PathBuf,
    /// Whether the browser was launched (or is assumed to run) headless.
    pub headless: bool,
}

#[derive(Debug)]
pub enum BrowserError {
    /// No Chrome (or Chromium) could be found to launch.
    NotFound,
    /// Spawned, but the CDP endpoint never answered.
    DidNotListen(std::io::Error),
}

impl std::fmt::Display for BrowserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BrowserError::NotFound => write!(
                f,
                "no Chrome found — set LOCKGATE_CHROME to the binary path"
            ),
            BrowserError::DidNotListen(e) => {
                write!(f, "Chrome never exposed CDP: {e}")
            }
        }
    }
}

impl std::error::Error for BrowserError {}

/// Make sure a CDP Chrome is up: return immediately when one already listens,
/// otherwise launch one and wait for the endpoint.
///
/// Idempotent by design — two callers (the `--cdp-chrome` startup flag, the
/// agent's `browser_ensure` tool) can race and both get an up browser.
pub async fn ensure(cfg: &CdpConfig) -> Result<CdpStatus, BrowserError> {
    let cdp_url = format!("http://127.0.0.1:{}/", cfg.port);
    let headless = cfg.resolves_headless();
    if is_listening(&cdp_url).await {
        // The binary may have been started by anything; the profile is only
        // known when we spawn. Report the profile as configured either way —
        // it is the one this run would use.
        return Ok(CdpStatus {
            already_running: true,
            cdp_url,
            profile: cfg.profile.clone(),
            binary: find_binary(&cfg.binary).unwrap_or_default(),
            headless,
        });
    }

    let binary = find_binary(&cfg.binary).ok_or(BrowserError::NotFound)?;
    let mut command = tokio::process::Command::new(&binary);
    command
        .arg(format!("--remote-debugging-port={}", cfg.port))
        .arg(format!("--user-data-dir={}", cfg.profile.display()))
        .args(["--no-first-run", "--no-default-browser-check"]);
    // A machine with no display cannot open a window; asking it to would fail
    // the launch outright rather than degrade.
    if headless {
        command.arg("--headless=new");
    }
    // We never wait on Chrome, and tokio does not kill a spawned child when
    // the handle drops (kill_on_drop defaults to false) — so letting the
    // handle go is exactly right: the browser outlives lockgate on purpose.
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(BrowserError::DidNotListen)?;

    // Chrome takes a few seconds to open its debugging socket. Poll rather
    // than sleep a fixed amount: fast when it is quick, bounded when it is not.
    let deadline = tokio::time::Duration::from_secs(15);
    let mut waited = tokio::time::Duration::ZERO;
    let step = tokio::time::Duration::from_millis(300);
    while waited < deadline {
        tokio::time::sleep(step).await;
        waited += step;
        if is_listening(&cdp_url).await {
            return Ok(CdpStatus {
                already_running: false,
                cdp_url,
                profile: cfg.profile.clone(),
                binary,
                headless,
            });
        }
    }
    Err(BrowserError::DidNotListen(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("no answer on {cdp_url} within {deadline:?}"),
    )))
}

/// Is the CDP endpoint answering? A cheap GET of `/json/version`, the same
/// probe the launch script used.
async fn is_listening(cdp_url: &str) -> bool {
    reqwest::Client::new()
        .get(format!("{cdp_url}json/version"))
        .timeout(std::time::Duration::from_millis(500))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

/// Where a launchable Chrome lives: an explicit override, then the macOS app
/// bundle, then whatever the PATH offers. Linux names last — that is the VPS
/// shape, and the `which`-style walk needs no subprocess.
fn find_binary(override_path: &Option<PathBuf>) -> Option<PathBuf> {
    if let Some(path) = override_path
        && path.exists()
    {
        return Some(path.clone());
    }
    let macos = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
    if std::path::Path::new(macos).exists() {
        return Some(PathBuf::from(macos));
    }
    for name in [
        "google-chrome-stable",
        "google-chrome",
        "chromium-browser",
        "chromium",
    ] {
        let path = std::path::Path::new("/usr/bin").join(name);
        if path.exists() {
            return Some(path);
        }
        let path = std::path::Path::new("/usr/local/bin").join(name);
        if path.exists() {
            return Some(path);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_hand_run_script() {
        let cfg = CdpConfig::default();
        assert_eq!(cfg.port, 9222);
        assert!(
            cfg.profile.ends_with(".chrome-mcp-profile"),
            "the profile is where existing sessions live: {:?}",
            cfg.profile
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn discovers_the_macos_chrome() {
        let found = find_binary(&None);
        assert!(
            found.as_ref().is_some_and(|p| p.ends_with("Google Chrome")),
            "expected the app bundle, got {found:?}"
        );
    }

    /// Explicit headless wins; auto is the no-display rule (VPS), never
    /// env-dependent on macOS.
    #[test]
    fn headless_resolves_explicit_over_auto() {
        let cfg = CdpConfig {
            headless: Some(true),
            ..CdpConfig::default()
        };
        assert!(cfg.resolves_headless());
        let cfg = CdpConfig {
            headless: Some(false),
            ..CdpConfig::default()
        };
        assert!(!cfg.resolves_headless());
    }

    #[test]
    fn an_existing_override_wins_and_a_missing_one_falls_through() {
        let real = std::env::temp_dir().join(format!("chrome-fake-{}", std::process::id()));
        std::fs::write(&real, b"").unwrap();

        let found = find_binary(&Some(real.clone()));
        assert_eq!(
            found.as_deref(),
            Some(real.as_path()),
            "explicit override wins"
        );

        let missing = std::path::PathBuf::from("/nowhere/chrome");
        let found = find_binary(&Some(missing.clone()));
        assert_ne!(
            found.as_deref(),
            Some(missing.as_path()),
            "a nonexistent override must not be reported as found"
        );
        std::fs::remove_file(&real).ok();
    }

    /// Nothing here spawns a real browser: `ensure` is exercised against a live
    /// Chrome only by hand, since a test run must not open windows on the
    /// operator's machine.
    #[tokio::test]
    async fn a_dead_endpoint_is_reported_as_silence() {
        assert!(!is_listening("http://127.0.0.1:59999/").await);
    }
}
