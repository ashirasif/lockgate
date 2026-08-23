use super::*;
use hudsucker::hyper::{HeaderMap, Method, Uri, Version, body::Bytes};
use lockgate_core::{CapturedRequest, CapturedResponse};
use ratatui::{
    Terminal,
    backend::TestBackend,
    crossterm::event::{KeyCode, KeyEvent, KeyModifiers},
};

/// Render to an in-memory buffer, one `String` per terminal row. Keeping
/// rows separate is what lets us assert on *layout*, not just content.
fn render_rows(app: &mut App) -> Vec<String> {
    let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
    terminal.draw(|frame| app.draw(frame)).unwrap();
    let buffer = terminal.backend().buffer().clone();
    let width = buffer.area.width as usize;
    buffer
        .content()
        .chunks(width)
        .map(|row| row.iter().map(|cell| cell.symbol()).collect())
        .collect()
}

fn render(app: &mut App) -> String {
    render_rows(app).join("\n")
}

fn get_request(uri: &'static str) -> CapturedRequest {
    CapturedRequest {
        method: Method::GET,
        uri: Uri::from_static(uri),
        version: Version::HTTP_11,
        headers: HeaderMap::new(),
        body: Bytes::new(),
    }
}

#[test]
fn shows_captured_flows_and_help() {
    let engine = Engine::new();
    engine.record_request(get_request("http://example.com/foo"));

    let mut app = App::new(engine);
    app.refresh();
    let out = render(&mut app);

    assert!(out.contains("HTTP History (1)"), "{out}");
    assert!(out.contains("GET"), "{out}");
    assert!(out.contains("example.com/foo"), "{out}");
    // The statusline is vim's: a mode indicator and a position counter.
    assert!(out.contains("NORMAL"), "{out}");
    assert!(out.contains("1/1"), "{out}");
}

/// Drive the app the way a user does — through keys, not method calls —
/// so the keymap and the app stay wired together.
fn press(app: &mut App, keys: &str) {
    for c in keys.chars() {
        if let Some(action) = app.input.feed(KeyEvent::from(KeyCode::Char(c))) {
            app.apply(action);
        }
        app.refresh();
    }
}

/// Feed one arbitrary key event (for the ones `press` can't spell: Ctrl
/// combos, Enter, Escape).
fn key(app: &mut App, event: KeyEvent) {
    if let Some(action) = app.input.feed(event) {
        app.apply(action);
    }
    app.refresh();
}

/// Record one flow at a given URI, for scope tests that care about hosts.
fn record_flow(engine: &Arc<Engine>, uri: &str) {
    let uri: Uri = uri.parse().unwrap();
    let id = engine.record_request(CapturedRequest {
        method: Method::GET,
        uri,
        version: Version::HTTP_11,
        headers: HeaderMap::new(),
        body: Bytes::new(),
    });
    engine.record_response(
        id,
        CapturedResponse {
            status: StatusCode::OK,
            version: Version::HTTP_11,
            headers: HeaderMap::new(),
            body: Bytes::new(),
        },
    );
}

/// Record a WebSocket connection the way the proxy handler does: a 101
/// upgrade with a couple of frames hanging off it.
fn record_ws(engine: &Arc<Engine>, uri: &str) -> u64 {
    let id = engine.record_request(CapturedRequest {
        method: Method::GET,
        uri: uri.parse().unwrap(),
        version: Version::HTTP_11,
        headers: HeaderMap::new(),
        body: Bytes::new(),
    });
    engine.record_response(
        id,
        CapturedResponse {
            status: StatusCode::SWITCHING_PROTOCOLS,
            version: Version::HTTP_11,
            headers: HeaderMap::new(),
            body: Bytes::new(),
        },
    );
    engine.record_ws_message(id, 0, "c2s", "text", Bytes::from_static(b"hello"));
    engine.record_ws_message(id, 1, "s2c", "text", Bytes::from_static(b"world"));
    id
}

fn engine_with(count: usize) -> Arc<Engine> {
    let engine = Engine::new();
    for i in 0..count {
        let uri: Uri = format!("http://example.com/{i}").parse().unwrap();
        engine.record_request(CapturedRequest {
            method: Method::GET,
            uri,
            version: Version::HTTP_11,
            headers: HeaderMap::new(),
            body: Bytes::new(),
        });
    }
    engine
}

#[test]
fn counts_reach_the_cursor() {
    let mut app = App::new(engine_with(20));
    app.refresh();
    press(&mut app, "5j");
    assert_eq!(app.cursor(), 5);
    press(&mut app, "2k");
    assert_eq!(app.cursor(), 3);
}

/// `G` goes to the end, `12G` goes to line 12 — the count must survive.
#[test]
fn goto_line_versus_goto_end() {
    let mut app = App::new(engine_with(20));
    app.refresh();
    press(&mut app, "G");
    assert_eq!(app.cursor(), 19);
    press(&mut app, "12G");
    assert_eq!(app.cursor(), 11);
    press(&mut app, "gg");
    assert_eq!(app.cursor(), 0);
}

#[test]
fn marks_survive_new_traffic_arriving() {
    let engine = engine_with(5);
    let mut app = App::new(engine.clone());
    app.refresh();
    press(&mut app, "3j");
    let marked = app.selected_id().unwrap();
    press(&mut app, "ma");

    // More requests land, shifting nothing here but proving ids are used.
    press(&mut app, "gg");
    press(&mut app, "'a");
    assert_eq!(app.selected_id(), Some(marked));
}

#[test]
fn jumplist_returns_to_where_you_left() {
    let mut app = App::new(engine_with(20));
    app.refresh();
    press(&mut app, "5j");
    press(&mut app, "G");
    assert_eq!(app.cursor(), 19);
    // `G` is a jump, so `<C-o>` goes back to where it was invoked from.
    app.apply(Action::JumpBack);
    assert_eq!(app.cursor(), 5);
    app.apply(Action::JumpForward);
    assert_eq!(app.cursor(), 19);
}

#[test]
fn search_moves_to_the_next_match() {
    let mut app = App::new(engine_with(20));
    app.refresh();
    app.apply(Action::Search {
        pattern: "/17".into(),
        backward: false,
    });
    // Newest first: `/17` is the 17th of 20 captured, so it sits at row 2.
    assert_eq!(app.cursor(), 2);
    assert_eq!(app.selected_id(), Some(17));
}

/// `q` no longer quits — that key belongs to macro recording — so the
/// whole `:q` round trip has to work through the command line.
#[test]
fn ex_quit_sets_the_quit_flag() {
    let mut app = App::new(engine_with(3));
    app.refresh();
    press(&mut app, ":q");
    assert!(!app.should_quit, "still typing the command");
    if let Some(action) = app.input.feed(KeyEvent::from(KeyCode::Enter)) {
        app.apply(action);
    }
    assert!(app.should_quit);
}

#[test]
fn bare_q_does_not_quit() {
    let mut app = App::new(engine_with(3));
    app.refresh();
    press(&mut app, "q");
    assert!(!app.should_quit, "q is reserved for macro recording");
}

/// A visual selection resends every covered flow, not just the cursor.
#[test]
fn visual_selection_covers_a_range() {
    let mut app = App::new(engine_with(10));
    app.refresh();
    press(&mut app, "2j");
    app.apply(Action::ModeChange(Mode::Visual));
    press(&mut app, "3j");
    assert_eq!(app.selected_rows(), 2..=5);
}

/// `:set rnu` swaps the id gutter for distances from the cursor.
#[test]
fn relative_numbers_are_a_set_option() {
    let mut app = App::new(engine_with(10));
    app.refresh();
    app.apply(Action::Command("set rnu".into()));
    press(&mut app, "5j");
    let rows = render_rows(&mut app);
    let cursor_row = rows.iter().position(|r| r.contains('▶')).unwrap();
    // The row directly above the cursor is one line away.
    assert!(rows[cursor_row - 1].contains(" 1 "), "{}", rows.join("\n"));
}

#[test]
fn detail_pane_tracks_selection_and_response() {
    let engine = Engine::new();
    engine.record_request(get_request("http://example.com/first"));
    let second = engine.record_request(get_request("http://example.com/second"));
    engine.record_response(
        second,
        CapturedResponse {
            status: hudsucker::hyper::StatusCode::NOT_FOUND,
            version: Version::HTTP_11,
            headers: HeaderMap::new(),
            body: Bytes::from_static(b"missing-marker"),
        },
    );

    let mut app = App::new(engine);
    app.refresh();

    // History is newest-first, so the cursor starts on `second` — the flow
    // that has the response.
    let out = render(&mut app);
    assert!(out.contains("404"), "{out}");
    assert!(out.contains("missing-marker"), "{out}");

    // `j` moves *down* the list, which is backwards in time, to `first`.
    app.move_cursor(Motion::Down, None);
    app.refresh();
    let out = render(&mut app);
    assert!(out.contains("/first"), "{out}");
    assert!(
        !out.contains("missing-marker"),
        "the older flow has no response: {out}"
    );
}

/// Capture time is a column in the history, rendered as a local wall clock.
#[test]
fn history_shows_capture_time() {
    let engine = Engine::new();
    engine.record_request(get_request("http://example.com/foo"));
    let mut app = App::new(engine);
    app.refresh();

    let out = render(&mut app);
    assert!(out.contains("TIME"), "expected a TIME column: {out}");

    // The recorded row should carry a real clock time, not the fallback.
    let stamped = clock_time(app.flows[0].started_at);
    assert!(
        stamped.contains(':') && stamped != "--:--:--",
        "expected a formatted time, got {stamped}"
    );
    assert!(out.contains(&stamped), "{stamped} should be shown: {out}");
}

/// A timestamp that cannot be represented renders as a placeholder rather
/// than a misleading number.
#[test]
fn an_unrepresentable_time_falls_back() {
    assert_eq!(clock_time(i64::MAX), "--:--:--");
}

/// Newest first, so the request you just made is at the top rather than
/// somewhere below the fold on a busy target.
#[test]
fn history_is_newest_first() {
    let engine = Engine::new();
    engine.record_request(get_request("http://example.com/oldest"));
    engine.record_request(get_request("http://example.com/newest"));

    let mut app = App::new(engine);
    app.refresh();
    assert_eq!(app.flows[0].uri.path(), "/newest");
    assert_eq!(app.flows[1].uri.path(), "/oldest");
}

/// New traffic inserts at the top and pushes rows down. The cursor has to
/// stay on the flow it was on, or it silently drifts onto another request
/// while the operator is reading it.
#[test]
fn selection_survives_new_traffic_arriving() {
    let engine = Engine::new();
    engine.record_request(get_request("http://example.com/watched"));

    let mut app = App::new(engine.clone());
    app.refresh();
    let watched = app.selected_id();
    assert_eq!(app.cursor(), 0);

    // Three more requests arrive; the watched flow is now three rows down.
    for _ in 0..3 {
        engine.record_request(get_request("http://example.com/noise"));
    }
    app.refresh();

    assert_eq!(app.cursor(), 3, "the cursor should have followed its flow");
    assert_eq!(app.selected_id(), watched, "and still point at it");
}

/// `:N` addresses the flow id shown in the gutter, not the Nth row.
#[test]
fn goto_addresses_a_flow_by_id() {
    let mut app = App::new(engine_with(20));
    app.refresh();
    app.run_command("7");
    assert_eq!(app.selected_id(), Some(7));

    app.run_command("999");
    assert_eq!(app.selected_id(), Some(7), "an unknown id should not move");
}

#[test]
fn request_and_response_panes_are_side_by_side() {
    let engine = Engine::new();
    engine.record_request(get_request("http://example.com/foo"));

    let mut app = App::new(engine);
    app.refresh();
    let rows = render_rows(&mut app);

    // Burp-style horizontal split: both titles share one row, request left.
    let titled = rows
        .iter()
        .find(|row| row.contains("Request") && row.contains("Response"))
        .unwrap_or_else(|| panic!("no row has both panes:\n{}", rows.join("\n")));
    assert!(
        titled.find("Request") < titled.find("Response"),
        "request pane should be left of response: {titled}"
    );
}

/// A keystroke goes through `refresh_view` alone. The history lists are the
/// expensive read — ~20ms against a real capture — and paying that per keypress
/// is what made editing feel slow, so the cheap path must not go near them.
#[test]
fn the_keystroke_path_leaves_the_history_alone() {
    let mut app = App::new(engine_with(5));
    app.refresh();
    assert_eq!(app.flows.len(), 5);

    // Stand in for the expensive rebuild: if `refresh_view` re-reads the list,
    // it will put these back.
    app.flows.clear();
    app.refresh_view(false);
    assert!(
        app.flows.is_empty(),
        "refresh_view must not re-read the history"
    );
}

/// ...but the detail pane still has to keep up with the cursor, which is the
/// one per-flow read the keystroke path does owe.
#[test]
fn the_detail_pane_follows_the_cursor_on_the_cheap_path() {
    let mut app = App::new(engine_with(3));
    app.refresh();
    let first = app
        .detail
        .as_ref()
        .expect("a flow is selected")
        .request
        .uri
        .clone();

    press(&mut app, "j");
    app.refresh_view(false);
    let second = app
        .detail
        .as_ref()
        .expect("a flow is selected")
        .request
        .uri
        .clone();

    assert_ne!(
        first, second,
        "the detail pane should have followed the cursor"
    );
}

/// Scope is applied when the history is read, so toggling it changes the list
/// without the engine moving — the one case the revision cannot speak for.
#[test]
fn toggling_the_scope_filter_asks_for_a_reload() {
    let mut app = App::new(engine_with(3));
    app.refresh();
    assert!(!app.flows_stale);

    app.set_scope_filter(false);
    assert!(
        app.flows_stale,
        "the history is read through the filter, so it has to be read again"
    );
}

/// The window math, away from any terminal. `offset` is where the last
/// frame left the window; the result is where this one puts it.
#[test]
fn the_window_moves_only_as_far_as_the_cursor_makes_it() {
    // Cursor already inside: nothing moves.
    assert_eq!(visible_window(0, 3, 100, 10), 0..10);
    assert_eq!(visible_window(20, 25, 100, 10), 20..30);
    // Off the top and off the bottom: the cursor lands on the edge it left
    // by, not in the middle — vim scrolls, it does not recentre.
    assert_eq!(visible_window(20, 15, 100, 10), 15..25);
    assert_eq!(visible_window(20, 35, 100, 10), 26..36);
    // A list shorter than the screen is shown whole, however stale the
    // offset is, and an empty one has no window at all.
    assert_eq!(visible_window(50, 2, 5, 10), 0..5);
    assert_eq!(visible_window(0, 0, 0, 10), 0..0);
    // A zero-height table cannot show a row, and must not try.
    assert_eq!(visible_window(0, 0, 100, 0), 0..0);
    // The end of a long list fills the screen rather than trailing blanks.
    assert_eq!(visible_window(0, 99, 100, 10), 90..100);
}

/// The history table builds rows for the slice on screen, not for the whole
/// capture — so the thing the window has to get right is that the cursor is
/// always in it, whichever end of the capture it is at.
#[test]
fn the_history_window_follows_the_cursor() {
    let mut app = App::new(engine_with(500));
    app.refresh();

    // Newest-first: the cursor starts on /499, and /0 is 500 rows below.
    let out = render(&mut app);
    assert!(out.contains("http://example.com/499"), "{out}");
    assert!(!out.contains("http://example.com/0 "), "{out}");

    press(&mut app, "G");
    let out = render(&mut app);
    assert!(out.contains("http://example.com/0 "), "{out}");
    assert!(!out.contains("http://example.com/499"), "{out}");
}

/// `H` / `M` / `L` are defined against what is on screen, so they read the
/// offset — which the windowed draw has to keep as an index into the whole
/// capture, not into the slice it handed the widget.
#[test]
fn screen_motions_read_the_windows_offset() {
    let mut app = App::new(engine_with(500));
    app.refresh();
    press(&mut app, "G");
    render(&mut app);

    let (offset, page) = (app.table.offset(), app.viewport);
    assert!(offset > 0, "the end of 500 flows should be scrolled to");

    press(&mut app, "H");
    assert_eq!(app.cursor(), offset, "H goes to the top of the screen");
    press(&mut app, "L");
    assert_eq!(
        app.cursor(),
        offset + page - 1,
        "L goes to the bottom of the screen"
    );
}

/// The tab strip is always on screen and shows every window with its key.
#[test]
fn tab_strip_lists_every_window() {
    let mut app = App::new(engine_with(1));
    app.refresh();
    // 100 columns cannot hold nine full names, so the strip goes compact —
    // but every window still has a chip, and every chip still has its key.
    let out = render(&mut app);
    for chip in [
        "Proxy (P)",
        "WS (W)",
        "Int (I)",
        "Rep (R)",
        "Scope (C)",
        "Find (T)",
        "Notes (K)",
        "Site (S)",
        "Auto (A)",
    ] {
        assert!(out.contains(chip), "missing tab {chip}:\n{out}");
    }
}

/// Given the room, the strip spells the names out.
#[test]
fn a_wide_terminal_gets_the_full_tab_names() {
    let mut app = App::new(engine_with(1));
    app.refresh();
    let mut terminal = Terminal::new(TestBackend::new(140, 24)).unwrap();
    terminal.draw(|frame| app.draw(frame)).unwrap();
    let out: String = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(out.contains("Intercept (I)"), "{out}");
    assert!(out.contains("Automate (A)"), "{out}");
}

/// A single uppercase key switches windows, and the body follows.
#[test]
fn shortcut_keys_switch_the_active_window() {
    let mut app = App::new(engine_with(3));
    app.refresh();
    assert_eq!(app.window, Window::Proxy);

    press(&mut app, "R");
    assert_eq!(app.window, Window::Repeater);
    assert!(render(&mut app).contains("Repeater"));

    press(&mut app, "I");
    assert_eq!(app.window, Window::Intercept);
    assert!(render(&mut app).contains("Queued requests"));

    press(&mut app, "A");
    assert_eq!(app.window, Window::Automate);
    assert!(render(&mut app).contains("BY HOST"), "{}", render(&mut app));

    // Proxy's history table only shows on the Proxy window.
    assert!(!render(&mut app).contains("HTTP History"));
    press(&mut app, "P");
    assert_eq!(app.window, Window::Proxy);
    assert!(render(&mut app).contains("HTTP History"));
}

#[test]
fn gt_cycles_through_the_windows() {
    let mut app = App::new(engine_with(1));
    app.refresh();
    press(&mut app, "gt");
    assert_eq!(app.window, Window::WebSocket);
    press(&mut app, "gT");
    assert_eq!(app.window, Window::Proxy);
}

/// Outside Proxy the motions scroll the content instead of a row cursor,
/// and the selection stays put so the inspected flow doesn't change.
#[test]
fn motions_scroll_content_off_the_proxy_window() {
    let mut app = App::new(engine_with(20));
    app.refresh();
    let selected = app.selected_id();
    press(&mut app, "A");
    // A frame is drawn between keypresses in the real loop; that draw is
    // what measures the content so downward scrolling knows its bound.
    render(&mut app);
    press(&mut app, "3j");
    assert_eq!(app.content_scroll, 3);
    assert_eq!(
        app.selected_id(),
        selected,
        "scrolling must not move the selection"
    );
    // Switching windows starts you back at the top.
    press(&mut app, "P");
    press(&mut app, "A");
    assert_eq!(app.content_scroll, 0);
}

/// Ctrl-K opens the palette; it floats above the window and lists commands.
#[test]
fn palette_opens_over_the_window_and_lists_commands() {
    let mut app = App::new(engine_with(3));
    app.refresh();
    key(
        &mut app,
        KeyEvent::new(KeyCode::Char('k'), KeyModifiers::CONTROL),
    );
    assert_eq!(app.input.mode(), Mode::Palette);
    let out = render(&mut app);
    assert!(out.contains("Command Palette"), "{out}");
    assert!(out.contains("Go to Repeater"), "{out}");
}

/// The catalog outgrew the box, so the list scrolls. An entry below the
/// fold has to be reachable by moving the highlight onto it.
#[test]
fn palette_scrolls_to_keep_the_highlight_visible() {
    let mut app = App::new(engine_with(3));
    app.refresh();
    key(
        &mut app,
        KeyEvent::new(KeyCode::Char('k'), KeyModifiers::CONTROL),
    );

    let last = app.palette_matches().len() - 1;
    assert!(last > 0);
    let hidden = &app.palette_matches()[last].0.clone();
    assert!(
        !render(&mut app).contains(hidden.as_str()),
        "the last entry should start below the fold"
    );

    for _ in 0..last {
        app.palette(PaletteKey::Down);
    }
    assert_eq!(app.palette_selected, last);
    assert!(
        render(&mut app).contains(hidden.as_str()),
        "moving onto it should scroll it into view"
    );
}

/// Typing filters the list; Enter runs the highlighted command — here,
/// switching windows — and closes the palette.
#[test]
fn palette_filters_and_runs_the_chosen_command() {
    let mut app = App::new(engine_with(3));
    app.refresh();
    key(
        &mut app,
        KeyEvent::new(KeyCode::Char('k'), KeyModifiers::CONTROL),
    );
    press(&mut app, "sitemap");
    // The filter has narrowed to the one obvious match.
    let matches = app.palette_matches();
    assert_eq!(
        matches.first().map(|(l, _)| l.as_str()),
        Some("Go to Sitemap")
    );

    key(&mut app, KeyEvent::from(KeyCode::Enter));
    assert_eq!(app.input.mode(), Mode::Normal, "Enter closes the palette");
    assert_eq!(app.window, Window::Sitemap, "the chosen command ran");
}

#[test]
fn palette_escape_dismisses_without_running_anything() {
    let mut app = App::new(engine_with(3));
    app.refresh();
    key(
        &mut app,
        KeyEvent::new(KeyCode::Char('k'), KeyModifiers::CONTROL),
    );
    press(&mut app, "quit");
    key(&mut app, KeyEvent::from(KeyCode::Esc));
    assert_eq!(app.input.mode(), Mode::Normal);
    assert!(!app.should_quit, "Escape must not run the highlighted Quit");
}

/// Ctrl-n walks the selection down the filtered list.
#[test]
fn palette_selection_moves_with_ctrl_n() {
    let mut app = App::new(engine_with(3));
    app.refresh();
    key(
        &mut app,
        KeyEvent::new(KeyCode::Char('k'), KeyModifiers::CONTROL),
    );
    assert_eq!(app.palette_selected, 0);
    key(
        &mut app,
        KeyEvent::new(KeyCode::Char('n'), KeyModifiers::CONTROL),
    );
    assert_eq!(app.palette_selected, 1);
}

#[test]
fn fuzzy_score_requires_order_and_prefers_contiguous() {
    assert!(
        fuzzy_score("", "anything").is_some(),
        "empty query matches all"
    );
    assert!(
        fuzzy_score("xyz", "Go to Proxy").is_none(),
        "missing chars fail"
    );
    // A contiguous substring should beat the same letters scattered.
    let contiguous = fuzzy_score("proxy", "Go to Proxy").unwrap();
    let scattered = fuzzy_score("proxy", "Prod runs on x, y").unwrap();
    assert!(contiguous > scattered, "{contiguous} !> {scattered}");
}

#[test]
fn pending_response_is_marked() {
    let engine = Engine::new();
    engine.record_request(get_request("http://example.com/slow"));

    let mut app = App::new(engine);
    app.refresh();
    assert!(render(&mut app).contains("(pending)"));
}

// --- websocket ---

/// The whole point: WebSocket connections leave the HTTP history and get
/// their own.
#[test]
fn websockets_are_split_out_of_the_proxy_history() {
    let engine = Engine::new();
    record_flow(&engine, "https://api.test/login");
    record_ws(&engine, "https://api.test/socket");
    let mut app = App::new(engine);
    app.refresh();

    assert_eq!(app.flows.len(), 1, "Proxy shows only the HTTP flow");
    assert!(app.flows[0].uri.to_string().contains("/login"));

    assert_eq!(app.ws_flows.len(), 1, "the socket is in the WS window");
    assert!(app.ws_flows[0].uri.to_string().contains("/socket"));
}

/// A flow still pending a response is HTTP, not a socket — it has no 101
/// yet, so it must not vanish from Proxy while it is in flight.
#[test]
fn a_pending_request_stays_in_the_http_history() {
    let engine = Engine::new();
    engine.record_request(CapturedRequest {
        method: Method::GET,
        uri: "https://api.test/slow".parse().unwrap(),
        version: Version::HTTP_11,
        headers: HeaderMap::new(),
        body: Bytes::new(),
    });
    let mut app = App::new(engine);
    app.refresh();
    assert_eq!(app.flows.len(), 1);
    assert!(app.ws_flows.is_empty());
}

/// The WS window navigates and renders its connection's frames.
#[test]
fn the_ws_window_shows_frames_for_the_selected_connection() {
    let engine = Engine::new();
    record_ws(&engine, "https://api.test/a");
    record_ws(&engine, "https://api.test/b");
    let mut app = App::new(engine);
    app.refresh();
    app.window = Window::WebSocket;

    let screen = render(&mut app);
    assert!(screen.contains("WebSocket (2)"), "{screen}");
    // The newest connection is selected first (id DESC), and its frames show.
    assert!(
        screen.contains("hello") || screen.contains("world"),
        "{screen}"
    );

    // j moves to the other connection.
    press(&mut app, "j");
    assert_eq!(app.ws_row, 1);
}

/// Scope narrows the WS history too, and the bypass widens it back.
#[test]
fn scope_filters_the_ws_history() {
    let engine = Engine::new();
    record_ws(&engine, "https://in.test/socket");
    record_ws(&engine, "https://out.test/socket");
    let mut app = App::new(engine.clone());
    app.refresh();
    assert_eq!(app.ws_flows.len(), 2);

    app.scope_new("s");
    app.scope_add_rule("in.test", lockgate_core::scope::Action::Include);
    app.refresh();
    assert_eq!(app.ws_flows.len(), 1, "only the in-scope socket");
    assert!(app.ws_flows[0].uri.to_string().contains("in.test"));
}

// --- findings ---

#[tokio::test]
async fn a_flow_can_be_filed_as_a_finding() {
    let engine = Engine::new();
    record_flow(&engine, "https://api.test/login");
    let mut app = App::new(engine.clone());
    app.refresh();
    assert!(app.findings.is_empty());

    app.file_finding("auth bypass on /login");
    // The write goes through the writer task.
    for _ in 0..200 {
        if !engine.list_findings().is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }

    app.refresh();
    assert_eq!(app.findings.len(), 1);
    let finding = &app.findings[0];
    assert_eq!(finding.title, "auth bypass on /login");
    assert_eq!(
        finding.severity, "info",
        "untriaged should not claim a severity"
    );
    assert_eq!(finding.status, "draft");
    assert_eq!(finding.host.as_deref(), Some("api.test"));
    assert_eq!(
        finding.evidence.len(),
        1,
        "the flow you were looking at is the evidence"
    );
}

/// Wait for a filed finding to reach the database, since `file_finding`
/// spawns its write rather than awaiting it.
async fn settle_findings(engine: &Arc<Engine>, expected: usize) {
    for _ in 0..200 {
        if engine.list_findings().len() == expected {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    panic!("finding never landed");
}

/// The point of the editor: type a write-up and have it still be there
/// afterwards, split into the columns a report is generated from. Saving is
/// on the way *out*, so this walks the path a user does.
#[tokio::test]
async fn a_write_up_is_typed_in_and_saved_on_the_way_out() {
    let engine = Engine::new();
    record_flow(&engine, "https://api.test/login");
    let mut app = App::new(engine.clone());
    app.refresh();
    app.file_finding("token in the URL");
    settle_findings(&engine, 1).await;
    app.refresh();

    app.show_window(Window::Findings);
    key(&mut app, KeyEvent::from(KeyCode::Enter));
    assert!(app.findings_view.focused, "<CR> steps into the write-up");

    key(&mut app, KeyEvent::from(KeyCode::Char('i')));
    press(&mut app, "leaks via Referer");
    key(&mut app, KeyEvent::from(KeyCode::Enter));
    press(&mut app, "## Impact");
    key(&mut app, KeyEvent::from(KeyCode::Enter));
    press(&mut app, "account takeover");
    // First <Esc> leaves INSERT; the second leaves the buffer, which is what
    // saves.
    key(&mut app, KeyEvent::from(KeyCode::Esc));
    key(&mut app, KeyEvent::from(KeyCode::Esc));

    assert!(!app.findings_view.focused);
    let finding = &engine.list_findings()[0];
    assert_eq!(finding.description_md, "leaks via Referer");
    assert_eq!(
        finding.impact_md.as_deref(),
        Some("account takeover"),
        "a `## Impact` section lands in its own column"
    );
}

/// A section deleted from the document has to be deleted from the row too,
/// or the report keeps printing prose the operator removed.
#[tokio::test]
async fn clearing_a_section_clears_its_column() {
    let engine = Engine::new();
    record_flow(&engine, "https://api.test/login");
    let mut app = App::new(engine.clone());
    app.refresh();
    app.file_finding("token in the URL");
    settle_findings(&engine, 1).await;
    app.refresh();

    let id = app.findings[0].id;
    engine.set_finding_write_up(
        id,
        &lockgate_core::WriteUp {
            description_md: "desc".into(),
            impact_md: Some("bad".into()),
            ..Default::default()
        },
    );
    app.refresh();

    app.show_window(Window::Findings);
    app.apply(Action::Enter);
    // The buffer opens as the rendered document; replace it with one that
    // has no impact section at all.
    let buffer = app.write_up_buffer().unwrap();
    buffer.set_text("desc only");
    buffer.mark_dirty();
    app.save_write_up();

    let finding = engine.get_finding(id).unwrap();
    assert_eq!(finding.description_md, "desc only");
    assert_eq!(finding.impact_md, None, "the deleted section is gone");
}

/// Notes and findings each keep an open buffer, and switching windows is
/// what saves them. The two must not reach into each other: leaving one
/// window has to commit that window's document and leave the other's alone.
#[tokio::test]
async fn a_note_and_a_write_up_can_be_open_at_once() {
    let engine = Engine::new();
    record_flow(&engine, "https://api.test/login");
    let mut app = App::new(engine.clone());
    app.refresh();
    app.file_finding("token in the URL");
    settle_findings(&engine, 1).await;
    app.create_note("auth teardown");
    settle_notes(&engine, 1).await;
    app.refresh();
    let (finding_id, note_id) = (app.findings[0].id, app.notes[0].id);

    // Type into the note, then leave for Findings without an explicit save.
    app.show_window(Window::Notes);
    app.apply(Action::Enter);
    app.apply(Action::Insert(InsertKey::Char('N')));
    app.show_window(Window::Findings);

    // Type into the write-up, then leave for Proxy.
    app.apply(Action::Enter);
    app.apply(Action::Insert(InsertKey::Char('F')));
    app.show_window(Window::Proxy);

    assert_eq!(engine.get_note(note_id).unwrap().body_md, "N");
    assert_eq!(
        engine.get_finding(finding_id).unwrap().description_md,
        "F",
        "the write-up took the write-up's keystroke, not the note's"
    );
    // Neither window is left holding the keys after the other was visited.
    assert!(!app.notes_view.focused);
    assert!(!app.findings_view.focused);
}

/// Deleting the open finding must not leave a buffer that saves its
/// write-up back into a row that no longer exists.
#[tokio::test]
async fn deleting_the_open_finding_drops_its_buffer() {
    let engine = Engine::new();
    record_flow(&engine, "https://api.test/login");
    let mut app = App::new(engine.clone());
    app.refresh();
    app.file_finding("scratch");
    settle_findings(&engine, 1).await;
    app.refresh();

    app.show_window(Window::Findings);
    app.apply(Action::Enter);
    app.apply(Action::Insert(InsertKey::Char('x')));
    app.delete_finding();

    assert!(app.findings_view.edit.is_none());
    assert!(!app.findings_view.focused);
    assert!(engine.list_findings().is_empty());
    // And leaving now has nothing to write back.
    app.save_write_up();
    assert!(engine.list_findings().is_empty());
}

/// Retitling is not rewriting: `:finding!` must leave the write-up alone.
#[tokio::test]
async fn a_finding_is_retitled_without_losing_its_write_up() {
    let engine = Engine::new();
    record_flow(&engine, "https://api.test/login");
    let mut app = App::new(engine.clone());
    app.refresh();
    app.file_finding("draft");
    settle_findings(&engine, 1).await;
    app.refresh();

    let id = app.findings[0].id;
    engine.set_finding_write_up(
        id,
        &lockgate_core::WriteUp {
            description_md: "the write-up".into(),
            ..Default::default()
        },
    );
    app.refresh();

    app.rename_finding("session token in the URL");

    let finding = engine.get_finding(id).unwrap();
    assert_eq!(finding.title, "session token in the URL");
    assert_eq!(finding.description_md, "the write-up");
    assert_eq!(finding.severity, "info", "a retitle is not a triage");
}

/// The write-up handed to $EDITOR is the whole document, and what comes back
/// is split into columns — the same contract as editing in place.
#[tokio::test]
async fn the_editor_handoff_carries_the_whole_write_up() {
    let engine = Engine::new();
    record_flow(&engine, "https://api.test/login");
    let mut app = App::new(engine.clone());
    app.refresh();
    app.file_finding("t");
    settle_findings(&engine, 1).await;
    app.refresh();

    let id = app.findings[0].id;
    engine.set_finding_write_up(
        id,
        &lockgate_core::WriteUp {
            description_md: "desc".into(),
            repro_md: Some("steps".into()),
            ..Default::default()
        },
    );
    app.refresh();
    app.show_window(Window::Findings);

    app.request_external_edit();
    let job = app.pending_edit.take().expect("a job to hand to $EDITOR");
    assert_eq!(
        job.before, "desc\n\n## Reproduction\nsteps",
        "the editor gets the sections, not just the description"
    );
    assert_eq!(job.target.extension(), "md");

    app.apply_edit(job, "desc\n\n## Remediation\npatch it".to_string());

    let finding = engine.get_finding(id).unwrap();
    assert_eq!(finding.remediation_md.as_deref(), Some("patch it"));
    assert_eq!(
        finding.repro_md, None,
        "a section dropped in $EDITOR is dropped in the row"
    );
}

/// The detail column carries two things that must not crowd each other out:
/// the facts a key changes, and the write-up you type.
#[tokio::test]
async fn the_detail_column_shows_the_facts_and_the_write_up() {
    let engine = Engine::new();
    record_flow(&engine, "https://api.test/login");
    let mut app = App::new(engine.clone());
    app.refresh();
    app.file_finding("token in the URL");
    settle_findings(&engine, 1).await;
    app.refresh();
    let id = app.findings[0].id;
    engine.set_finding_write_up(
        id,
        &lockgate_core::WriteUp {
            description_md: "leaks via Referer".into(),
            impact_md: Some("account takeover".into()),
            ..Default::default()
        },
    );
    app.refresh();
    app.show_window(Window::Findings);

    let screen = render(&mut app);
    assert!(screen.contains("Findings (1)"), "{screen}");
    assert!(screen.contains("api.test/login"), "the facts: {screen}");
    assert!(screen.contains("evidence:"), "the facts: {screen}");
    assert!(screen.contains("leaks via Referer"), "{screen}");
    assert!(
        screen.contains("## Impact"),
        "sections show as the document they are: {screen}"
    );
    // The write-up pane is titled by the finding, the way an open file is.
    assert!(screen.contains("token in the URL"), "{screen}");

    app.apply(Action::Enter);
    let focused = render(&mut app);
    assert!(focused.contains("$EDITOR"), "the banner follows the keys");
}

/// A finding filed from Proxy should be the one under the cursor when you
/// reach Findings — filing is usually the prelude to writing it up.
#[tokio::test]
async fn a_new_finding_takes_the_cursor() {
    let engine = Engine::new();
    record_flow(&engine, "https://api.test/login");
    let mut app = App::new(engine.clone());
    app.refresh();
    app.file_finding("first");
    settle_findings(&engine, 1).await;
    app.refresh();
    app.file_finding("second");
    settle_findings(&engine, 2).await;
    app.refresh();

    assert_eq!(app.findings[app.findings_view.row].title, "second");
}

/// Wait for a spawned writer round-trip to land, the way the finding tests
/// do — `create_note` cannot be awaited from the draw loop.
async fn settle_notes(engine: &Arc<Engine>, expected: usize) {
    for _ in 0..200 {
        if engine.list_notes().len() == expected {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    panic!("note never landed");
}

/// The whole point of the window: type into a note and have it still be
/// there afterwards. Saving is on the way *out* of the buffer, so this
/// walks the same path a user does — `<CR>`, type, `<Esc>`.
#[tokio::test]
async fn typing_into_a_note_saves_on_the_way_out() {
    let engine = Engine::new();
    let mut app = App::new(engine.clone());
    app.create_note("auth teardown");
    settle_notes(&engine, 1).await;
    app.refresh();

    app.show_window(Window::Notes);
    key(&mut app, KeyEvent::from(KeyCode::Enter));
    assert!(app.notes_view.focused, "<CR> steps into the body");

    key(&mut app, KeyEvent::from(KeyCode::Char('i')));
    press(&mut app, "hi");
    key(&mut app, KeyEvent::from(KeyCode::Esc));
    // First <Esc> leaves INSERT; the second leaves the buffer, which is
    // what saves.
    key(&mut app, KeyEvent::from(KeyCode::Esc));

    assert!(!app.notes_view.focused);
    assert_eq!(engine.list_notes()[0].body_md, "hi");
}

/// The cursor has to land on the note that was just created, not on
/// whatever was at the top before the write committed.
#[tokio::test]
async fn a_new_note_takes_the_cursor() {
    let engine = Engine::new();
    let mut app = App::new(engine.clone());
    app.create_note("first");
    settle_notes(&engine, 1).await;
    app.refresh();
    app.create_note("second");
    settle_notes(&engine, 2).await;
    app.refresh();

    let selected = &app.notes[app.notes_view.row];
    assert_eq!(selected.title, "second");
}

/// Deleting the open note must not leave a buffer that saves its body back
/// into a row that no longer exists.
#[tokio::test]
async fn deleting_the_open_note_drops_its_buffer() {
    let engine = Engine::new();
    let mut app = App::new(engine.clone());
    app.create_note("scratch");
    settle_notes(&engine, 1).await;
    app.refresh();

    app.show_window(Window::Notes);
    app.apply(Action::Enter);
    app.apply(Action::Insert(InsertKey::Char('x')));
    app.delete_note();

    assert!(app.notes_view.edit.is_none());
    assert!(!app.notes_view.focused);
    assert!(engine.list_notes().is_empty());
    // And leaving now has nothing to write back.
    app.save_note();
    assert!(engine.list_notes().is_empty());
}

#[tokio::test]
async fn a_note_is_retitled_without_losing_its_body() {
    let engine = Engine::new();
    let mut app = App::new(engine.clone());
    app.create_note("draft");
    settle_notes(&engine, 1).await;
    app.refresh();
    let id = app.notes[0].id;
    engine.update_note(id, None, Some("body text"));
    app.refresh();

    app.rename_note("auth teardown");

    let note = engine.get_note(id).unwrap();
    assert_eq!(note.title, "auth teardown");
    assert_eq!(note.body_md, "body text", "a retitle is not a rewrite");
}

#[test]
fn an_empty_note_title_is_refused() {
    let engine = Engine::new();
    let mut app = App::new(engine.clone());
    app.create_note("   ");
    assert!(engine.list_notes().is_empty());
    let status = app.status.lock().unwrap().clone();
    assert!(status.contains("usage: :note"), "{status}");
}

#[test]
fn filing_without_a_flow_says_so() {
    let engine = Engine::new();
    let mut app = App::new(engine);
    app.refresh();
    app.file_finding("something");
    let status = app.status.lock().unwrap().clone();
    assert!(status.contains("no flow selected"), "{status}");
}

#[test]
fn an_empty_title_is_refused() {
    let engine = Engine::new();
    record_flow(&engine, "https://api.test/x");
    let mut app = App::new(engine.clone());
    app.refresh();
    app.file_finding("   ");
    assert!(engine.list_findings().is_empty());
}

/// Triage is a repeated motion, so severity and status are one key each.
#[tokio::test]
async fn severity_and_status_cycle_through_their_vocabularies() {
    let engine = Engine::new();
    record_flow(&engine, "https://api.test/x");
    let mut app = App::new(engine.clone());
    app.refresh();
    app.file_finding("t");
    for _ in 0..200 {
        if !engine.list_findings().is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    app.refresh();

    assert_eq!(app.findings[0].severity, "info");
    app.cycle_finding(true);
    assert_eq!(app.findings[0].severity, "low");
    app.cycle_finding(true);
    assert_eq!(app.findings[0].severity, "medium");

    assert_eq!(app.findings[0].status, "draft");
    app.cycle_finding(false);
    assert_eq!(app.findings[0].status, "confirmed");

    // And it wraps rather than sticking at the end.
    for _ in 0..3 {
        app.cycle_finding(true);
    }
    assert_eq!(app.findings[0].severity, "info", "severity should wrap");
}

#[tokio::test]
async fn a_finding_can_be_deleted() {
    let engine = Engine::new();
    record_flow(&engine, "https://api.test/x");
    let mut app = App::new(engine.clone());
    app.refresh();
    app.file_finding("t");
    for _ in 0..200 {
        if !engine.list_findings().is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    app.refresh();
    assert_eq!(app.findings.len(), 1);

    app.delete_finding();
    assert!(app.findings.is_empty());
    assert!(engine.list_findings().is_empty());
}

/// The vocabularies must match what the MCP tools validate against — the
/// columns are free text with no CHECK, so a divergence would persist.
#[test]
fn the_vocabularies_are_the_documented_ones() {
    assert_eq!(
        App::SEVERITIES,
        ["info", "low", "medium", "high", "critical"]
    );
    assert_eq!(
        App::STATUSES,
        [
            "draft",
            "confirmed",
            "false_positive",
            "reported",
            "fixed",
            "wont_fix"
        ]
    );
}

// --- scope ---

/// The whole loop, through real keys: add a host from the Sitemap, see the
/// Proxy list narrow, then bypass and see it widen again.
#[test]
fn scoping_a_host_filters_the_other_windows() {
    let engine = Engine::new();
    record_flow(&engine, "https://in-scope.test/a");
    record_flow(&engine, "https://other.test/b");
    let mut app = App::new(engine);
    app.refresh();
    assert_eq!(app.flows.len(), 2, "no scope means everything");

    // Put the first host in scope from the Sitemap.
    press(&mut app, "S");
    assert_eq!(app.window, Window::Sitemap);
    let rows = app.sitemap_rows();
    let row = rows
        .iter()
        .position(|r| r.host == "in-scope.test")
        .expect("host should be in the tree");
    app.sitemap.selected = row;
    press(&mut app, "a");

    app.refresh();
    assert_eq!(
        app.flows.len(),
        1,
        "Proxy should now list only the scoped host"
    );
    assert!(app.flows[0].uri.to_string().contains("in-scope.test"));

    // The bypass shows everything again without touching the rules.
    press(&mut app, " c");
    assert_eq!(app.flows.len(), 2, "bypass should widen the view");
    assert!(!app.scope_filter);
    press(&mut app, " c");
    assert_eq!(app.flows.len(), 1, "and put it back");
}

/// `*.host` does not match the apex `host`, so adding a host has to create
/// both or it silently misses one of them.
#[test]
fn adding_a_host_covers_the_apex_and_its_subdomains() {
    let engine = Engine::new();
    record_flow(&engine, "https://linear.app/a");
    let mut app = App::new(engine.clone());
    app.refresh();
    app.window = Window::Sitemap;
    app.sitemap.selected = 0;
    app.scope_add_host();

    let scope_id = app.scopes.iter().find(|s| s.is_active).expect("a scope").id;
    let patterns: Vec<String> = engine
        .scope_rules(scope_id)
        .iter()
        .filter_map(|r| r.spec.host.as_ref().map(|(_, p)| p.clone()))
        .collect();
    assert!(patterns.contains(&"linear.app".to_string()), "{patterns:?}");
    assert!(
        patterns.contains(&"*.linear.app".to_string()),
        "{patterns:?}"
    );

    // Adding twice must not pile up duplicates.
    app.scope_add_host();
    let after = engine.scope_rules(scope_id).len();
    assert_eq!(after, 2, "adding an already-scoped host should be a no-op");
}

#[test]
fn removing_a_host_drops_both_of_its_rules() {
    let engine = Engine::new();
    record_flow(&engine, "https://linear.app/a");
    let mut app = App::new(engine.clone());
    app.refresh();
    app.window = Window::Sitemap;
    app.sitemap.selected = 0;
    app.scope_add_host();
    let scope_id = app.scopes.iter().find(|s| s.is_active).unwrap().id;
    assert_eq!(engine.scope_rules(scope_id).len(), 2);

    app.scope_remove_host();
    assert!(
        engine.scope_rules(scope_id).is_empty(),
        "both apex and wildcard should go"
    );
}

/// Glob unless asked otherwise, because an unanchored regex silently
/// matches more than it looks like.
#[test]
fn rule_patterns_default_to_glob_with_prefixes_for_the_rest() {
    let engine = Engine::new();
    let mut app = App::new(engine.clone());
    app.refresh();
    app.scope_new("t");

    app.scope_add_rule("*.linear.app", lockgate_core::scope::Action::Include);
    app.scope_add_rule("re:^api\\.", lockgate_core::scope::Action::Include);
    app.scope_add_rule("cidr:10.0.0.0/8", lockgate_core::scope::Action::Exclude);

    let scope_id = app.scopes[0].id;
    let kinds: Vec<_> = engine
        .scope_rules(scope_id)
        .iter()
        .filter_map(|r| r.spec.host.as_ref().map(|(k, _)| *k))
        .collect();
    assert_eq!(
        kinds,
        vec![
            lockgate_core::scope::HostKind::Glob,
            lockgate_core::scope::HostKind::Regex,
            lockgate_core::scope::HostKind::Cidr,
        ]
    );
}

/// A pattern that will not compile must be refused when it is typed, not
/// when the matcher next runs.
#[test]
fn a_bad_pattern_is_rejected_on_entry() {
    let engine = Engine::new();
    let mut app = App::new(engine.clone());
    app.refresh();
    app.scope_new("t");
    let scope_id = app.scopes[0].id;

    app.scope_add_rule("re:[unclosed", lockgate_core::scope::Action::Include);
    assert!(
        engine.scope_rules(scope_id).is_empty(),
        "a bad regex must not be stored"
    );
    let status = app.status.lock().unwrap().clone();
    assert!(status.contains("rejected"), "{status}");
}

/// Excludes always beat includes, which is what makes the result
/// independent of rule order.
#[test]
fn an_exclude_carves_a_hole_in_an_include() {
    let engine = Engine::new();
    record_flow(&engine, "https://app.linear.app/a");
    record_flow(&engine, "https://admin.linear.app/b");
    let mut app = App::new(engine.clone());
    app.refresh();
    app.scope_new("t");
    app.scope_add_rule("*.linear.app", lockgate_core::scope::Action::Include);
    app.refresh();
    assert_eq!(app.flows.len(), 2);

    app.scope_add_rule("admin.linear.app", lockgate_core::scope::Action::Exclude);
    app.refresh();
    assert_eq!(app.flows.len(), 1, "the exclude should win");
    assert!(app.flows[0].uri.to_string().contains("app.linear.app"));
}

/// Turning a rule off is not the same as deleting it.
#[test]
fn a_disabled_rule_stops_filtering_but_survives() {
    let engine = Engine::new();
    record_flow(&engine, "https://a.test/x");
    record_flow(&engine, "https://b.test/y");
    let mut app = App::new(engine.clone());
    app.refresh();
    app.scope_new("t");
    app.scope_add_rule("a.test", lockgate_core::scope::Action::Include);
    app.refresh();
    assert_eq!(app.flows.len(), 1);

    app.scope.column = Column::Right;
    app.scope.rule_row = 0;
    app.scope_enter();
    app.refresh();
    assert_eq!(app.flows.len(), 2, "a disabled rule should not narrow");
    assert_eq!(app.scope_rules.len(), 1, "but it is still there");
    assert!(!app.scope_rules[0].enabled);
}

/// Only one scope filters at a time, and which one has to be switchable.
#[test]
fn switching_the_active_scope_changes_what_is_listed() {
    let engine = Engine::new();
    record_flow(&engine, "https://a.test/x");
    record_flow(&engine, "https://b.test/y");
    let mut app = App::new(engine.clone());
    app.refresh();

    app.scope_new("only-a");
    app.scope_add_rule("a.test", lockgate_core::scope::Action::Include);
    app.scope_new("only-b");
    app.scope_add_rule("b.test", lockgate_core::scope::Action::Include);

    app.run_scope_command("use", "only-a");
    assert!(app.flows[0].uri.to_string().contains("a.test"));
    assert_eq!(app.flows.len(), 1);

    app.run_scope_command("use", "only-b");
    assert_eq!(app.flows.len(), 1);
    assert!(app.flows[0].uri.to_string().contains("b.test"));
}

/// Deleting the active scope leaves nothing active, which means
/// unrestricted — the safe direction to fail.
#[test]
fn deleting_the_active_scope_widens_rather_than_hides() {
    let engine = Engine::new();
    record_flow(&engine, "https://a.test/x");
    record_flow(&engine, "https://b.test/y");
    let mut app = App::new(engine.clone());
    app.refresh();
    app.scope_new("only-a");
    app.scope_add_rule("a.test", lockgate_core::scope::Action::Include);
    app.refresh();
    assert_eq!(app.flows.len(), 1);

    app.scope.column = Column::Left;
    app.scope.scope_row = 0;
    app.scope_delete();
    app.refresh();
    assert_eq!(app.flows.len(), 2, "no scope means everything");
}

/// Hiding a held item would strand a live connection with no way to answer
/// it, so Intercept is deliberately not filtered.
#[test]
fn intercept_queues_are_not_filtered_by_scope() {
    let (engine, mut app, _rt) = app_with_both_legs_held();
    app.refresh();
    app.scope_new("nothing-matches");
    app.scope_add_rule(
        "no-such-host.invalid",
        lockgate_core::scope::Action::Include,
    );
    app.refresh();

    assert_eq!(
        engine.intercept().queue_of(true).len(),
        1,
        "the hold is still on the queue"
    );
    assert_eq!(
        app.held_requests.len(),
        1,
        "and still visible, or it could never be answered"
    );
}

// --- repeater ---

/// The Repeater is loaded explicitly and then stops tracking the Proxy
/// cursor. This is the whole reason it owns a buffer: moving the cursor
/// after loading must not throw away what you were editing.
#[test]
fn repeater_loads_on_demand_and_then_ignores_the_cursor() {
    let mut app = App::new(engine_with(3));
    app.refresh();
    assert!(
        render(&mut app).contains("HTTP History (3)"),
        "fixture should have loaded"
    );

    press(&mut app, " s");
    assert_eq!(app.window, Window::Repeater);
    let loaded = app.repeater.session().origin;
    assert!(loaded.is_some());

    // Go back and move the cursor; the Repeater must not follow.
    press(&mut app, "Pj");
    assert_eq!(
        app.repeater.session().origin,
        loaded,
        "the buffer should be pinned"
    );
}

#[test]
fn repeater_is_empty_until_something_is_sent_to_it() {
    let mut app = App::new(engine_with(1));
    app.refresh();
    press(&mut app, "R");
    assert!(
        render(&mut app).contains("<Space>s"),
        "should say how to load"
    );
}

/// `i` types into the buffer instead of being interpreted as a motion, and
/// the edit is visible.
#[test]
fn repeater_buffer_takes_typed_text() {
    let mut app = App::new(engine_with(1));
    app.refresh();
    press(&mut app, " s");

    key(&mut app, KeyEvent::from(KeyCode::Char('i')));
    assert_eq!(app.input.mode(), Mode::Insert);
    press(&mut app, "XY");
    assert!(
        app.repeater.session().request.text().starts_with("XY"),
        "typed text should land at the cursor: {:?}",
        app.repeater.session().request.text()
    );
    assert!(app.repeater.session().request.is_dirty());
    // The pane marks itself edited so the operator can see it diverged.
    assert!(render(&mut app).contains("Request*"));

    key(&mut app, KeyEvent::from(KeyCode::Esc));
    assert_eq!(app.input.mode(), Mode::Normal);
}

/// A buffer that no longer parses must refuse to send and say why, rather
/// than quietly sending the pre-edit request.
/// Tabs are 1-based on screen, so the key you press must be the number you
/// see — an off-by-one here would be invisible until it selected the wrong
/// request.
#[test]
fn session_tabs_open_close_and_select() {
    let mut app = App::new(engine_with(3));
    app.refresh();
    assert_eq!(app.repeater.sessions.len(), 1, "one session always exists");

    app.apply(Action::NewSession);
    app.apply(Action::NewSession);
    assert_eq!(app.repeater.sessions.len(), 3);
    assert_eq!(app.repeater.active, 2, "opening switches to the new tab");

    app.apply(Action::SelectSession(Some(1)));
    assert_eq!(app.repeater.active, 0, "1 selects the first tab");

    app.apply(Action::SelectSession(Some(9)));
    assert_eq!(
        app.repeater.active, 0,
        "a tab that isn't there changes nothing"
    );

    app.apply(Action::CloseSession);
    assert_eq!(app.repeater.sessions.len(), 2);
}

/// Driven through the real key path, not `apply` — the original bug was
/// that the keystrokes never became actions at all, which an action-level
/// test cannot see.
#[test]
fn tab_keys_actually_reach_the_repeater() {
    let mut app = App::new(engine_with(3));
    app.refresh();
    press(&mut app, " s");
    assert_eq!(app.window, Window::Repeater);

    press(&mut app, "n");
    press(&mut app, "n");
    assert_eq!(app.repeater.sessions.len(), 3, "`n` should open tabs");
    assert_eq!(app.repeater.active, 2);

    press(&mut app, "1gs");
    assert_eq!(app.repeater.active, 0, "`1gs` should select the first tab");

    press(&mut app, "3gs");
    assert_eq!(app.repeater.active, 2, "`3gs` should select the third");

    press(&mut app, "gs");
    assert_eq!(app.repeater.active, 0, "bare `gs` cycles and wraps");

    press(&mut app, "x");
    assert_eq!(app.repeater.sessions.len(), 2, "`x` should close a tab");
}

/// There must always be somewhere to land, or the draw path would index an
/// empty vector.
#[test]
fn closing_the_last_tab_empties_it_rather_than_removing_it() {
    let mut app = App::new(engine_with(3));
    app.refresh();
    app.apply(Action::SendToRepeater);
    assert!(app.repeater.session().original.is_some());

    app.apply(Action::CloseSession);
    assert_eq!(app.repeater.sessions.len(), 1);
    assert!(
        app.repeater.session().original.is_none(),
        "the survivor should be blank"
    );
}

/// Loading a second flow must not discard a request you were editing.
#[test]
fn a_second_flow_lands_in_its_own_tab() {
    let mut app = App::new(engine_with(3));
    app.refresh();
    app.apply(Action::SendToRepeater);
    let first = app.repeater.active;

    app.apply(Action::SendToRepeater);
    assert_ne!(app.repeater.active, first, "should not overwrite the first");
    assert_eq!(app.repeater.sessions.len(), 2);
}

/// Each send is recorded before it lands, so history shows an in-flight
/// request rather than nothing.
#[test]
fn sending_records_an_exchange_immediately() {
    // A send spawns onto the runtime; it only has to *start* for the
    // exchange to be recorded, which is what these assert on.
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();
    let mut app = App::new(engine_with(3));
    app.refresh();
    app.apply(Action::SendToRepeater);
    assert!(app.repeater.session().history.is_empty());

    app.send_repeater();
    assert_eq!(app.repeater.session().history.len(), 1);
    assert_eq!(app.repeater.session().position(), Some((1, 1)));
    // The request text is snapshotted as sent, not read back off the buffer.
    assert!(
        app.repeater.session().history[0]
            .request
            .contains("HTTP/1.1")
    );
}

#[test]
fn history_steps_and_stops_at_the_ends() {
    // A send spawns onto the runtime; it only has to *start* for the
    // exchange to be recorded, which is what these assert on.
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();
    let mut app = App::new(engine_with(3));
    app.refresh();
    app.apply(Action::SendToRepeater);
    app.send_repeater();
    app.send_repeater();
    app.send_repeater();
    assert_eq!(app.repeater.session().position(), Some((3, 3)));

    app.apply(Action::History { forward: false });
    assert_eq!(app.repeater.session().position(), Some((2, 3)));
    app.apply(Action::History { forward: false });
    assert_eq!(app.repeater.session().position(), Some((1, 3)));

    // The oldest is the end of the line.
    app.apply(Action::History { forward: false });
    assert_eq!(app.repeater.session().position(), Some((1, 3)));

    app.apply(Action::History { forward: true });
    assert_eq!(app.repeater.session().position(), Some((2, 3)));
}

/// Stepping past the newest goes back to *following* the newest, so a later
/// send appears without having to navigate to it.
#[test]
fn stepping_past_the_newest_resumes_following_it() {
    // A send spawns onto the runtime; it only has to *start* for the
    // exchange to be recorded, which is what these assert on.
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();
    let mut app = App::new(engine_with(3));
    app.refresh();
    app.apply(Action::SendToRepeater);
    app.send_repeater();
    app.send_repeater();

    app.apply(Action::History { forward: false });
    assert!(
        app.repeater.session().viewing.is_some(),
        "pinned to an older one"
    );

    app.apply(Action::History { forward: true });
    assert_eq!(
        app.repeater.session().viewing,
        None,
        "back to following the newest"
    );

    // And a new send is what you now see.
    app.send_repeater();
    assert_eq!(app.repeater.session().position(), Some((3, 3)));
}

/// A send always shows you what you just asked for, even if you were
/// reading an older exchange.
#[test]
fn sending_unpins_the_history_view() {
    // A send spawns onto the runtime; it only has to *start* for the
    // exchange to be recorded, which is what these assert on.
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();
    let mut app = App::new(engine_with(3));
    app.refresh();
    app.apply(Action::SendToRepeater);
    app.send_repeater();
    app.send_repeater();
    app.apply(Action::History { forward: false });
    assert!(app.repeater.session().viewing.is_some());

    app.send_repeater();
    assert_eq!(app.repeater.session().viewing, None);
}

/// Sessions are independent: history in one must not show up in another.
#[test]
fn history_is_per_session() {
    // A send spawns onto the runtime; it only has to *start* for the
    // exchange to be recorded, which is what these assert on.
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();
    let mut app = App::new(engine_with(3));
    app.refresh();
    app.apply(Action::SendToRepeater);
    app.send_repeater();
    assert_eq!(app.repeater.session().history.len(), 1);

    app.apply(Action::NewSession);
    assert!(
        app.repeater.session().history.is_empty(),
        "a fresh tab is empty"
    );

    app.apply(Action::SelectSession(Some(1)));
    assert_eq!(
        app.repeater.session().history.len(),
        1,
        "the first tab kept its own"
    );
}

/// Pairing the live buffer with an old response would show a request that
/// never produced the reply beside it.
#[test]
fn pinned_history_shows_the_request_as_it_was_sent() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();
    let mut app = App::new(engine_with(3));
    app.refresh();
    app.apply(Action::SendToRepeater);
    app.send_repeater();

    // Change the buffer after sending, so live and historical differ.
    app.repeater.session_mut().request = TextBuffer::from_text("GET /changed HTTP/1.1\n\n");
    app.send_repeater();

    app.apply(Action::History { forward: false });
    let screen = render(&mut app);
    assert!(
        screen.contains("Request (sent)"),
        "should flag the pinned view"
    );
    assert!(
        !screen.contains("/changed"),
        "the live edit must not appear beside an older response:\n{screen}"
    );
}

/// Typing into a view of a past request would put keystrokes somewhere they
/// cannot go, so editing snaps back to the live one.
#[test]
fn editing_while_pinned_returns_to_the_newest() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();
    let mut app = App::new(engine_with(3));
    app.refresh();
    app.apply(Action::SendToRepeater);
    app.send_repeater();
    app.send_repeater();

    app.apply(Action::History { forward: false });
    assert!(app.repeater.session().viewing.is_some());

    app.apply(Action::Enter);
    assert_eq!(
        app.repeater.session().viewing,
        None,
        "entering the buffer must unpin"
    );
    assert!(app.repeater.focused);
}

#[test]
fn the_view_toggle_flips_and_says_so() {
    let mut app = App::new(engine_with(3));
    app.refresh();
    assert_eq!(app.repeater.view, View::Raw, "raw is the honest default");

    app.apply(Action::ToggleView);
    assert_eq!(app.repeater.view, View::Pretty);
    let status = app.status.lock().unwrap().clone();
    assert!(status.contains("pretty"), "{status}");

    app.apply(Action::ToggleView);
    assert_eq!(app.repeater.view, View::Raw);
}

/// The tab label is what tells two sessions apart at a glance.
#[test]
fn tabs_are_labelled_by_host() {
    let mut app = App::new(engine_with(3));
    app.refresh();
    app.apply(Action::SendToRepeater);
    let label = app.repeater.session().label();
    assert_ne!(label, "empty", "a loaded session should name its host");

    app.apply(Action::NewSession);
    assert_eq!(app.repeater.session().label(), "empty");
}

#[test]
fn repeater_reports_an_unsendable_buffer() {
    let mut app = App::new(engine_with(1));
    app.refresh();
    press(&mut app, " s");
    app.repeater.session_mut().request =
        TextBuffer::from_text("GET /x HTTP/1.1\nbroken-header\n\n");
    app.repeater.session_mut().request.insert_char(' ');

    app.send_repeater();
    assert!(
        app.repeater.session().error.is_some(),
        "should refuse to send"
    );
    assert!(render(&mut app).contains("cannot send"));
}

// --- intercept ---

#[test]
fn intercept_starts_off_and_toggles() {
    let mut app = App::new(Engine::new());
    app.refresh();
    press(&mut app, "I");
    assert!(render(&mut app).contains("OFF"));

    press(&mut app, " i");
    assert!(app.engine.intercept().is_enabled());
    assert!(render(&mut app).contains("ON"));

    press(&mut app, " i");
    assert!(!app.engine.intercept().is_enabled());
}

/// Hold one request and one response, so the two columns each have content.
fn app_with_both_legs_held() -> (Arc<Engine>, App, tokio::runtime::Runtime) {
    let engine = Engine::new();
    engine.intercept().set_enabled(true);
    let rt = tokio::runtime::Runtime::new().unwrap();

    let e = engine.clone();
    rt.spawn(async move {
        e.intercept()
            .hold_request(7, get_request("http://example.com/req-path"))
            .await
    });
    let e = engine.clone();
    rt.spawn(async move {
        e.intercept()
            .hold_response(
                8,
                CapturedResponse {
                    status: hudsucker::hyper::StatusCode::NOT_FOUND,
                    version: Version::HTTP_11,
                    headers: HeaderMap::new(),
                    body: Bytes::from_static(b"res-marker"),
                },
            )
            .await
    });
    for _ in 0..200 {
        if engine.intercept().len() >= 2 {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }

    let mut app = App::new(engine.clone());
    app.refresh();
    // Through `show_window`, not by assignment: that is what tells the
    // input layer which window-scoped bindings apply.
    app.show_window(Window::Intercept);
    (engine, app, rt)
}

/// The reference layout: requests and responses in their own queues, side by
/// side, each above its own preview.
#[test]
fn intercept_shows_four_panes() {
    let (_engine, mut app, _rt) = app_with_both_legs_held();
    let rows = render_rows(&mut app);
    let out = rows.join("\n");

    assert!(out.contains("Queued requests (1)"), "{out}");
    assert!(out.contains("Queued responses (1)"), "{out}");
    // Each column's queue title shares a row with the other's, and each
    // preview title likewise — that is what makes it a 2x2.
    let queue_row = rows
        .iter()
        .position(|r| r.contains("Queued requests"))
        .unwrap();
    assert!(
        rows[queue_row].contains("Queued responses"),
        "queues should be side by side, got: {}",
        rows[queue_row]
    );
    let view_row = rows.iter().position(|r| r.contains(" Request ")).unwrap();
    assert!(
        rows[view_row].contains(" Response "),
        "previews should be side by side, got: {}",
        rows[view_row]
    );
    assert!(view_row > queue_row, "previews sit below their queues");
}

/// Each column previews its own leg.
#[test]
fn each_column_previews_its_own_leg() {
    let (_engine, mut app, _rt) = app_with_both_legs_held();
    let out = render(&mut app);
    assert!(out.contains("/req-path"), "request preview: {out}");
    assert!(out.contains("res-marker"), "response preview: {out}");
}

/// `<C-w>` moves focus, and the focused column is the one keys act on.
#[test]
fn focus_moves_between_columns_and_directs_answers() {
    let (engine, mut app, _rt) = app_with_both_legs_held();
    assert_eq!(app.intercept.focus, Column::Left);

    // Forwarding with the left column focused answers the request.
    app.apply(Action::Forward);
    app.refresh();
    assert_eq!(engine.intercept().queue_of(true).len(), 0);
    assert_eq!(
        engine.intercept().queue_of(false).len(),
        1,
        "the response must be untouched"
    );

    // Move to the right column; now it answers the response.
    app.apply(Action::Focus(Some(Column::Right)));
    assert_eq!(app.intercept.focus, Column::Right);
    app.apply(Action::Forward);
    app.refresh();
    assert_eq!(engine.intercept().queue_of(false).len(), 0);
}

#[test]
fn focus_cycles_with_ctrl_w_w() {
    let (_engine, mut app, _rt) = app_with_both_legs_held();
    app.apply(Action::Focus(None));
    assert_eq!(app.intercept.focus, Column::Right);
    app.apply(Action::Focus(None));
    assert_eq!(app.intercept.focus, Column::Left);
}

/// Editing happens in the focused column's buffer.
#[test]
fn editing_targets_the_focused_column() {
    let (_engine, mut app, _rt) = app_with_both_legs_held();

    app.apply(Action::Insert(InsertKey::Char('Z')));
    assert!(
        app.intercept.request_edit.is_some(),
        "the left column should have forked a buffer"
    );
    let (_, req) = app.intercept.request_edit.as_ref().unwrap();
    assert!(req.text().starts_with('Z'));
}

/// The preview is a vim buffer: `w` moves by word, `dd` deletes a line,
/// `p` puts it back.
#[test]
fn preview_supports_vim_motions_and_operators() {
    let (_engine, mut app, _rt) = app_with_both_legs_held();
    app.apply(Action::Enter);

    // `w` from column 0 of "GET /req-path HTTP/1.1" lands on the slash.
    press(&mut app, "w");
    assert_eq!(app.preview_buffer(true).unwrap().cursor().col, 4);

    press(&mut app, "dd");
    let text = app.preview_buffer(true).unwrap().text();
    assert!(!text.starts_with("GET"), "the line should be gone: {text}");

    press(&mut app, "p");
    assert!(
        app.preview_buffer(true).unwrap().text().contains("GET"),
        "p should put the deleted line back"
    );
}

/// `u` undoes, and a whole insert session undoes as one step.
#[test]
fn preview_undo_covers_a_whole_insert_session() {
    let (_engine, mut app, _rt) = app_with_both_legs_held();
    app.apply(Action::Enter);
    let original = app.preview_buffer(true).unwrap().text();

    press(&mut app, "i");
    assert_eq!(app.input.mode(), Mode::Insert);
    press(&mut app, "XYZ");
    key(&mut app, KeyEvent::from(KeyCode::Esc));
    assert!(app.preview_buffer(true).unwrap().text().starts_with("XYZ"));

    press(&mut app, "u");
    assert_eq!(
        app.preview_buffer(true).unwrap().text(),
        original,
        "the whole session should undo at once"
    );
}

/// The register is on the app, so a yank in one preview pastes into the
/// other — copying a header from a response into a request.
#[test]
fn the_register_is_shared_between_previews() {
    let (_engine, mut app, _rt) = app_with_both_legs_held();

    // Yank the status line out of the response.
    app.apply(Action::Focus(Some(Column::Right)));
    app.apply(Action::Enter);
    press(&mut app, "yy");
    assert!(app.yank.text.contains("404"), "yanked: {}", app.yank.text);

    // Put it into the request.
    app.apply(Action::Focus(Some(Column::Left)));
    press(&mut app, "p");
    assert!(
        app.preview_buffer(true).unwrap().text().contains("404"),
        "the yank should cross panes"
    );
}

/// A count repeats the command.
#[test]
fn counts_repeat_buffer_commands() {
    let (_engine, mut app, _rt) = app_with_both_legs_held();
    app.apply(Action::Enter);
    let lines = app.preview_buffer(true).unwrap().lines().len();

    press(&mut app, "2dd");
    assert_eq!(
        app.preview_buffer(true).unwrap().lines().len(),
        lines - 2,
        "2dd should delete two lines"
    );
}

/// The buffer keymap claims `I`, `A`, `P` and `gt`, so a window that is
/// always focused would be one you cannot leave. Escape has to get out.
#[test]
fn escape_releases_the_buffer_so_window_keys_work_again() {
    let (_engine, mut app, _rt) = app_with_both_legs_held();
    app.apply(Action::Enter);

    // While focused, `P` is a vim put, not a jump to Proxy.
    press(&mut app, "P");
    assert_eq!(app.window, Window::Intercept, "P must not switch windows");

    key(&mut app, KeyEvent::from(KeyCode::Esc));
    press(&mut app, "P");
    assert_eq!(app.window, Window::Proxy, "and must switch once released");
}

/// Same trap in the Repeater, which is almost all buffer.
#[test]
fn the_repeater_buffer_can_be_left() {
    let mut app = App::new(engine_with(1));
    app.refresh();
    press(&mut app, " s");
    assert!(!app.repeater.focused, "should not start focused");

    // Unfocused, window keys work.
    press(&mut app, "P");
    assert_eq!(app.window, Window::Proxy);

    press(&mut app, "R");
    key(&mut app, KeyEvent::from(KeyCode::Enter));
    assert!(app.repeater.focused);
    press(&mut app, "P");
    assert_eq!(app.window, Window::Repeater, "focused: P is a put");

    key(&mut app, KeyEvent::from(KeyCode::Esc));
    press(&mut app, "P");
    assert_eq!(app.window, Window::Proxy);
}

/// `W` steps over a whole dotted host where `w` stops at each dot — the
/// difference that actually matters on a URL.
#[test]
fn big_word_motions_work_in_the_preview() {
    let (_engine, mut app, _rt) = app_with_both_legs_held();
    app.apply(Action::Enter);

    // On "GET /req-path HTTP/1.1" the first step coincides — both land on
    // the slash. The second is where they diverge: `w` stops inside
    // `/req-path` at the punctuation, `W` clears the whole chunk.
    press(&mut app, "ww");
    let small = app.preview_buffer(true).unwrap().cursor().col;
    press(&mut app, "0WW");
    let big = app.preview_buffer(true).unwrap().cursor().col;
    assert!(
        big > small,
        "W should travel further than w ({big} vs {small})"
    );
}

/// Visual mode selects, and an operator applies to the selection.
#[test]
fn visual_mode_selects_and_operates() {
    let (_engine, mut app, _rt) = app_with_both_legs_held();
    app.apply(Action::Enter);

    press(&mut app, "v");
    assert!(app.preview_buffer(true).unwrap().has_selection());
    press(&mut app, "ll");
    press(&mut app, "d");

    let buffer = app.preview_buffer(true).unwrap();
    assert!(!buffer.has_selection(), "operating clears the selection");
    assert!(
        buffer.text().starts_with(" /req-path"),
        "GET should have lost its first three chars: {:?}",
        buffer.text()
    );
}

/// `V` takes whole lines.
#[test]
fn visual_line_mode_takes_whole_lines() {
    let (_engine, mut app, _rt) = app_with_both_legs_held();
    app.apply(Action::Enter);
    let before = app.preview_buffer(true).unwrap().lines().len();

    press(&mut app, "Vd");
    assert_eq!(
        app.preview_buffer(true).unwrap().lines().len(),
        before - 1,
        "Vd should remove exactly the current line"
    );
}

/// Text objects: `ciw` replaces the word under the cursor.
#[test]
fn text_objects_work_in_the_preview() {
    let (_engine, mut app, _rt) = app_with_both_legs_held();
    app.apply(Action::Enter);

    press(&mut app, "ciw");
    assert_eq!(app.input.mode(), Mode::Insert, "c should enter insert");
    press(&mut app, "POST");
    key(&mut app, KeyEvent::from(KeyCode::Esc));
    assert!(
        app.preview_buffer(true)
            .unwrap()
            .text()
            .starts_with("POST "),
        "got: {:?}",
        app.preview_buffer(true).unwrap().text()
    );
}

/// `f` finds a character on the line, and an operator can use it.
#[test]
fn find_char_works_as_an_operator_target() {
    let (_engine, mut app, _rt) = app_with_both_legs_held();
    app.apply(Action::Enter);

    press(&mut app, "df/");
    assert!(
        app.preview_buffer(true)
            .unwrap()
            .text()
            .starts_with("req-path"),
        "df/ should delete through the slash: {:?}",
        app.preview_buffer(true).unwrap().text()
    );
}

/// The whole point of a grammar: counts multiply across the operator.
#[test]
fn counts_multiply_across_the_operator() {
    let (_engine, mut app, _rt) = app_with_both_legs_held();
    app.apply(Action::Enter);
    let before = app.preview_buffer(true).unwrap().lines().len();

    press(&mut app, "2dd");
    assert_eq!(app.preview_buffer(true).unwrap().lines().len(), before - 2);
}

/// Escape narrows the scope by one step: drop the selection first, only
/// then leave the buffer.
#[test]
fn escape_drops_the_selection_before_leaving() {
    let (_engine, mut app, _rt) = app_with_both_legs_held();
    app.apply(Action::Enter);

    press(&mut app, "v");
    assert!(app.preview_buffer(true).unwrap().has_selection());

    key(&mut app, KeyEvent::from(KeyCode::Esc));
    assert!(!app.preview_buffer(true).unwrap().has_selection());
    assert_eq!(app.intercept.pane, Pane::Preview, "still in the buffer");

    key(&mut app, KeyEvent::from(KeyCode::Esc));
    assert_eq!(app.intercept.pane, Pane::Table, "now it leaves");
}

/// Every yank form, end to end through the keymap, and a put to prove the
/// register actually round-trips.
#[test]
fn yank_forms_all_reach_the_register() {
    let cases: [(&str, &str, bool); 6] = [
        // keys,      expected register text,  linewise
        ("yy", "GET /req-path HTTP/1.1", true),
        ("yw", "GET ", false),
        ("y$", "GET /req-path HTTP/1.1", false),
        ("yiw", "GET", false),
        ("yaw", "GET ", false),
        ("vlly", "GET", false),
    ];
    for (keys, expected, linewise) in cases {
        let (_engine, mut app, _rt) = app_with_both_legs_held();
        app.apply(Action::Enter);
        press(&mut app, keys);
        assert_eq!(app.yank.text, expected, "`{keys}` yanked the wrong text");
        assert_eq!(app.yank.linewise, linewise, "`{keys}` wrong shape");
    }
}

/// An explicit yank reports going to the clipboard; a delete does not.
/// Deletes fill the internal register so `dd`+`p` is a move, but having
/// every `x` clobber the system clipboard would make it useless for
/// carrying a token to another window.
#[test]
fn only_explicit_yanks_reach_the_clipboard() {
    let (_engine, mut app, _rt) = app_with_both_legs_held();
    app.apply(Action::Enter);

    press(&mut app, "yy");
    let note = app.status.lock().unwrap().clone();
    assert!(
        note.starts_with("yanked"),
        "expected a yank note, got {note:?}"
    );

    // Clear it, or the previous yank's note is what we would read back.
    app.note("");
    press(&mut app, "dd");
    let note = app.status.lock().unwrap().clone();
    assert!(
        !note.contains("yanked"),
        "a delete should not announce a clipboard write: {note:?}"
    );
    // ...but it still filled the register.
    assert_eq!(app.yank.text, "GET /req-path HTTP/1.1");
}

/// Visual yank copies out too — it is just as explicit as `yy`.
#[test]
fn visual_yank_reaches_the_clipboard() {
    let (_engine, mut app, _rt) = app_with_both_legs_held();
    app.apply(Action::Enter);
    press(&mut app, "vlly");
    let note = app.status.lock().unwrap().clone();
    assert!(note.starts_with("yanked"), "got {note:?}");
    assert_eq!(app.yank.text, "GET");
}

/// A yank must not change the buffer — the classic way to get this wrong is
/// to implement `y` as delete-then-undo.
#[test]
fn yank_leaves_the_buffer_untouched() {
    let (_engine, mut app, _rt) = app_with_both_legs_held();
    app.apply(Action::Enter);
    let before = app.preview_buffer(true).unwrap().text();

    press(&mut app, "yy");
    assert_eq!(app.preview_buffer(true).unwrap().text(), before);
    assert!(
        !app.preview_buffer(true).unwrap().is_dirty(),
        "yanking is not an edit"
    );
}

/// Deleting yanks too, which is what makes `dd` then `p` a move.
#[test]
fn delete_populates_the_register() {
    let (_engine, mut app, _rt) = app_with_both_legs_held();
    app.apply(Action::Enter);

    press(&mut app, "dd");
    assert_eq!(app.yank.text, "GET /req-path HTTP/1.1");
    assert!(app.yank.linewise);

    press(&mut app, "p");
    assert!(
        app.preview_buffer(true)
            .unwrap()
            .text()
            .contains("GET /req-path"),
        "dd then p should move the line back"
    );
}

/// `P` puts before, `p` after — linewise, so they land on their own lines.
#[test]
fn put_before_and_after_differ() {
    let (_engine, mut app, _rt) = app_with_both_legs_held();
    app.apply(Action::Enter);
    press(&mut app, "yy");

    press(&mut app, "P");
    let lines = app.preview_buffer(true).unwrap().lines().to_vec();
    assert_eq!(lines[0], "GET /req-path HTTP/1.1");
    assert_eq!(lines[1], "GET /req-path HTTP/1.1", "P puts above");
}

/// Formatting must be one undoable step: the whole point is that it is safe
/// to try on a request you care about.
#[test]
fn gq_reformats_a_json_body_and_undo_puts_it_back() {
    let (_engine, mut app, _rt) = app_with_both_legs_held();
    app.apply(Action::Enter);

    let original = "POST /a HTTP/1.1\nContent-Type: application/json\n\n{\"a\":[1,2]}";
    app.active_buffer().unwrap().set_text(original);

    press(&mut app, "gq");
    let formatted = app.preview_buffer(true).unwrap().text();
    assert!(
        formatted.ends_with("{\n  \"a\": [\n    1,\n    2\n  ]\n}"),
        "body should be indented: {formatted}"
    );
    assert!(
        formatted.starts_with("POST /a HTTP/1.1\n"),
        "the head must be untouched: {formatted}"
    );

    press(&mut app, "u");
    assert_eq!(
        app.preview_buffer(true).unwrap().text(),
        original,
        "one checkpoint, so one undo restores the original exactly"
    );
}

/// A body that is not JSON is left alone and the reason is reported —
/// silently mangling a payload would be the worst outcome here.
#[test]
fn gq_leaves_a_non_json_body_alone() {
    let (_engine, mut app, _rt) = app_with_both_legs_held();
    app.apply(Action::Enter);

    let original = "POST /a HTTP/1.1\nHost: x\n\nnot json at all";
    app.active_buffer().unwrap().set_text(original);

    press(&mut app, "gq");
    assert_eq!(app.preview_buffer(true).unwrap().text(), original);
    let status = app.status.lock().unwrap().clone();
    assert!(status.contains("cannot format"), "should say why: {status}");
}

fn view(buffer: &TextBuffer, focused: bool) -> BufferView<'_> {
    BufferView {
        buffer,
        cache: None,
        title: " Preview ".into(),
        focused,
        inserting: false,
        border: Style::new(),
        scroll: 0,
    }
}

/// A minified body is one very long line; without sideways scrolling the
/// far end of it is unreachable, which is what made the pane look broken.
#[test]
fn the_view_follows_the_cursor_along_a_long_line() {
    const COLS: u16 = 37;
    let mut buffer = TextBuffer::from_text(&"x".repeat(500));

    assert_eq!(
        view(&buffer, true).horizontal_scroll(COLS),
        0,
        "a cursor already on screen must not shift the view"
    );

    buffer.set_cursor(Cursor { line: 0, col: 200 });
    let scroll = view(&buffer, true).horizontal_scroll(COLS);
    assert!(scroll > 0, "the view should follow the cursor");
    // The cursor must land inside the visible columns, not past the edge.
    let visible = COLS as usize - 1;
    assert!(
        (200 - scroll as usize) <= visible,
        "cursor at {} of {visible} visible",
        200 - scroll as usize
    );
}

/// Short lines must not scroll sideways at all, or the whole pane would
/// drift whenever the cursor sat near the end of one.
#[test]
fn short_lines_stay_pinned_at_column_zero() {
    let mut buffer = TextBuffer::from_text("GET / HTTP/1.1");
    buffer.set_cursor(Cursor { line: 0, col: 13 });
    assert_eq!(view(&buffer, true).horizontal_scroll(77), 0);
}

/// The reported bug: after `gq` turns one line into many, moving down must
/// bring the view with it. Vim motions never touched `content_scroll`, so
/// the cursor used to walk off the bottom of the pane.
#[test]
fn the_view_follows_the_cursor_down_a_long_buffer() {
    const ROWS: u16 = 10;
    let mut buffer = TextBuffer::from_text(&"line\n".repeat(100));

    assert_eq!(
        view(&buffer, true).vertical_scroll(ROWS),
        0,
        "a cursor near the top must not scroll the view"
    );

    buffer.set_cursor(Cursor { line: 9, col: 0 });
    assert_eq!(
        view(&buffer, true).vertical_scroll(ROWS),
        0,
        "the last visible row is still on screen"
    );

    buffer.set_cursor(Cursor { line: 50, col: 0 });
    let scroll = view(&buffer, true).vertical_scroll(ROWS);
    assert_eq!(scroll, 41, "cursor pinned to the bottom row");
    assert!(
        (50 - scroll as usize) < ROWS as usize,
        "the cursor must be inside the pane"
    );
}

/// Without focus there is no cursor to follow, so the window's own `j`/`k`
/// offset stays in charge — otherwise entering a preview would yank the
/// read-only view back to the top.
#[test]
fn an_unfocused_buffer_keeps_its_manual_scroll() {
    let mut buffer = TextBuffer::from_text(&"line\n".repeat(100));
    buffer.set_cursor(Cursor { line: 50, col: 0 });

    let mut unfocused = view(&buffer, false);
    unfocused.scroll = 7;
    assert_eq!(unfocused.vertical_scroll(10), 7);
}

/// The gutter must be wide enough for the largest line number, or the
/// numbers would truncate on a long body.
#[test]
fn the_gutter_grows_with_the_line_count() {
    let short = TextBuffer::from_text("a\nb");
    let long = TextBuffer::from_text(&"x\n".repeat(1000));
    assert!(
        view(&long, true).gutter_width() > view(&short, true).gutter_width(),
        "a 1000-line body needs more room than a 2-line one"
    );
}

/// Vim's hybrid: distance from the cursor everywhere, absolute on the
/// cursor's own line, where `0` would say nothing useful.
#[test]
fn the_gutter_is_relative_except_on_the_cursor_line() {
    let mut buffer = TextBuffer::from_text("a\nb\nc\nd\ne");
    buffer.set_cursor(Cursor { line: 2, col: 0 });

    let v = view(&buffer, true);
    let text: Vec<String> = v
        .gutter(v.gutter_width())
        .iter()
        .map(|l| l.spans.iter().map(|s| s.content.to_string()).collect())
        .collect();
    let trimmed: Vec<&str> = text.iter().map(|s| s.trim()).collect();
    assert_eq!(trimmed, ["2", "1", "3", "1", "2"], "{text:?}");
}

/// `<C-g>` stages the focused buffer for the external editor. The handoff
/// itself needs a real terminal, so the test stops at the staging.
#[test]
fn ctrl_g_stages_the_held_item_for_the_external_editor() {
    let (_engine, mut app, _rt) = app_with_both_legs_held();
    key(
        &mut app,
        KeyEvent::new(KeyCode::Char('g'), KeyModifiers::CONTROL),
    );

    let job = app.pending_edit.as_ref().expect("an edit should be staged");
    assert!(
        job.before.contains("/req-path"),
        "should hand over the held request: {}",
        job.before
    );
    match job.target {
        EditTarget::Held { requests, .. } => assert!(requests, "the focused leg"),
        _ => panic!("expected a held target"),
    }
}

/// Edits already made in the pane are what gets handed over, so `i` then
/// `e` does not silently discard the first ones.
#[test]
fn external_edit_carries_in_pane_edits_forward() {
    let (_engine, mut app, _rt) = app_with_both_legs_held();
    app.apply(Action::Insert(InsertKey::Char('Z')));
    app.apply(Action::ExternalEdit);

    let job = app.pending_edit.as_ref().unwrap();
    assert!(job.before.starts_with('Z'), "got: {}", job.before);
}

/// Coming back from the editor marks the buffer dirty — otherwise
/// forwarding, which only reparses dirty buffers, would ignore the edit.
#[test]
fn an_applied_edit_is_marked_dirty_and_returns_to_the_queue() {
    let (_engine, mut app, _rt) = app_with_both_legs_held();
    app.apply(Action::Enter);
    let ticket = app.held_requests[0].ticket;

    app.apply_edit(
        EditJob {
            target: EditTarget::Held {
                requests: true,
                ticket,
            },
            before: String::new(),
        },
        "GET /from-editor HTTP/1.1\nhost: example.com\n\n".to_string(),
    );

    let buffer = app.preview_buffer(true).unwrap();
    assert!(buffer.text().contains("/from-editor"));
    assert!(buffer.is_dirty(), "must be dirty or forwarding ignores it");
    assert_eq!(
        app.intercept.pane,
        Pane::Table,
        "saving should return to the queue"
    );
}

/// An item answered while the editor was open must not have the edit landed
/// on whatever took its place.
#[test]
fn an_edit_for_a_vanished_item_is_discarded() {
    let (engine, mut app, _rt) = app_with_both_legs_held();
    let ticket = app.held_requests[0].ticket;
    engine.intercept().forward(ticket, None);
    app.refresh();

    app.apply_edit(
        EditJob {
            target: EditTarget::Held {
                requests: true,
                ticket,
            },
            before: String::new(),
        },
        "GET /too-late HTTP/1.1\n\n".to_string(),
    );
    assert!(app.intercept.request_edit.is_none());
}

/// Arguments in `$VISUAL`/`$EDITOR` survive, and the file is always last.
#[test]
fn editor_command_keeps_configured_arguments() {
    let path = std::path::Path::new("/tmp/x.http");

    let command = editor_command_from("nvim --clean", path);
    assert_eq!(command.as_std().get_program(), "nvim");
    let args: Vec<_> = command.as_std().get_args().collect();
    assert_eq!(args, ["--clean", "/tmp/x.http"]);

    let command = editor_command_from("ed", path);
    assert_eq!(command.as_std().get_program(), "ed");
}

/// With nothing configured we still have to open *something*.
#[test]
fn editor_command_falls_back_when_unset() {
    let command = editor_command_from("", std::path::Path::new("/tmp/x.http"));
    let program = command.as_std().get_program().to_string_lossy().to_string();
    assert!(
        program == "nvim" || program == "vi",
        "unexpected fallback: {program}"
    );
}

/// `i` straight from the queue opens the preview and edits there, rather
/// than leaving INSERT mode pointed at nothing.
#[test]
fn insert_from_the_queue_opens_the_preview() {
    let (_engine, mut app, _rt) = app_with_both_legs_held();
    assert_eq!(app.intercept.pane, Pane::Table);

    app.apply(Action::Insert(InsertKey::Char('Z')));
    assert_eq!(app.intercept.pane, Pane::Preview);
    assert!(app.preview_buffer(true).unwrap().text().starts_with('Z'));
}

/// Responses are editable too — the core forwards an edited response and
/// the client receives it.
#[test]
fn the_response_preview_accepts_edits() {
    let (_engine, mut app, _rt) = app_with_both_legs_held();
    app.apply(Action::Focus(Some(Column::Right)));
    app.apply(Action::Enter);

    app.apply(Action::Insert(InsertKey::Char('Z')));
    let buffer = app.preview_buffer(false).unwrap();
    assert!(buffer.text().starts_with('Z'));
    assert!(buffer.is_dirty());
}

/// Enter steps into the preview; Escape steps back out. Movement follows
/// whichever has the keys.
#[test]
fn enter_opens_the_preview_and_escape_leaves() {
    let (_engine, mut app, _rt) = app_with_both_legs_held();
    assert_eq!(app.intercept.pane, Pane::Table);

    app.apply(Action::Enter);
    assert_eq!(app.intercept.pane, Pane::Preview);

    // In the preview, `j` walks buffer lines rather than queue rows.
    let row_before = app.intercept.request_row;
    app.apply(Action::Move {
        motion: Motion::Down,
        count: None,
    });
    assert_eq!(
        app.intercept.request_row, row_before,
        "the queue row is fixed"
    );
    assert_eq!(app.preview_buffer(true).unwrap().cursor().line, 1);

    app.apply(Action::Escape);
    assert_eq!(app.intercept.pane, Pane::Table);
}

/// Leaving the window puts you back on the queue rather than stranding the
/// focus inside a preview you can no longer see.
#[test]
fn switching_windows_returns_focus_to_the_queue() {
    let (_engine, mut app, _rt) = app_with_both_legs_held();
    app.apply(Action::Enter);
    assert_eq!(app.intercept.pane, Pane::Preview);

    app.show_window(Window::Proxy);
    app.show_window(Window::Intercept);
    assert_eq!(app.intercept.pane, Pane::Table);
}

/// The whole loop, driven by keys: hold a request, forward it with `f`.
#[test]
fn bare_f_forwards_from_the_queue() {
    let (engine, mut app, _rt) = app_with_both_legs_held();
    assert_eq!(engine.intercept().queue_of(true).len(), 1);

    press(&mut app, "f");
    assert_eq!(
        engine.intercept().queue_of(true).len(),
        0,
        "f should have forwarded the held request"
    );
}

#[test]
fn bare_d_drops_from_the_queue() {
    let (engine, mut app, _rt) = app_with_both_legs_held();
    press(&mut app, "d");
    assert_eq!(engine.intercept().queue_of(true).len(), 0);
}

/// Legs can be switched off independently, and the pane says so.
#[test]
fn holding_can_be_limited_to_one_leg() {
    let mut app = App::new(Engine::new());
    app.refresh();
    press(&mut app, "I");
    press(&mut app, " i");
    assert!(app.engine.intercept().holds_responses());

    press(&mut app, " 2");
    assert!(!app.engine.intercept().holds_responses());
    assert!(app.engine.intercept().holds_requests(), "only one leg off");
    let out = render(&mut app);
    assert!(out.contains("[x] requests"), "{out}");
    assert!(out.contains("[ ] responses"), "{out}");
}

#[test]
fn intercept_shows_held_items_and_answers_them() {
    let engine = Engine::new();
    engine.intercept().set_enabled(true);
    let mut app = App::new(engine.clone());

    // Hold something from another task, as the proxy handler would.
    let held = tokio::runtime::Runtime::new().unwrap();
    let _guard = held.enter();
    let e = engine.clone();
    held.spawn(async move {
        e.intercept()
            .hold_request(42, get_request("http://example.com/secret"))
            .await
    });
    // Give the spawned hold a moment to reach the queue.
    for _ in 0..100 {
        if !engine.intercept().is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }

    app.refresh();
    press(&mut app, "I");
    let out = render(&mut app);
    assert!(out.contains("#42"), "the held flow should be listed: {out}");
    assert!(out.contains("/secret"), "{out}");

    press(&mut app, "f");
    assert!(engine.intercept().is_empty(), "forwarding should answer it");
}

// --- sitemap ---

fn node(id: i64, parent: Option<i64>, host: &str, path: &str, name: &str) -> SitemapNode {
    SitemapNode {
        id,
        parent_id: parent,
        kind: "dir".into(),
        host: host.into(),
        path: path.into(),
        name: name.into(),
        first_seen: 0,
        last_seen: 0,
        flow_count: 1,
        origin: "observed".into(),
        comment: None,
        highlight: None,
    }
}

#[test]
fn sitemap_nests_paths_under_their_host() {
    let nodes = vec![
        node(1, None, "a.test", "/api", "api"),
        node(2, Some(1), "a.test", "/api/v1", "v1"),
        node(3, None, "b.test", "/x", "x"),
    ];
    let rows = build_sitemap_rows(&nodes, &HashSet::new());
    let shape: Vec<(usize, &str)> = rows.iter().map(|r| (r.depth, r.label.as_str())).collect();
    assert_eq!(
        shape,
        vec![
            (0, "a.test"),
            (1, "api"),
            (2, "v1"),
            (0, "b.test"),
            (1, "x"),
        ]
    );
}

#[test]
fn folding_a_node_hides_its_descendants() {
    let nodes = vec![
        node(1, None, "a.test", "/api", "api"),
        node(2, Some(1), "a.test", "/api/v1", "v1"),
    ];
    let mut collapsed = HashSet::new();
    collapsed.insert("node:1".to_string());
    let rows = build_sitemap_rows(&nodes, &collapsed);
    let labels: Vec<&str> = rows.iter().map(|r| r.label.as_str()).collect();
    assert_eq!(labels, vec!["a.test", "api"], "v1 should be folded away");

    collapsed.insert("host:a.test".to_string());
    let rows = build_sitemap_rows(&nodes, &collapsed);
    assert_eq!(rows.len(), 1, "folding the host hides everything under it");
}

/// A node whose parent fell outside the fetched page must still appear.
/// Dropping it would silently hide a path that was actually observed.
#[test]
fn orphaned_nodes_are_shown_as_roots() {
    let nodes = vec![node(2, Some(999), "a.test", "/api/v1", "v1")];
    let rows = build_sitemap_rows(&nodes, &HashSet::new());
    let labels: Vec<&str> = rows.iter().map(|r| r.label.as_str()).collect();
    assert_eq!(labels, vec!["a.test", "v1"]);
}

#[test]
fn sitemap_window_renders_captured_paths() {
    let engine = Engine::new();
    engine.record_request(get_request("http://example.com/foo/bar"));
    let mut app = App::new(engine);
    app.refresh();
    press(&mut app, "S");
    let out = render(&mut app);
    assert!(out.contains("example.com"), "{out}");
    assert!(out.contains("foo"), "{out}");
}
