//! sudo-frei-tui: terminal UI for scripts/sudo-frei.
//!
//! The bash script stays the only thing that touches hosts; this UI shows
//! `sudo-frei status --raw` and runs `sudo-frei grant|revoke` with the real
//! terminal handed over, so sudo can ask for a password the usual way.
//! It also shows the SSH agent: which keys in ~/.ssh are loaded and whether
//! each host's key (from `ssh -G`) is, since grant/revoke need it.

use std::{
    collections::HashSet,
    env,
    io::{self, Write},
    path::PathBuf,
    process::{Command, Stdio},
    sync::mpsc::{self, Receiver, Sender},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use chrono::{Local, TimeZone};
use ratatui::{
    crossterm::{
        event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
        execute,
        terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    },
    layout::{Constraint, Flex, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Cell, Clear, Paragraph, Row, Table, TableState},
    DefaultTerminal, Frame,
};
use serde::Deserialize;

/// Hard limit of the script; the dialog refuses anything above it.
const MAX_MIN: u32 = 240;
/// How often `ssh-add -l` is re-read; cheap, so it follows changes made elsewhere.
const AGENT_EVERY: Duration = Duration::from_secs(3);

// ---------------------------------------------------------------- config

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    /// Hosts in display order; empty means the script's built-in list.
    #[serde(default)]
    hosts: Vec<String>,
    #[serde(default = "default_presets")]
    presets: Vec<u32>,
    #[serde(default = "default_minutes")]
    default_minutes: u32,
    #[serde(default = "default_refresh")]
    refresh_seconds: u64,
    /// Path or name of the sudo-frei script.
    #[serde(default = "default_script")]
    script: String,
}

fn default_presets() -> Vec<u32> {
    vec![5, 15, 30, 60]
}
fn default_minutes() -> u32 {
    30
}
fn default_refresh() -> u64 {
    30
}
fn default_script() -> String {
    "sudo-frei".into()
}

impl Default for Config {
    fn default() -> Self {
        Config {
            hosts: Vec::new(),
            presets: default_presets(),
            default_minutes: default_minutes(),
            refresh_seconds: default_refresh(),
            script: default_script(),
        }
    }
}

fn home() -> PathBuf {
    PathBuf::from(env::var_os("HOME").unwrap_or_default())
}

fn config_path() -> PathBuf {
    if let Some(p) = env::var_os("SUDO_FREI_CONFIG") {
        return p.into();
    }
    let base = env::var_os("XDG_CONFIG_HOME").map(PathBuf::from).unwrap_or_else(|| home().join(".config"));
    base.join("sudo-frei/config.toml")
}

fn load_config() -> Result<Config, String> {
    let path = config_path();
    let cfg = match std::fs::read_to_string(&path) {
        Ok(text) => toml::from_str::<Config>(&text).map_err(|e| format!("{}: {e}", path.display()))?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => Config::default(),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    if cfg.presets.iter().any(|&m| m == 0 || m > MAX_MIN) {
        return Err(format!("{}: presets müssen zwischen 1 und {MAX_MIN} liegen", path.display()));
    }
    if cfg.refresh_seconds == 0 {
        return Err(format!("{}: refresh_seconds muss mindestens 1 sein", path.display()));
    }
    if cfg.default_minutes == 0 || cfg.default_minutes > MAX_MIN {
        return Err(format!("{}: default_minutes muss zwischen 1 und {MAX_MIN} liegen", path.display()));
    }
    Ok(cfg)
}

// ---------------------------------------------------------------- sudo state

#[derive(Clone, PartialEq, Debug)]
enum State {
    Unknown,
    On(i64),
    Off,
    /// Rule present but no expiry timer: passwordless until revoke or reboot.
    Orphan,
    Offline,
}

fn parse_status(out: &str) -> Vec<(String, State)> {
    out.lines()
        .filter_map(|line| {
            let mut f = line.split('\t');
            let host = f.next()?.to_string();
            let state = match (f.next()?, f.next().unwrap_or("")) {
                ("an", end) => end.parse().map(State::On).unwrap_or(State::Unknown),
                ("aus", _) => State::Off,
                ("verwaist", _) => State::Orphan,
                _ => State::Offline,
            };
            Some((host, state))
        })
        .collect()
}

fn is_local(host: &str) -> bool {
    host == "local" || hostname().as_deref() == Some(host)
}

fn hostname() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/hostname").ok().map(|s| s.trim().to_string())
}

// ---------------------------------------------------------------- ssh keys

/// One line of `ssh-add -l` or `ssh-keygen -l`: "256 SHA256:… comment (ED25519)".
#[derive(Clone, Debug, PartialEq)]
struct KeyId {
    fp: String,
    comment: String,
    kind: String,
}

fn parse_key_line(line: &str) -> Option<KeyId> {
    let mut parts = line.split_whitespace();
    let _bits = parts.next()?;
    let fp = parts.next()?;
    if !fp.starts_with("SHA256:") {
        return None;
    }
    let rest: Vec<&str> = parts.collect();
    let (kind, comment) = match rest.split_last() {
        Some((last, init)) if last.starts_with('(') && last.ends_with(')') => {
            (last.trim_matches(|c| c == '(' || c == ')').to_string(), init.join(" "))
        }
        _ => (String::new(), rest.join(" ")),
    };
    Some(KeyId { fp: fp.to_string(), comment, kind })
}

enum AgentState {
    Keys(Vec<KeyId>),
    NoAgent,
}

fn read_agent() -> AgentState {
    match Command::new("ssh-add").args(["-l", "-E", "sha256"]).stdin(Stdio::null()).output() {
        // Exit 1 = agent reachable but empty, 2 = no agent.
        Ok(o) if o.status.code() == Some(0) || o.status.code() == Some(1) => {
            AgentState::Keys(String::from_utf8_lossy(&o.stdout).lines().filter_map(parse_key_line).collect())
        }
        _ => AgentState::NoAgent,
    }
}

/// A public key in ~/.ssh; `private` is the identity file ssh would use.
struct KeyFile {
    name: String,
    private: PathBuf,
    id: KeyId,
}

fn read_key_files() -> Vec<KeyFile> {
    let dir = home().join(".ssh");
    let Ok(entries) = std::fs::read_dir(&dir) else { return Vec::new() };
    let mut keys: Vec<KeyFile> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "pub"))
        .filter_map(|pub_path| {
            let out = Command::new("ssh-keygen").args(["-E", "sha256", "-lf"]).arg(&pub_path).output().ok()?;
            let id = parse_key_line(String::from_utf8_lossy(&out.stdout).lines().next()?)?;
            let private = pub_path.with_extension("");
            let name = private.file_name()?.to_string_lossy().into_owned();
            Some(KeyFile { name, private, id })
        })
        .collect();
    keys.sort_by(|a, b| a.name.cmp(&b.name));
    keys
}

/// What `ssh -G HOST` says about keys, without connecting.
#[derive(Default)]
struct HostKeys {
    files: Vec<PathBuf>,
    identities_only: bool,
}

fn expand_tilde(p: &str) -> PathBuf {
    match p.strip_prefix("~/") {
        Some(rest) => home().join(rest),
        None => PathBuf::from(p),
    }
}

fn read_host_keys(host: &str) -> HostKeys {
    let Ok(out) = Command::new("ssh").args(["-G", "--", host]).stdin(Stdio::null()).stderr(Stdio::null()).output() else {
        return HostKeys::default();
    };
    let mut hk = HostKeys::default();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        match line.split_once(' ') {
            Some(("identityfile", v)) => hk.files.push(expand_tilde(v)),
            Some(("identitiesonly", v)) => hk.identities_only = v == "yes",
            _ => {}
        }
    }
    hk
}

#[derive(Debug, PartialEq)]
enum KeyReady {
    /// This machine; no ssh involved.
    Local,
    /// A key from the host's IdentityFile list is in the agent.
    Loaded(String),
    /// None of its own keys, but ssh would still offer the agent's keys.
    Maybe,
    Missing,
}

fn key_ready(host: &str, hk: &HostKeys, files: &[KeyFile], loaded: &HashSet<String>) -> KeyReady {
    if is_local(host) {
        return KeyReady::Local;
    }
    for f in &hk.files {
        if let Some(k) = files.iter().find(|k| &k.private == f)
            && loaded.contains(&k.id.fp) {
                return KeyReady::Loaded(k.name.clone());
            }
    }
    if !hk.identities_only && !loaded.is_empty() {
        KeyReady::Maybe
    } else {
        KeyReady::Missing
    }
}

// ---------------------------------------------------------------- app

struct HostRow {
    name: String,
    state: State,
    keys: HostKeys,
}

enum Mode {
    Normal,
    Grant { input: String },
    AddKey { candidates: Vec<usize> },
}

type StatusResult = Result<Vec<(String, State)>, String>;

struct App {
    cfg: Config,
    rows: Vec<HostRow>,
    table: TableState,
    mode: Mode,
    refreshing: bool,
    last_refresh: Option<Instant>,
    agent: AgentState,
    agent_read: Instant,
    key_files: Vec<KeyFile>,
    message: Option<(String, Instant)>,
    tx: Sender<StatusResult>,
    rx: Receiver<StatusResult>,
    quit: bool,
}

fn now_epoch() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

impl App {
    fn new(cfg: Config) -> Self {
        let (tx, rx) = mpsc::channel();
        let rows = cfg
            .hosts
            .iter()
            .map(|h| HostRow { name: h.clone(), state: State::Unknown, keys: read_host_keys(h) })
            .collect();
        let mut table = TableState::default();
        table.select(Some(0));
        App {
            cfg,
            rows,
            table,
            mode: Mode::Normal,
            refreshing: false,
            last_refresh: None,
            agent: read_agent(),
            agent_read: Instant::now(),
            key_files: read_key_files(),
            message: None,
            tx,
            rx,
            quit: false,
        }
    }

    fn loaded_fps(&self) -> HashSet<String> {
        match &self.agent {
            AgentState::Keys(keys) => keys.iter().map(|k| k.fp.clone()).collect(),
            AgentState::NoAgent => HashSet::new(),
        }
    }

    fn reread_agent(&mut self) {
        self.agent = read_agent();
        self.agent_read = Instant::now();
    }

    fn refresh(&mut self) {
        if self.refreshing {
            return;
        }
        self.refreshing = true;
        let tx = self.tx.clone();
        let script = self.cfg.script.clone();
        let hosts = self.cfg.hosts.clone();
        thread::spawn(move || {
            let result = Command::new(&script)
                .arg("status")
                .arg("--raw")
                .args(&hosts)
                .stdin(Stdio::null())
                .output()
                .map_err(|e| format!("{script}: {e}"))
                .and_then(|o| {
                    if o.status.success() {
                        Ok(parse_status(&String::from_utf8_lossy(&o.stdout)))
                    } else {
                        Err(String::from_utf8_lossy(&o.stderr).trim().to_string())
                    }
                });
            let _ = tx.send(result);
        });
    }

    fn take_results(&mut self) {
        while let Ok(result) = self.rx.try_recv() {
            self.refreshing = false;
            self.last_refresh = Some(Instant::now());
            match result {
                Ok(list) => {
                    if self.cfg.hosts.is_empty() {
                        // No config: the script decided the hosts.
                        // Reuse each host's `ssh -G` result; only new names are read.
                        let mut old = std::mem::take(&mut self.rows);
                        self.rows = list
                            .into_iter()
                            .map(|(name, state)| {
                                let keys = match old.iter().position(|r| r.name == name) {
                                    Some(i) => old.swap_remove(i).keys,
                                    None => read_host_keys(&name),
                                };
                                HostRow { name, state, keys }
                            })
                            .collect();
                    } else {
                        for (name, state) in list {
                            if let Some(r) = self.rows.iter_mut().find(|r| r.name == name) {
                                r.state = state;
                            }
                        }
                    }
                    if self.table.selected().unwrap_or(0) >= self.rows.len() {
                        self.table.select(Some(0));
                    }
                }
                Err(e) => self.flash(format!("Status fehlgeschlagen: {e}")),
            }
        }
    }

    fn tick(&mut self) {
        self.take_results();
        if self.agent_read.elapsed() >= AGENT_EVERY {
            self.reread_agent();
        }
        let due = match self.last_refresh {
            None => true,
            Some(t) => t.elapsed() >= Duration::from_secs(self.cfg.refresh_seconds),
        };
        // A grant that just ran out: check right away instead of waiting.
        let expired = self.rows.iter().any(|r| matches!(r.state, State::On(end) if end <= now_epoch()))
            && self.last_refresh.is_some_and(|t| t.elapsed() > Duration::from_secs(3));
        if due || expired {
            self.refresh();
        }
        if self.message.as_ref().is_some_and(|(_, t)| t.elapsed() > Duration::from_secs(6)) {
            self.message = None;
        }
    }

    fn flash(&mut self, text: String) {
        self.message = Some((text, Instant::now()));
    }

    fn selected(&self) -> Option<&HostRow> {
        self.table.selected().and_then(|i| self.rows.get(i))
    }

    fn select_offset(&mut self, delta: isize) {
        if self.rows.is_empty() {
            return;
        }
        let n = self.rows.len() as isize;
        let i = self.table.selected().unwrap_or(0) as isize;
        self.table.select(Some(((i + delta).rem_euclid(n)) as usize));
    }

    /// Key files not in the agent, the selected host's own keys first.
    fn unloaded_keys(&self) -> Vec<usize> {
        let loaded = self.loaded_fps();
        let own: Vec<&PathBuf> = self.selected().map(|r| r.keys.files.iter().collect()).unwrap_or_default();
        let mut idx: Vec<usize> =
            (0..self.key_files.len()).filter(|&i| !loaded.contains(&self.key_files[i].id.fp)).collect();
        idx.sort_by_key(|&i| !own.contains(&&self.key_files[i].private));
        idx
    }
}

// ---------------------------------------------------------------- actions

/// Hand the terminal to PROGRAM ARGS (for password prompts), then take it back.
extern "C" fn ignore_sigint(_: libc::c_int) {}

fn run_external(terminal: &mut DefaultTerminal, program: &str, args: &[&str]) -> io::Result<bool> {
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;
    // ratatui hides the cursor while drawing; password prompts need it.
    terminal.show_cursor()?;
    println!("\n$ {program} {}", args.join(" "));
    // Outside raw mode Ctrl-C reaches us too; a no-op handler (not SIG_IGN,
    // which the child would inherit) lets it cancel only the child.
    // SAFETY: installs and later restores a plain signal handler that does nothing.
    let previous = unsafe { libc::signal(libc::SIGINT, ignore_sigint as extern "C" fn(libc::c_int) as libc::sighandler_t) };
    let ok = match Command::new(program).args(args).status() {
        Ok(s) => s.success(),
        Err(e) => {
            eprintln!("{program}: {e}");
            false
        }
    };
    // SAFETY: restores the handler that was active before.
    unsafe { libc::signal(libc::SIGINT, previous) };
    if !ok {
        print!("\nFehlgeschlagen. Enter zum Zurückkehren … ");
        io::stdout().flush()?;
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
    }
    enable_raw_mode()?;
    execute!(io::stdout(), EnterAlternateScreen)?;
    terminal.hide_cursor()?;
    terminal.clear()?;
    Ok(ok)
}

fn add_key(app: &mut App, terminal: &mut DefaultTerminal, i: usize) -> io::Result<()> {
    let path = app.key_files[i].private.to_string_lossy().into_owned();
    let name = app.key_files[i].name.clone();
    if run_external(terminal, "ssh-add", &[&path])? {
        app.flash(format!("Schlüssel {name} geladen."));
    }
    app.reread_agent();
    Ok(())
}

fn handle_key(app: &mut App, terminal: &mut DefaultTerminal, code: KeyCode, mods: KeyModifiers) -> io::Result<()> {
    if code == KeyCode::Char('c') && mods.contains(KeyModifiers::CONTROL) {
        app.quit = true;
        return Ok(());
    }
    match &mut app.mode {
        Mode::Normal => match code {
            KeyCode::Char('q') | KeyCode::Esc => app.quit = true,
            KeyCode::Up | KeyCode::Char('k') => app.select_offset(-1),
            KeyCode::Down | KeyCode::Char('j') => app.select_offset(1),
            KeyCode::Char('u') | KeyCode::F(5) => {
                app.reread_agent();
                app.refresh();
            }
            KeyCode::Char('g') | KeyCode::Enter => match app.selected().map(|r| r.state.clone()) {
                Some(State::Offline) => app.flash("Rechner nicht erreichbar.".into()),
                Some(_) => app.mode = Mode::Grant { input: app.cfg.default_minutes.to_string() },
                None => {}
            },
            KeyCode::Char('r') => {
                let Some(row) = app.selected() else { return Ok(()) };
                let host = row.name.clone();
                match row.state {
                    State::Off => app.flash(format!("{host} ist schon aus.")),
                    State::Offline => app.flash("Rechner nicht erreichbar.".into()),
                    _ => {
                        let script = app.cfg.script.clone();
                        if run_external(terminal, &script, &["revoke", &host])? {
                            app.flash(format!("{host}: widerrufen."));
                        }
                        app.refresh();
                    }
                }
            }
            KeyCode::Char('a') => {
                if matches!(app.agent, AgentState::NoAgent) {
                    app.flash("Kein SSH-Agent erreichbar (SSH_AUTH_SOCK).".into());
                    return Ok(());
                }
                let candidates = app.unloaded_keys();
                match candidates.len() {
                    0 => app.flash("Alle Schlüssel aus ~/.ssh sind geladen.".into()),
                    1 => add_key(app, terminal, candidates[0])?,
                    _ => app.mode = Mode::AddKey { candidates },
                }
            }
            KeyCode::Char('x') => {
                let ok = Command::new("ssh-add")
                    .arg("-D")
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .is_ok_and(|s| s.success());
                app.reread_agent();
                app.flash(if ok { "Agent geleert.".into() } else { "Agent leeren fehlgeschlagen.".into() });
            }
            _ => {}
        },
        Mode::AddKey { candidates } => match code {
            KeyCode::Esc => app.mode = Mode::Normal,
            KeyCode::Char(c) if c.is_ascii_digit() => {
                let n = c.to_digit(10).unwrap_or(0) as usize;
                if let Some(&i) = n.checked_sub(1).and_then(|n| candidates.get(n)) {
                    app.mode = Mode::Normal;
                    add_key(app, terminal, i)?;
                }
            }
            _ => {}
        },
        Mode::Grant { input } => match code {
            KeyCode::Esc => app.mode = Mode::Normal,
            KeyCode::Char(c) if c.is_ascii_digit() && input.len() < 3 => input.push(c),
            KeyCode::Backspace => {
                input.pop();
            }
            KeyCode::Left | KeyCode::Right => {
                let presets = &app.cfg.presets;
                if !presets.is_empty() {
                    let cur: u32 = input.parse().unwrap_or(0);
                    let pos = presets.iter().position(|&p| p == cur);
                    let next = match (code, pos) {
                        (KeyCode::Right, Some(i)) => (i + 1) % presets.len(),
                        (KeyCode::Left, Some(i)) => (i + presets.len() - 1) % presets.len(),
                        (KeyCode::Right, None) => presets.iter().position(|&p| p > cur).unwrap_or(0),
                        _ => presets.iter().rposition(|&p| p < cur).unwrap_or(presets.len() - 1),
                    };
                    *input = presets[next].to_string();
                }
            }
            KeyCode::Enter => {
                let min: u32 = input.parse().unwrap_or(0);
                if !(1..=MAX_MIN).contains(&min) {
                    app.flash(format!("Minuten: 1 bis {MAX_MIN}."));
                    return Ok(());
                }
                app.mode = Mode::Normal;
                let Some(host) = app.selected().map(|r| r.name.clone()) else { return Ok(()) };
                let script = app.cfg.script.clone();
                if run_external(terminal, &script, &["grant", &host, &min.to_string()])? {
                    app.flash(format!("{host}: frei für {min} min."));
                }
                app.refresh();
            }
            _ => {}
        },
    }
    Ok(())
}

// ---------------------------------------------------------------- drawing

fn fmt_clock(epoch: i64) -> String {
    Local.timestamp_opt(epoch, 0).single().map(|t| t.format("%H:%M").to_string()).unwrap_or_default()
}

fn fmt_left(secs: i64) -> String {
    if secs <= 0 {
        return "läuft ab …".into();
    }
    if secs >= 3600 {
        format!("{}:{:02}:{:02}", secs / 3600, secs / 60 % 60, secs % 60)
    } else {
        format!("{}:{:02}", secs / 60, secs % 60)
    }
}

fn short_fp(fp: &str) -> String {
    let body = fp.strip_prefix("SHA256:").unwrap_or(fp);
    format!("SHA256:{}…", body.chars().take(10).collect::<String>())
}

fn draw(frame: &mut Frame, app: &mut App) {
    let agent_lines = agent_panel(app);
    let [header, body, agent, help, msg] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(4),
        Constraint::Length(agent_lines.len() as u16 + 2),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    let status = if app.refreshing {
        "prüfe …".to_string()
    } else {
        match app.last_refresh {
            Some(t) => format!("geprüft vor {} s", t.elapsed().as_secs()),
            None => String::new(),
        }
    };
    frame.render_widget(
        Line::from(vec![Span::from(" sudo-frei ").bold().reversed(), Span::from("  "), Span::from(status).dim()]),
        header,
    );

    let now = now_epoch();
    let loaded = app.loaded_fps();
    let rows: Vec<Row> = app
        .rows
        .iter()
        .map(|r| {
            let (state, until, left, style) = match r.state {
                State::On(end) => (
                    "frei",
                    fmt_clock(end),
                    fmt_left(end - now),
                    Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                ),
                State::Off => ("aus", String::new(), String::new(), Style::new().fg(Color::Green)),
                State::Orphan => (
                    "verwaist",
                    String::new(),
                    "ohne Timer!".into(),
                    Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
                State::Offline => ("offline", String::new(), String::new(), Style::new().fg(Color::DarkGray)),
                State::Unknown => ("…", String::new(), String::new(), Style::new().fg(Color::DarkGray)),
            };
            let key = match key_ready(&r.name, &r.keys, &app.key_files, &loaded) {
                KeyReady::Local => Cell::from("lokal").dim(),
                KeyReady::Loaded(name) => Cell::from(format!("✓ {name}")).green(),
                KeyReady::Maybe => Cell::from("? Agent").yellow(),
                KeyReady::Missing => Cell::from("✗ fehlt").red(),
            };
            Row::new(vec![Cell::from(r.name.clone()), Cell::from(state).style(style), Cell::from(until), Cell::from(left), key])
        })
        .collect();
    let table = Table::new(
        rows,
        [
            Constraint::Length(14),
            Constraint::Length(9),
            Constraint::Length(7),
            Constraint::Length(11),
            Constraint::Min(10),
        ],
    )
    .header(Row::new(["Rechner", "sudo", "bis", "Rest", "SSH-Schlüssel"]).style(Style::new().dim()))
    .row_highlight_style(Style::new().reversed())
    .highlight_symbol("› ")
    .block(Block::bordered());
    frame.render_stateful_widget(table, body, &mut app.table);

    frame.render_widget(Paragraph::new(agent_lines).block(Block::bordered().title(" SSH-Agent ")), agent);

    let keys = match app.mode {
        Mode::Normal => " ↑↓ wählen  g freigeben  r widerrufen  a Schlüssel laden  x Agent leeren  u prüfen  q beenden",
        Mode::Grant { .. } => " Zahl tippen  ←→ Vorschläge  Enter freigeben  Esc abbrechen",
        Mode::AddKey { .. } => " Ziffer wählt den Schlüssel  Esc abbrechen",
    };
    frame.render_widget(Line::from(keys).dim(), help);
    if let Some((text, _)) = &app.message {
        frame.render_widget(Line::from(format!(" {text}")).yellow(), msg);
    }

    match &app.mode {
        Mode::Grant { input } => draw_grant(frame, app, input),
        Mode::AddKey { candidates } => draw_add_key(frame, app, candidates),
        Mode::Normal => {}
    }
}

/// Keys in ~/.ssh with their agent state, then agent keys without a file (e.g. forwarded).
fn agent_panel(app: &App) -> Vec<Line<'static>> {
    let keys = match &app.agent {
        AgentState::NoAgent => return vec![Line::from("kein Agent erreichbar (SSH_AUTH_SOCK)").red()],
        AgentState::Keys(k) => k,
    };
    let loaded: HashSet<&str> = keys.iter().map(|k| k.fp.as_str()).collect();
    let mut lines: Vec<Line> = app
        .key_files
        .iter()
        .map(|k| {
            let on = loaded.contains(k.id.fp.as_str());
            let mark = if on { Span::from("● geladen ").green() } else { Span::from("○ nicht geladen ").dim() };
            Line::from(vec![
                mark,
                Span::from(format!("{:<12}", k.name)).bold(),
                Span::from(format!(" {:<8} {} {}", k.id.kind, short_fp(&k.id.fp), k.id.comment)).dim(),
            ])
        })
        .collect();
    for k in keys.iter().filter(|k| !app.key_files.iter().any(|f| f.id.fp == k.fp)) {
        lines.push(Line::from(vec![
            Span::from("● geladen ").green(),
            Span::from(format!("{:<12}", k.comment)).bold(),
            Span::from(format!(" {:<8} {} (keine Datei in ~/.ssh)", k.kind, short_fp(&k.fp))).dim(),
        ]));
    }
    if lines.is_empty() {
        lines.push(Line::from("keine Schlüssel").dim());
    }
    lines
}

fn draw_grant(frame: &mut Frame, app: &App, input: &str) {
    let host = app.selected().map(|r| r.name.as_str()).unwrap_or("?");
    let presets = app
        .cfg
        .presets
        .iter()
        .map(|p| {
            let s = Span::from(format!(" {p} "));
            if input.parse::<u32>().ok() == Some(*p) { s.reversed() } else { s }
        })
        .collect::<Vec<_>>();
    let mut text = vec![
        Line::from(vec![Span::from("Minuten: "), Span::from(format!("{input}▏")).bold()]),
        Line::from(presets),
        Line::from(""),
        Line::from(format!("Danach fragt {host} ggf. nach dem sudo-Passwort.")).dim(),
    ];
    if let Some(r) = app.selected()
        && key_ready(&r.name, &r.keys, &app.key_files, &app.loaded_fps()) == KeyReady::Missing {
            text.push(Line::from("Schlüssel nicht geladen: ssh fragt nach der Passphrase.").yellow());
        }
    let area = centered(frame.area(), 58, text.len() as u16 + 2);
    frame.render_widget(Clear, area);
    frame.render_widget(Paragraph::new(text).block(Block::bordered().title(format!(" {host} freigeben "))), area);
}

fn draw_add_key(frame: &mut Frame, app: &App, candidates: &[usize]) {
    let text: Vec<Line> = candidates
        .iter()
        .take(9)
        .enumerate()
        .map(|(n, &i)| {
            let k = &app.key_files[i];
            Line::from(vec![
                Span::from(format!(" {} ", n + 1)).reversed(),
                Span::from(format!(" {:<12}", k.name)).bold(),
                Span::from(format!(" {} {}", k.id.kind, k.id.comment)).dim(),
            ])
        })
        .collect();
    let area = centered(frame.area(), 58, text.len() as u16 + 2);
    frame.render_widget(Clear, area);
    frame.render_widget(Paragraph::new(text).block(Block::bordered().title(" Schlüssel laden ")), area);
}

fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let [row] = Layout::vertical([Constraint::Length(h.min(area.height))]).flex(Flex::Center).areas(area);
    let [cell] = Layout::horizontal([Constraint::Length(w.min(area.width))]).flex(Flex::Center).areas(row);
    cell
}

// ---------------------------------------------------------------- main

fn run(terminal: &mut DefaultTerminal, app: &mut App) -> io::Result<()> {
    while !app.quit {
        app.tick();
        terminal.draw(|f| draw(f, app))?;
        if event::poll(Duration::from_millis(250))?
            && let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press {
                    handle_key(app, terminal, key.code, key.modifiers)?;
                }
    }
    Ok(())
}

fn main() {
    if env::args().any(|a| a == "-h" || a == "--help") {
        println!(
            "sudo-frei-tui: zeitlich begrenztes sudo ohne Passwort, Oberfläche für sudo-frei.\n\
             Konfiguration: {} (hosts, presets, default_minutes, refresh_seconds, script)",
            config_path().display()
        );
        return;
    }
    let cfg = match load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sudo-frei-tui: {e}");
            std::process::exit(1);
        }
    };
    let mut app = App::new(cfg);
    let mut terminal = ratatui::init();
    let result = run(&mut terminal, &mut app);
    let _ = terminal.show_cursor();
    drop(terminal);
    ratatui::restore();
    if let Err(e) = result {
        eprintln!("sudo-frei-tui: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_raw_status() {
        let out = "local\taus\t\nlaptop\tan\t1793900000\nserver\toffline\t\nbad line\npi\tverwaist\t\n";
        let got = parse_status(out);
        assert_eq!(got[0], ("local".into(), State::Off));
        assert_eq!(got[1], ("laptop".into(), State::On(1793900000)));
        assert_eq!(got[2], ("server".into(), State::Offline));
        assert_eq!(got[3], ("pi".into(), State::Orphan));
        assert_eq!(got.len(), 4);
    }

    #[test]
    fn parses_key_lines() {
        let k = parse_key_line("256 SHA256:AbCdEf12 me@laptop (ED25519)").unwrap();
        assert_eq!(k, KeyId { fp: "SHA256:AbCdEf12".into(), comment: "me@laptop".into(), kind: "ED25519".into() });
        let k = parse_key_line("3072 SHA256:abc my laptop key (RSA)").unwrap();
        assert_eq!(k.comment, "my laptop key");
        assert!(parse_key_line("The agent has no identities.").is_none());
    }

    #[test]
    fn key_ready_rules() {
        let file = KeyFile {
            name: "laptop".into(),
            private: PathBuf::from("/h/.ssh/laptop"),
            id: KeyId { fp: "SHA256:x".into(), comment: String::new(), kind: "ED25519".into() },
        };
        let strict = HostKeys { files: vec![PathBuf::from("/h/.ssh/laptop")], identities_only: true };
        let loose = HostKeys { files: vec![PathBuf::from("/h/.ssh/other")], identities_only: false };
        let none = HashSet::new();
        let some: HashSet<String> = ["SHA256:x".to_string()].into();
        let other: HashSet<String> = ["SHA256:y".to_string()].into();
        assert_eq!(key_ready("server", &strict, std::slice::from_ref(&file), &some), KeyReady::Loaded("laptop".into()));
        assert_eq!(key_ready("server", &strict, std::slice::from_ref(&file), &none), KeyReady::Missing);
        assert_eq!(key_ready("server", &strict, std::slice::from_ref(&file), &other), KeyReady::Missing);
        assert_eq!(key_ready("server", &loose, std::slice::from_ref(&file), &other), KeyReady::Maybe);
        assert_eq!(key_ready("local", &strict, std::slice::from_ref(&file), &none), KeyReady::Local);
    }

    #[test]
    fn example_config_parses() {
        let cfg: Config = toml::from_str(include_str!("../config.example.toml")).unwrap();
        assert!(!cfg.hosts.is_empty());
        assert!(cfg.presets.iter().all(|&p| (1..=MAX_MIN).contains(&p)));
    }

    #[test]
    fn tilde_expands() {
        assert_eq!(expand_tilde("~/.ssh/laptop"), home().join(".ssh/laptop"));
        assert_eq!(expand_tilde("/abs/key"), std::path::Path::new("/abs/key"));
    }
}
