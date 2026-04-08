//! Interactive TUI for dlpscan — menu system and live stats dashboard.
//!
//! Requires the `tui` feature flag (`ratatui` + `crossterm`).

#[cfg(feature = "tui")]
pub mod app {
    use crossterm::{
        event::{self, Event, KeyCode, KeyEventKind},
        terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
        ExecutableCommand,
    };
    use ratatui::{
        prelude::*,
        widgets::*,
    };
    use std::io::stdout;
    use std::time::{Duration, Instant};

    // -----------------------------------------------------------------------
    // Menu System
    // -----------------------------------------------------------------------

    #[derive(Clone, Copy, PartialEq)]
    enum Screen {
        MainMenu,
        QuickScan,
        ScanResult,
        Config,
        Info,
        LiveStats,
    }

    struct App {
        screen: Screen,
        menu_index: usize,
        should_quit: bool,
        // Quick scan
        scan_input: String,
        scan_results: Vec<ScanFinding>,
        scan_time_ms: f64,
        // Config
        config: crate::config::Config,
        config_index: usize,
        // Live stats
        stats: LiveStats,
        // Status message
        status: String,
    }

    #[derive(Clone)]
    struct ScanFinding {
        category: String,
        sub_category: String,
        confidence: f64,
        text_redacted: String,
        has_context: bool,
    }

    struct LiveStats {
        total_scans: u64,
        total_findings: u64,
        total_bytes: u64,
        start_time: Instant,
        recent_scans: Vec<(Instant, usize, f64)>, // (time, findings, duration_ms)
        pattern_count: usize,
        category_count: usize,
    }

    const MENU_ITEMS: &[&str] = &[
        "Quick Scan        Scan text for sensitive data",
        "Scan File         Scan a file from disk",
        "Scan Directory    Scan all files in a directory",
        "Configuration     View and modify settings",
        "Pattern Tester    Test regex patterns",
        "Live Dashboard    Real-time scan statistics",
        "System Info       Version, patterns, features",
        "Quit              Exit dlpscan",
    ];

    impl App {
        fn new() -> Self {
            let config_path = super::find_config();
            let config = super::load_config_tui(&config_path);
            Self {
                screen: Screen::MainMenu,
                menu_index: 0,
                should_quit: false,
                scan_input: String::new(),
                scan_results: Vec::new(),
                scan_time_ms: 0.0,
                config,
                config_index: 0,
                stats: LiveStats {
                    total_scans: 0,
                    total_findings: 0,
                    total_bytes: 0,
                    start_time: Instant::now(),
                    recent_scans: Vec::new(),
                    pattern_count: crate::patterns::PATTERNS.len(),
                    category_count: crate::patterns::categories().len(),
                },
                status: String::new(),
            }
        }

        fn do_scan(&mut self) {
            if self.scan_input.trim().is_empty() {
                self.status = "No text to scan".into();
                return;
            }
            let start = Instant::now();
            match crate::scanner::scan_text(&self.scan_input) {
                Ok(matches) => {
                    self.scan_time_ms = start.elapsed().as_secs_f64() * 1000.0;
                    let finding_count = matches.len();
                    self.scan_results = matches
                        .iter()
                        .map(|m| ScanFinding {
                            category: m.category.clone(),
                            sub_category: m.sub_category.clone(),
                            confidence: m.confidence,
                            text_redacted: m.redacted_text(),
                            has_context: m.has_context,
                        })
                        .collect();
                    // Update stats
                    self.stats.total_scans += 1;
                    self.stats.total_findings += finding_count as u64;
                    self.stats.total_bytes += self.scan_input.len() as u64;
                    self.stats.recent_scans.push((
                        Instant::now(),
                        finding_count,
                        self.scan_time_ms,
                    ));
                    // Keep last 100 scans
                    if self.stats.recent_scans.len() > 100 {
                        self.stats.recent_scans.remove(0);
                    }
                    self.status = format!(
                        "{} findings in {:.1}ms",
                        finding_count, self.scan_time_ms
                    );
                    self.screen = Screen::ScanResult;
                }
                Err(e) => {
                    self.status = format!("Scan error: {e}");
                }
            }
        }
    }

    pub fn run_menu() -> Result<(), Box<dyn std::error::Error>> {
        enable_raw_mode()?;
        stdout().execute(EnterAlternateScreen)?;
        let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;

        let mut app = App::new();

        loop {
            terminal.draw(|frame| draw(frame, &app))?;

            if event::poll(Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }
                    handle_input(&mut app, key.code);
                }
            }

            if app.should_quit {
                break;
            }
        }

        disable_raw_mode()?;
        stdout().execute(LeaveAlternateScreen)?;
        Ok(())
    }

    pub fn run_live_stats() -> Result<(), Box<dyn std::error::Error>> {
        enable_raw_mode()?;
        stdout().execute(EnterAlternateScreen)?;
        let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;

        let mut app = App::new();
        app.screen = Screen::LiveStats;

        loop {
            terminal.draw(|frame| draw_live_stats(frame, &app))?;

            if event::poll(Duration::from_millis(500))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        _ => {}
                    }
                }
            }
        }

        disable_raw_mode()?;
        stdout().execute(LeaveAlternateScreen)?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Input handling
    // -----------------------------------------------------------------------

    fn handle_input(app: &mut App, key: KeyCode) {
        match app.screen {
            Screen::MainMenu => match key {
                KeyCode::Up | KeyCode::Char('k') => {
                    if app.menu_index > 0 {
                        app.menu_index -= 1;
                    }
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if app.menu_index < MENU_ITEMS.len() - 1 {
                        app.menu_index += 1;
                    }
                }
                KeyCode::Enter => match app.menu_index {
                    0 => {
                        app.scan_input.clear();
                        app.scan_results.clear();
                        app.screen = Screen::QuickScan;
                    }
                    1 => app.status = "Use: dlpscan scan <file>".into(),
                    2 => app.status = "Use: dlpscan scan-dir <dir>".into(),
                    3 => app.screen = Screen::Config,
                    4 => app.status = "Use: dlpscan test-pattern".into(),
                    5 => app.screen = Screen::LiveStats,
                    6 => app.screen = Screen::Info,
                    7 => app.should_quit = true,
                    _ => {}
                },
                KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
                _ => {}
            },
            Screen::QuickScan => match key {
                KeyCode::Esc => app.screen = Screen::MainMenu,
                KeyCode::Enter => app.do_scan(),
                KeyCode::Backspace => {
                    app.scan_input.pop();
                }
                KeyCode::Char(c) => {
                    app.scan_input.push(c);
                }
                _ => {}
            },
            Screen::ScanResult => match key {
                KeyCode::Esc | KeyCode::Char('q') | KeyCode::Backspace => {
                    app.screen = Screen::QuickScan;
                }
                _ => {}
            },
            Screen::Config => match key {
                KeyCode::Esc | KeyCode::Char('q') => app.screen = Screen::MainMenu,
                KeyCode::Up | KeyCode::Char('k') => {
                    if app.config_index > 0 {
                        app.config_index -= 1;
                    }
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if app.config_index < 7 {
                        app.config_index += 1;
                    }
                }
                _ => {}
            },
            Screen::Info => match key {
                KeyCode::Esc | KeyCode::Char('q') => app.screen = Screen::MainMenu,
                _ => {}
            },
            Screen::LiveStats => match key {
                KeyCode::Esc | KeyCode::Char('q') => app.screen = Screen::MainMenu,
                _ => {}
            },
        }
    }

    // -----------------------------------------------------------------------
    // Drawing
    // -----------------------------------------------------------------------

    fn draw(frame: &mut Frame, app: &App) {
        match app.screen {
            Screen::MainMenu => draw_main_menu(frame, app),
            Screen::QuickScan => draw_quick_scan(frame, app),
            Screen::ScanResult => draw_scan_result(frame, app),
            Screen::Config => draw_config(frame, app),
            Screen::Info => draw_info(frame, app),
            Screen::LiveStats => draw_live_stats(frame, app),
        }
    }

    fn draw_main_menu(frame: &mut Frame, app: &App) {
        let area = frame.area();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(5),  // header
                Constraint::Min(12),   // menu
                Constraint::Length(3), // status bar
            ])
            .split(area);

        // Header
        let header = Paragraph::new(vec![
            Line::from(Span::styled(
                " dlpscan",
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                format!(" v{}  |  {} patterns  |  {} categories",
                    env!("CARGO_PKG_VERSION"),
                    crate::patterns::PATTERNS.len(),
                    crate::patterns::categories().len()
                ),
                Style::default().fg(Color::DarkGray),
            )),
        ])
        .block(Block::default().borders(Borders::ALL).title(" DLP Scanner "));
        frame.render_widget(header, chunks[0]);

        // Menu
        let items: Vec<ListItem> = MENU_ITEMS
            .iter()
            .enumerate()
            .map(|(i, item)| {
                let style = if i == app.menu_index {
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                };
                ListItem::new(format!("  {item}")).style(style)
            })
            .collect();
        let menu = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(" Menu (j/k or arrows, Enter to select) "));
        frame.render_widget(menu, chunks[1]);

        // Status bar
        let status_text = if app.status.is_empty() {
            "Press q to quit".to_string()
        } else {
            app.status.clone()
        };
        let status = Paragraph::new(status_text)
            .style(Style::default().fg(Color::Yellow))
            .block(Block::default().borders(Borders::ALL));
        frame.render_widget(status, chunks[2]);
    }

    fn draw_quick_scan(frame: &mut Frame, app: &App) {
        let area = frame.area();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // title
                Constraint::Min(5),   // input
                Constraint::Length(3), // help
            ])
            .split(area);

        let title = Paragraph::new(" Quick Scan — type text and press Enter to scan")
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .block(Block::default().borders(Borders::ALL));
        frame.render_widget(title, chunks[0]);

        let input_text = if app.scan_input.is_empty() {
            "Type or paste text here...".to_string()
        } else {
            app.scan_input.clone()
        };
        let input_style = if app.scan_input.is_empty() {
            Style::default().fg(Color::DarkGray)
        } else {
            Style::default().fg(Color::White)
        };
        let input = Paragraph::new(input_text)
            .style(input_style)
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL).title(format!(
                " Input ({} chars) ",
                app.scan_input.len()
            )));
        frame.render_widget(input, chunks[1]);

        let help = Paragraph::new(" Enter: scan  |  Esc: back to menu")
            .style(Style::default().fg(Color::DarkGray))
            .block(Block::default().borders(Borders::ALL));
        frame.render_widget(help, chunks[2]);
    }

    fn draw_scan_result(frame: &mut Frame, app: &App) {
        let area = frame.area();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // summary
                Constraint::Min(5),   // findings
                Constraint::Length(3), // help
            ])
            .split(area);

        let is_clean = app.scan_results.is_empty();
        let summary_style = if is_clean {
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
        };
        let summary_text = if is_clean {
            format!(" CLEAN — no sensitive data found ({:.1}ms)", app.scan_time_ms)
        } else {
            format!(
                " {} findings detected ({:.1}ms)",
                app.scan_results.len(),
                app.scan_time_ms
            )
        };
        let summary = Paragraph::new(summary_text)
            .style(summary_style)
            .block(Block::default().borders(Borders::ALL).title(" Scan Results "));
        frame.render_widget(summary, chunks[0]);

        // Findings table
        let header = Row::new(vec!["Conf", "Category", "Pattern", "Match", "Ctx"])
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .bottom_margin(1);

        let rows: Vec<Row> = app
            .scan_results
            .iter()
            .map(|f| {
                let conf_color = if f.confidence >= 0.8 {
                    Color::Red
                } else if f.confidence >= 0.5 {
                    Color::Yellow
                } else {
                    Color::DarkGray
                };
                Row::new(vec![
                    Cell::from(format!("{:.0}%", f.confidence * 100.0))
                        .style(Style::default().fg(conf_color)),
                    Cell::from(f.category.clone()),
                    Cell::from(f.sub_category.clone()),
                    Cell::from(f.text_redacted.clone()),
                    Cell::from(if f.has_context { "yes" } else { "" }),
                ])
            })
            .collect();

        let table = Table::new(
            rows,
            [
                Constraint::Length(6),
                Constraint::Percentage(25),
                Constraint::Percentage(20),
                Constraint::Percentage(35),
                Constraint::Length(5),
            ],
        )
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(" Findings "));
        frame.render_widget(table, chunks[1]);

        let help = Paragraph::new(" Esc/q: back to scan  |  Enter new text to scan again")
            .style(Style::default().fg(Color::DarkGray))
            .block(Block::default().borders(Borders::ALL));
        frame.render_widget(help, chunks[2]);
    }

    fn draw_config(frame: &mut Frame, app: &App) {
        let area = frame.area();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(12),
                Constraint::Length(3),
            ])
            .split(area);

        let title = Paragraph::new(" Configuration")
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .block(Block::default().borders(Borders::ALL));
        frame.render_widget(title, chunks[0]);

        let config_items = vec![
            format!("min_confidence:     {:.2}", app.config.min_confidence),
            format!("require_context:    {}", app.config.require_context),
            format!("deduplicate:        {}", app.config.deduplicate),
            format!("max_matches:        {}", app.config.max_matches),
            format!("format:             {}", app.config.format),
            format!("block_unreadable:   {}", app.config.block_unreadable),
            format!("blocked_extensions: {} types", app.config.blocked_extensions.len()),
            format!("context_backend:    {}", app.config.context_backend),
        ];

        let items: Vec<ListItem> = config_items
            .iter()
            .enumerate()
            .map(|(i, item)| {
                let style = if i == app.config_index {
                    Style::default().fg(Color::Black).bg(Color::Cyan)
                } else {
                    Style::default().fg(Color::White)
                };
                ListItem::new(format!("  {item}")).style(style)
            })
            .collect();

        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(" Settings (use `dlpscan config set` to modify) "));
        frame.render_widget(list, chunks[1]);

        let help = Paragraph::new(" Esc/q: back to menu  |  j/k: navigate")
            .style(Style::default().fg(Color::DarkGray))
            .block(Block::default().borders(Borders::ALL));
        frame.render_widget(help, chunks[2]);
    }

    fn draw_info(frame: &mut Frame, _app: &App) {
        let area = frame.area();

        let exts = crate::extractors::supported_extensions();
        let mut features = vec!["core"];
        #[cfg(feature = "metrics")] features.push("metrics");
        #[cfg(feature = "pdf")] features.push("pdf");
        #[cfg(feature = "office")] features.push("office");
        #[cfg(feature = "archives")] features.push("archives");
        #[cfg(feature = "data-formats")] features.push("data-formats");
        #[cfg(feature = "msg")] features.push("msg");
        #[cfg(feature = "barcode")] features.push("barcode");
        #[cfg(feature = "async-support")] features.push("async-support");
        #[cfg(feature = "tui")] features.push("tui");

        let info_text = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("  Version:     ", Style::default().fg(Color::Cyan)),
                Span::raw(env!("CARGO_PKG_VERSION")),
            ]),
            Line::from(vec![
                Span::styled("  Patterns:    ", Style::default().fg(Color::Cyan)),
                Span::raw(format!("{} across {} categories",
                    crate::patterns::PATTERNS.len(),
                    crate::patterns::categories().len()
                )),
            ]),
            Line::from(vec![
                Span::styled("  Features:    ", Style::default().fg(Color::Cyan)),
                Span::raw(features.join(", ")),
            ]),
            Line::from(vec![
                Span::styled("  Formats:     ", Style::default().fg(Color::Cyan)),
                Span::raw(format!("{} file types supported", exts.len())),
            ]),
            Line::from(vec![
                Span::styled("  Blocked:     ", Style::default().fg(Color::Cyan)),
                Span::raw(format!("{} extensions blocked by default",
                    crate::extractors::DEFAULT_BLOCKED_EXTENSIONS.len()
                )),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "  Validators: Luhn, SWIFT/BIC, CUSIP, SEDOL, TFN, SSN",
                Style::default().fg(Color::DarkGray),
            )),
        ];

        let info = Paragraph::new(info_text)
            .block(Block::default().borders(Borders::ALL).title(" System Info (Esc to go back) "));
        frame.render_widget(info, area);
    }

    fn draw_live_stats(frame: &mut Frame, app: &App) {
        let area = frame.area();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),  // title
                Constraint::Length(9),  // stats panel
                Constraint::Min(6),    // recent scans
                Constraint::Length(3), // throughput gauge
                Constraint::Length(3), // help
            ])
            .split(area);

        let elapsed = app.stats.start_time.elapsed();
        let uptime = format!(
            "{}h {:02}m {:02}s",
            elapsed.as_secs() / 3600,
            (elapsed.as_secs() % 3600) / 60,
            elapsed.as_secs() % 60
        );

        let title = Paragraph::new(format!(" dlpscan Live Dashboard  |  Uptime: {uptime}"))
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .block(Block::default().borders(Borders::ALL));
        frame.render_widget(title, chunks[0]);

        // Stats panel
        let scans_per_sec = if elapsed.as_secs() > 0 {
            app.stats.total_scans as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };
        let avg_latency = if !app.stats.recent_scans.is_empty() {
            app.stats.recent_scans.iter().map(|s| s.2).sum::<f64>()
                / app.stats.recent_scans.len() as f64
        } else {
            0.0
        };

        let stats_text = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("  Total Scans:      ", Style::default().fg(Color::Cyan)),
                Span::styled(
                    format!("{}", app.stats.total_scans),
                    Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!("  ({scans_per_sec:.1}/s)")),
            ]),
            Line::from(vec![
                Span::styled("  Total Findings:   ", Style::default().fg(Color::Cyan)),
                Span::styled(
                    format!("{}", app.stats.total_findings),
                    Style::default().fg(if app.stats.total_findings > 0 {
                        Color::Red
                    } else {
                        Color::Green
                    }).add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled("  Bytes Scanned:    ", Style::default().fg(Color::Cyan)),
                Span::raw(format_bytes(app.stats.total_bytes)),
            ]),
            Line::from(vec![
                Span::styled("  Avg Latency:      ", Style::default().fg(Color::Cyan)),
                Span::raw(format!("{avg_latency:.1}ms")),
            ]),
            Line::from(vec![
                Span::styled("  Patterns:         ", Style::default().fg(Color::Cyan)),
                Span::raw(format!(
                    "{} ({} categories)",
                    app.stats.pattern_count, app.stats.category_count
                )),
            ]),
        ];

        let stats = Paragraph::new(stats_text)
            .block(Block::default().borders(Borders::ALL).title(" Statistics "));
        frame.render_widget(stats, chunks[1]);

        // Recent scans
        let header = Row::new(vec!["Time", "Findings", "Latency"])
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .bottom_margin(1);

        let rows: Vec<Row> = app
            .stats
            .recent_scans
            .iter()
            .rev()
            .take(20)
            .map(|(time, findings, ms)| {
                let ago = time.elapsed().as_secs();
                let time_str = if ago < 60 {
                    format!("{ago}s ago")
                } else {
                    format!("{}m ago", ago / 60)
                };
                let color = if *findings > 0 { Color::Red } else { Color::Green };
                Row::new(vec![
                    Cell::from(time_str),
                    Cell::from(format!("{findings}")).style(Style::default().fg(color)),
                    Cell::from(format!("{ms:.1}ms")),
                ])
            })
            .collect();

        let table = Table::new(
            rows,
            [
                Constraint::Length(12),
                Constraint::Length(10),
                Constraint::Length(12),
            ],
        )
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(" Recent Scans "));
        frame.render_widget(table, chunks[2]);

        // Throughput gauge
        let throughput = if elapsed.as_secs_f64() > 0.0 {
            app.stats.total_bytes as f64 / elapsed.as_secs_f64() / 1024.0 / 1024.0
        } else {
            0.0
        };
        let gauge_ratio = (throughput / 100.0).min(1.0); // Scale to 100 MB/s max
        let gauge = Gauge::default()
            .block(Block::default().borders(Borders::ALL).title(" Throughput "))
            .gauge_style(Style::default().fg(Color::Cyan).bg(Color::DarkGray))
            .ratio(gauge_ratio)
            .label(format!("{throughput:.1} MB/s"));
        frame.render_widget(gauge, chunks[3]);

        let help = Paragraph::new(" q/Esc: exit dashboard")
            .style(Style::default().fg(Color::DarkGray))
            .block(Block::default().borders(Borders::ALL));
        frame.render_widget(help, chunks[4]);
    }

    fn format_bytes(bytes: u64) -> String {
        if bytes < 1024 {
            format!("{bytes} B")
        } else if bytes < 1024 * 1024 {
            format!("{:.1} KB", bytes as f64 / 1024.0)
        } else if bytes < 1024 * 1024 * 1024 {
            format!("{:.1} MB", bytes as f64 / 1024.0 / 1024.0)
        } else {
            format!("{:.2} GB", bytes as f64 / 1024.0 / 1024.0 / 1024.0)
        }
    }
}

// Re-export shared config helpers
pub fn find_config() -> String {
    crate::config::find_config_path()
}

pub fn load_config_tui(path: &str) -> crate::config::Config {
    crate::config::load_config_json(path)
}
