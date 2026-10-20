//! Rendering only: no database or network calls occur here.
use super::*;

/// Render a titled selectable list.
fn draw_list(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    items: Vec<String>,
    selected: usize,
    help: &str,
) {
    let sections = Layout::vertical([Constraint::Min(0), Constraint::Length(2)]).split(area);

    let mut state = ListState::default();
    if !items.is_empty() {
        state.select(Some(selected.min(items.len() - 1)));
    }

    // Draw the outer frame independently of the list.
    let block = Block::bordered().title(title);
    let inner = block.inner(sections[0]);
    frame.render_widget(block, sections[0]);

    // Size the list to the longest choice, plus the selection marker.
    let list_width = items
        .iter()
        .map(|item| item.chars().count())
        .max()
        .unwrap_or(0)
        .saturating_add(2)
        .min(inner.width as usize) as u16;

    // Limit the height so long lists can still scroll.
    let list_height = items.len().min(inner.height as usize) as u16;

    // Center the list horizontally and vertically.
    let list_area = Rect {
        x: inner.x + (inner.width - list_width) / 2,
        y: inner.y + (inner.height - list_height) / 2,
        width: list_width,
        height: list_height,
    };

    frame.render_stateful_widget(
        List::new(items)
            .highlight_style(HIGHLIGHT)
            .highlight_symbol(" "),
        list_area,
        &mut state,
    );

    frame.render_widget(Paragraph::new(help).wrap(Wrap { trim: true }), sections[1]);
}

/// Render the current screen, notices, forms and confirmations.
pub(super) fn draw(frame: &mut Frame, app: &mut App) {
    let area = frame.area();
    if area.width < 60 || area.height < 20 {
        frame.render_widget(
            Paragraph::new("Please resize to at least 60 columns by 20 rows. Ctrl+C exits."),
            area,
        );
        return;
    }
    let page = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(0),
        Constraint::Length(3),
    ])
    .split(area);
    let title = match app.screen {
        Screen::Main => "SECURE VOTING MACHINE",
        Screen::AdminHome => "Election Administrator",
        Screen::Editor => "Election Editor",
        Screen::Voters => "Voter Registration",
        Screen::Audit => "Election Audit Log",
        Screen::District => "District Official",
        Screen::Vote => "Vote!",
        Screen::Results => "Election Results",
        Screen::Elections => "Choose Election",
        Screen::Setup => "Staff Sign Up",
        _ => "Authentication",
    };
    frame.render_widget(
        Paragraph::new(app.session.as_ref().map_or_else(
            || title.to_owned(),
            |session| format!("{title} | User {}", session.user_id()),
        ))
        .alignment(Alignment::Center)
        .style(Style::new().add_modifier(Modifier::BOLD)),
        page[0],
    );
    match app.screen {
        Screen::Main => {
            let mut items = vec![
                "Election Administrator".into(),
                "District Official".into(),
                "Voter".into(),
            ];
            if app.setup_mode {
                items.push("Sign up admin / district official".into());
            }
            draw_list(
                frame,
                page[1],
                "who dis? (choose a role)",
                items,
                app.selected,
                "Up/Down: navigate | Enter: select | Q: quit",
            );
        }
        Screen::AdminHome => {
            let items = vec![
                "Create new election".into(),
                "Edit existing election".into(),
                "Register a voter".into(),
                "View audit log".into(),
            ];
            draw_list(
                frame,
                page[1],
                "wat do? (what to do)",
                items,
                app.selected,
                "Up/Down: navigate | Enter: select | R: register voters | Esc: sign out",
            );
        }
        Screen::Elections => {
            let items = app
                .elections
                .iter()
                .map(|e| format!("#{} {} [{}]", e.id, e.name, e.status))
                .collect();
            draw_list(
                frame,
                page[1],
                "Your available elections",
                items,
                app.selected,
                "Enter: select | R: refresh | Esc: back / sign out",
            );
        }
        Screen::Editor | Screen::Vote => draw_ballot_editor(frame, page[1], app),
        Screen::Voters => {
            let items = app
                .voters
                .iter()
                .map(|v| {
                    let participation = if v.has_voted { "Voted" } else { "Not voted" };
                    format!("#{} {} | {}", v.id, v.full_name, participation)
                })
                .collect();
            draw_list(frame, page[1], "Enrolled voters", items, app.selected,
                "R: Register a new voter | I: enroll by NID | E: edit | D: remove enrollment | Esc: back");
        }
        Screen::District => draw_district(frame, page[1], app),
        Screen::Audit | Screen::Results => {
            let sections =
                Layout::vertical([Constraint::Min(0), Constraint::Length(2)]).split(page[1]);
            let lines = app
                .lines
                .iter()
                .skip(app.scroll)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n");
            frame.render_widget(
                Paragraph::new(lines)
                    .block(Block::bordered())
                    .wrap(Wrap { trim: false }),
                sections[0],
            );
            frame.render_widget(
                Paragraph::new("Up/Down: scroll | Audit: R refresh, F flag concern | Esc: back"),
                sections[1],
            );
        }
        _ => {}
    }
    frame.render_widget(
        Paragraph::new(app.notice.as_str())
            .style(Style::new().fg(Color::Yellow))
            .wrap(Wrap { trim: true }),
        page[2],
    );
    if let Some(form) = &app.form {
        draw_form(frame, page[1], form);
    }
    if let Some(confirm) = &app.confirmation {
        let rect = Rect {
            x: area.x + 3,
            y: area.y + area.height / 3,
            width: area.width - 6,
            height: 7,
        };
        frame.render_widget(Clear, rect);
        frame.render_widget(
            Paragraph::new(format!(
                "{}\n\nEnter/Y: confirm | Esc/N: cancel",
                confirm.message
            ))
            .block(
                Block::bordered()
                    .title("Confirm")
                    .border_style(Style::new().fg(ACTIVE)),
            )
            .wrap(Wrap { trim: true }),
            rect,
        );
    }
}
/// Render positions and candidates with the current editor selection.
fn draw_ballot_editor(frame: &mut Frame, area: Rect, app: &mut App) {
    let voting = app.screen == Screen::Vote;
    let help = if voting {
        "Up/Down: navigate | Space: choose | S: submit whole ballot | Esc: back"
    } else {
        "Arrows: select | P: position | C: candidate | E: edit | D: delete | L: link candidate | F2: rename election | X: cancel election | R: voters | Esc: back"
    };
    let parts = Layout::vertical([Constraint::Min(0), Constraint::Length(3)]).split(area);
    frame.render_widget(Paragraph::new(help).wrap(Wrap { trim: true }), parts[1]);
    let title = app
        .election
        .as_ref()
        .map(|e| format!("{} [{}]", e.name, e.status))
        .unwrap_or_default();
    let block = Block::bordered().title(title);
    let inner = block.inner(parts[0]);
    frame.render_widget(block, parts[0]);
    let rows = app.rows();
    let height = inner.height.saturating_sub(1) as usize;
    if height == 0 {
        return;
    }
    app.ballot_cursor.row = app.ballot_cursor.row.min(rows.len().saturating_sub(1));
    if app.ballot_cursor.row < app.ballot_scroll {
        app.ballot_scroll = app.ballot_cursor.row;
    }
    if app.ballot_cursor.row >= app.ballot_scroll + height {
        app.ballot_scroll = app.ballot_cursor.row + 1 - height;
    }
    let header = Layout::horizontal([
        Constraint::Percentage(30),
        Constraint::Percentage(42),
        Constraint::Percentage(28),
    ])
    .split(Rect { height: 1, ..inner });
    for (i, s) in ["Position", "Candidate", "Party"].iter().enumerate() {
        frame.render_widget(Paragraph::new(*s).style(Style::new().fg(MUTED)), header[i]);
    }
    for (index, (pi, ci)) in rows.iter().enumerate().skip(app.ballot_scroll).take(height) {
        let p = &app.positions[*pi];
        let mut values = [p.name.clone(), String::new(), String::new()];
        if let Some(ci) = ci {
            let c = &p.candidates[*ci];
            values[1] = if voting {
                format!(
                    "{} {}",
                    if app.voting_choices.get(*pi) == Some(&Some(c.id)) {
                        "[x]"
                    } else {
                        "[ ]"
                    },
                    c.name
                )
            } else {
                format!("#{} {}", c.id, c.name)
            };
            values[2] = c.party.clone();
        }
        let cols = Layout::horizontal([
            Constraint::Percentage(30),
            Constraint::Percentage(42),
            Constraint::Percentage(28),
        ])
        .split(Rect {
            x: inner.x,
            y: inner.y + 1 + (index - app.ballot_scroll) as u16,
            width: inner.width,
            height: 1,
        });
        for (col, value) in values.iter().enumerate() {
            let selected = index == app.ballot_cursor.row
                && (voting
                    || col
                        == match app.ballot_cursor.column {
                            BallotColumn::Position => 0,
                            BallotColumn::Candidate => 1,
                            BallotColumn::Party => 2,
                        });
            frame.render_widget(
                Paragraph::new(value.as_str()).style(if selected {
                    HIGHLIGHT
                } else {
                    Style::default()
                }),
                cols[col],
            );
        }
    }
}
/// Render fields with secret values masked.
fn draw_form(frame: &mut Frame, area: Rect, form: &Form) {
    frame.render_widget(Clear, area);
    let block = Block::bordered()
        .title(form.title.as_str())
        .border_style(Style::new().fg(ACTIVE));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let sections = Layout::vertical([Constraint::Min(0), Constraint::Length(2)]).split(inner);
    let rows = form.fields.len().div_ceil(2);
    let slots = Layout::vertical((0..rows).map(|_| Constraint::Length(3)).collect::<Vec<_>>())
        .split(sections[0]);
    for (i, f) in form.fields.iter().enumerate() {
        let cols = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(slots[i / 2]);
        let content = if f.secret {
            "*".repeat(f.value.chars().count())
        } else if matches!(form.purpose, FormPurpose::Setup) && i == 4 {
            if f.value == "admin" {
                "< Administrator >".into()
            } else {
                "< District Official >".into()
            }
        } else {
            f.value.clone()
        };
        let width = cols[i % 2].width.saturating_sub(2) as usize;
        let chars: Vec<char> = content.chars().collect();
        let tail: String = chars[chars.len().saturating_sub(width)..].iter().collect();
        frame.render_widget(
            Paragraph::new(tail).block(
                Block::bordered()
                    .title(f.label)
                    .border_style(Style::new().fg(if i == form.focus { ACTIVE } else { MUTED })),
            ),
            cols[i % 2],
        );
    }
    let help = concat!(
        "Tab/Shift+Tab: change field | Enter: submit | Esc: cancel\n",
        "OTP/PIN delivery uses the separate local virtual SMS inbox."
    );
    frame.render_widget(Paragraph::new(help).wrap(Wrap { trim: true }), sections[1]);
}

/// Render election state and district-official action hints.
fn draw_district(frame: &mut Frame, area: Rect, app: &App) {
    let Some(election) = &app.election else {
        return;
    };
    let announced = if election.announced { "Yes" } else { "No" };
    let content = format!(
        concat!(
            "#{} {}\nStatus: {}\nResults announced: {}\n\n",
            "S: Start election\nF: Finish / close election\n",
            "T: Tally candidate and party votes\nA: Announce winners\n",
            "R: Show tallies and winners\nEsc: choose another election"
        ),
        election.id, election.name, election.status, announced,
    );
    frame.render_widget(
        Paragraph::new(content)
            .block(Block::bordered().title("Election lifecycle"))
            .wrap(Wrap { trim: true }),
        area,
    );
}
