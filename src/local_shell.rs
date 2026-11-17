//! A shell on this computer in a pseudo-terminal, behind the same
//! [`ShellHandle`] as a shell on a server, so the terminal view cannot tell
//! them apart. The pty comes from alacritty_terminal, the emulator's crate.

use std::path::PathBuf;

use crate::shell::ShellHandle;

/// Start the user's login shell in `working_dir` (home when `None`).
#[cfg(unix)]
pub fn open_local_shell(
    rows: u16,
    cols: u16,
    working_dir: Option<PathBuf>,
) -> std::io::Result<ShellHandle> {
    open_with_shell(rows, cols, working_dir, None)
}

/// `shell` is `None` for the user's login shell.
#[cfg(unix)]
fn open_with_shell(
    rows: u16,
    cols: u16,
    working_dir: Option<PathBuf>,
    shell: Option<alacritty_terminal::tty::Shell>,
) -> std::io::Result<ShellHandle> {
    // Without a folder the shell would start in the app's own, "/" from the Dock.
    let working_dir = working_dir.or_else(dirs::home_dir);
    let pty = unix::spawn_pty(rows, cols, working_dir, shell)?;
    let (cmd_tx, cmd_rx) = async_channel::bounded(64);
    let (event_tx, event_rx) = async_channel::bounded(64);
    let (visible_tx, visible_rx) = tokio::sync::watch::channel(true);
    std::thread::Builder::new()
        .name("local-shell".into())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(e) => {
                    tracing::error!(%e, "no runtime for the local shell");
                    return;
                }
            };
            let local = tokio::task::LocalSet::new();
            local.block_on(&runtime, async move {
                let link = match unix::LocalPty::new(pty) {
                    Ok(link) => link,
                    Err(e) => {
                        let message = format!("could not watch the terminal: {e}");
                        let _ = event_tx
                            .send(crate::shell::ShellEvent::Error(message))
                            .await;
                        return;
                    }
                };
                crate::shell::handle_shell_commands(
                    crate::shell::ShellLink::Local(link),
                    rows,
                    cols,
                    cmd_rx,
                    event_tx,
                    visible_rx,
                )
                .await;
            });
        })?;
    tracing::info!(rows, cols, "local shell opened");
    Ok(ShellHandle::new(cmd_tx, event_rx, visible_tx))
}

// shortcut: ConPTY is not wired up yet; alacritty_terminal::tty has it for Windows.
#[cfg(not(unix))]
pub fn open_local_shell(
    _rows: u16,
    _cols: u16,
    _working_dir: Option<PathBuf>,
) -> std::io::Result<ShellHandle> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "a local terminal is not available on Windows yet",
    ))
}

#[cfg(unix)]
pub(crate) mod unix {
    use std::collections::HashMap;
    use std::fs::File;
    use std::io::{Read as _, Write as _};
    use std::path::PathBuf;
    use std::time::Duration;

    use alacritty_terminal::event::{OnResize as _, WindowSize};
    use alacritty_terminal::tty::{self, ChildEvent, EventedPty as _, Options, Pty};
    use tokio::io::unix::AsyncFd;

    /// How often a shell that left its terminal to a background job is looked for.
    const EXIT_CHECK: Duration = Duration::from_millis(500);

    pub(crate) fn spawn_pty(
        rows: u16,
        cols: u16,
        working_dir: Option<PathBuf>,
        shell: Option<tty::Shell>,
    ) -> std::io::Result<Pty> {
        // An app started from the Dock has no TERM and often no LANG. The emulator
        // speaks xterm, as the SSH side tells servers.
        let mut env = HashMap::from([
            ("TERM".to_string(), "xterm-256color".to_string()),
            ("COLORTERM".to_string(), "truecolor".to_string()),
        ]);
        if std::env::var_os("LANG").is_none() {
            env.insert("LANG".to_string(), "en_US.UTF-8".to_string());
        }
        let options = Options {
            shell,
            working_directory: working_dir,
            drain_on_exit: false,
            env,
        };
        tty::new(&options, window_size(rows, cols), 0)
    }

    fn window_size(rows: u16, cols: u16) -> WindowSize {
        WindowSize {
            num_lines: rows.max(1),
            num_cols: cols.max(1),
            cell_width: 8,
            cell_height: 16,
        }
    }

    pub(crate) enum PtyEvent {
        Output(Vec<u8>),
        Exited,
    }

    pub struct LocalPty {
        /// A copy of the pty's descriptor that the reactor watches and owns.
        fd: AsyncFd<File>,
        /// Hangs up the shell when dropped.
        pty: Pty,
        buffer: Vec<u8>,
    }

    impl LocalPty {
        /// Inside the runtime that will drive it.
        pub(crate) fn new(pty: Pty) -> std::io::Result<Self> {
            let file = pty.file().try_clone()?;
            // `new` is deprecated in tokio 1.54 for fds the AsyncFd does not own, but
            // the apps still build with older tokio, which has no `register`. This one
            // owns its File, so its descriptor stays open as long as the AsyncFd.
            #[allow(deprecated)]
            let fd = AsyncFd::new(file)?;
            Ok(Self {
                fd,
                pty,
                buffer: vec![0; 64 * 1024],
            })
        }

        pub(crate) async fn recv(&mut self) -> PtyEvent {
            loop {
                tokio::select! {
                    ready = self.fd.readable() => {
                        let Ok(mut guard) = ready else {
                            return PtyEvent::Exited;
                        };
                        let buffer = &mut self.buffer;
                        match guard.try_io(|fd| fd.get_ref().read(buffer)) {
                            // EOF, or EIO once the shell is gone (Linux).
                            Ok(Ok(0)) | Ok(Err(_)) => return PtyEvent::Exited,
                            Ok(Ok(count)) => return PtyEvent::Output(self.buffer[..count].to_vec()),
                            Err(_would_block) => continue,
                        }
                    }
                    () = tokio::time::sleep(EXIT_CHECK) => {
                        if let Some(ChildEvent::Exited(_)) = self.pty.next_child_event() {
                            return PtyEvent::Exited;
                        }
                    }
                }
            }
        }

        pub(crate) async fn send(&mut self, data: &[u8]) -> std::io::Result<()> {
            let mut written = 0;
            while written < data.len() {
                let mut guard = self.fd.writable().await?;
                match guard.try_io(|fd| fd.get_ref().write(&data[written..])) {
                    Ok(Ok(count)) => written += count,
                    Ok(Err(e)) => return Err(e),
                    Err(_would_block) => continue,
                }
            }
            Ok(())
        }

        pub(crate) fn resize(&mut self, rows: u16, cols: u16) {
            self.pty.on_resize(window_size(rows, cols));
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::shell::ShellEvent;

    /// The text on screen once `marker` shows up, or what is there after `wait`.
    fn screen_with(shell: &ShellHandle, marker: &str, wait: std::time::Duration) -> String {
        let events = shell.subscribe();
        let started = std::time::Instant::now();
        let mut last = String::new();
        while started.elapsed() < wait {
            // Polled, so a shell that goes quiet cannot block the test past `wait`.
            let event = match events.try_recv() {
                Ok(event) => event,
                Err(async_channel::TryRecvError::Empty) => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    continue;
                }
                Err(async_channel::TryRecvError::Closed) => break,
            };
            match event {
                ShellEvent::Snapshot(snapshot) => {
                    last = snapshot
                        .cells
                        .iter()
                        .map(|row| row.iter().map(|cell| cell.c).collect::<String>())
                        .collect::<Vec<_>>()
                        .join("\n");
                    if last.contains(marker) {
                        return last;
                    }
                }
                ShellEvent::Exited => return format!("{last}\n<exited>"),
                _ => {}
            }
        }
        last
    }

    fn send(shell: &ShellHandle, text: &str) {
        let shell = shell.clone();
        let text = text.as_bytes().to_vec();
        futures::executor::block_on(shell.send_input(text));
    }

    #[test]
    fn without_a_folder_the_shell_starts_at_home() {
        let sh = alacritty_terminal::tty::Shell::new("/bin/sh".into(), Vec::new());
        let shell = open_with_shell(24, 200, None, Some(sh)).unwrap();
        send(&shell, "echo \"at $(pwd -P) end\"\n");
        let home = dirs::home_dir().unwrap().canonicalize().unwrap();
        let expected = format!("at {} end", home.display());
        let screen = screen_with(&shell, &expected, std::time::Duration::from_secs(10));
        assert!(screen.contains(&expected), "{screen}");
    }

    #[test]
    fn a_resize_reaches_the_programs_in_the_terminal() {
        let sh = alacritty_terminal::tty::Shell::new("/bin/sh".into(), Vec::new());
        let shell = open_with_shell(24, 80, None, Some(sh)).unwrap();
        futures::executor::block_on(shell.resize(40, 120));
        send(&shell, "echo \"size $(stty size)\"\n");
        let screen = screen_with(&shell, "size 40 120", std::time::Duration::from_secs(10));
        assert!(screen.contains("size 40 120"), "{screen}");
    }

    #[test]
    fn a_local_shell_runs_commands_and_ends_on_exit() {
        let dir = tempfile::tempdir().unwrap();
        // Plain sh: the user's own shell may take long to start, or print anything.
        let sh = alacritty_terminal::tty::Shell::new("/bin/sh".into(), Vec::new());
        let shell = open_with_shell(24, 80, Some(dir.path().to_path_buf()), Some(sh)).unwrap();
        // $((...)) so the marker only appears once the shell has run the line.
        send(&shell, "echo \"$TERM in $(basename \"$PWD\") $((6*7))\"\n");
        let expected = format!(
            "xterm-256color in {} 42",
            dir.path().file_name().unwrap().to_string_lossy()
        );
        let screen = screen_with(&shell, &expected, std::time::Duration::from_secs(15));
        assert!(screen.contains(&expected), "{screen}");

        send(&shell, "exit\n");
        let screen = screen_with(&shell, "<exited>", std::time::Duration::from_secs(10));
        assert!(screen.ends_with("<exited>"), "{screen}");
    }
}
