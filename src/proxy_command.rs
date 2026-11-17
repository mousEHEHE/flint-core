//! `ProxyCommand`, as in OpenSSH: a local command whose stdin and stdout are
//! the link to the first host, e.g. `cloudflared access ssh --hostname %h`.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::io::{AsyncBufReadExt as _, AsyncRead, AsyncWrite, ReadBuf};
use tokio::process::{Child, ChildStdin, ChildStdout};

/// `command` with `%h`, `%p`, `%r` and `%%` filled in. `None` when the host or
/// user has characters a shell could read as code (as OpenSSH 9.6 refuses).
pub fn expand(command: &str, host: &str, port: u16, user: &str) -> Option<String> {
    let is_safe = |value: &str| {
        !value.is_empty()
            && value.chars().all(|c| {
                c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '@' | '[' | ']')
            })
    };
    if !is_safe(host) || !is_safe(user) {
        return None;
    }
    let mut out = String::with_capacity(command.len());
    let mut chars = command.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('h') | Some('n') => out.push_str(host),
            Some('p') => out.push_str(&port.to_string()),
            Some('r') => out.push_str(user),
            Some('%') => out.push('%'),
            // Tokens flint does not know stay as they are.
            Some(other) => {
                out.push('%');
                out.push(other);
            }
            None => out.push('%'),
        }
    }
    Some(out)
}

/// The command's stdin and stdout as one stream. The process lives as long as
/// the stream and is killed with it.
pub(crate) struct ProxyCommandStream {
    stdout: ChildStdout,
    stdin: ChildStdin,
    // Read only by the unix Drop; elsewhere it is held for kill_on_drop.
    #[cfg_attr(not(unix), allow(dead_code))]
    child: Child,
}

#[cfg(unix)]
impl Drop for ProxyCommandStream {
    fn drop(&mut self) {
        // The command leads a group of its own; this also ends the rest of a pipeline.
        if let Some(pid) = self.child.id() {
            unsafe { libc::killpg(pid as libc::pid_t, libc::SIGKILL) };
        }
    }
}

/// The last line the command wrote to stderr, for the error when it fails.
#[derive(Clone, Default)]
pub(crate) struct LastError(Arc<Mutex<String>>);

impl LastError {
    pub(crate) fn get(&self) -> String {
        self.0.lock().map(|line| line.clone()).unwrap_or_default()
    }
}

pub(crate) fn spawn(command: &str) -> std::io::Result<(ProxyCommandStream, LastError)> {
    let mut child = shell(command)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let missing = || std::io::Error::other("the command has no pipes");
    let stdin = child.stdin.take().ok_or_else(missing)?;
    let stdout = child.stdout.take().ok_or_else(missing)?;
    let stderr = child.stderr.take().ok_or_else(missing)?;
    let last_error = LastError::default();
    let sink = last_error.clone();
    tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(stderr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            tracing::warn!(%line, "ProxyCommand stderr");
            if let Ok(mut last) = sink.0.lock() {
                *last = line;
            }
        }
    });
    // Only the program: the rest may hold a token or a password.
    let program = command.split_whitespace().next().unwrap_or_default();
    tracing::info!(program, "ProxyCommand started");
    let stream = ProxyCommandStream {
        stdout,
        stdin,
        child,
    };
    Ok((stream, last_error))
}

#[cfg(unix)]
fn shell(command: &str) -> tokio::process::Command {
    let mut shell = tokio::process::Command::new("/bin/sh");
    shell
        .arg("-c")
        .arg(format!("exec {command}"))
        .process_group(0);
    // shortcut: an app started from Finder has a short PATH without Homebrew;
    // reading the login shell's PATH would find the rest.
    if cfg!(target_os = "macos") {
        let path = std::env::var("PATH").unwrap_or_default();
        shell.env("PATH", format!("{path}:/opt/homebrew/bin:/usr/local/bin"));
    }
    shell
}

#[cfg(windows)]
fn shell(command: &str) -> tokio::process::Command {
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let mut shell = tokio::process::Command::new("cmd");
    shell
        .arg("/C")
        .arg(command)
        .creation_flags(CREATE_NO_WINDOW);
    shell
}

impl AsyncRead for ProxyCommandStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stdout).poll_read(cx, buf)
    }
}

impl AsyncWrite for ProxyCommandStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stdin).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stdin).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stdin).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_filled_in_and_unknown_ones_kept() {
        assert_eq!(
            expand(
                "ssh -W %h:%p -l %r gate %% %x %",
                "web.example.com",
                2222,
                "deploy"
            )
            .unwrap(),
            "ssh -W web.example.com:2222 -l deploy gate % %x %"
        );
        assert_eq!(
            expand("nc %h %p", "[2001:db8::1]", 22, "root").unwrap(),
            "nc [2001:db8::1] 22"
        );
    }

    #[test]
    fn a_host_or_user_that_a_shell_would_run_is_refused() {
        for bad in ["web;id", "$(id)", "`id`", "a b", "a|b", "a'b", "a\nb", ""] {
            assert_eq!(expand("nc %h %p", bad, 22, "root"), None, "{bad:?}");
            assert_eq!(expand("nc %h %p", "web", 22, bad), None, "{bad:?}");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_command_is_the_stream() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let (mut stream, _) = spawn("cat").unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut answer = [0u8; 4];
        stream.read_exact(&mut answer).await.unwrap();
        assert_eq!(&answer, b"ping");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_pipeline_ends_with_the_stream() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("still-running");
        let command = format!("sh -c 'sleep 1; touch {}' | cat", marker.display());
        let (stream, _) = spawn(&command).unwrap();
        // Long enough for sh to start the pipeline.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        drop(stream);
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        assert!(!marker.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn what_a_failing_command_says_is_kept() {
        use tokio::io::AsyncReadExt as _;
        let (mut stream, last_error) = spawn("echo 'no route to gate' >&2; exit 1").unwrap();
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).await.unwrap();
        for _ in 0..50 {
            if !last_error.get().is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(last_error.get(), "no route to gate");
    }
}
