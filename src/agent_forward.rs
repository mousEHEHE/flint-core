//! Agent forwarding (`ssh -A`): the server opens an `auth-agent@openssh.com`
//! channel for every request a program on it makes to `$SSH_AUTH_SOCK`, and
//! each one is joined to a new connection to the local agent. Keys never
//! leave the agent; it only signs.
//!
//! russh 0.45 gives the client no stream for these channels, only an id and
//! callbacks, so the handler sends [`AgentEvent`]s to `run_connection`,
//! which answers through the session handle.

use std::collections::HashMap;
use std::rc::Rc;

use russh::client::Handle;
use russh::{ChannelId, CryptoVec};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::{mpsc, RwLock};

pub(crate) enum AgentEvent {
    Opened(ChannelId),
    Data(ChannelId, Vec<u8>),
    Closed(ChannelId),
}

/// The open agent channels, and where the bytes the server sends on each go.
pub(crate) type AgentChannels = HashMap<ChannelId, mpsc::UnboundedSender<Vec<u8>>>;

pub(crate) fn handle_event<H: russh::client::Handler + 'static>(
    handle: &Rc<RwLock<Handle<H>>>,
    event: AgentEvent,
    channels: &mut AgentChannels,
) {
    match event {
        AgentEvent::Opened(id) => {
            let (tx, rx) = mpsc::unbounded_channel();
            channels.insert(id, tx);
            tokio::task::spawn_local(join_to_agent(handle.clone(), id, rx));
        }
        AgentEvent::Data(id, bytes) => {
            if let Some(tx) = channels.get(&id) {
                let _ = tx.send(bytes);
            }
        }
        // Dropping the sender ends the pump, which closes its agent connection.
        AgentEvent::Closed(id) => {
            channels.remove(&id);
        }
    }
}

/// SSH_AGENT_FAILURE, as a message of its own: length 1, type 5.
const AGENT_FAILURE: [u8; 5] = [0, 0, 0, 1, 5];

// shortcut: russh 0.45 cannot close a channel from the handle, so a channel
// stays open until the server closes it; upgrade russh to close it here.
async fn join_to_agent<H: russh::client::Handler>(
    handle: Rc<RwLock<Handle<H>>>,
    id: ChannelId,
    from_server: mpsc::UnboundedReceiver<Vec<u8>>,
) {
    match connect_agent().await {
        Ok(agent) => {
            tracing::debug!(?id, "forwarded agent request");
            pump(&handle, id, from_server, agent).await;
        }
        Err(e) => {
            tracing::warn!(%e, "agent forwarding: no local SSH agent to forward to");
            refuse_requests(&handle, id, from_server).await;
        }
    }
}

/// Without an agent, every request gets the answer an agent gives when it
/// cannot help, so `ssh-add -l` on the server says so instead of hanging.
async fn refuse_requests<H: russh::client::Handler>(
    handle: &RwLock<Handle<H>>,
    id: ChannelId,
    mut from_server: mpsc::UnboundedReceiver<Vec<u8>>,
) {
    let mut pending = Vec::new();
    while let Some(bytes) = from_server.recv().await {
        pending.extend_from_slice(&bytes);
        // The most OpenSSH's agent accepts; more is not a request.
        if pending.len() > 256 * 1024 {
            return;
        }
        while let Some(length) = whole_message_length(&pending) {
            pending.drain(..length);
            let failure = CryptoVec::from_slice(&AGENT_FAILURE);
            if handle.read().await.data(id, failure).await.is_err() {
                return;
            }
        }
    }
}

/// The length of the first agent message in `buffer` with its 4-byte length
/// prefix, once all of it has arrived.
fn whole_message_length(buffer: &[u8]) -> Option<usize> {
    let prefix: [u8; 4] = buffer.get(..4)?.try_into().ok()?;
    let length = u32::from_be_bytes(prefix) as usize + 4;
    (buffer.len() >= length).then_some(length)
}

async fn pump<H: russh::client::Handler>(
    handle: &RwLock<Handle<H>>,
    id: ChannelId,
    mut from_server: mpsc::UnboundedReceiver<Vec<u8>>,
    agent: impl AsyncRead + AsyncWrite,
) {
    let (mut agent_read, mut agent_write) = tokio::io::split(agent);
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        tokio::select! {
            bytes = from_server.recv() => {
                let Some(bytes) = bytes else { return };
                if agent_write.write_all(&bytes).await.is_err() {
                    return;
                }
            }
            read = agent_read.read(&mut buffer) => {
                let count = match read {
                    Ok(0) | Err(_) => return,
                    Ok(count) => count,
                };
                let sent = handle.read().await.data(id, CryptoVec::from_slice(&buffer[..count])).await;
                if sent.is_err() {
                    return;
                }
            }
        }
    }
}

#[cfg(unix)]
async fn connect_agent() -> std::io::Result<tokio::net::UnixStream> {
    let path = std::env::var_os("SSH_AUTH_SOCK").ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "SSH_AUTH_SOCK is not set")
    })?;
    tokio::net::UnixStream::connect(path).await
}

#[cfg(windows)]
async fn connect_agent() -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    // The pipe of the Win32-OpenSSH "OpenSSH Authentication Agent" service.
    tokio::net::windows::named_pipe::ClientOptions::new().open(r"\\.\pipe\openssh-ssh-agent")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_message_counts_once_all_of_it_is_there() {
        assert_eq!(whole_message_length(&[]), None);
        assert_eq!(whole_message_length(&[0, 0, 0]), None);
        assert_eq!(whole_message_length(&[0, 0, 0, 1]), None);
        assert_eq!(whole_message_length(&[0, 0, 0, 1, 11]), Some(5));
        // Two requests in one piece: the first is taken first.
        assert_eq!(
            whole_message_length(&[0, 0, 0, 1, 11, 0, 0, 0, 1, 11]),
            Some(5)
        );
        assert_eq!(whole_message_length(&[0, 0, 0, 0]), Some(4));
    }
}
