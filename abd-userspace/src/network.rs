//! Network layer

use std::net::SocketAddr;

use abd_common::message::{AbdRole, ArchivedAbdMessage};
use anyhow::Result;
use rkyv::{access_mut, rancor};
use tokio::net::UdpSocket;

use crate::{node, protocol::Context, server};

pub fn create_socket(bind_addr: SocketAddr) -> Result<UdpSocket> {
    use socket2::{Domain, Socket, Type};
    let sock = Socket::new(
        if bind_addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        },
        Type::DGRAM,
        None,
    )?;
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&bind_addr.into())?;
    Ok(UdpSocket::from_std(sock.into())?)
}

// Fast receive loop
pub async fn run_worker(ctx: Context) -> Result<()> {
    let mut buf = vec![0u8; 65_536].into_boxed_slice();
    loop {
        let (n, peer) = ctx.socket.recv_from(&mut buf).await?;
        // Safety: packet is always exactly ArchivedAbdMessage size
        let msg = access_mut::<ArchivedAbdMessage, rancor::Error>(&mut buf[..n])?.unseal();

        match AbdRole::try_from(msg.recipient_role.to_native()) {
            Ok(AbdRole::Server) => server::handle_server(&ctx, msg, peer).await,
            Ok(AbdRole::Reader) => node::handle_node(&ctx, msg, peer, AbdRole::Reader).await,
            Ok(AbdRole::Writer) => node::handle_node(&ctx, msg, peer, AbdRole::Writer).await,
            #[cfg(not(feature = "multi-writer"))]
            Ok(AbdRole::Client) => node::proxy_ack(&ctx, msg).await,
            _ => {}
        }
    }
}
