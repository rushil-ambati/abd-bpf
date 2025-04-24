use abd_bpf_common::{AbdMsg, AbdMsgType, ArchivedAbdMsg, ABD_UDP_PORT};
use rkyv::{deserialize, rancor::Error};
use std::convert::TryInto;
use std::env;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        eprintln!(
            "Usage: {} <server_ipv4> <sender_id> <write|read> [tag value counter]",
            args[0]
        );
        std::process::exit(1);
    }

    let server_ip: Ipv4Addr = args[1].parse().expect("Invalid IPv4 address provided");
    let sender_id: u8 = args[2].parse().expect("Invalid sender ID");
    let op = args[3].to_lowercase();

    let (msg_type, tag, value, counter) = match op.as_str() {
        "write" => {
            if args.len() < 7 {
                eprintln!(
                    "Usage for write: {} <server_ipv4> <sender_id> write <tag> <value> <counter>",
                    args[0]
                );
                std::process::exit(1);
            }
            (
                AbdMsgType::Write,
                args[4].parse().expect("Invalid tag"),
                args[5].parse().expect("Invalid value"),
                args[6].parse().expect("Invalid counter"),
            )
        }
        "read" => {
            if args.len() < 5 {
                eprintln!(
                    "Usage for read: {} <server_ipv4> <sender_id> read <counter>",
                    args[0]
                );
                std::process::exit(1);
            }
            (
                AbdMsgType::Read,
                0, // tag not used for read
                0, // value not used for read
                args[4].parse().expect("Invalid counter"),
            )
        }
        _ => {
            eprintln!("Invalid operation: use 'write' or 'read'");
            std::process::exit(1);
        }
    };

    // Build the server socket address (IPv4)
    let server_addr = SocketAddrV4::new(server_ip, ABD_UDP_PORT);

    // Bind a UDP socket to an ephemeral port
    let socket = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind UDP socket");

    println!("Sending {} request to {}", op.to_uppercase(), server_addr);

    // Construct the ABD message
    let msg = AbdMsg::new(sender_id, msg_type, tag, value, counter);
    // Serialize the message into a byte slice
    let msg_bytes = rkyv::to_bytes::<Error>(&msg).expect("Failed to serialize ABD message");

    // Send the ABD message to the server
    socket
        .send_to(&msg_bytes, server_addr)
        .expect("Failed to send ABD request");

    // Prepare a buffer for the response
    let mut buf = [0u8; 1024];
    let (amt, _) = socket
        .recv_from(&mut buf)
        .expect("Failed to receive response");

    // Deserialize the received bytes as an AbdMsg
    let archived = rkyv::access::<ArchivedAbdMsg, Error>(&buf[..amt])
        .expect("Failed to deserialize ABD message");
    let resp: AbdMsg =
        deserialize::<AbdMsg, Error>(archived).expect("Failed to deserialize ABD message");

    match resp.type_.try_into() {
        Ok(AbdMsgType::WriteAck) => println!("Received W-ACK from server {}", resp.sender),
        Ok(AbdMsgType::ReadAck) => println!(
            "Received R-ACK from server {}: tag={}, value={}",
            resp.sender, resp.tag, resp.value
        ),
        _ => println!("Operation: unknown (type {:?})", resp.type_),
    }
}
