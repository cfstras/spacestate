use std::{env, io};
use std::net::{TcpStream, ToSocketAddrs};
use std::process::exit;
use std::sync::Arc;

use rustls::Session;

mod mumble_ping;

pub mod mumble {
    include!(concat!(env!("OUT_DIR"), "/mumble_proto.rs"));
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let port = match args.len() {
        2 => 64738,
        3 => args[2].parse().unwrap(),
        _ => {
            eprintln!("Usage: spacestate <host> [port]");
            exit(1)
        }
    };
    let host = &args[1];

    match mumble_ping::send_ping(host, port) {
        Ok(data) => println!("{:?}", data),
        Err(e) => eprintln!("Err: {}", e),
    }

    match connect_proto(host, port) {
        Ok(data) => println!("{:?}", data),
        Err(e) => eprintln!("Err: {}", e),
    }
}

fn connect_proto(host: &str, port: i32) -> Result<&str, io::Error> {
    let mut config = rustls::ClientConfig::new();
    config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

    let rc_config = Arc::new(config);
    let name_ref = webpki::DNSNameRef::try_from_ascii_str(host).unwrap();
    let mut client = rustls::ClientSession::new(&rc_config, name_ref);

    let addr = format!("{}:{}", host, port).to_socket_addrs()?.next().expect("wat?");
    let sock = TcpStream::connect(&addr).unwrap();

    Ok("")
}
