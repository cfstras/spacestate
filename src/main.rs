use std::{io, env};
use std::net::{UdpSocket, ToSocketAddrs};
use rand::prelude::*;
use std::convert::TryInto;
use std::time::{Instant, Duration};
use std::process::exit;

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

    match send_ping(host, port) {
        Ok(data) => {
            println!("{:?}", data);
        }
        Err(e) => {
            eprintln!("Err: {}", e);
        }
    }
}

#[derive(Debug)]
struct PingData {
    version: [i8; 4],
    packet_id: u64,
    users: i32,
    max_users: i32,
    bandwidth: i32,
    ping: u128
}

impl PingData {
    fn decode(buf: &[u8], start_date: Instant) -> PingData {
        PingData {
            version: [
                PingData::parse_u8(&buf[0..]),
                PingData::parse_u8(&buf[1..]),
                PingData::parse_u8(&buf[2..]),
                PingData::parse_u8(&buf[3..]),
            ],
            packet_id: PingData::parse_u64(&buf[4..]),
            users: PingData::parse_i32(&buf[12..]),
            max_users: PingData::parse_i32(&buf[16..]),
            bandwidth: PingData::parse_i32(&buf[20..]),
            ping: start_date.elapsed().as_millis(),
        }
    }
    fn parse_u8(arr: &[u8]) -> i8 {
        i8::from_be_bytes(arr[..1].try_into().unwrap())
    }
    fn parse_i32(arr: &[u8]) -> i32 {
        i32::from_be_bytes(arr[..4].try_into().unwrap())
    }
    fn parse_u64(arr: &[u8]) -> u64 {
        u64::from_be_bytes(arr[..8].try_into().unwrap())
    }
}

fn send_ping(host: &str, port: i32) -> Result<PingData, io::Error> {
    let target = format!("{}:{}", host, port).to_socket_addrs()?.next().expect("wat?");

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;

    let mut rng = rand::thread_rng();
    // random id as packet id
    let packet_id = rng.gen::<u64>();
    let ping = [&(0u32.to_be_bytes())[..], &(packet_id.to_be_bytes())[..]].concat();

    //println!("Sending {:?}", ping);
    let start_date = Instant::now();
    socket.send_to(&ping, target)?;
    //println!("Sent {} bytes", sent);

    let mut buf = [0; 24];
    let (num_bytes, _src) = socket.recv_from(&mut buf)?;
    let buf = &mut buf[..num_bytes];
    //println!("Received {} bytes: {:?}", num_bytes, buf);

    let data = PingData::decode(buf, start_date);
    if data.packet_id != packet_id {
        Err(io::Error::new(io::ErrorKind::Other, format!("packet_id was different: {} != {}", packet_id, data.packet_id)))
    } else {
        Ok(data)
    }
}
