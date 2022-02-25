use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use std::cmp;
use std::convert::TryInto;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use rand::prelude::*;

#[cfg(test)]
use fake_clock::FakeClock as Instant;
#[cfg(not(test))]
use std::time::Instant;

#[derive(Debug, cmp::PartialEq, Serialize, Clone)]
pub struct PingData {
    version: [i8; 4],
    packet_id: u64,
    users: i32,
    max_users: i32,
    bandwidth: i32,
    ping: u64,
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
            ping: start_date.elapsed().as_millis() as u64,
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

pub fn send_ping(host: &str, port: u16) -> Result<PingData> {
    let target = format!("{}:{}", host, port)
        .to_socket_addrs()
        .context("could not resolve hostname")?
        // force IPv4 (has to match socket bind)
        .filter(SocketAddr::is_ipv4)
        .next()
        .expect("No IPv4 address for this hostname");

    let socket = UdpSocket::bind("0.0.0.0:0").context("unable to open UDP socket")?;
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .context("could not set socket timeout")?;

    let mut rng = rand::thread_rng();
    // random id as packet id
    let packet_id = rng.gen::<u64>();
    let ping = [&(0u32.to_be_bytes())[..], &(packet_id.to_be_bytes())[..]].concat();

    //println!("Sending {:?}", ping);
    let start_date = Instant::now();
    socket
        .send_to(&ping, target)
        .context("could not send ping packet")?;
    //println!("Sent {} bytes", sent);

    let mut buf = [0; 24];
    let (num_bytes, _src) = socket
        .recv_from(&mut buf)
        .context("did not receive ping response")?;
    let buf = &mut buf[..num_bytes];
    //println!("Received {} bytes: {:?}", num_bytes, buf);

    let data = PingData::decode(buf, start_date);
    if data.packet_id != packet_id {
        Err(anyhow!(
            "packet_id was different: {} != {}",
            packet_id,
            data.packet_id
        ))
    } else {
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::PingData;

    const RAW: [u8; 24] = [
        0, 1, 3, 0, 139, 162, 102, 131, 242, 120, 10, 6, 0, 0, 0, 4, 0, 0, 0, 200, 0, 4, 147, 224,
    ];

    #[test]
    fn test_decode() {
        let clock = fake_clock::FakeClock::now();
        fake_clock::FakeClock::advance_time(23);
        let data = PingData::decode(&RAW, clock);
        assert_eq!(
            data,
            PingData {
                version: [0, 1, 3, 0],
                packet_id: 10061717234393811462,
                users: 4,
                max_users: 200,
                bandwidth: 300000,
                ping: 23
            }
        )
    }
}
