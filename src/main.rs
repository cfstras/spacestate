#![feature(proc_macro_hygiene, decl_macro)]

use crate::mumble_ping::PingData;

use bytes::{Buf, BufMut, BytesMut};
use bytes::buf::BufExt;
use prost::bytes;
use prost::encoding::encode_varint;
use prost::Message;
use rocket_contrib::json::Json;
use rocket::State;
use rustls::{Session, ClientSession};
use serde::Serialize;
use std::{env, io};
use std::collections::HashMap;
use std::io::{Read, Write, ErrorKind};
use std::net::{TcpStream, ToSocketAddrs, Shutdown};
use std::process::exit;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

mod mumble_ping;

#[macro_use] extern crate rocket;

pub mod mumble {
    use serde::Serialize;
    include!(concat!(env!("OUT_DIR"), "/mumble_proto.rs"));
}

#[get("/")]
fn index() -> &'static str {
    "Hello, world!"
}

#[get("/ping")]
fn ping() -> Json<PingData> {
    Json(mumble_ping::send_ping("mumble.flipdot.org", 64738)
        .unwrap())
}

#[get("/status")]
fn status(state: State<Box<MumbleState>>) -> Json<&MumbleState> {
    Json(state.inner().clone().as_ref())
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
        Err(e) => eprintln!("Ping Err: {}", e),
    }

    let rkt = rocket::ignite()
        .mount("/", routes![index, status]);

    let res = connect_proto(host, port);
    let rkt = match res {
        Ok(data) => {
            println!("State finished! {} channels, {} users", data.channels.len(), data.users.len());
            rkt.manage(Box::new(data))
        }
        Err(e) => {
            eprintln!("Read state err: {}", e);
            rkt
        },
    };
    rkt.launch();
}

#[derive(Debug, Serialize)]
struct Header {
    message_type: u16,
    message_len: u32,
}

#[derive(Debug, Serialize)]
struct MumbleState {
    header: Option<Header>,

    channels: HashMap<u32, mumble::ChannelState>,
    users: HashMap<u32, mumble::UserState>,

    server_version: Option<mumble::Version>,
    suggest_config: Option<mumble::SuggestConfig>,
    server_sync: Option<mumble::ServerSync>,
    server_config: Option<mumble::ServerConfig>,
}

struct AcceptAllCertsVerifier {}
impl rustls::ServerCertVerifier for AcceptAllCertsVerifier {
    fn verify_server_cert(
        &self,
        _: &rustls::RootCertStore,
        _: &[rustls::Certificate],
        _: webpki::DNSNameRef,
        _: &[u8],
    ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
        return Ok(rustls::ServerCertVerified::assertion());
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::Certificate,
        _: &rustls::internal::msgs::handshake::DigitallySignedStruct,
    ) -> Result<rustls::HandshakeSignatureValid, rustls::TLSError> {
        Ok(rustls::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::Certificate,
        _: &rustls::internal::msgs::handshake::DigitallySignedStruct,
    ) -> Result<rustls::HandshakeSignatureValid, rustls::TLSError> {
        Ok(rustls::HandshakeSignatureValid::assertion())
    }
}

const MAX_MSG_LEN: u32 = 1024 * 1024; // 1 MiB

fn connect_proto(host: &str, port: i32) -> Result<MumbleState, io::Error> {
    let mut config = rustls::ClientConfig::new();
    config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

    if !env::var("IGNORE_CERT").is_err() {
        config.dangerous()
            .set_certificate_verifier(Arc::new(AcceptAllCertsVerifier{}));
    }
    
    let rc_config = Arc::new(config);
    let name_ref = webpki::DNSNameRef::try_from_ascii_str(host).unwrap();
    let mut client = rustls::ClientSession::new(&rc_config, name_ref);

    let addr = format!("{}:{}", host, port).to_socket_addrs()?.next().expect("wat?");
    let mut sock = TcpStream::connect(&addr).expect("Connection failed!");
    println!("sock: {:?}", sock);

    let mut state = MumbleState::new();

    let mut read_buf = BytesMut::with_capacity(1024);
    let mut read_buf2 = [0; 512];

    loop {
        if !pull_push_tls(&mut client, &mut sock)? {
            println!("EOF");
            close(&mut client, &mut sock)?;
            return Err(io::Error::new(ErrorKind::Other, "EOF before we got all data"));
        }
        client.process_new_packets()
            .map_err(|f| io::Error::new(io::ErrorKind::Other, f.to_string()))?;


        let read = client.read(&mut read_buf2)?;
        read_buf.extend(&read_buf2[..read]);
        //println!("read_buf {}: {:x?}", read_buf.len(), read_buf.to_vec());

        match state.run(&mut read_buf)? {
            None => {},
            Some(answer) => {
                println!("answering with {:x?}", answer.to_vec());
                client.write(&answer)?;
            },
        }

        if state.server_config.is_some() && state.server_sync.is_some() {
            close(&mut client, &mut sock)?;
            return Ok(state);
        }
    }
}

fn close(mut client: &mut ClientSession, mut sock: &mut TcpStream) -> Result<(), io::Error> {
    client.send_close_notify();
    pull_push_tls(&mut client, &mut sock)?;
    sock.shutdown(Shutdown::Both)
}

fn pull_push_tls(client: &mut ClientSession, mut sock: &mut TcpStream) -> Result<bool, io::Error> {
    if client.wants_write() {
        client.write_tls(&mut sock)?;
    } else if client.wants_read() {
        let read = client.read_tls(&mut sock)?;
        if read == 0 {
            return Ok(false)
        }
    }
    Ok(true)
}

impl Header {
    fn parse(buf: &mut BytesMut) -> Option<Header> {
        if buf.len() < 6 {
            return None;
        }
        Some(Header {
            message_type: buf.get_u16(),
            message_len: buf.get_u32()
        })
    }
}

impl MumbleState {
    fn new() -> MumbleState {
        MumbleState {
            header: None, channels: Default::default(), users: Default::default(),
            server_version: None, suggest_config: None, server_sync: None, server_config: None
        }
    }

    fn run(&mut self, buf: &mut BytesMut) -> Result<Option<BytesMut>, io::Error> {
        if self.header.is_none() {
            self.header = Header::parse(buf);
        }
        match &self.header {
            Some(header) => {
                //println!("Parsed header {:?}", header);
                if buf.len() >= header.message_len as usize {
                    let answer = self.parse_mumble_msg(buf);
                    self.header = None;
                    return answer;
                }
                if header.message_len > MAX_MSG_LEN {
                    return Err(io::Error::new(io::ErrorKind::Other, "way too much data... aborting"));
                }
                Ok(None)
            }
            None => Ok(None)
        }
    }

    fn response_header(response: &dyn prost::Message, code: u16) -> BytesMut {
        let encoded_len = response.encoded_len();
        let mut resp_buf = BytesMut::with_capacity(encoded_len + 2 + 4);
        resp_buf.put_u16(code);
        resp_buf.put_u32(encoded_len as u32);
        resp_buf
    }

    fn parse_mumble_msg(&mut self, buf: &mut BytesMut) -> Result<Option<BytesMut>, io::Error> {
        let header = self.header.as_ref().unwrap();
        //println!("Decoding {:?}", header);
        //println!("Decoding {:?} from {:x?}", header, buf.to_vec());
        let mut limited_buf = buf.take(header.message_len as usize);

        match header.message_type {
            0 => {
                let msg = mumble::Version::decode(limited_buf)?;
                println!("message: {:#?}", msg);
                self.server_version = Some(msg);

                let response = mumble::Authenticate {
                    username: Some(String::from("ZiffBot")),
                    password: None,
                    tokens: [].to_vec(),
                    celt_versions: [0x0000_0B_00, 0x0000_07_00].to_vec(),
                    opus: Some(false),
                };
                println!("sending answer {:?}", response);
                let mut resp_buf = MumbleState::response_header(&response, 2);
                response.encode(&mut resp_buf)?;
                Ok(Some(resp_buf))
            },
            1 => {
                //let msg = mumble::UdpTunnel::decode(limited_buf)?;
                println!("message: UdpTunnel {:x?}", limited_buf.bytes());
                limited_buf.advance(limited_buf.limit());
                // ignore, cannot parse this
                Ok(None)
            },
            2 => {
                let msg = mumble::Authenticate::decode(limited_buf)?;
                println!("message: {:#?}", msg);
                Ok(None)
            },
            3 => {
                let msg = mumble::Ping::decode(limited_buf)?;
                println!("message: {:#?}", msg);
                Ok(None)
            },
            4 => {
                let msg = mumble::Reject::decode(limited_buf)?;
                println!("message: {:#?}", msg);
                Ok(None)
            },
            5 => {
                let msg = mumble::ServerSync::decode(limited_buf)?;
                println!("message: {:#?}", msg);
                self.server_sync = Some(msg);
                Ok(None)
            },
            6 => {
                let msg = mumble::ChannelRemove::decode(limited_buf)?;
                println!("message: {:#?}", msg);
                Ok(None)
            },
            7 => {
                let msg = mumble::ChannelState::decode(limited_buf)?;
                //println!("message: Channel {:#?}", &msg.name.clone().unwrap());
                self.channels.insert(msg.channel_id.unwrap(), msg);

                /*let response = mumble::Ping {
                    good: Some(1), late: Some(2), lost: Some(3), resync: Some(4),
                    tcp_packets: Some(5), tcp_ping_avg: Some(6.2f32), tcp_ping_var: Some(7.3f32),
                    timestamp: None,
                    udp_packets: Some(8), udp_ping_avg: Some(9.5f32), udp_ping_var: Some(10.6f32),
                };
                println!("sending answer {:?}", response);
                let mut resp_buf = State::response_header(&response, 3);
                response.encode(&mut resp_buf)?;
                Ok(Some(resp_buf))*/
                Ok(None)
            },
            8 => {
                let msg = mumble::UserRemove::decode(limited_buf)?;
                println!("message: {:#?}", msg);
                Ok(None)
            },
            9 => {
                let msg = mumble::UserState::decode(limited_buf)?;
                println!("message: {:#?}", msg);
                self.users.insert(msg.session.unwrap(), msg);
                Ok(None)
            },
            10 => {
                let msg = mumble::BanList::decode(limited_buf)?;
                println!("message: {:#?}", msg);
                Ok(None)
            },
            11 => {
                let msg = mumble::TextMessage::decode(limited_buf)?;
                println!("message: {:#?}", msg);
                Ok(None)
            },
            12 => {
                let msg = mumble::PermissionDenied::decode(limited_buf)?;
                println!("message: {:#?}", msg);
                Ok(None)
            },
            13 => {
                let msg = mumble::Acl::decode(limited_buf)?;
                println!("message: {:#?}", msg);
                Ok(None)
            },
            14 => {
                let msg = mumble::QueryUsers::decode(limited_buf)?;
                println!("message: {:#?}", msg);
                Ok(None)
            },
            15 => {
                let msg = mumble::CryptSetup::decode(limited_buf)?;
                println!("message: {:#?}", msg);


                let response = mumble::Version {
                    version: Some(99u32),
                    release: Some("'; DROP TABLE 'clients'".to_string()),
                    os: Some("Hannah Montana Linux".to_string()),
                    os_version: Some("99.1 Chilly Cheetah".to_string()),
                };
                println!("sending answer {:?}", response);
                let mut resp_buf = MumbleState::response_header(&response, 0);
                response.encode(&mut resp_buf)?;
                Ok(Some(resp_buf))
            },
            16 => {
                let msg = mumble::ContextActionModify::decode(limited_buf)?;
                println!("message: {:#?}", msg);
                Ok(None)
            },
            17 => {
                let msg = mumble::ContextAction::decode(limited_buf)?;
                println!("message: {:#?}", msg);
                Ok(None)
            },
            18 => {
                let msg = mumble::UserList::decode(limited_buf)?;
                println!("message: {:#?}", msg);
                Ok(None)
            },
            19 => {
                let msg = mumble::VoiceTarget::decode(limited_buf)?;
                println!("message: {:#?}", msg);
                Ok(None)
            },
            20 => {
                let msg = mumble::PermissionQuery::decode(limited_buf)?;
                println!("message: {:#?}", msg);
                Ok(None)
            },
            21 => {
                let msg = mumble::CodecVersion::decode(limited_buf)?;
                println!("message: {:#?}", msg);
                
                let mut udp_tunnel_buf = BytesMut::with_capacity(1 + 10); // maxlen 64-bit varint
                udp_tunnel_buf.put_u8(0b001_00000); // ping packet, normal talking
                encode_varint(SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("time failed").as_millis() as u64, 
                    &mut udp_tunnel_buf);
                // 60 81 10 0
                //let raw: &[u8] = &[0x60, 0x0, 0x69, 0x7f, 0x7c, 0xf5, 0xe8, 0xa7, 0xad, 0xb8, 0x62, 0x1b, 0x73, 0x5, 0xd5, 0x84, 0x3, 0xe7, 0x1a, 0x7f, 0xdc, 0xdf, 0x26, 0xf8, 0x44, 0x2b, 0x24, 0x13, 0xc0, 0x77, 0x4d, 0x38, 0x10, 0x7e, 0x37, 0xe5, 0xbd, 0xb7, 0x97, 0x0, 0xde, 0x12, 0xa0, 0x73, 0x4d, 0x46, 0xcd, 0xc2, 0x8, 0x52, 0x92, 0x15, 0xe7, 0xe8, 0x80, 0x0, 0x1, 0x5c, 0x56, 0xec, 0xd9, 0xf8, 0x68, 0xbd, 0xf3, 0x6c, 0x17, 0x54, 0x57, 0x41, 0x22, 0x5d, 0xe7, 0xd5, 0x11, 0xc1, 0xea, 0x13, 0x44, 0x70, 0x3, 0x8e, 0xa4, 0x9b, 0x77, 0x59, 0x8c, 0x71, 0xe2, 0x7a, 0x2, 0xf5, 0xe, 0xd0, 0x46, 0x38, 0xf6, 0xaa, 0xe7, 0x7c, 0xbd, 0x1, 0xf4, 0x73, 0xab, 0x47, 0x58, 0xc4];
                //udp_tunnel_buf.put(raw);
                    
                let encoded_len = udp_tunnel_buf.len();
                let mut resp_buf = BytesMut::with_capacity(6 + encoded_len);
                resp_buf.put_u16(1); // UdpTunnel
                resp_buf.put_u32(encoded_len as u32);
                resp_buf.put(udp_tunnel_buf);
                
                Ok(Some(resp_buf))
            },
            22 => {
                let msg = mumble::UserStats::decode(limited_buf)?;
                println!("message: {:#?}", msg);
                Ok(None)
            },
            23 => {
                let msg = mumble::RequestBlob::decode(limited_buf)?;
                println!("message: {:#?}", msg);
                Ok(None)
            },
            24 => {
                let msg = mumble::ServerConfig::decode(limited_buf)?;
                println!("message: {:#?}", msg);
                self.server_config = Some(msg);
                Ok(None)
            },
            25 => {
                let msg = mumble::SuggestConfig::decode(limited_buf)?;
                println!("message: {:#?}", msg);
                self.suggest_config = Some(msg);
                Ok(None)
            },
            unknown => {
                Err(io::Error::new(io::ErrorKind::Other, format!("unknown type {}", unknown)))
            }
        }
    }
}
