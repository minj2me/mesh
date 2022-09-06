use std::borrow::{Borrow, BorrowMut};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Context, Error};
use boringtun::noise::Tunn;
use boringtun::noise::TunnResult;
use log::{debug, error, trace};
use log::Level;
use tokio::net::UdpSocket;
use tokio::time::Duration;

/**
 WireGuard Tunnel. encapsulates or decapsulates ip packets to
 send and receive from a remote endpoint.
*/

const MAX_PACKET: usize = 65535;

pub struct WireGuardTunnel {
    pub(crate) source_peer_ip: IpAddr,
    //for WireGuard connections
    //peer: Box<Tunn>,
    peer: Tunn,
    //UDP socket for WireGuard connection
    udp: UdpSocket,
    //WireGuard endpoint
    pub(crate) endpoint: SocketAddr,
}

impl WireGuardTunnel {
    pub async fn new() -> anyhow::Result<Self> {
        //just for test
        let source_peer_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let peer = Self::create_tunnel();
        //let peer_box = Box::new(peer.unwrap());
        let peer_ = peer.unwrap();
        let udp = UdpSocket::bind("0.0.0.0:8080").await.unwrap();
        let endpoint: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 8)), 8080);

        Ok(Self {
            source_peer_ip,
            peer: peer_,
            udp,
            endpoint,
        })
    }

    /*
    encapsulate ip packet and send to WireGuard endpoint
    */
    pub async fn send_ip_packet(&mut self, packet: &[u8]) -> anyhow::Result<()> {
        let mut send_buf = [0u8; MAX_PACKET];
        //把dev/net/tun读取的buffer 封装为 WireGuard 协议
        match self.peer.encapsulate(packet, &mut send_buf) {
            TunnResult::WriteToNetwork(packet) => {
                //can send
                self.udp.send_to(packet, self.endpoint).await
                    .with_context(|| "Failure to send IP packet to WireGuard endpoint")?;
                debug!(
                    "Sent {} bytes to WireGuard endpoint (encrypted IP packet)",
                    packet.len()
                );
            }
            TunnResult::Err(e) => {
                error!("Failure to encapsulate ip packet:{:?}", e);
            }
            TunnResult::Done => {}
            other => {
                error!(
                    "Unexpected WireGuard state during encapsulation: {:?}",
                    other
                );
            }
        };
        Ok(())
    }

    /*
    decapsulate ip packet from WireGuard endpoint and dispatch it
    */
    pub async fn receive_ip_packet(&mut self) -> ! {
        debug!("Starting WireGuard receive_ip_packet task");
        println!("Starting WireGuard receive_ip_packet task");
        loop {
            let mut recv_buf = [0u8; MAX_PACKET];
            let mut send_buf = [0u8; MAX_PACKET];

            let size = match self.udp.recv(&mut recv_buf).await {
                Ok(size) => size,
                Err(e) => {
                    error!("Failure to read from WireGuard endpoint: {:?}", e);
                    println!("Failure to read from WireGuard endpoint: {:?}", e);
                    //sleep a bit and try again
                    tokio::time::sleep(Duration::from_millis(1));
                    continue;
                }
            };

            let data = &recv_buf[..size];
            //根据WireGuard协议，解析为buffer 回写到 tun虚拟网卡
            match self.peer.decapsulate(None, data, &mut send_buf) {
                TunnResult::WriteToNetwork(packet) => {
                    match self.udp.send_to(packet, self.endpoint).await {
                        Ok(_) => {}
                        Err(e) => {
                            error!("Failed to send decapsulation-instructed packet to WireGuard endpoint: {:?}", e);
                            println!("Failed to send decapsulation-instructed packet to WireGuard endpoint: {:?}", e);
                            continue;
                        }
                    };
                    /*
                    Form Docuement:
                    If the result is of type TunnResult::WriteToNetwork, should repeat the call with empty datagram, until TunnResult::Done is returned.
                    If batch processing packets, it is OK to defer until last packet is processed.
                    */
                    loop {
                        let mut send_buf = [0u8; MAX_PACKET];
                        match self.peer.decapsulate(None, &[], &mut send_buf) {
                            TunnResult::WriteToNetwork(packet) => {
                                match self.udp.send_to(packet, self.endpoint).await {
                                    Ok(_) => {}
                                    Err(e) => {
                                        error!("Failed to send decapsulation-instructed packet to WireGuard endpoint: {:?}", e);
                                        println!("Failed to send decapsulation-instructed packet to WireGuard endpoint: {:?}", e);
                                        break;
                                    }
                                };
                            }
                            _ => {
                                break;
                            }
                        }
                    }//end loop
                }
                TunnResult::WriteToTunnelV4(packet, _) => {
                    debug!("WireGuard endpoint send ip packet of {} bytes", packet.len());
                    println!("WireGuard endpoint send ip packet of {} bytes", packet.len());

                }
                _ => {}
            };
        }
    }

    fn create_tunnel() -> Result<Tunn, Error> {
        //let private_key: x25519_dalek::StaticSecret = "aa".parse::<x25519_dalek::StaticSecret>().map_err(|e| anyhow::anyhow!("{}", e)).unwrap();
        let private_key: x25519_dalek::StaticSecret = x25519_dalek::StaticSecret::from([0u8; 32]);
        //let public_key: x25519_dalek::PublicKey = "bb".parse::<x25519_dalek::PublicKey>().map_err(|e| anyhow::anyhow!("{}", e)).unwrap();
        let public_key: x25519_dalek::PublicKey = x25519_dalek::PublicKey::from([0u8; 32]);
        let keepalive_seconds: Option<u16> = Some(20);
        Tunn::new(
            private_key,
            public_key,
            None,
            keepalive_seconds,
            0,
            None)
            .map_err(|s| anyhow::anyhow!("{}", s))
            .with_context(|| "Failed to initialize Tunn")
    }
}

/*
 let private_key = match static_private.parse::<KeyBytes>() {
        Err(_) => return ptr::null_mut(),
        Ok(key) => StaticSecret::from(key.0),
    };

    let public_key = match server_static_public.parse::<KeyBytes>() {
        Err(_) => return ptr::null_mut(),
        Ok(key) => PublicKey::from(key.0),
    };
*/

