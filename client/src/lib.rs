use std::sync::Arc;

use anyhow::Context;

use crate::wgt::WireGuardTunnel;

mod device;
mod config;
mod wgt;
use log::debug;

/*
start mesh tunnels
*/
pub async fn start_tunnels() -> anyhow::Result<()> {
    //debug!("starting tunnels");
    println!("starting tunnels");
    let mut wgt = WireGuardTunnel::new().await.with_context(|| "Failure to init WireGuard tunnel")?;
    //let wgt = Arc::new(wgt);
    //let mut wgt_handler_receive = wgt.clone();
    //wgt.receive_ip_packet();
    tokio::spawn(async move { wgt.receive_ip_packet().await });
    Ok(())
}
