use clap::Parser;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    mesh::start_tunnels().await?;

    futures::future::pending().await
}
