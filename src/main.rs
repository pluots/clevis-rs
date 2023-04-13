use clap::{Args, Parser, Subcommand};
use clevis_rs::{EncryptConfig, EncryptSource};

#[derive(Debug, Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Encrypt(EncryptArgs),
    Decrypt { name: Option<String> },
}

#[derive(Debug, Args)]
struct EncryptArgs {
    /// The base URL of the Tang server
    #[arg(long)]
    url: Option<String>,
    /// The thumbprint of a trusted signing key
    #[arg(long)]
    thp: Option<String>,
    /// A filename containing a trusted advertisement
    #[arg(long)]
    adv: Option<String>,
    /// A trusted advertisement (raw JSON)
    #[arg(long)]
    adv_file: Option<String>,
    /// Skip the advertisement check
    #[arg(short = 'y', long, default_value_t = false)]
    skip_trust: bool,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Encrypt(v) => run_encryption(v),
        Commands::Decrypt { name: _ } => run_decryption(),
    }
}

fn run_encryption(args: EncryptArgs) {
    let thp = args.thp.unwrap_or_default();
    let process = EncryptConfig {
        thp,
        source: EncryptSource::Server(args.url.unwrap()),
    };

    let res = process.encrypt();

    if let Err(err) = res {
        eprintln!("error: {err:?}");
    }
}

fn run_decryption() {
    todo!()
}
