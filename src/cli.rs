use crate::scan::ScanArgs;
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Command {
    #[command(subcommand)]
    pub subcommand: Sub,

    /// Run with verbose output
    #[arg(long, short, default_value_t = false, global = true)]
    pub verbose: bool,
}

#[derive(Subcommand, Debug)]
pub enum Sub {
    Scan(ScanArgs),
    Report,
}

pub fn parse() -> Command {
    Command::parse()
}
