mod cli;
mod models;
mod scan;

fn main() {
    let commands = cli::parse();

    if commands.verbose {
        println!("Verbose mode enabled");
    }

    match &commands.subcommand {
        cli::Sub::Scan(args) => {
            let target = scan::ScanTarget { path: &args.path };

            match scan::run_scan(&target) {
                Ok(models::Decision::Allow) => std::process::exit(0),
                Ok(models::Decision::Block) => std::process::exit(1),
                Err(error) => {
                    eprintln!("Scan error: {:?}", error);
                    std::process::exit(2);
                }
            }
        }
        cli::Sub::Report => {
            println!("Report command is not implemented yet");
        }
    }
}
