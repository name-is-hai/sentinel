mod cli;
mod config;
mod models;
mod policy;
mod report;
mod scan;
mod scanner;

fn main() {
    let commands = cli::parse();

    if commands.verbose {
        println!("Verbose mode enabled");
    }

    match &commands.subcommand {
        cli::Sub::Scan(args) => {
            let target = models::ScanTarget { path: &args.path };
            match scan::run_scan(&target, &args.allowed_ids, &args.config, &args.output) {
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
        cli::Sub::Doctor => {
            scan::run_doctor();
        }
        cli::Sub::Sbom(args) => {
            let target = models::ScanTarget { path: &args.path };

            match scanner::syft::run_sbom(&target, &args.output) {
                Ok(_) => std::process::exit(0),
                Err(error) => {
                    eprintln!("SBOM error: {:?}", error);
                    std::process::exit(2);
                }
            }
        }
        cli::Sub::Config => {
            let config = config::load_config(None);
            println!("{:?}", config);
        }
    }
}
