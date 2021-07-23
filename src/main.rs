use getopts::Options;
use pcap_parser::{traits::PcapReaderIterator, *};
use std::{env, fs::File, path::Path, str, time::Instant};

mod quote;
mod helper;

use quote::Quote;
use helper::*;

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} FILE [options]", program);
    print!("{}", opts.usage(&brief));
}

fn main() {
    let now = Instant::now();
    let args: Vec<String> = env::args().collect();

    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optflag("r", "", "sort quotes by accept time");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!(f.to_string()),
    };

    let path = if !matches.free.is_empty() {
        Path::new(&matches.free[0])
    } else {
        print_usage(&program, opts);
        return;
    };

    let file = File::open(path).unwrap();
    let mut reader = LegacyPcapReader::new(65536, file).expect("PcapReader");
    let mut quote_pkts: Vec<(u32, Vec<u8>)> = Vec::new();

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::Legacy(b) => {
                        // filter for valid quotes
                        if is_valid_quote(b.data) {
                            let quote_pkt: Vec<u8> = b.data[42..256].iter().map(|x| *x).collect();
                            quote_pkts.push((b.ts_sec, quote_pkt));
                        }
                    }
                    _ => (),
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete) => {
                reader.refill().unwrap();
            }
            Err(e) => panic!("error while reading: {:?}", e),
        }
    }

    let mut quotes = quote_pkts
        .iter()
        .map(|(x, y)| build_quote(*x, y))
        .collect::<Vec<Quote>>();

    if matches.opt_present("r") {
        quotes.sort();
    }

    for q in quotes {
        println!("{}", q.to_string());
    }

    println!("finished at: {} seconds", now.elapsed().as_secs());
}
