use pcap_parser::*;
use pcap_parser::traits::PcapReaderIterator;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::str;

fn main() {

    let path: &Path = Path::new("./data/mdf-kospi200.20110216-0.pcap");
    let file = File::open(path).unwrap();
    let mut num_blocks = 0;
    let mut reader = LegacyPcapReader::new(65536, file).expect("PcapNGReader");
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                //println!("got new block");
                num_blocks += 1;
                match block {
                    PcapBlockOwned::LegacyHeader(_hdr) => {
                        // save hdr.network (linktype)
                    },
                    PcapBlockOwned::Legacy(b) => {
                        // use linktype to parse b.data()
                        //let convert = match str::from_utf8(b.data) {
                        //    Ok(v) => v,
                        //    Err(e) => panic!("invalid utf-8 sequence: {}", e),
                        //};
                        println!("{}", b.ts_sec);
                    },
                    PcapBlockOwned::NG(_) => unreachable!(),
                }
                reader.consume(offset);
            },
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete) => {
                reader.refill().unwrap();
            },
            Err(e) => panic!("error while reading: {:?}", e),
        }
    }
    println!("num_blocks: {}", num_blocks);
}


struct Quote {
    pkt_time: u8,
    accept_time: u8,
    issue_code: u8,
    bid_qty_1: u8,
    bid_qty_2: u8,
    bid_qty_3: u8,
    bid_qty_4: u8,
    bid_qty_5: u8,
    bid_price_1: u8,
    bid_price_2: u8,
    bid_price_3: u8,
    bid_price_4: u8,
    bid_price_5: u8,
    ask_qty_1: u8,
    ask_qty_2: u8,
    ask_qty_3: u8,
    ask_qty_4: u8,
    ask_qty_5: u8,
    ask_price_1: u8,
    ask_price_2: u8,
    ask_price_3: u8,
    ask_price_4: u8,
    ask_price_5: u8,
}
