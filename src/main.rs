use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::*;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::str;

fn main() {
    let path: &Path = Path::new("./data/mdf-kospi200.20110216-0.pcap");
    let file = File::open(path).unwrap();
    let mut num_blocks = 0;
    let mut reader = LegacyPcapReader::new(65536, file).expect("PcapReader");
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                num_blocks += 1;
                match block {
                    PcapBlockOwned::LegacyHeader(_hdr) => {
                        // save hdr.network (linktype)
                    }
                    PcapBlockOwned::Legacy(b) => {
                        // check if data length is long enough
                        if b.data.len() > 255 {
                            // filter out valid quotes
                            match str::from_utf8(&b.data[42..256]) {
                                Ok(s) if s.starts_with("B6034") => {
                                    // build the quote here
                                    let pkt_time = b.ts_sec;
                                    let mut byte_string = s.chars().skip(5);
                                    let issue_code = consume_and_spit(&mut byte_string, 12);
                                    let mut byte_string = byte_string.skip(12);
                                    let bid_price_1 = consume_and_spit(&mut byte_string, 5);
                                    let bid_qty_1 = consume_and_spit(&mut byte_string, 7);
                                    let bid_price_2 = consume_and_spit(&mut byte_string, 5);
                                    let bid_qty_2 = consume_and_spit(&mut byte_string, 7);
                                    let bid_price_3 = consume_and_spit(&mut byte_string, 5);
                                    let bid_qty_3 = consume_and_spit(&mut byte_string, 7);
                                    let bid_price_4 = consume_and_spit(&mut byte_string, 5);
                                    let bid_qty_4 = consume_and_spit(&mut byte_string, 7);
                                    let bid_price_5 = consume_and_spit(&mut byte_string, 5);
                                    let bid_qty_5 = consume_and_spit(&mut byte_string, 7);
                                    let mut byte_string = byte_string.skip(7);
                                    let ask_price_1 = consume_and_spit(&mut byte_string, 5);
                                    let ask_qty_1 = consume_and_spit(&mut byte_string, 7);
                                    let ask_price_2 = consume_and_spit(&mut byte_string, 5);
                                    let ask_qty_2 = consume_and_spit(&mut byte_string, 7);
                                    let ask_price_3 = consume_and_spit(&mut byte_string, 5);
                                    let ask_qty_3 = consume_and_spit(&mut byte_string, 7);
                                    let ask_price_4 = consume_and_spit(&mut byte_string, 5);
                                    let ask_qty_4 = consume_and_spit(&mut byte_string, 7);
                                    let ask_price_5 = consume_and_spit(&mut byte_string, 5);
                                    let ask_qty_5 = consume_and_spit(&mut byte_string, 7);
                                    let mut byte_string = byte_string.skip(50);
                                    let accept_time = consume_and_spit(&mut byte_string, 8);
                                    println!("{} {} {} {}@{} {}@{} {}@{} {}@{} {}@{} {}@{} {}@{} {}@{} {}@{} {}@{}", pkt_time, accept_time, issue_code, bid_qty_5, bid_price_5, bid_qty_4, bid_price_4, bid_qty_3, bid_price_3, bid_qty_2, bid_price_2, bid_qty_1, bid_price_1, ask_qty_1, ask_price_1, ask_qty_2, ask_price_2, ask_qty_3, ask_price_3, ask_qty_4, ask_price_4, ask_qty_5, ask_price_5);
                                }
                                Ok(_) => (),
                                Err(_) => println!("not a quote"),
                            }
                        }
                    }
                    PcapBlockOwned::NG(_) => unreachable!(),
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
    println!("num_blocks: {}", num_blocks);
}

struct Quote<'a> {
    pkt_time: u8,
    data_type: &'a str,
    info_type: &'a str,
    market_type: &'a str,
    accept_time: u8,
    issue_code: u8,
    issue_seq_no: u8,
    market_status_type: u8,
    total_bid_vol: u8,
    total_ask_vol: u8,
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

fn consume_and_spit(it: &mut Iterator<Item = char>, num: u32) -> String {
    let mut count = 0;
    let mut out: String = "".into();
    while count < num {
        out.push(it.next().unwrap());
        count += 1;
    }
    out
}
