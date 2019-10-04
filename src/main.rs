use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::*;
use std::fs::File;
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
                                    let mut byte_string = s.chars();
                                    // the chunk lengths of the iterator we're grouping together,
                                    // negative numbers means skip
                                    let slice_instructions = vec![
                                        -5, 12, -12, 5, 7, 5, 7, 5, 7, 5, 7, 5, 7, -7, 5, 7, 5, 7,
                                        5, 7, 5, 7, 5, 7, -50, 8,
                                    ];
                                    let arr = consume(&mut byte_string, slice_instructions);
                                    let pkt_time = b.ts_sec;
                                    let issue_code = &arr[0];
                                    let bid_price_1 = &arr[1].parse::<f32>().unwrap() / 100.0;
                                    let bid_qty_1 = &arr[2].parse::<f32>().unwrap() / 100.0;
                                    let bid_price_2 = &arr[3].parse::<f32>().unwrap() / 100.0;
                                    let bid_qty_2 = &arr[4].parse::<f32>().unwrap() / 100.0;
                                    let bid_price_3 = &arr[5].parse::<f32>().unwrap() / 100.0;
                                    let bid_qty_3 = &arr[6].parse::<f32>().unwrap() / 100.0;
                                    let bid_price_4 = &arr[7].parse::<f32>().unwrap() / 100.0;
                                    let bid_qty_4 = &arr[8].parse::<f32>().unwrap() / 100.0;
                                    let bid_price_5 = &arr[9].parse::<f32>().unwrap() / 100.0;
                                    let bid_qty_5 = &arr[10].parse::<f32>().unwrap() / 100.0;
                                    let ask_price_1 = &arr[11].parse::<f32>().unwrap() / 100.0;
                                    let ask_qty_1 = &arr[12].parse::<f32>().unwrap() / 100.0;
                                    let ask_price_2 = &arr[13].parse::<f32>().unwrap() / 100.0;
                                    let ask_qty_2 = &arr[14].parse::<f32>().unwrap() / 100.0;
                                    let ask_price_3 = &arr[15].parse::<f32>().unwrap() / 100.0;
                                    let ask_qty_3 = &arr[16].parse::<f32>().unwrap() / 100.0;
                                    let ask_price_4 = &arr[17].parse::<f32>().unwrap() / 100.0;
                                    let ask_qty_4 = &arr[18].parse::<f32>().unwrap() / 100.0;
                                    let ask_price_5 = &arr[19].parse::<f32>().unwrap() / 100.0;
                                    let ask_qty_5 = &arr[20].parse::<f32>().unwrap() / 100.0;
                                    let accept_time = &arr[21];
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

fn consume(it: &mut Iterator<Item = char>, slices: Vec<i32>) -> Vec<String> {
    let mut out: Vec<String> = vec![];
    // this is N^2 time complexity...
    for n in slices {
        if n < 0 {
            let skip = n * -1;
            let mut count = 0;
            while count < skip {
                it.next();
                count += 1;
            }
        } else {
            let mut count = 0;
            let mut el: String = "".into();
            while count < n {
                el.push(it.next().unwrap());
                count += 1;
            }
            out.push(el);
        }
    }
    out
}
