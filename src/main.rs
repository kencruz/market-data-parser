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
                                    // negative is the number of elements to skip
                                    let slice_instructions = vec![
                                        -5, 12, -12, 5, 7, 5, 7, 5, 7, 5, 7, 5, 7, -7, 5, 7, 5, 7,
                                        5, 7, 5, 7, 5, 7, -50, 8,
                                    ];
                                    let arr = consume(&mut byte_string, slice_instructions);
                                    let pkt_time = b.ts_sec;
                                    let issue_code = &arr[0];
                                    let (bids, asks) = build_bidasks(&arr, 5, 1);
                                    let accept_time = &arr[21];

                                    println!("{} {} {} {:.2}@{:.2} {:.2}@{:.2} {:.2}@{:.2} {:.2}@{:.2} {:.2}@{:.2} {:.2}@{:.2} {:.2}@{:.2} {:.2}@{:.2} {:.2}@{:.2} {:.2}@{:.2}", pkt_time, accept_time, issue_code, bids[4].1, bids[4].0, bids[3].1, bids[3].0, bids[2].1, bids[2].0, bids[1].1, bids[1].0, bids[0].1, bids[0].0,  asks[0].1, asks[0].0, asks[1].1, asks[1].0, asks[2].1, asks[2].0, asks[2].1, asks[2].0, asks[4].1, asks[4].0);
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

fn consume(it: &mut dyn Iterator<Item = char>, slices: Vec<i32>) -> Vec<String> {
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

fn build_bidasks(v: &Vec<String>, n: u32, offset: usize) -> (Vec<(f32, f32)>, Vec<(f32, f32)>) {
    let mut bids = vec![];
    let mut asks = vec![];
    let mut ptr = offset;

    for _ in 0..n {
        let bid_price = *&v[ptr].two_dec();
        let bid_qty = *&v[ptr + 1].two_dec();
        bids.push((bid_price, bid_qty));
        ptr += 2;
    }
    for _ in 0..n {
        let ask_price = *&v[ptr].two_dec();
        let ask_qty = *&v[ptr + 1].two_dec();
        asks.push((ask_price, ask_qty));
        ptr += 2;
    }

    (bids, asks)
}

trait StockFormat {
    fn two_dec(&self) -> f32;
}

// formats string to f32 with 2 decimal places
impl StockFormat for str {
    fn two_dec(&self) -> f32 {
        self.parse::<f32>().unwrap() / 100.0
    }
}
