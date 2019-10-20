use chrono::{DateTime, Duration, TimeZone, Utc};
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::*;
use std::cmp::Ordering;
use std::env;
use std::fs::File;
use std::path::Path;
use std::str;
use std::time::Instant;

fn main() {
    let now = Instant::now();
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        panic!("Error: no file was specified");
    }
    let path: &Path = Path::new(&args[1]);

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
    quotes.sort();
    for q in quotes {
        println!("{}", q.to_string());
    }
    println!("finished at: {} seconds", now.elapsed().as_secs());
}

fn is_valid_quote(b: &[u8]) -> bool {
    return b.len() > 225 && &b[42..47] == [66, 54, 48, 51, 52];
}

fn build_quote(t: u32, b: &[u8]) -> Quote {
    let s = str::from_utf8(&b[..214]).unwrap();
    // the lengths of the slices we're grouping together,
    // negative is the number of chars to skip
    let slice_instructions = vec![
        -5, 12, -12, 5, 7, 5, 7, 5, 7, 5, 7, 5, 7, -7, 5, 7, 5, 7, 5, 7, 5, 7, 5, 7, -50, 8,
    ];
    let arr = digest(s, slice_instructions);
    let pkt_time = Utc.timestamp(t as i64, 0);
    let issue_code = &arr[0];
    let (bids, asks) = build_bidasks(&arr, 5, 1);
    let accept_time = accept_dt(&arr[21]).unwrap();
    let quote = Quote {
        pkt_time,
        accept_time,
        issue_code,
        bids,
        asks,
    };
    quote
}

struct Quote<'a> {
    pkt_time: DateTime<Utc>,
    accept_time: i64,
    issue_code: &'a str,
    bids: Vec<(f32, f32)>,
    asks: Vec<(f32, f32)>,
}

impl<'a> Quote<'a> {
    pub fn to_string(&self) -> String {
        let accept_dt_fmt = accept_fmt(&self.accept_time).unwrap();
        format!(
            "{} {} {} {} {} {} {} {} {} {} {} {} {}",
            self.pkt_time.format("%Y-%m-%dT%H:%M:%S").to_string(),
            accept_dt_fmt.format("%Y-%m-%dT%H:%M:%S%.f").to_string(),
            //self.accept_time,
            self.issue_code,
            qp_fmt(&self.bids[4]),
            qp_fmt(&self.bids[3]),
            qp_fmt(&self.bids[2]),
            qp_fmt(&self.bids[1]),
            qp_fmt(&self.bids[0]),
            qp_fmt(&self.asks[0]),
            qp_fmt(&self.asks[1]),
            qp_fmt(&self.asks[2]),
            qp_fmt(&self.asks[3]),
            qp_fmt(&self.asks[4]),
        )
    }
}

// convert to quantity@price string
fn qp_fmt(s: &(f32, f32)) -> String {
    format!("{:.2}@{:.2}", s.1, s.0)
}

impl<'a> Ord for Quote<'a> {
    fn cmp(&self, other: &Quote) -> Ordering {
        self.accept_time.cmp(&other.accept_time)
    }
}

impl<'a> PartialOrd for Quote<'a> {
    fn partial_cmp(&self, other: &Quote) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<'a> PartialEq for Quote<'a> {
    fn eq(&self, other: &Quote) -> bool {
        self.accept_time == other.accept_time
    }
}

impl<'a> Eq for Quote<'a> {}

fn digest(s: &str, slices: Vec<i32>) -> Vec<&str> {
    let mut out: Vec<&str> = vec![];
    let mut ptr = 0 as usize;
    for n in slices {
        let len = n.abs() as usize;
        if n < 0 {
            ptr += len;
        } else {
            out.push(s.get(ptr..ptr + len).unwrap());
            ptr += len;
        }
    }
    out
}

fn build_bidasks(v: &Vec<&str>, n: u32, offset: usize) -> (Vec<(f32, f32)>, Vec<(f32, f32)>) {
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

fn accept_dt(a: &str) -> Option<i64> {
    // convert time units to microseconds
    let hour = a.get(0..2)?.parse::<i64>().ok()? * 3_600_000_000;
    let minute = a.get(2..4)?.parse::<i64>().ok()? * 60_000_000;
    let second = a.get(4..6)?.parse::<i64>().ok()? * 1_000_000;
    let microsecond = a.get(6..8)?.parse::<i64>().ok()?;

    let sum = hour + minute + second + microsecond;
    let difference = sum - (3_600_000_000 * 9);

    Some(difference)
}

fn accept_fmt(a: &i64) -> Option<chrono::DateTime<chrono::offset::Utc>> {
    // using february 16, 2011 midnight as the base
    let accept_base = Utc.timestamp(1297814400, 0);
    let accept_time = Duration::microseconds(*a);
    accept_base.checked_add_signed(accept_time)
}
