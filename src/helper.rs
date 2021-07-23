use crate::quote::Quote;
use chrono::{TimeZone, Utc};
use std::str;

pub fn is_valid_quote(b: &[u8]) -> bool {
    return b.len() > 225 && &b[42..47] == [66, 54, 48, 51, 52];
}

pub fn digest(s: &str, slices: Vec<i32>) -> Vec<&str> {
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

pub fn build_bidasks(v: &Vec<&str>, n: u32, offset: usize) -> (Vec<(f32, f32)>, Vec<(f32, f32)>) {
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

    (bids.into_iter().rev().collect(), asks)
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

pub fn build_quote(t: u32, b: &[u8]) -> Quote {
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

    Quote {
        pkt_time,
        accept_time,
        issue_code,
        bids,
        asks,
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
