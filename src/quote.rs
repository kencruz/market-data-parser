use chrono::{DateTime, Duration, TimeZone, Utc};
use std::cmp::Ordering;

pub struct Quote<'a> {
    pub pkt_time: DateTime<Utc>,
    pub accept_time: i64,
    pub issue_code: &'a str,
    pub bids: Vec<(f32, f32)>,
    pub asks: Vec<(f32, f32)>,
}

impl<'a> Quote<'a> {
    pub fn to_string(&self) -> String {
        let accept_dt_fmt = accept_fmt(&self.accept_time).unwrap();
        format!(
            "{} {} {} {} {}",
            self.pkt_time.format("%Y-%m-%dT%H:%M:%S").to_string(),
            accept_dt_fmt.format("%Y-%m-%dT%H:%M:%S%.f").to_string(),
            self.issue_code,
            qp_string(&self.bids),
            qp_string(&self.asks),
        )
    }
}

fn qp_string<'a>(s: &'a [(f32, f32)]) -> String {
    s.into_iter()
        .map(|x| qp_fmt(x))
        .collect::<Vec<String>>()
        .join(" ")
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

fn accept_fmt(a: &i64) -> Option<chrono::DateTime<chrono::offset::Utc>> {
    // using february 16, 2011 midnight as the base
    let accept_base = Utc.timestamp(1297814400, 0);
    let accept_time = Duration::microseconds(*a);
    accept_base.checked_add_signed(accept_time)
}
