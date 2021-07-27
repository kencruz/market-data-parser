# Market Data Parser

A market data parser app written in Rust. It will that will parse and print quote messages from a market data feed, particularly from UDP packets stored from a standard pcap file.  Features support to output parsed data to a CSV compatible format.

## Getting started

Ensure [rust](https://www.rust-lang.org/tools/install) is installed in your system.

Clone this repo:

```
$ git clone https://github.com/kencruz/market-data-parser.git && cd market-data-parser
```

## Usage

Print out the market data feed. Sample data from the Kospi 200 market feed is included in the repo.
```
$ cargo run data/mdf-kospi200.20110216-0.pcap
```
To sort by quote accept time:
```
$ cargo run data/mdf-kospi200.20110216-0.pcap -r
```
To display results in a csv file format
```
$ cargo run data/mdf-kospi200.20110216-0.pcap -c
```
To save csv results in a file named `output.csv`:
```
$ cargo run data/mdf-kospi200.20110216-0.pcap -c > output.csv
```

## Dependencies

- [pcap-parser](https://crates.io/crates/pcap-parser)
- [chrono](https://crates.io/crates/chrono)
- [getopts](https://crates.io/crates/getopts)
