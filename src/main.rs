extern crate lambda_runtime as lambda;

extern crate log;
extern crate simple_logger;

extern crate chrono;
extern crate data_encoding;

extern crate serde;
extern crate serde_json;
extern crate serde_derive;

#[macro_use]
extern crate lazy_static;
extern crate regex;
extern crate rayon;

use serde_derive::{Serialize, Deserialize};
use lambda::{lambda, Context, error::HandlerError};
use std::error::Error;

use std::fmt;
use chrono::prelude::*;
use data_encoding::BASE64;
use regex::Regex;
use rayon::prelude::*;

lazy_static! {
    static ref RE: Regex = Regex::new(r#"^([\d.]+) (\S+) (\S+) \[([\w:/]+\s[\+\-]\d{2}:?\d{2}){0,1}\] "(.+?)" (\d{3}) (\d+)"#).unwrap();
}

fn main() -> Result<(), Box<dyn Error>> {
    simple_logger::init_with_level(log::Level::Error).unwrap();
    lambda!(my_handler);

    Ok(())
}

#[derive(Debug)]
enum LogError {
    RegexParseError,
    UTF8Error(std::string::FromUtf8Error),
    EncodingError(data_encoding::DecodeError),
    DateTimeParseError(chrono::ParseError),
    IntError(std::num::ParseIntError),
    JsonError(serde_json::Error)
}

impl From<std::string::FromUtf8Error> for LogError {
    fn from(err: std::string::FromUtf8Error) -> LogError {
        LogError::UTF8Error(err)
    }
}

impl From<data_encoding::DecodeError> for LogError {
    fn from(err: data_encoding::DecodeError) -> LogError {
        LogError::EncodingError(err)
    }
}

impl From<chrono::ParseError> for LogError {
    fn from(err: chrono::ParseError) -> LogError {
        LogError::DateTimeParseError(err)
    }
}

impl From<std::num::ParseIntError> for LogError {
    fn from(err: std::num::ParseIntError) -> LogError {
        LogError::IntError(err)
    }
}

impl From<serde_json::Error> for LogError {
    fn from(err: serde_json::Error) -> LogError {
        LogError::JsonError(err)
    }
}

impl fmt::Display for LogError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            LogError::RegexParseError => fmt::Display::fmt(self, f),
            LogError::UTF8Error(ref err) => fmt::Display::fmt(err, f),
            LogError::EncodingError(ref err) => fmt::Display::fmt(err, f),
            LogError::DateTimeParseError(ref err) => fmt::Display::fmt(err, f),
            LogError::IntError(ref err) => fmt::Display::fmt(err, f),
            LogError::JsonError(ref err) => fmt::Display::fmt(err, f),
        }
    }
}

impl std::error::Error for LogError {
    fn description(&self) -> &str {
        match *self {
            LogError::RegexParseError => "FAIL. unmatched pattern.",
            LogError::UTF8Error(ref err) => err.description(),
            LogError::EncodingError(ref err) => err.description(),
            LogError::DateTimeParseError(ref err) => err.description(),
            LogError::IntError(ref err) => err.description(),
            LogError::JsonError(ref err) => err.description(),
        }
    }
}

fn apache_log2json(s: &str) -> Result<serde_json::Value, LogError> {
    let xs = RE.captures(s).ok_or(LogError::RegexParseError)?;

    let time =
        DateTime::parse_from_str(&xs[4], "%d/%b/%Y:%H:%M:%S %:z")
            .or_else(|_| DateTime::parse_from_str(&xs[4], "%d/%b/%Y:%H:%M:%S %z"))?;

    let log =  AccessLog {
        host: &xs[1],
        ident: &xs[2],
        authuser: &xs[3],
        timestamp: time.to_rfc3339(),
        timestamp_utc: time.with_timezone(&Utc).to_rfc3339(),
        request: &xs[5],
        response: xs[6].parse::<u32>()?,
        bytes: xs[7].parse::<u32>()?,
    };
    serde_json::to_value(log).map_err(|e| LogError::JsonError(e))
}

fn transform_data(data: Vec<u8>) -> std::result::Result<Vec<u8>, LogError> {
    let s = String::from_utf8(data)?;
    let r = apache_log2json(&s)?;
    serde_json::to_vec(&r).map_err(|e| LogError::JsonError(e))
}

#[test]
fn transform_data_test() {
    let data = r#"7.248.7.119 - - [14/Dec/2017:22:16:45 +09:00] "GET /explore" 200 9947 "-" "Mozilla/5.0 (Windows NT 6.2; WOW64; rv:8.5) Gecko/20100101 Firefox/8.5.1" "#;
    let a = apache_log2json(data).unwrap();

    println!("{}", a);
}

fn transform_record(record: &FirehoseRecord) -> TransformationRecord {
    BASE64.decode(record.data.as_bytes()).map_err(|e| LogError::EncodingError(e))
        .and_then(|x|
            transform_data(x)
                .map(|x|
                    TransformationRecord {
                        record_id: record.record_id.to_string(),
                        data: BASE64.encode(&x),
                        result: OK,
                    }
                )
        )
        .unwrap_or_else(|_|
            TransformationRecord {
                record_id: record.record_id.to_string(),
                data: record.data.to_string(),
                result: NG,
            }
        )
}

fn my_handler<'a>(event: FirehoseEvent, _: Context) -> Result<TransformationEvent, HandlerError> {
    let records = event.records
        .par_iter()
        .map(|x| transform_record(x))
        .collect();

    Ok(TransformationEvent { records })
}

#[derive(Serialize, Deserialize, Debug)]
struct AccessLog<'a> {
    host: &'a str,
    ident: &'a str,
    authuser: &'a str,
    #[serde(rename = "@timestamp")]
    timestamp: String,
    #[serde(rename = "@timestamp_utc")]
    timestamp_utc: String,
    request: &'a str,
    response: u32,
    bytes: u32,
}

#[derive(Serialize, Deserialize, Debug)]
struct FirehoseEvent {
    records: Vec<FirehoseRecord>,
    region: String,
    #[serde(rename = "invocationId")]
    invocation_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct FirehoseRecord {
    #[serde(rename = "recordId")]
    record_id: String,
    data: String,
    #[serde(rename = "approximateArrivalTimestamp")]
    approximate_arrival_timestamp: f64,
}

#[derive(Serialize, Debug)]
struct TransformationEvent {
    records: Vec<TransformationRecord>,
}

static OK: &'static str = "Ok";
static NG: &'static str = "ProcessingFailed";

#[derive(Serialize, Debug)]
struct TransformationRecord {
    #[serde(rename = "recordId")]
    record_id: String,
    result: &'static str,
    data: String,
}