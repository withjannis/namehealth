// ...existing code...
use serde_json::{Value, json};

use domain::base::{Name, Rtype};

use domain::rdata;
use std::str::FromStr;

use std::net::{IpAddr, SocketAddr};

use aws_config::{self, Region};
use aws_sdk_dynamodb::types::AttributeValue;
use chrono::Utc;

mod dns;
// mod db;

async fn get_auth_ns() {
    // Placeholder for future implementation
    dns::get_auth_ns(Name::vec_from_str("akamai.com").unwrap(), None).await; 
    todo!();
    // query dns for NS records

    // return list of authoritative nameservers
}

async fn collect_plain() {
    // Placeholder for future implementation
    todo!();
    // query dns record

    // store in dynamodb

    // return Result
}

async fn collect_dnssec_chain() {
    // Placeholder for future implementation
    todo!();
    // for each level in the chain
    //      query dns record
    
    // verify dnssec chain (do this later)

    // store in dynamodb

    // return Result
}

#[tokio::main]
async fn main() {
    let awsconfig = aws_config::from_env()
        .profile_name("nh-ddb-rw")
        .region(Region::new("eu-west-3"))
        .load().await;

    let dynamodb_client = aws_sdk_dynamodb::Client::new(&awsconfig);

    let nsaddr = SocketAddr::new(
        IpAddr::from_str("1.1.1.1").unwrap(), 53
    );

    let dnsmsg = dns::get_dns_msg(nsaddr,
        Name::vec_from_str("akamai.com").unwrap(),
        Rtype::A,
    ).await;

    // println!("DNS Message: {:?}", dnsmsg.answer().expect("")));
    let records = dnsmsg.answer().expect("").limit_to_in::<rdata::AllRecordData<_, _>>();

    for record in  records {
        let record = record.expect("");
        println!("Record: {:?}", json!(record).to_string());
    }
    return;
}

// Idea
// 