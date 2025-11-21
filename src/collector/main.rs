use serde_json::{Value, json};

use domain::base::{Name, Rtype};

use domain::rdata;
use std::str::FromStr;

use std::net::{IpAddr, SocketAddr};

use aws_config::{self, Region};
use aws_sdk_dynamodb::types::AttributeValue;
use chrono::Utc;

mod dns;
mod db;

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("")
}

async fn collect_records(qname: &str, nsaddr: SocketAddr, rtype: Rtype) -> Vec<Value> {
    let msg = dns::get_dns_msg(
        nsaddr,
        Name::vec_from_str(qname).unwrap(),
        rtype,
    ).await;

    match rtype {
        Rtype::SOA => {
            let rcrds = dns::get_dns_rcrd::<rdata::Soa<_>>(msg, Rtype::SOA, false).await;
            rcrds.into_iter().map(|r| {
                json!({
                    "name": r.owner().to_string(),
                    "class": r.class().to_string(),
                    "type": r.rtype().to_string(),
                    "ttl": r.ttl().as_secs(),
                    "data": {
                        "expire": r.data().expire().as_secs(),
                        "minimum": r.data().minimum().as_secs(),
                        "mname": r.data().mname().to_string(),
                        "refresh": r.data().refresh().as_secs(),
                        "retry": r.data().retry().as_secs(),
                        "rname": r.data().rname().to_string(),
                        "serial": r.data().serial().into_int(),
                    }
                })
            }).collect()
        }
        Rtype::A => {
            let rcrds = dns::get_dns_rcrd::<rdata::A>(msg, Rtype::A, false).await;
            rcrds.into_iter().map(|r| {
                json!({
                    "name": r.owner().to_string(),
                    "class": r.class().to_string(),
                    "type": r.rtype().to_string(),
                    "ttl": r.ttl().as_secs(),
                    "data": {
                        "addr": r.data().addr(),
                    }
                })
            }).collect()
        }
        Rtype::AAAA => {
            let rcrds = dns::get_dns_rcrd::<rdata::Aaaa>(msg, Rtype::AAAA, false).await;
            rcrds.into_iter().map(|r| {
                json!({
                    "name": r.owner().to_string(),
                    "class": r.class().to_string(),
                    "type": r.rtype().to_string(),
                    "ttl": r.ttl().as_secs(),
                    "data": {
                        "addr": r.data().addr(),
                    }
                })
            }).collect()
        }
        Rtype::MX => {
            let rcrds = dns::get_dns_rcrd::<rdata::Mx<_>>(msg, Rtype::MX, false).await;
            rcrds.into_iter().map(|r| {
                json!({
                    "name": r.owner().to_string(),
                    "class": r.class().to_string(),
                    "type": r.rtype().to_string(),
                    "ttl": r.ttl().as_secs(),
                    "data": {
                        "exchange": r.data().exchange().to_string(),
                        "preference": r.data().preference(),
                    }
                })
            }).collect()
        }
        Rtype::DS => {
            let rcrds = dns::get_dns_rcrd::<rdata::Ds<_>>(msg, Rtype::DS, false).await;
            rcrds.into_iter().map(|r| {
                let ds = r.data();
                json!({
                    "name": r.owner().to_string(),
                    "class": r.class().to_string(),
                    "type": r.rtype().to_string(),
                    "ttl": r.ttl().as_secs(),
                    "data": {
                        "key_tag": ds.key_tag().to_string(),
                        "algorithm": ds.algorithm().to_int(),
                        "digest_type": ds.digest_type().to_int(),
                        "digest": hex_encode(ds.digest()),
                    }
                })
            }).collect()
        }
        Rtype::DNSKEY => {
            let rcrds = dns::get_dns_rcrd::<rdata::Dnskey<_>>(msg, Rtype::DNSKEY, false).await;
            rcrds.into_iter().map(|r| {
                let k = r.data();
                json!({
                    "name": r.owner().to_string(),
                    "class": r.class().to_string(),
                    "type": r.rtype().to_string(),
                    "ttl": r.ttl().as_secs(),
                    "data": {
                        "flags": k.flags().to_string(),
                        "protocol": k.protocol().to_string(),
                        "algorithm": k.algorithm().to_int(),
                        "public_key": hex_encode(k.public_key()),
                    }
                })
            }).collect()
        }
        Rtype::TXT => {
            let rcrds = dns::get_dns_rcrd::<rdata::Txt<_>>(msg, Rtype::TXT, false).await;
            rcrds.into_iter().map(|r| {
                let k = r.data();
                json!({
                    "name": r.owner().to_string(),
                    "class": r.class().to_string(),
                    "type": r.rtype().to_string(),
                    "ttl": r.ttl().as_secs(),
                    "data": {
                        "text": String::from_utf8(k.text::<Vec<u8>>()).unwrap(),
                    }
                })
            }).collect()
        }
        _ => Vec::new(),
    }
}

async fn probe_and_store(
    client: &aws_sdk_dynamodb::Client,
    table: &str,
    qname: &str,
    nsaddr: SocketAddr,
    rtype: Rtype,
) {
    let records = collect_records(qname, nsaddr, rtype).await;

    let mark = format!("{}#{}", qname, rtype);
    let now_utc = Utc::now();
    let timestamp = now_utc.timestamp();

    let item = db::Item::new(
        ("mark".to_string(), AttributeValue::S(mark.clone())),
        ("timestamp".to_string(), AttributeValue::N(timestamp.to_string())),
        vec![
            ("fqdn".to_string(), AttributeValue::S(qname.to_string())),
            ("ns".to_string(), AttributeValue::S(nsaddr.to_string())),
            ("type".to_string(), AttributeValue::S(rtype.to_string())),
            ("records".to_string(), AttributeValue::S(serde_json::to_string(&records).unwrap())),
        ]
    );

    let _res = db::add_item(
        client,
        table.to_string(),
        item,
    ).await;

}

/// Ensure a domain config item exists in the table. If it does not exist, create it.
/// Runs the same logic that was previously inline in `main`.
async fn ensure_domain_config(
    client: aws_sdk_dynamodb::Client,
    table: &str,
    qname: String,
) {
    let domain_config = db::Item::new(
        ("mark".to_string(), AttributeValue::S(format!("config#domain#{}", qname))),
        ("timestamp".to_string(), AttributeValue::N("0".to_string())),
        vec![],
    );

    match db::get_item(&client, table.to_string(), domain_config.clone()).await {
        Ok(x) => {
            match x.item {
                Some(_) => println!("Domain {} is configured for probing.", qname),
                None => {
                    println!("Domain {} is NOT configured for probing.", qname);
                    if let Err(e) = db::add_item(&client, table.to_string(), domain_config).await {
                        eprintln!("failed to create domain config for {}: {:?}", qname, e);
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("error checking domain config for {}: {:?}", qname, e);
        }
    }
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

    // test
    // list of (fqdn, types to probe)
    let probes = vec![
        ("akamai.com",     vec![Rtype::SOA, Rtype::A, Rtype::MX, Rtype::AAAA, Rtype::DS, Rtype::DNSKEY, Rtype::TXT]),
        ("aws.com",        vec![Rtype::SOA, Rtype::A, Rtype::MX, Rtype::AAAA, Rtype::DS, Rtype::DNSKEY, Rtype::TXT]),
        ("cloudflare.com", vec![Rtype::SOA, Rtype::A, Rtype::MX, Rtype::AAAA, Rtype::DS, Rtype::DNSKEY, Rtype::TXT]),
        ("example.com",    vec![Rtype::SOA, Rtype::A, Rtype::MX, Rtype::AAAA, Rtype::DS, Rtype::DNSKEY, Rtype::TXT]),
        ("github.com",     vec![Rtype::SOA, Rtype::A, Rtype::MX, Rtype::AAAA, Rtype::DS, Rtype::DNSKEY, Rtype::TXT]),
        ("google.com",     vec![Rtype::SOA, Rtype::A, Rtype::MX, Rtype::AAAA, Rtype::DS, Rtype::DNSKEY, Rtype::TXT]),
        ("zg.ch",          vec![Rtype::SOA, Rtype::A, Rtype::MX, Rtype::AAAA, Rtype::DS, Rtype::DNSKEY, Rtype::TXT]),
    ];

    // collect handles for all probe tasks + config-check tasks, run them concurrently
    let mut handles = Vec::new();

    for (qname, types) in probes {
        // spawn a concurrent task to ensure domain config exists
        {
            let client_clone = dynamodb_client.clone();
            let q = qname.to_string();
            let table = "namehealth-v1".to_string();
            let handle = tokio::spawn(async move {
                ensure_domain_config(client_clone, &table, q).await;
            });
            handles.push(handle);
        }
 
         // spawn probe tasks for each rtype
         for rtype in types {
             let client_clone = dynamodb_client.clone();
             let q = qname.to_string();
             let ns = nsaddr;
             // rtype is copied/moved into closure
             let handle = tokio::spawn(async move {
                 probe_and_store(&client_clone, "namehealth-v1", &q, ns, rtype).await;
             });
             handles.push(handle);
         }
     }
 
     // wait for all probe tasks to finish
     for h in handles {
         if let Err(e) = h.await {
             eprintln!("probe task failed / panicked: {:?}", e);
         }
     }
 
     println!("All probes finished.");
 }


// What is the plan?
// collect_dnssec("aws.com")
//      aws.com. SOA, DS, DNSKEY
//      com. SOA, DS, DNSKEY
//      . SOA, (DS), DNSKEY

// collect("aws.com")
//      aws.com. SOA, DS, DNSKEY
//      com. SOA, DS, DNSKEY
//      . SOA, (DS), DNSKEY