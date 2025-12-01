use std::str::FromStr;

mod dns;

#[tokio::main]
async fn main() {
    println!("INFO: main started");
    let r = dns::NhResolver::new().await;

    println!("{:?}", r);

    let q = dns::NhQuery::new(
        domain::base::Name::<Vec<u8>>::from_str("akamai.com.").unwrap(),
        domain::base::Rtype::SOA,
        None
    ).await;

    let rslt = r.query::<domain::rdata::Soa<_>>(q).await;
    println!("{:?}", rslt);
}