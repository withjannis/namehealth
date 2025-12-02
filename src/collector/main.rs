use std::str::FromStr;

mod dns;

#[tokio::main]
async fn main() {
    println!("INFO: main started");
    let r = dns::NhResolver::new().await;

    println!("{:?}", r);

    let q = dns::NhQuery::new(
        domain::base::Name::<Vec<u8>>::from_str("namehealth.org.").unwrap(),
        domain::base::Rtype::TXT,
        None,
    )
    .await;

    let rslt = r.query::<domain::rdata::Txt<_>>(q).await;
    println!("{:?}", rslt);
}
