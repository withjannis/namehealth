use aws_sdk_dynamodb::config::auth;
use bytes::Bytes;

use domain::base::{
    self,
    Message,
    MessageBuilder,
    Name,
    ParseRecordData,
    ParsedName,
    Record,
    Rtype,
};

use domain::rdata;

use domain::net::client::{ dgram, dgram_stream, multi_stream, stream };
use domain::net::client::protocol::{ TcpConnect, UdpConnect };
use domain::net::client::request::{ ComposeRequest, RequestMessage, SendRequest };

use std::borrow::Cow;
use once_cell::sync::Lazy;
use std::net::SocketAddr;

use std::fmt::Debug;
use std::net::IpAddr;
use std::str::FromStr;

use std::time::Duration;

// replace the broken async get_root_nameservers with a static Lazy vector
static ROOT_NS: Lazy<Vec<SocketAddr>> = Lazy::new(|| vec![
    SocketAddr::new(IpAddr::from_str("198.41.0.4").unwrap(), 53),
    SocketAddr::new(IpAddr::from_str("170.247.170.2").unwrap(), 53),
    SocketAddr::new(IpAddr::from_str("192.33.4.12").unwrap(), 53),
    SocketAddr::new(IpAddr::from_str("199.7.91.13").unwrap(), 53),
    SocketAddr::new(IpAddr::from_str("192.203.230.10").unwrap(), 53),
    SocketAddr::new(IpAddr::from_str("192.5.5.241").unwrap(), 53),
    SocketAddr::new(IpAddr::from_str("192.112.36.4").unwrap(), 53),
    SocketAddr::new(IpAddr::from_str("198.97.190.53").unwrap(), 53),
    SocketAddr::new(IpAddr::from_str("192.36.148.17").unwrap(), 53),
    SocketAddr::new(IpAddr::from_str("192.58.128.30").unwrap(), 53),
    SocketAddr::new(IpAddr::from_str("193.0.14.129").unwrap(), 53),
    SocketAddr::new(IpAddr::from_str("199.7.83.42").unwrap(), 53),
    SocketAddr::new(IpAddr::from_str("202.12.27.33").unwrap(), 53),
]);

pub fn get_root_nameservers() -> &'static [SocketAddr] {
    &ROOT_NS
}

pub async fn get_dns_msg(ns: SocketAddr, na: Name<Vec<u8>>, rt: Rtype) -> Message<bytes::Bytes> {
    // Destination for UDP and TCP
    let mut msg = MessageBuilder::new_vec();
    msg.header_mut().set_rd(true);
    // msg.header_mut().set_ad(true);
    msg.header_mut().set_random_id();

    let mut qst = msg.question();
    qst.push((na, rt)).unwrap();

    let mut reqmsg = RequestMessage::new(qst).unwrap();

    reqmsg.set_dnssec_ok(true);
    reqmsg.set_udp_payload_size(1400);

    let mut stream_config = stream::Config::new();

    stream_config.set_response_timeout(Duration::from_millis(100));

    let multi_stream_config = multi_stream::Config::from(stream_config.clone());

    // Create a new UDP+TCP transport connection. Pass the destination address
    // and port as parameter.

    let mut dgram_config = dgram::Config::new();
    dgram_config.set_max_parallel(1);
    dgram_config.set_read_timeout(Duration::from_millis(1000));
    dgram_config.set_max_retries(1);
    dgram_config.set_udp_payload_size(Some(1400));

    let dgram_stream_config = dgram_stream::Config::from_parts(
        dgram_config.clone(),
        multi_stream_config.clone()
    );

    let udp_connect = UdpConnect::new(ns);
    let tcp_connect = TcpConnect::new(ns);

    let (udptcp_conn, transport) = dgram_stream::Connection::with_config(
        udp_connect,
        tcp_connect,
        dgram_stream_config.clone()
    );

    tokio::spawn(transport.run());

    // Send a query message.
    let mut request = udptcp_conn.send_request(reqmsg.clone());

    // Get the reply
    let reply = request.get_response().await;

    let answer = reply.expect("");

    answer
}

pub async fn get_dns_rcrd<RecordData>(
    dnsmsg: Message<bytes::Bytes>,
    rt: Rtype, // record type
    rs: bool // record signature
) -> Vec<Record<ParsedName<bytes::Bytes>, RecordData>>
    where for<'a> RecordData: Debug + ParseRecordData<'a, Bytes>
{
    let mut records: Vec<Record<ParsedName<bytes::Bytes>, RecordData>> = vec![];
    let dnsanswer = dnsmsg.answer().expect("");

    for rpr in dnsanswer {
        let pr = rpr.expect("");
        if pr.rtype() == rt {
            let ar = pr.to_record::<RecordData>();
            records.push(ar.expect("").unwrap());
        }
        if rs && pr.rtype() == Rtype::RRSIG {
            todo!();
        }
    }
    records
}

use futures::{FutureExt, future::BoxFuture};

// Replace the recursive async fn with a boxed-returning function to allow recursion.
pub fn get_auth_ns(
    na: Name<Vec<u8>>,
    base_ns: Option<Vec<SocketAddr>>
) -> BoxFuture<'static, Vec<Record<ParsedName<bytes::Bytes>, rdata::Ns<ParsedName<bytes::Bytes>>>>> {
    Box::pin(async move {
        // use borrowed slice when possible to avoid copying ROOT_NS
        let ns_cow: Cow<'_, [SocketAddr]> = match base_ns {
            Some(v) => Cow::Owned(v),
            None => Cow::Borrowed(get_root_nameservers()),
        };

        println!("Getting NS for {:?} using NS {:?}", na, ns_cow);

        for &ns_addr in ns_cow.iter() {
            let dnsmsg = get_dns_msg(ns_addr, na.clone(), Rtype::NS).await;

            if dnsmsg.header_counts().ancount() > 0 {
                let rcrds = dnsmsg.answer().expect("").limit_to_in::<rdata::Ns<_>>();
                let mut result: Vec<Record<ParsedName<bytes::Bytes>, rdata::Ns<ParsedName<bytes::Bytes>>>> = vec![];

                for rcrd in rcrds {
                    let rcrd = rcrd.expect("");
                    result.push(rcrd);
                }
                return result;
            } else {
                let mut auth_ns: Vec<SocketAddr> = vec![];
                println!("No answer, checking authority/additional sections");
                println!("DNS Message: {}", dnsmsg.display_dig_style());
                if dnsmsg.header_counts().nscount() > 0 {
                    let nsc = dnsmsg.authority().expect("").limit_to_in::<rdata::Ns<_>>();

                    for auth_rcrd in nsc {
                        println!("Found NS Name in authority section: {:?}", auth_rcrd);
                        let auth_rcrd = auth_rcrd.expect("");

                        println!("Searching for NS IP in additional section: {:?}", auth_rcrd);
                        let mut found_ip = false;
                        for add_rcrd in dnsmsg.additional().expect("") {
                            let add_rcrd = add_rcrd.expect("");

                            if add_rcrd.owner() == auth_rcrd.data().nsdname()
                                && add_rcrd.rtype() == Rtype::A
                            {
                                let a_rcrd = add_rcrd.to_record::<rdata::A>().expect("").unwrap();
                                let ipv4 = SocketAddr::new(IpAddr::V4(a_rcrd.data().addr()), 53);
                                auth_ns.push(ipv4);
                                found_ip = true;
                            }
                        }
                        if !found_ip {
                            println!("No A record found in additional section for NS: {:?}", auth_rcrd.data().nsdname());
                            println!("Need to resolve NS name to IP separately");
                            let ns_dnsmsg = get_dns_msg(ns_addr, na.clone(), Rtype::A).await;
                            let a_rcrds = ns_dnsmsg.answer().expect("").limit_to_in::<rdata::A>();
                            for a_rcrd in a_rcrds {
                                let a_rcrd = a_rcrd.expect("");
                                if a_rcrd.owner() == auth_rcrd.data().nsdname() {
                                    let ipv4 = SocketAddr::new(IpAddr::V4(a_rcrd.data().addr()), 53);
                                    auth_ns.push(ipv4);
                                }
                            }
                        }
                        
                    }
                    // recursive call is allowed now because function returns a boxed future
                    return get_auth_ns(na.clone(), Some(auth_ns)).await;
                }
            }
        }

        vec![]
    })
}

mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_dns_msg() {
        assert_eq!(get_root_nameservers().len(), 13);
    }
//    async fn test_get_auth_ns() {
//        let ns_records = super::get_auth_ns(
//            domain::base::Name::vec_from_str("akamai.com").unwrap(),
//            None
//        ).await;
//
//        println!("NS Records: {:?}", ns_records);
//    }
}