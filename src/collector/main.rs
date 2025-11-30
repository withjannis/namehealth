use std::{ vec, str::FromStr };

use std::net::{ IpAddr, SocketAddr };

use domain::base::{
    Message,
    MessageBuilder,
    Name,
    Rtype,
    ToName,
    Record,
    ParsedName,
    message::RecordSection,
    wire::ParseError,
};

use domain::net::client::{ dgram, dgram_stream, multi_stream, stream };
use domain::net::client::protocol::{ TcpConnect, UdpConnect };
use domain::net::client::request::{ ComposeRequest, RequestMessage, SendRequest };

use domain::rdata::{ A, Ns };

use std::time::Duration;

#[derive(Debug)]
struct NhQuery {
    na: Name<Vec<u8>>,
    rt: Rtype,
    ns: Vec<SocketAddr>,
}

impl NhQuery {
    async fn new(a: Name<Vec<u8>>, b: Rtype, c: Option<Vec<SocketAddr>>) -> Self {
        NhQuery { na: a, rt: b, ns: c.unwrap_or(NhResolver::root_ns().await) }
    }
}

#[derive(Debug)]
struct NhResolver {}

impl NhResolver {
    async fn new() -> NhResolver {
        NhResolver {}
    }

    async fn root_ns() -> Vec<SocketAddr> {
        vec![
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
            SocketAddr::new(IpAddr::from_str("202.12.27.33").unwrap(), 53)
        ]
    }

    async fn _sctn_rcrds(
        &self,
        a: Result<&RecordSection<'_, bytes::Bytes>, &ParseError>,
        b: &mut Vec<Record<ParsedName<bytes::Bytes>, A>>
    ) -> () {
        let answ_sec = match a {
            Ok(o) => o.limit_to_in::<A>(),
            Err(e) => panic!("{e}"),
        };

        for rcrd_res in answ_sec {
            let rcrd = match rcrd_res {
                Ok(o) => o,
                Err(e) => {
                    eprintln!("RECORD PANICED, skipping this record {}", e);
                    continue;
                }
            };

            b.push(rcrd);
        }
        return ();
    }

    async fn _ns_rcrds(
        &self,
        a: Result<&RecordSection<'_, bytes::Bytes>, &ParseError>,
        b: Result<&RecordSection<'_, bytes::Bytes>, &ParseError>,
        c: &mut Vec<SocketAddr>,
    ) -> () {

        let a_sec = match a {
            Ok(o) => o.limit_to_in::<Ns<_>>(),
            Err(e) => panic!("{e}"),
        };

        let b_sec = match b {
            Ok(o) => o.limit_to_in::<A>(),
            Err(e) => panic!("{e}"),
        };

        for ns_rcrd_res in a_sec {
            let ns_rcrd = ns_rcrd_res.expect("");
            for a_rcrd_res in b_sec.clone() {
                let a_rcrd = a_rcrd_res.expect("");
                if ns_rcrd.data().nsdname() == a_rcrd.owner() {
                    c.push(
                        SocketAddr::new(a_rcrd.data().addr().try_into().unwrap(), 53)
                    );

                }
                
            } 
        }
        
    }

    async fn _get_rcrds(
        &self,
        nhq: NhQuery
    ) -> Vec<Record<ParsedName<bytes::Bytes>, domain::rdata::A>> {

        for ns in nhq.ns {
            println!("query {} {} @{:?}", nhq.na, nhq.rt, ns);
            let rspns = self._get_msg(nhq.na.clone(), nhq.rt, ns).await;

            // check if contains answer
            if rspns.header_counts().ancount() > 0 {
                println!("answer");
                let mut rslt_rcrds: Vec<
                    Record<ParsedName<bytes::Bytes>, domain::rdata::A>
                > = vec![];

                // extract records from section into vector
                self._sctn_rcrds(rspns.answer().as_ref(), &mut rslt_rcrds).await;

                return rslt_rcrds;
            }

            if rspns.header_counts().nscount() > 0 {
                println!("authority");
                let ns_auth_sec = match rspns.authority() {
                    Ok(o) => o.limit_to_in::<Ns<_>>(),
                    Err(e) => panic!("{e}"),
                };

                for ns_rcrd_res in ns_auth_sec {
                    let ns_rcrd = match ns_rcrd_res {
                        Ok(o) => o,
                        Err(e) => {
                            eprintln!("RECORD PANICED, skipping this record {}", e);
                            continue;
                        }
                    };

                    println!("{:?}", ns_rcrd.data());

                    // start looking for ip of this nameserver
                    // now searching for a new authority to send the next request to.
                    let mut nxt_auth_ns: Vec<SocketAddr> = vec![];

                    if rspns.header_counts().adcount() > 0 {

                        self._ns_rcrds(rspns.authority().as_ref(), rspns.additional().as_ref(), &mut nxt_auth_ns).await;

                        // let a_add_sec = match rspns.additional() {
                        //     Ok(o) => o.limit_to_in::<A>(),
                        //     Err(e) => panic!("{e}"),
                        // };
                        // for a_rcrd_res in a_add_sec {
                        //     let a_rcrd = match a_rcrd_res {
                        //         Ok(o) => o,
                        //         Err(e) => {
                        //             eprintln!("RECORD PANICED, skipping this record {}", e);
                        //             continue;
                        //         }
                        //     };

                        //     if a_rcrd.owner() == ns_rcrd.data().nsdname() {
                        //         println!(
                        //             "found address ({}) for {}",
                        //             a_rcrd.data().addr(),
                        //             ns_rcrd.data().nsdname()
                        //         );
                        //         nxt_auth_ns.push(
                        //             SocketAddr::new(a_rcrd.data().addr().try_into().unwrap(), 53)
                        //         );
                        //     }
                        // }
                    }

                    if nxt_auth_ns.len() == 0 {
                        // f***ing useless additional section
                        let a_rcrd_q = NhQuery::new(
                            ns_rcrd.data().nsdname().to_name(),
                            Rtype::A,
                            None
                        ).await;
                        let a_rcrd_rspns = Box::pin(self._get_rcrds(a_rcrd_q)).await;
                        for a_rcrd in a_rcrd_rspns {
                            nxt_auth_ns.push(
                                SocketAddr::new(a_rcrd.data().addr().try_into().unwrap(), 53)
                            );
                        }
                    }

                    println!(
                        "created list of ips ({:?}) for {:?} | {:?}",
                        nxt_auth_ns,
                        ns_rcrd.data().nsdname(),
                        rspns.authority().expect("").next().expect("").expect("").owner()
                    );

                    // create new request
                    let q = NhQuery::new(nhq.na.clone(), nhq.rt, Some(nxt_auth_ns)).await;

                    return Box::pin(self._get_rcrds(q)).await;
                }
            }

            break;
        }

        return vec![];
    }

    async fn query(&self, nhq: NhQuery) -> String {
        self._get_rcrds(nhq).await;
        "wip".to_string()
    }

    // some magic here!
    async fn _get_msg(
        &self,
        na: Name<Vec<u8>>,
        rt: Rtype,
        ns: SocketAddr
    ) -> Message<bytes::Bytes> {
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
}

#[tokio::main]
async fn main() {
    println!("INFO: main started");
    let r = NhResolver::new().await;

    println!("{:?}", r);

    let q = NhQuery::new(
        domain::base::Name::<Vec<u8>>::from_str("example.com.").unwrap(),
        domain::base::Rtype::A,
        None
    ).await;

    let rslt = r.query(q).await;
    println!("{:?}", rslt);
}
