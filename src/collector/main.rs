use std::{ vec, str::FromStr };

use std::net::{ IpAddr, SocketAddr };

use domain::base::ToName;
use domain::base::{
    Message,
    MessageBuilder,
    Name,
    Rtype,
    Record,
    ParsedName,
    message::RecordSection,
};

use domain::net::client::{ dgram, dgram_stream, multi_stream, stream };
use domain::net::client::protocol::{ TcpConnect, UdpConnect };
use domain::net::client::request::{ ComposeRequest, RequestMessage, SendRequest };

use domain::rdata::{ A, Ns };

use rand;

use std::time::Duration;

async fn chaos_monkey(info: &str) -> bool {
    let x = rand::random::<u8>();
    if 10 > x {
        println!("⚠️ {}: trigger error {}", info, x);
        return true;
    };
    return false;
}

#[derive(Debug, Clone)]
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
        a: &RecordSection<'_, bytes::Bytes>,
        b: &mut Vec<Record<ParsedName<bytes::Bytes>, A>>
    ) -> Result<(), ()> {

        // fuzzing my code so trigger errors on purpose
        if chaos_monkey("_sctn_rcrds").await {
            return Err(());
        }

        let answ_sec = a.limit_to_in::<A>();

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
        return Ok(());
    }

    async fn _ns_a_rcrds(
        &self,
        a: &RecordSection<'_, bytes::Bytes>,
        b: &RecordSection<'_, bytes::Bytes>,
        c: &mut Vec<SocketAddr>
    ) -> Result<(), ()> {

        // fuzzing my code so trigger errors on purpose
        if chaos_monkey("_ns_a_rcrds").await {
            return Err(());
        }

        let athrty_sec = a.limit_to_in::<Ns<_>>();
        let addtnl_sec = b.limit_to_in::<A>();

        for ns_rcrd_res in athrty_sec {
            let ns_rcrd = ns_rcrd_res.expect("");
            for a_rcrd_res in addtnl_sec.clone() {
                let a_rcrd = a_rcrd_res.expect("");
                if ns_rcrd.data().nsdname() == a_rcrd.owner() {
                    c.push(SocketAddr::new(a_rcrd.data().addr().try_into().unwrap(), 53));
                }
            }
        }
        return if c.len() > 0 { Ok(()) } else { Err(()) };
    }

    async fn _get_rcrds(
        &self,
        nhq: NhQuery
    ) -> Result<Vec<Record<ParsedName<bytes::Bytes>, domain::rdata::A>>, ()> {

        // fuzzing my code so trigger errors on purpose
        if chaos_monkey("_get_rcrds").await {
            return Err(());
        }

        for ns in nhq.ns {
            println!("query {} {} @{:?}", nhq.na, nhq.rt, ns);
            let rspns = self._get_msg(nhq.na.clone(), nhq.rt, ns).await;

            // prepare all sections (answer, authority & additional)
            let answr_sctn = rspns.answer().expect("Answer Section failed to parse!");
            let athrty_sctn = rspns.authority().expect("Authority Section failed to parse!");
            let addtnl_sctn = rspns.additional().expect("Additional Section failed to parse!");

            // check if contains answer
            if rspns.header_counts().ancount() > 0 {
                let mut rslt_rcrds: Vec<
                    Record<ParsedName<bytes::Bytes>, domain::rdata::A>
                > = vec![];

                // extract records from section into vector
                if self._sctn_rcrds(&answr_sctn, &mut rslt_rcrds).await.is_ok() {
                    println!("RESULT {:?}", rslt_rcrds);
                    return Ok(rslt_rcrds);
                } else {
                    return Err(());
                }
            }

            if rspns.header_counts().nscount() > 0 {
                println!("authority");

                let mut nxt_auth_ns: Vec<SocketAddr> = vec![];
                if rspns.header_counts().adcount() > 0 {
                    match self._ns_a_rcrds(&athrty_sctn, &addtnl_sctn, &mut nxt_auth_ns).await {
                        Ok(_) => (),
                        Err(_) => {
                            eprintln!("Extracting Nameserver with Glue was not possible.");
                        }
                    }
                }
                let mut ns_iterator = athrty_sctn.limit_to_in::<Ns<_>>();
                loop {
                    if nxt_auth_ns.len() == 0 {
                        let x = match ns_iterator.next() {
                            Some(s) => {
                                println!("next ns is {:?}", s);
                                s
                            },
                            None => {
                                break;
                            }
                        };

                        let y = x.expect("");
                        let a_rcrd_q = NhQuery::new(
                            y.data().nsdname().to_name(),
                            Rtype::A,
                            None
                        ).await;

                        let a_rcrd_rspns = match Box::pin(self._get_rcrds(a_rcrd_q)).await {
                            Ok(o) => o,
                            Err(_) => {
                                eprintln!("Failed to query ip for nameserver {}", y.data().nsdname());
                                continue;
                            }
                        };

                        for a_rcrd in a_rcrd_rspns {
                            nxt_auth_ns.push(
                                SocketAddr::new(a_rcrd.data().addr().try_into().unwrap(), 53)
                            );
                        }
                    }
                    // create new request
                    let q = NhQuery::new(nhq.na.clone(), nhq.rt, Some(nxt_auth_ns)).await;

                    return Box::pin(self._get_rcrds(q)).await;
                }
            }
        }
        eprintln!("WHAT THE FUCK WHY AM I HERE");
        return Err(());
    }

    async fn query(&self, nhq: NhQuery) -> String {
        match self._get_rcrds(nhq.clone()).await {
            Ok(o) => {
                println!("{:?}", o);
            }
            Err(e) => println!("Resultion for {} failed: {:?}", nhq.na, e),
        }
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
        domain::base::Name::<Vec<u8>>::from_str("akamai.com.").unwrap(),
        domain::base::Rtype::A,
        None
    ).await;

    let rslt = r.query(q).await;
    println!("{:?}", rslt);
}
