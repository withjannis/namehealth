use bytes::Bytes;

use domain::base::{
    Message, MessageBuilder, Name, Rtype, ParseRecordData, Record, ParsedName
};


use domain::net::client::{
    dgram, dgram_stream, multi_stream, stream,
};
use domain::net::client::protocol::{TcpConnect, UdpConnect};
use domain::net::client::request::{
    ComposeRequest, RequestMessage, SendRequest
};

use std::fmt::Debug;
use std::net::{SocketAddr};

use std::time::Duration;

pub async fn get_dns_msg(
    ns: SocketAddr,
    na: Name<Vec<u8>>,
    rt: Rtype,
    ) -> Message<bytes::Bytes> {

    // Destination for UDP and TCP
    let mut msg = MessageBuilder::new_vec();
    msg.header_mut().set_rd(true);
    // msg.header_mut().set_ad(true);
    msg.header_mut().set_random_id();

    let mut qst= msg.question();
    qst.push(
        (na, rt)
    ).unwrap();

    let mut reqmsg = RequestMessage::new(qst).unwrap();

    reqmsg.set_dnssec_ok(true);
    reqmsg.set_udp_payload_size(1400);

    let mut stream_config = stream::Config::new();

    stream_config.set_response_timeout(Duration::from_millis(100));

    let multi_stream_config = multi_stream::Config::from(
        stream_config.clone()
    );

    // Create a new UDP+TCP transport connection. Pass the destination address
    // and port as parameter.

    let mut dgram_config = dgram::Config::new();
    dgram_config.set_max_parallel(1);
    dgram_config.set_read_timeout(Duration::from_millis(1000));
    dgram_config.set_max_retries(1);
    dgram_config.set_udp_payload_size(Some(1400));

    let dgram_stream_config = dgram_stream::Config::from_parts(
        dgram_config.clone(),
        multi_stream_config.clone(),
    );

    let udp_connect = UdpConnect::new(ns);
     let tcp_connect = TcpConnect::new(ns);

    let (
        udptcp_conn, 
        transport)
        = dgram_stream::Connection::with_config(
        udp_connect,
        tcp_connect,
        dgram_stream_config.clone(),
    );

    tokio::spawn(transport.run());

    // Send a query message.
    let mut request = udptcp_conn
        .send_request(reqmsg.clone());

    // Get the reply
    let reply = request.get_response().await;

    let answer = reply.expect("");

    answer

}

pub async fn get_dns_rcrd<RecordData>(
    dnsmsg: Message<bytes::Bytes>,
    rt: Rtype, // record type
    rs: bool, // record signature
) -> Vec<Record<ParsedName<bytes::Bytes>, RecordData>>
    where
        for<'a> RecordData: Debug + ParseRecordData<'a, Bytes>
{

    let mut records: Vec<Record<ParsedName<bytes::Bytes>, RecordData>> = vec![];
    let dnsanswer = dnsmsg.answer().expect("");

    for rpr in dnsanswer {

            let pr = rpr.expect("");
            if pr.rtype() == rt {
                let ar = pr
                    .to_record::<RecordData>();
                records.push(ar.expect("").unwrap());

            }
            if rs && pr.rtype() == Rtype::RRSIG {
                todo!();
            }
            
    }
    records
}
