use std::vec;

use std::net::IpAddr;
use std::net::SocketAddr;
use std::str::FromStr;

use once_cell::sync::Lazy;

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

#[derive(Debug)]
struct NsResolver {
    // nameservers
    ns: Vec<SocketAddr>,
}

impl NsResolver {
    fn new(ns: Option<Vec<SocketAddr>>) -> Self {
        NsResolver { ns: ns.unwrap_or(ROOT_NS.to_vec())  }
    }
    fn query(&self, q: NsQuery) -> NsAnswer {
        NsAnswer { q: q, an: vec![], au: vec![], ad: vec![] }
    }
}

#[derive(Debug)]
struct NsQuery {
    // query name
    qn: domain::base::Name<Vec<u8>>,
    // query type
    qt: domain::base::Rtype,
    // validate dnssec
    vd: bool,
}

impl NsQuery {
    fn new(
        qn: domain::base::Name<Vec<u8>>,
        qt: domain::base::Rtype,
        vd: bool
    ) -> Self {
        NsQuery { qn: qn, qt: qt, vd: vd }
    }
}

#[derive(Debug)]
struct NsAnswer {
    q: NsQuery,
    // answer
    an: Vec<i32>,
    // authority
    au: Vec<i32>,
    // additional
    ad: Vec<i32>,
}


mod test {
    #[allow(unused)]
    use std::str::FromStr;

    use crate::testing::{NsResolver, NsQuery};

    #[test]
    fn test_iterator(){
        let r = NsResolver::new(None);
        let q = NsQuery::new(
            domain::base::Name::from_str("akamai.com").unwrap(),
            domain::base::Rtype::A,
            false
        );
        let a = r.query(q);
        println!("{:?}", a);
    }
}
