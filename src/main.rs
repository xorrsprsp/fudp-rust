#[macro_use]
extern crate clap;
extern crate ipaddress;
extern crate pnet;

use clap::{Arg, App};
use ipaddress::IPAddress;


fn main() {
    let matches = App::new("fudp")
        .before_help("Please use responsibly")
        .version(format!("v{}", crate_version!()).as_ref())
        .author("xorrsprsp - https://github.com/xorrsprsp/")
        .about("fudp is a simple and very easy to use UDP flooding utility")
        .arg(Arg::with_name("target IP")
            .help("The IP to be targeted")
            .required(true))
        .arg(Arg::with_name("single-packet")
            .short("1")
            .help("Sends a single datagram and then exits"))
        .arg(Arg::with_name("random-source")
            .short("r")
            .help("Spoofs a random sender IP"))
        .arg(Arg::with_name("threads")
            .short("i")
            .help("Spin up extra threads generating datagrams")
            .takes_value(true))
        .arg(Arg::with_name("dst-port")
            .short("p")
            .help("Destination port")
            .takes_value(true))
        .arg(Arg::with_name("datagram-size")
            .short("z")
            .help("Datagram size")
            .takes_value(true))
        .arg(Arg::with_name("src-ip")
            .short("s")
            .help("Spoofs a specified source IP")
            .takes_value(true))
        .arg(Arg::with_name("land-attack")
            .short("l")
            .help("Land Attack"))
        .get_matches();

    let attack_ip = matches.value_of("target IP").unwrap();
    let attack_ip = match IPAddress::parse(attack_ip) {
        Ok(ip) => ip,
        Err(err) => {
            println!("Error: {}", err);
            std::process::exit(1);
        }
    };
    println!("{:?}", attack_ip);

}

