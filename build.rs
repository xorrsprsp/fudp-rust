fn main() {
    #[cfg(target_os = "windows")]
    {
        println!("cargo:rustc-link-search=C:\\Windows\\System32\\Npcap\\Lib\\x64");
        println!("cargo:rustc-link-lib=Packet");
    }

    #[cfg(not(target_os = "windows"))]
    {
        println!("cargo:rustc-link-lib=pcap");
    }
}