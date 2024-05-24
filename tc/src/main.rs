use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn, debug};
use tokio::signal;
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use aya::maps::RingBuf;
use std::net::Ipv4Addr;
use aya::maps::HashMap;
use std::fs::File;
use std::io::{self, BufRead};
#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "enp0s3")]
    iface: String,
    #[clap(long)]
    file: String,
    #[clap(long)]
    log:String
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    if opt.log == "true"
{
    std::env::set_var("RUST_LOG", "info");
    env_logger::init();
}   
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };

    
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/tc"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/tc"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
       warn!("failed to initialize eBPF logger: {}", e);
    }    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    let _ = tc::qdisc_add_clsact(&opt.iface);
   // let program: &mut SchedClassifier = bpf.program_mut("tc").unwrap().try_into()?;
   //let program: &mut SchedClassifier = bpf.program_mut("tc_ringbuf").unwrap().try_into()?;
    let program: &mut SchedClassifier = bpf.program_mut("tc_hashmap").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, TcAttachType::Ingress)?;
   /*  let mut ring = RingBuf::try_from(bpf.map_mut("DATA").unwrap())?;
    let _ = ring.readable_mut().await?;*/
    let mut blocklist: HashMap<_, u32, u32> =
    HashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap())?;

    let file = File::open(&opt.file).expect("there is no file");
    for line in io::BufReader::new(file).lines() {
        let ip_str = line?;
        let ip: Ipv4Addr = ip_str.parse()?;
        let ip_be = u32::from(ip).to_be();
        blocklist.insert(ip_be, 0, 0)?;
    }
// 
println!("Contents of BLOCKLIST:");
    for key in blocklist.keys() {
        if let Ok(ip) = key {
            let ip_host_order = u32::from_be(ip);
            let ip_addr = Ipv4Addr::from(ip_host_order);
            println!("{}", ip_addr);
        }
    }
/*let block_addr: u32 = Ipv4Addr::new(1, 1, 1, 1).try_into()?;
let block_addr_2: u32 = Ipv4Addr::new(192,168,1,5).try_into()?;

// 

blocklist.insert(block_addr, 0, 0)?;
blocklist.insert(block_addr_2, 0, 0)?;*/

   /* loop {
         if let Some(item) = ring.next() {
            info!("item: {:?}", &*item);
        }



    }*/
     info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
