use aya::programs::tc::TcOptions;
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
    #[clap(long, default_value = "enp0s3")]
    iface: String,
    #[clap(long, default_value = "enp0s8")]
    iface_2: String,
    #[clap(long)]
    file: String,
    #[clap(long)]
    log:String
}






fn block_ip_ingress(bpf: &mut Bpf, file_path: &str) -> Result<(), anyhow::Error>  {
    info!("block_ip_ingress");
    let mut blocklist: HashMap<_, u32, u32> =
    HashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap())?;

    let file = File::open(file_path).expect("there is no file");
    for line in io::BufReader::new(file).lines() {
        let ip_str = line?;
        let ip: Ipv4Addr = ip_str.parse()?;
        let ip_be = u32::from(ip).to_be();
        blocklist.insert(ip_be, 0, 0)?;
    }

    info!("Contents of BLOCKLIST:");
    for key in blocklist.keys() {
        if let Ok(ip) = key {
            let ip_host_order = u32::from_be(ip);
            let ip_addr = Ipv4Addr::from(ip_host_order);
            info!("{}", ip_addr);
        }
    }

    Ok(())
}

fn block_ip_egress(bpf: &mut Bpf, file_path: &str) -> Result<(), anyhow::Error>  {
    let mut blocklist: HashMap<_, u32, u32> =
    HashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap())?;

    let file = File::open(file_path).expect("there is no file");
    for line in io::BufReader::new(file).lines() {
        let ip_str = line?;
        let ip: Ipv4Addr = ip_str.parse()?;
        let ip_be = u32::from(ip).to_be();
        blocklist.insert(ip_be, 0, 0)?;
    }

    info!("Contents of BLOCKLIST egress:");
    for key in blocklist.keys() {
        if let Ok(ip) = key {
            let ip_host_order = u32::from_be(ip);
            let ip_addr = Ipv4Addr::from(ip_host_order);
            info!("{}", ip_addr);
        }
    }

    Ok(())
}

// Function to load the "tc_hashmap" program
fn load_tc_program(bpf: &mut Bpf,program_name:&str,if_name:&str,attach_type:TcAttachType) -> Result<(), anyhow::Error> {
   let opts:TcOptions = TcOptions{
                                  priority: 1,handle: 0};
    let program: &mut SchedClassifier = bpf.program_mut(program_name).unwrap().try_into()?;
    program.load()?;
    program.attach(if_name, attach_type)?;
    Ok(())
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
    //let _ = tc::qdisc_add_clsact(&opt.iface_2);

   // let program: &mut SchedClassifier = bpf.program_mut("tc").unwrap().try_into()?;
   //let program: &mut SchedClassifier = bpf.program_mut("tc_ringbuf").unwrap().try_into()?;
 // Load "tc_hashmap" program
 load_tc_program(&mut bpf,"tc_hashmap",&opt.iface,TcAttachType::Ingress)?;

 // Load "tc_test" program
 //load_tc_program(&mut bpf,"tc_test",&opt.iface_2,TcAttachType::Ingress)?;
 
 load_tc_program(&mut bpf,"tc_masquerade",&opt.iface,TcAttachType::Egress)?;

   /*  #[cfg(feature = "ingress")]
    program.attach(&opt.iface, TcAttachType::Ingress)?;
    #[cfg(feature = "egress")]
    program.attach(&opt.iface, TcAttachType::Egress)?;
*/



   /*  #[cfg(all(feature = "block_ip", feature = "ingress"))]
    let _ = block_ip_ingress(& mut bpf,&opt.file);
    
    #[cfg(all(feature = "block_ip", feature = "egress"))]
    let _ = block_ip_egress(&mut bpf,&opt.file);
*/

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
