use aya::programs::tc::TcOptions;
use aya::programs::{tc, SchedClassifier, TcAttachType,TracePoint};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn, debug};
use tokio::signal;
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use netstat::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};
use aya::maps::RingBuf;
use aya::Pod;
use std::net::Ipv4Addr;
use aya::maps::{HashMap,PerCpuHashMap,PerCpuValues,MapData};
use aya::util::nr_cpus;
use tokio::time::Duration;
use tokio::time;
use std::fs::File;
use std::io::{self, BufRead};
use std::collections::HashMap as StdHashMap;
use std::collections::HashSet;
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


#[derive(Debug, Clone, Copy,Hash,Eq,PartialEq,)]
#[repr(C)]
struct UdpServerInfo {
    pid: u32,
    ip: u32,
    port: u16,
}

unsafe impl Pod for UdpServerInfo {}

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

fn create_udp_servers(bpf: &mut Bpf) -> Result<PerCpuHashMap<&mut MapData, UdpServerInfo, u32>, anyhow::Error>  {
   
    info!("udp_servers");
    let mut udp_servers: PerCpuHashMap<_, UdpServerInfo, u32> =
    PerCpuHashMap::try_from(bpf.map_mut("udp_servers").unwrap())?;
    
    udp_servers.insert(
      UdpServerInfo{  pid: 123,
            ip: 0xC0A80101, // Example IPv4 address 192.168.1.1
            port: 8080,},
            PerCpuValues::try_from(vec![3u32; nr_cpus()?])?,
            0);
    Ok(udp_servers)
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
 //load_tc_program(&mut bpf,"tc_hashmap",&opt.iface,TcAttachType::Ingress)?;
 load_tc_program(&mut bpf,"tc_conntrack",&opt.iface,TcAttachType::Ingress)?;
 load_tc_program(&mut bpf,"tc_egress_conntrack",&opt.iface,TcAttachType::Egress)?;

 // Load "tc_test" program
 //load_tc_program(&mut bpf,"tc_test",&opt.iface_2,TcAttachType::Ingress)?;
 
 //load_tc_program(&mut bpf,"tc_masquerade",&opt.iface,TcAttachType::Egress)?;

   /*  #[cfg(feature = "ingress")]
    program.attach(&opt.iface, TcAttachType::Ingress)?;
    #[cfg(feature = "egress")]
    program.attach(&opt.iface, TcAttachType::Egress)?;
*/



let udp_servers_key =  UdpServerInfo{  pid: 123,
    ip: 0xC0A80101, // Example IPv4 address 192.168.1.1
    port: 8080};

 // Load and attach Tracepoint program
 /*let trace_prog: &mut TracePoint = bpf.program_mut("aya_tracepoint").unwrap().try_into()?;
 trace_prog.load()?;
 trace_prog.attach("sock", "inet_sock_set_state")?;
*/
let trace_prog_bind: &mut TracePoint = bpf.program_mut("aya_tracepoint_bind").unwrap().try_into()?;
 trace_prog_bind.load()?;
 trace_prog_bind.attach("syscalls", "sys_enter_bind")?;

 /*
 let trace_prog_sock_enter: &mut TracePoint = bpf.program_mut("aya_tracepoint_socket_enter").unwrap().try_into()?;
 trace_prog_sock_enter.load()?;
 trace_prog_sock_enter.attach("syscalls", "sys_enter_socket")?;

 let trace_prog_sock_exit: &mut TracePoint = bpf.program_mut("aya_tracepoint_socket_exit").unwrap().try_into()?;
 trace_prog_sock_exit.load()?;
 trace_prog_sock_exit.attach("syscalls", "sys_exit_socket")?;



 let trace_prog_recvfrom_enter: &mut TracePoint = bpf.program_mut("aya_tracepoint_recvfrom_enter").unwrap().try_into()?;
 trace_prog_recvfrom_enter.load()?;
 trace_prog_recvfrom_enter.attach("syscalls", "sys_enter_recvfrom")?;

 */

   /*  #[cfg(all(feature = "block_ip", feature = "ingress"))]
    let _ = block_ip_ingress(& mut bpf,&opt.file);
    
    #[cfg(all(feature = "block_ip", feature = "egress"))]
    let _ = block_ip_egress(&mut bpf,&opt.file);
*/
let mut udp_serv=create_udp_servers(&mut bpf).unwrap();

let retval=udp_serv.get( &udp_servers_key, 0);

info!("udp_Servers got:{:?},{:?}",udp_servers_key,retval);

let mut current_active_udp_servers:StdHashMap<UdpServerInfo, u32>=Default::default(); 
    loop {
        time::sleep(Duration::from_secs(5)).await; // Update every 60 seconds

        let active_udp_servers = match get_udp_servers() {
            Ok(servers) => servers,
            Err(e) => {
                warn!("Error updating active UDP servers: {}", e);
                continue; // Handle error gracefully
            }
        };

        info!("Active UDP Servers:");
       /*  for (server_info,val) in &active_udp_servers {
            info!("IP: {}, Port: {}, Info: {}", Ipv4Addr::from(server_info.ip), server_info.port, val); // Print each server in human-readable format
        } */
     // Compare current_active_udp_servers and active_udp_servers
        let current_set: HashSet<_> = current_active_udp_servers.keys().collect();
        let new_set: HashSet<_> = active_udp_servers.keys().collect();

        let to_delete: Vec<_> = current_set.difference(&new_set).cloned().collect();
        let to_add: Vec<_> = new_set.difference(&current_set).cloned().collect();

        
        for server_info in to_delete {
            udp_serv.remove(&server_info).unwrap_or_else(|e| {
                warn!("Failed to delete server info {:?}: {}", server_info, e);
            });
        }

        for server_info in to_add {
            udp_serv.insert(server_info.clone(), PerCpuValues::try_from(vec![3u32; nr_cpus()?])?,0).unwrap_or_else(|e| {
                warn!("Failed to insert server info {:?}: {}", server_info, e);
            });
        }

       // info!("To delete: {:?}", to_delete);
       // info!("To add: {:?}", to_add);

        // Update the current active UDP servers
        current_active_udp_servers = active_udp_servers;
     }
    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}



fn get_udp_servers() -> Result<StdHashMap<UdpServerInfo, u32>, Box<dyn std::error::Error>> {
    let af_flags = AddressFamilyFlags::IPV4;
    let proto_flags = ProtocolFlags::UDP;
    let mut udp_servers = StdHashMap::new();

    let sockets = get_sockets_info(af_flags, proto_flags)?;
    for socket in sockets {
        if let ProtocolSocketInfo::Udp(info) = socket.protocol_socket_info {
            if let std::net::IpAddr::V4(local_addr) = info.local_addr {
                let server_info = UdpServerInfo {
                    pid: 1, // Replace with actual PID if available
                    ip: u32::from(local_addr),
                    port: info.local_port,
                };
                udp_servers.insert(server_info, 1);
            }
        }
    }

    Ok(udp_servers)
}