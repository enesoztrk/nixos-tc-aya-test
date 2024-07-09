/*
* tcp new connection 
- tcph.syn && !tcph.ack

* udp stateful

UDP sessions are created with basic two way connectivity verification.
Upon receiving the first packet that does not match a connection, the src/dst IP, 
and protocol are inspected and the session is created in a limited state. 
This state has a shortened conn-track timer in which it waits for a response to be seen before the connection 
is considered established. These timers are much shorter 
due to the lack of connection state and always timeout opposed to TCP where the FIN can close the sessions.

Summary:

UDP packet --> create session --> start connection timer (10s) --> forward

UDP packet response --> match connection --> mark established --> start connection timer (3m) --> forward

I should probably add that typically it's also required the firewall
 inspects protocol payloads for what's considered related connection else many protocols would lose functionality.

For example with ICMP or UDP ping, if an error response is seen within the path, the response 
is not coming from the end point and the src/dst in the headers would not match the connection. 
So many firewall inspect the protocol payload that contain the original header information such as ICMP.
This results in a related match and can be forward.


Concurancy

__sync_fetch_and_add(&val->packets, 1); in rust core::sync::atomic::atomic_add
bpf_spin_lock

*/


#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::*, helpers::bpf_map_lookup_elem, macros::{classifier, map,tracepoint}, maps::{Array, HashMap, PerCpuArray, PerCpuHashMap, RingBuf}, programs::{TcContext,TracePointContext}
};


use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr},
    udp::UdpHdr,
    icmp::IcmpHdr,
    tcp::TcpHdr
};

use network_types::*;
use aya_log_ebpf::{info,error,warn};
use memoffset::offset_of;
use core::net::Ipv4Addr;

use aya_ebpf::bpf_printk;
use aya_ebpf::helpers::{bpf_redirect,
     bpf_sk_redirect_hash,bpf_csum_diff,bpf_l3_csum_replace,bpf_l4_csum_replace,bpf_skc_lookup_tcp, bpf_sk_release,bpf_sk_fullsock,bpf_map_lookup_percpu_elem,bpf_probe_read_kernel,bpf_probe_read_user,bpf_get_current_pid_tgid};
use aya_ebpf::cty::{c_void};
use aya_ebpf::cty::{c_int, c_short, c_uchar,c_long};

use crate::mem::zeroed;
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod bindings;

use bindings::{ethhdr, iphdr, ipv6hdr, __u32, __u8, __u16};
use aya_ebpf::EbpfContext;

//[root@nixos:/sys/kernel/debug/tracing/events/sock/inet_sock_set_state]# cat format 
#[repr(C)]
struct InetSockSetState {
    common_type: u16,
    common_flags: u8,
    common_preempt_count: u8,
    common_pid: i32,
    skaddr: u64,//*const core::ffi::c_void,
    oldstate: i32,
    newstate: i32,
    sport: u16,
    dport: u16,
    family: u16,
    protocol: u16,
    saddr: [u8; 4],
    daddr: [u8; 4],
    saddr_v6: [u8; 16],
    daddr_v6: [u8; 16],
}


#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sockaddr_in {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: u32, // Assuming IPv4 address in Network Byte Order
    pub sin_zero: [u8; 8], // Padding to match struct sockaddr
}

#[repr(C)]
#[repr(packed)]
struct SysEnterBind {
    common_type: u16,
    common_flags: u8,
    common_preempt_count: u8,
    common_pid: i32,
    __syscall_nr: i32,
    fd: u64,
    umyaddr: *const sockaddr,
    addrlen: u64,
}



#[repr(C)]
struct SysEnterSocket {
    common_type: c_short,               // unsigned short
    common_flags: c_uchar,              // unsigned char
    common_preempt_count: c_uchar,      // unsigned char
    common_pid: c_int,                  // int

    __syscall_nr: c_int,                // int
    family: i64,                        // int (8 bytes)
    socket_type: i64,                   // int (8 bytes)
    protocol: i64,                      // int (8 bytes)
}
#[repr(C)]
struct SysExitSocket {
    common_type: c_short,               // unsigned short
    common_flags: c_uchar,              // unsigned char
    common_preempt_count: c_uchar,      // unsigned char
    common_pid: c_int,                  // int

    __syscall_nr: c_int,                // int
    ret: c_long,                        // long (8 bytes)
}
//#[map]
//static DATA: RingBuf = RingBuf::with_max_entries(256 * 1024, 0); // 256 KB
#[map]
static BLOCKLIST: HashMap<u32, u32> = HashMap::with_max_entries(1000100, 0);

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;



#[repr(C)]
struct StaticFlowIngressKey {
    src_ip:u32,
    //dest_ip:u32, -> dest ip kendi ipmiz
    //protocol:u8,
    src_port:u16,
    dest_port:u16,
}

#[repr(C)]
struct FlowIngressKey {
    src_ip:u32,
    dest_ip:u32,
    protocol:u8,
    src_port:u16,
    dest_port:u16,
}

#[repr(C)]
struct FlowValue {
    packet_count:u64,
    byte_count:u64,
    last_seen:u64, 
    conn_state:i32
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct UdpServerInfo {
    pid: u32,
    ip: u32,
    port: u16,
}


#[map]
pub static udp_servers: PerCpuHashMap<UdpServerInfo, u32> = PerCpuHashMap::with_max_entries(1024, 0);




#[map]
pub static ingress_conntrack: PerCpuHashMap<FlowIngressKey, FlowValue> = PerCpuHashMap::with_max_entries(2048, 0);//array indexi protocol numarasını temsil eder.



#[map]
static static_tcp_rules: HashMap<StaticFlowIngressKey, u8> = HashMap::with_max_entries(1024, 0);

#[map]
static static_udp_rules: HashMap<StaticFlowIngressKey, u8> = HashMap::with_max_entries(1024, 0);


#[map]
static rule_tcp_masks: Array<u8> = Array::with_max_entries(8, 0);

#[map]
static rule_udp_masks: Array<u8> = Array::with_max_entries(8, 0);


//non tcp/udp static rules
//ICMP,IPv4,RDP,IRTP,IPv6,
//ARP de ipv4,ipv6 yok düşün bu durumu
//0-255 -> standard protocols
//256 -> arp
//it shows whether the protocol is allowed
static rule_other_proto_allowed: Array<bool> = Array::with_max_entries(257, 0);
#[repr(C)]
union IpAddress {
    v4: u32,
    v6: [u8; 16],
}

#[repr(C)]
struct OtherProtoFlowIngressKey {
    src_ip:IpAddress,
    src_ip_type: u8, // 0 for IPv4, 1 for IPv6
    protocol:u16,
}

#[repr(C)]
struct OtherProtoFlowValue {
    packet_count:u64,
    byte_count:u64,
    last_seen:u64, 
}
//other protocols map and statistics
#[map]
static other_proto_conn_map: HashMap<OtherProtoFlowIngressKey, OtherProtoFlowValue> = HashMap::with_max_entries(1024, 0);



fn is_rate_limiting_ok(conn:&FlowIngressKey) ->bool{
    true
}

fn is_static_rules_allowed(rules: &FlowIngressKey,conn:&FlowIngressKey) -> bool{


    true
}


/*fn ingress_filter()-> i32{
    let rules:FlowIngressKey=FlowIngressKey{dest_port:0,src_port:0,protocol:0,src_ip:0}; //hashmap olmalı

    //parse packet
    let parsed_packet:FlowIngressKey=FlowIngressKey{dest_port:0,src_port:0,protocol:0,src_ip:0};
    
    if is_static_rules_allowed(&rules, &parsed_packet) {

            //dynamic rules - conntrack, rate limiting, attack analysis
         
                    

    }
    
    TC_ACT_SHOT
}*/


#[tracepoint]
pub fn aya_tracepoint(ctx: TracePointContext) -> u32 {
    match try_aya_tracepoint(ctx) {
        Ok(ret) => ret,
        Err(ret) => match ret.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}


fn try_aya_tracepoint(ctx: TracePointContext) -> Result<u32, i64> {
    let sock = unsafe {
        bpf_probe_read_kernel(ctx.as_ptr() as *mut InetSockSetState)?
    };
   
     
  
      // Log the relevant information
      warn!(&ctx, "skaddr: 0x{:x},protocol:{} newstate {}, oldstate {}, {}.{}.{}.{}:{} -> {}.{}.{}.{}:{}",sock.skaddr,sock.protocol,
      state_to_string(sock.newstate), state_to_string(sock.oldstate), sock.saddr[0], sock.saddr[1], sock.saddr[2], sock.saddr[3], sock.sport,sock.daddr[0], sock.daddr[1], sock.daddr[2], sock.daddr[3],  sock.dport);
    
    Ok(0)

}

#[tracepoint]
pub fn aya_tracepoint_bind(ctx: TracePointContext) -> u32 {
    match try_aya_tracepoint_bind(ctx) {
        Ok(ret) => ret,
        Err(ret) => match ret.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}


fn try_aya_tracepoint_bind(ctx: TracePointContext) -> Result<u32, i64> {

    let pid = bpf_get_current_pid_tgid() as u32;

    let sockaddr_ptr:*const sockaddr_in = unsafe {ctx.read_at(24)?};
    let sockaddr_info = unsafe { bpf_probe_read_user(sockaddr_ptr as *const sockaddr_in) }?;
    let common_pid:i32 = unsafe {ctx.read_at(4)?};



    let fd:u64= unsafe {ctx.read_at(16)?};
    /*let bind_var = unsafe {
        bpf_probe_read_kernel(ctx.as_ptr() as *mut SysEnterBind)?
    };*/

  // Validate umyaddr pointer
  if sockaddr_ptr.is_null() {
    return Err(-1); // or handle appropriately
}


    
  // Access sa_family field through raw pointer
    // Now you can access fields of sockaddr
    // Note: Adjust this according to the actual fields of `sockaddr` in your implementation
//    let sin_family = umyaddr.sa_family;
    let key = UdpServerInfo{pid:1,ip:0,port:5002};
    // Log the relevant information
    let map_ptr: *mut c_void = &udp_servers as *const _ as *mut c_void;
    let key_ptr: *const c_void = &key as *const _ as *const c_void;

    info!(&ctx,"[Sock_bind]pid: {}, fd: {},sin_family: {},sin_port: {},sin_addr : {:i}",pid,fd,sockaddr_info.sin_family,u16::from_be(sockaddr_info.sin_port),u32::from_be(sockaddr_info.sin_addr));
      // Loop through possible CPU IDs
    
 // Perform the map lookup
 unsafe {
    let result = bpf_map_lookup_elem(map_ptr, key_ptr);
    if result.is_null() {
        // Handle when the element is not found in the map
        // For example:
        // return Err(-1);
        warn!(&ctx,"element not found");
    } else {
        // Use the result pointer as needed
           // Cast the result pointer to the appropriate type
           let value_ptr: *const u32 = result as *const u32;
           let value = *value_ptr;
           info!(
               &ctx,
               "Found value {} for key: pid={}, ip={}, port={}",
               value, key.pid, key.ip, key.port
           );
    }
}
   
 
 //info!(&ctx,"fd:{}, sa_family:{}",fd,sockaddr_info.sin_family,);
    Ok(0)
}


#[tracepoint]
pub fn aya_tracepoint_socket_enter(ctx: TracePointContext) -> u32 {
    match try_aya_tracepoint_socket_enter(ctx) {
        Ok(ret) => ret,
        Err(ret) => match ret.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}


fn try_aya_tracepoint_socket_enter(ctx: TracePointContext) -> Result<u32, i64> {

    let pid = bpf_get_current_pid_tgid() as u32;


    let sock_enter = unsafe {
        bpf_probe_read_kernel(ctx.as_ptr() as *mut SysEnterSocket)?
    };
   
    // Log the relevant information
    info!(&ctx,"[Sock_enter]pid: {},family:{},type:{},proto:{}",pid,sock_enter.family,sock_enter.socket_type,sock_enter.protocol);
 //info!(&ctx,"fd:{}, sa_family:{}",fd,sockaddr_info.sin_family,);
    Ok(0)
}

#[tracepoint]
pub fn aya_tracepoint_socket_exit(ctx: TracePointContext) -> u32 {
    match try_aya_tracepoint_socket_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => match ret.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}


fn try_aya_tracepoint_socket_exit(ctx: TracePointContext) -> Result<u32, i64> {

    let pid = bpf_get_current_pid_tgid() as u32;

    let sock_exit = unsafe {
        bpf_probe_read_kernel(ctx.as_ptr() as *mut SysExitSocket)?
    };
   
    // Log the relevant information
    info!(&ctx,"[Sock_exit]pid: {},ret_val:{}", pid,sock_exit.ret);
 //info!(&ctx,"fd:{}, sa_family:{}",fd,sockaddr_info.sin_family,);
    Ok(0)
}


#[tracepoint]
pub fn aya_tracepoint_recvfrom_enter(ctx: TracePointContext) -> u32 {
    match try_aya_tracepoint_recvfrom_enter(ctx) {
        Ok(ret) => ret,
        Err(ret) => match ret.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}


fn try_aya_tracepoint_recvfrom_enter(ctx: TracePointContext) -> Result<u32, i64> {

    let pid = bpf_get_current_pid_tgid() as u32;

    let fd:u64= unsafe {ctx.read_at(16)?};
   
    // Log the relevant information
    info!(&ctx,"[Recvfrom_enter]pid: {}, fd: {}", pid,fd);
 //info!(&ctx,"fd:{}, sa_family:{}",fd,sockaddr_info.sin_family,);
    Ok(0)
}



fn state_to_string(state: i32) -> &'static str {
    match state {
        1 => "ESTABLISHED",
        2 => "SYN_SENT",
        3 => "SYN_RECV",
        4 => "FIN_WAIT1",
        5 => "FIN_WAIT2",
        6 => "TIME_WAIT",
        7 => "CLOSE",
        8 => "CLOSE_WAIT",
        9 => "LAST_ACK",
        10 => "LISTEN",
        11 => "CLOSING",
        12 => "NEW_SYN_RECV",
        13 => "BOUND_INACTIVE",
        _ => "UNKNOWN",
    }
}

#[classifier]
pub fn tc_egress_conntrack(ctx: TcContext) -> i32 {
    match try_egress_conntrack(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_egress_conntrack(mut ctx: TcContext) -> Result<i32, i32>{

    let ethhdr: EthHdr = ctx
    .load::<EthHdr>(0)
    .map_err(|_| TC_ACT_OK)?;


   // let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    match ethhdr.ether_type {
        EtherType::Ipv4 => {}
        _ => return Ok(TC_ACT_PIPE),
    }

    //info!(&ctx, "enp0s8-Incoming ICMP packet {:i} -> {:i}", source,dest);
    let ip_proto = ctx
    .load::<u8>(ETH_HDR_LEN + offset_of!(iphdr, protocol))
    .map_err(|_| TC_ACT_OK)?;


    if ip_proto == IPPROTO_TCP{
        let ipv4hdr: Ipv4Hdr = ctx
        .load::<Ipv4Hdr>(EthHdr::LEN)
        .map_err(|_| TC_ACT_OK)?;

        let tcphdr: TcpHdr = ctx
        .load::<TcpHdr>(EthHdr::LEN + Ipv4Hdr::LEN)
        .map_err(|_| TC_ACT_OK)?;

    // Convert boolean flags to u16 values
let syn_u16 = if tcphdr.syn()>0 { 1 } else { 0 };
let ack_u16 = if tcphdr.ack()>0 { 1 } else { 0 };
let psh_u16 = if tcphdr.psh()>0 { 1 } else { 0 };
let rst_u16 = if tcphdr.rst()>0 { 1 } else { 0 };
let fin_u16 = if tcphdr.fin()>0 { 1 } else { 0 };
    info!(&ctx, "TCP[OUT],SYN={},ACK={},PSH={},RST={},FIN={} {:i} :{} -> {:i}:{}",syn_u16,ack_u16, psh_u16,rst_u16,fin_u16, u32::from_be(ipv4hdr.src_addr), u16::from_be(tcphdr.source), u32::from_be(ipv4hdr.dst_addr), u16::from_be(tcphdr.dest));
    
    }

    Ok(TC_ACT_PIPE)
}


#[classifier]
pub fn tc_conntrack(ctx: TcContext) -> i32 {
    match try_tc_conntrack(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tc_conntrack(mut ctx: TcContext) -> Result<i32, i32>{

    let ethhdr: EthHdr = ctx
    .load::<EthHdr>(0)
    .map_err(|_| TC_ACT_OK)?;


   // let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    match ethhdr.ether_type {
        EtherType::Ipv4 => {}
        _ => return Ok(TC_ACT_PIPE),
    }

    //info!(&ctx, "enp0s8-Incoming ICMP packet {:i} -> {:i}", source,dest);
    let ip_proto = ctx
    .load::<u8>(ETH_HDR_LEN + offset_of!(iphdr, protocol))
    .map_err(|_| TC_ACT_OK)?;


    if ip_proto == IPPROTO_TCP{
        let ipv4hdr: Ipv4Hdr = ctx
        .load::<Ipv4Hdr>(EthHdr::LEN)
        .map_err(|_| TC_ACT_OK)?;

        let tcphdr: TcpHdr = ctx
        .load::<TcpHdr>(EthHdr::LEN + Ipv4Hdr::LEN)
        .map_err(|_| TC_ACT_OK)?;

    // Convert boolean flags to u16 values
let syn_u16 = if tcphdr.syn()>0 { 1 } else { 0 };
let ack_u16 = if tcphdr.ack()>0 { 1 } else { 0 };
let psh_u16 = if tcphdr.psh()>0 { 1 } else { 0 };
let rst_u16 = if tcphdr.rst()>0 { 1 } else { 0 };
let fin_u16 = if tcphdr.fin()>0 { 1 } else { 0 };
    info!(&ctx, "TCP[IN],SYN={},ACK={},PSH={},RST={},FIN={} {:i} :{} -> {:i}:{}",syn_u16,ack_u16, psh_u16,rst_u16,fin_u16, u32::from_be(ipv4hdr.src_addr), u16::from_be(tcphdr.source), u32::from_be(ipv4hdr.dst_addr), u16::from_be(tcphdr.dest));

   // Prepare the socket tuple
   let mut tuple = bpf_sock_tuple {
    __bindgen_anon_1: bpf_sock_tuple__bindgen_ty_1 {
        ipv4: bpf_sock_tuple__bindgen_ty_1__bindgen_ty_1 {
            saddr:  ipv4hdr.src_addr,
            daddr:  ipv4hdr.dst_addr,
            sport:  tcphdr.source,
            dport: tcphdr.dest,
        },
    },
};
let tuple_size = mem::size_of::<bpf_sock_tuple>();
let skb = ctx.skb.skb;


  // Perform the socket lookup
 /*  let sk = unsafe {
    bpf_skc_lookup_tcp(
        skb as *mut _,
         &mut tuple as *mut _,
        tuple_size as u32,
        0,
        0,
    ) as *mut c_void
};
//info!(&ctx, "in-{:i} :{} -> {:i}:{}", u32::from_be(ipv4hdr.src_addr),  u16::from_be(tcphdr.source),  u32::from_be(ipv4hdr.dst_addr), u16::from_be(tcphdr.dest));

if !sk.is_null(){
    let sk_state = unsafe { (*(sk as *const bpf_sock)).state };
    info!(&ctx, "{:i} :{} -> {:i}:{},{}", u32::from_be(ipv4hdr.src_addr),  u16::from_be(tcphdr.source), 
    u32::from_be(ipv4hdr.dst_addr), u16::from_be(tcphdr.dest),state_to_string(sk_state));
    unsafe {  bpf_sk_release(sk)};

} */


    }

    Ok(TC_ACT_PIPE)
}







// Helper function to check if two IPs are in the same network
fn same_network(ip1: u32, ip2: u32) -> bool {
     // Define the network mask (e.g., /24)
     let network_mask = 0xFFFFFF00; // 255.255.255.0
    (ip1 & network_mask) == (ip2 & network_mask)
}

#[classifier]
pub fn tc_masquerade(ctx: TcContext) -> i32 {
    match try_masquerade(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_masquerade(mut ctx: TcContext) -> Result<i32, i32>{
    let ethhdr: EthHdr = ctx
    .load::<EthHdr>(0)
    .map_err(|_| TC_ACT_OK)?;


   // let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    match ethhdr.ether_type {
        EtherType::Ipv4 => {}
        _ => return Ok(TC_ACT_PIPE),
    }
    let ipv4hdr: Ipv4Hdr = ctx
    .load::<Ipv4Hdr>(EthHdr::LEN)
    .map_err(|_| TC_ACT_OK)?;
    let source = u32::from_be(ipv4hdr.src_addr);
    let dest = u32::from_be(ipv4hdr.dst_addr);

    //info!(&ctx, "enp0s8-Incoming ICMP packet {:i} -> {:i}", source,dest);
    let ip_proto = ctx
    .load::<u8>(ETH_HDR_LEN + offset_of!(iphdr, protocol))
    .map_err(|_| TC_ACT_OK)?;
    if  !same_network(source,EXTERNAL_IP) {


 

        info!(&ctx, "enp0s3-Outgoing ICMP packet {:i} -> {:i}", source,dest);
            // Change destination MAC address to a new one
            let new_src_mac:[u8; 6] = [0x08,0x00,0x27,0x10,0xe7,0x06];
            ctx.store(offset_of!(EthHdr, src_addr), &new_src_mac,BPF_F_RECOMPUTE_CSUM.into()).map_err(|_| TC_ACT_OK)?;



           // Change destination IP address to a new one
           let new_src_ip =EXTERNAL_IP;
           ctx.store(
               ETH_HDR_LEN + offset_of!(Ipv4Hdr, src_addr),
               &new_src_ip,
               BPF_F_RECOMPUTE_CSUM.into(),
           )
           .map_err(|_| TC_ACT_OK)?;
          
           let offset = match ip_proto {
            IPPROTO_UDP => (ETH_HDR_LEN + IP_HDR_LEN + offset_of!(UdpHdr, check)) as u32,
            IPPROTO_ICMP => (ETH_HDR_LEN + IP_HDR_LEN + offset_of!(IcmpHdr, checksum)) as u32,
            _ => return  Ok(TC_ACT_SHOT), // Default value for other protocols
        };

           let skb = ctx.skb.skb;
           let from = ipv4hdr.src_addr as u64;
           let to = new_src_ip as u64;
           let size = 4; // IPv4 addresses are 4 bytes
           //
           if IPPROTO_UDP ==ip_proto{
            let ret = unsafe{bpf_l4_csum_replace(skb, offset, from, to,
                (BPF_F_MARK_MANGLED_0 |BPF_F_PSEUDO_HDR | 4).into())};
 
                if ret != 0{
                    error!(&ctx, "l4 csum replace err:{}",ret );
                    return Err(TC_ACT_OK);
                }
           }
          
           // Update the checksum using bpf_l3_csum_replace
          
           let offset = (ETH_HDR_LEN + offset_of!(Ipv4Hdr, check)) as u32;

   if unsafe{bpf_l3_csum_replace(skb, offset, from, to, size)} != 0 {
       error!(&ctx, "l3 csum replace err");
       return Err(TC_ACT_OK);
   }

           // Update the checksum using bpf_l3_csum_replace
  


    }
    Ok(TC_ACT_PIPE)
}

#[classifier]
pub fn tc_test(ctx: TcContext) -> i32 {
    match try_tc_enp0s8(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tc_enp0s8(ctx: TcContext) -> Result<i32, i32>{
    let ethhdr: EthHdr = ctx
    .load::<EthHdr>(0)
    .map_err(|_| TC_ACT_OK)?;


   // let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    match ethhdr.ether_type {
        EtherType::Ipv4 => {}
        _ => return Ok(TC_ACT_PIPE),
    }
    let ipv4hdr: Ipv4Hdr = ctx
    .load::<Ipv4Hdr>(EthHdr::LEN)
    .map_err(|_| TC_ACT_OK)?;
    let source = u32::from_be(ipv4hdr.src_addr);
    let dest = u32::from_be(ipv4hdr.dst_addr);

    //info!(&ctx, "enp0s8-Incoming ICMP packet {:i} -> {:i}", source,dest);
    let ip_proto = ctx
    .load::<u8>(ETH_HDR_LEN + offset_of!(iphdr, protocol))
    .map_err(|_| TC_ACT_OK)?;
    if  ip_proto == IPPROTO_ICMP  {
        info!(&ctx, "enp0s8-Incoming ICMP packet {:i} -> {:i}", source,dest);
    }
    Ok(TC_ACT_PIPE)
}


#[classifier]
pub fn tc_hashmap(ctx: TcContext) -> i32 {
#[cfg(all(feature = "block_ip", feature = "ingress"))]
    match try_tc_ingress_blockip(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
#[cfg(all(feature = "redirect", feature = "ingress"))]
    match try_tc_ingress_redirect(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
#[cfg(all(feature = "block_ip", feature = "egress"))]
    match try_tc_egress_blockip(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn block_ip(ctx: &TcContext, address: u32) -> bool {
   unsafe { BLOCKLIST.get(&address).is_some() }
   
}
#[cfg(all(feature = "block_ip", feature = "ingress"))]
fn try_tc_ingress_blockip(ctx: TcContext) -> Result<i32, i32> {

    let ethhdr: EthHdr = ctx
    .load::<EthHdr>(0)
    .map_err(|_| TC_ACT_OK)?;
info!(&ctx, "Ingress redirect");

   // let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    match ethhdr.ether_type {
        EtherType::Ipv4 => {}
        _ => return Ok(TC_ACT_PIPE),
    }

    //let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    let ipv4hdr: Ipv4Hdr = ctx
    .load::<Ipv4Hdr>(EthHdr::LEN)
    .map_err(|_| TC_ACT_OK)?;
    let source = u32::from_be(ipv4hdr.src_addr);

    let action = if block_ip(&ctx,ipv4hdr.src_addr) {
        info!(&ctx, "Blocking packet to DEST {:i}", source);
        TC_ACT_SHOT
    } else {
     //   info!(&ctx, "Allowing packet to DEST {:i}", source);
        TC_ACT_PIPE
    };

    //info!(&ctx, "Ingress-DEST {:i}, ACTION {}", source, action);

    Ok(action)
}



#[cfg(all(feature = "block_ip", feature = "egress"))]
fn try_tc_egress_blockip(ctx: TcContext) -> Result<i32, i32> {
    let ethhdr: EthHdr = ctx
    .load::<EthHdr>(0)
    .map_err(|_| TC_ACT_OK)?;


   // let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    match ethhdr.ether_type {
        EtherType::Ipv4 => {}
        _ => return Ok(TC_ACT_PIPE),
    }

    //let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    let ipv4hdr: Ipv4Hdr = ctx
    .load::<Ipv4Hdr>(EthHdr::LEN)
    .map_err(|_| TC_ACT_OK)?;
    let dest = u32::from_be(ipv4hdr.dst_addr);

    let action = if block_ip(&ctx,ipv4hdr.dst_addr) {
        info!(&ctx, "Blocking packet to DEST {:i}", dest);
        TC_ACT_SHOT
    } else {
        info!(&ctx, "Allowing packet to DEST {:i}", dest);
        TC_ACT_PIPE
    };
    info!(&ctx, "egress-DEST {:i}, ACTION {}", dest, action);

    Ok(action)
}

#[cfg(all(feature = "redirect", feature = "ingress"))]
fn try_tc_ingress_redirect(mut ctx: TcContext) -> Result<i32, i32> {
    // Assuming you have defined EthHdr, EtherType, Ipv4Hdr, and IcmpHdr somewhere

    //use core::{error, intrinsics::size_of};

    use ip::IpHdr;

    let ethhdr: EthHdr = ctx
    .load::<EthHdr>(0)
    .map_err(|_| TC_ACT_OK)?;


   // let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    match ethhdr.ether_type {
        EtherType::Ipv4 => {}
        _ => return Ok(TC_ACT_PIPE),
    }
    let ipv4hdr: Ipv4Hdr = ctx
    .load::<Ipv4Hdr>(EthHdr::LEN)
    .map_err(|_| TC_ACT_OK)?;
    let source = u32::from_be(ipv4hdr.src_addr);
    let dest = u32::from_be(ipv4hdr.dst_addr);

    //info!(&ctx, "Incoming packet {:i} -> {:i}", source,dest);


        let ip_proto = ctx
        .load::<u8>(ETH_HDR_LEN + offset_of!(iphdr, protocol))
        .map_err(|_| TC_ACT_OK)?;
   

        if  ip_proto == IPPROTO_UDP || ip_proto == IPPROTO_ICMP {
       
        
        if ip_proto == IPPROTO_UDP {
            // Handle UDP packets
            let udphdr: UdpHdr = ctx.load::<UdpHdr>(EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| TC_ACT_OK)?;
            info!(&ctx, "Incoming UDP packet {:i} :{} -> {:i}:{}", source, u16::from_be(udphdr.source), dest, u16::from_be(udphdr.dest));
            
            if u16::from_be(udphdr.dest) != 12345 {
                return Ok(TC_ACT_PIPE);
            }
        } else if ip_proto == IPPROTO_ICMP {
            // Handle ICMP packets
            let icmphdr: IcmpHdr = ctx.load::<IcmpHdr>(EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| TC_ACT_OK)?;
            info!(&ctx, "Incoming ICMP packet {:i} -> {:i}", source, dest);
        }

        
            
             // Change destination MAC address to a new one
             let new_dest_mac:[u8; 6] = [0x08,0x00,0x27,0xe7,0x3e,0xdb];
             ctx.store(0, &new_dest_mac,BPF_F_RECOMPUTE_CSUM.into()).map_err(|_| TC_ACT_OK)?;
 


            // Change destination IP address to a new one
            let new_dest_ip =u32::from_le_bytes([192,168,58,101]);
            ctx.store(
                ETH_HDR_LEN + offset_of!(Ipv4Hdr, dst_addr),
                &new_dest_ip,
                BPF_F_RECOMPUTE_CSUM.into(),
            )
            .map_err(|_| TC_ACT_OK)?;
           
            let offset = match ip_proto {
                IPPROTO_UDP => (ETH_HDR_LEN + IP_HDR_LEN + offset_of!(UdpHdr, check)) as u32,
                IPPROTO_ICMP => (ETH_HDR_LEN + IP_HDR_LEN + offset_of!(IcmpHdr, checksum)) as u32,
                _ => return  Ok(TC_ACT_PIPE), // Default value for other protocols
            };


            let skb = ctx.skb.skb;
            let from = ipv4hdr.dst_addr as u64;
            let to = new_dest_ip as u64;
            let size = 4; // IPv4 addresses are 4 bytes
            //
            if IPPROTO_UDP ==ip_proto{
              let ret = unsafe{bpf_l4_csum_replace(skb, offset, from, to,
                (BPF_F_MARK_MANGLED_0 |BPF_F_PSEUDO_HDR | 4).into())};

                if ret != 0{
                    error!(&ctx, "l4 csum replace err:{}",ret );
                    return Err(TC_ACT_OK);
                }
            
            }
          
            // Update the checksum using bpf_l3_csum_replace
           
    let offset = (ETH_HDR_LEN + offset_of!(Ipv4Hdr, check)) as u32;

    if unsafe{bpf_l3_csum_replace(skb, offset, from, to, size)} != 0 {
        error!(&ctx, "l3 csum replace err");
        return Err(TC_ACT_OK);
    }
   
            // Redirect the packet to interface enp0s8
            unsafe {
                info!(&ctx, "Redirecting ICMP packet: IP: {:i} MAC: {:x}:{:x}:{:x}:{:x}:{:x}:{:x}", 
                new_dest_ip,
                new_dest_mac[0], new_dest_mac[1], new_dest_mac[2], new_dest_mac[3], new_dest_mac[4], new_dest_mac[5]);
                let result = unsafe { bpf_redirect(4, 0) };
                info!(&ctx,"result {}",result);
                return Ok(result as i32 );
            }
        }
    

    Ok(TC_ACT_PIPE)
}


/* fn try_tc_ringbuf(ctx: TcContext) -> Result<i32, i32> {
    // info!(&ctx, "received a packet");

    // TODO(vaodorvsky): This should be faster, but sadly it's annoying the
    // verifier.
    // if let Some(mut buf) = DATA.reserve::<PacketBuffer>(0) {
    //     let len = ctx.skb.len() as usize;
    //     let buf_inner = unsafe { &mut (*buf.as_mut_ptr()).buf };

    //     unsafe { (*buf.as_mut_ptr()).size = len };
    //     ctx.load_bytes(0, buf_inner).map_err(|_| TC_ACT_PIPE)?;

    //     buf.submit(0);
    // }

    // This is slower (`output` method is going to perform a copy)... and it
    // also annoys the verifier, FML.
    // let buf = unsafe {
    //     let ptr = BUF.get_ptr_mut(0).ok_or(0)?;
    //     &mut *ptr
    // };
    // if buf.buf.len() < MAX_MTU {
    //     return Err(TC_ACT_PIPE);
    // }
    // if ctx.data() + MAX_MTU > ctx.data_end() {
    //     return Err(TC_ACT_PIPE);
    // }

    // ctx.load_bytes(0, &mut buf.buf[..MAX_MTU])
    //     .map_err(|_| TC_ACT_PIPE)?;

    // DATA.output(buf, 0).map_err(|_| TC_ACT_PIPE)?;

    // Just send the struct for now, without filling it up with packet data.
    if let Some(mut buf) = DATA.reserve::<PacketBuffer>(0) {
        let len = ctx.skb.len() as usize;

        unsafe { (*buf.as_mut_ptr()).size = len };

        buf.submit(0);
    }

    Ok(TC_ACT_PIPE)
}

fn try_tc(ctx: TcContext) -> Result<i32, i32> {
    let h_proto = u16::from_be(
        ctx.load(offset_of!(ethhdr, h_proto))
            .map_err(|_| TC_ACT_OK)?,
    );

    match h_proto {
        ETH_P_ARP => {
            info!(&ctx, "ARP packet detected and dropped");
            return Err(TC_ACT_SHOT); // Drop the packet by returning TC_ACT_OK
        }
        ETH_P_IP => {
            //info!(&ctx, "eth ipv4!");

            let ip_proto = ctx
            .load::<u8>(ETH_HDR_LEN + offset_of!(iphdr, protocol))
            .map_err(|_| TC_ACT_OK)?;
        
             // Check if it's an ICMP packet
             if ip_proto == IPPROTO_ICMP {
                let dest_ip = ctx
                    .load::<u32>(ETH_HDR_LEN + offset_of!(iphdr, daddr))
                    .map_err(|_| TC_ACT_OK)?;

                let dest_ip_be = u32::to_be(dest_ip); // Convert to big-endian for comparison

                info!(&ctx, "dest IP (ICMP): {:i}", dest_ip_be); // Log the destination IP in hex format

                let target_ip = u32::from_be_bytes([192, 168, 1, 12]);

                if dest_ip_be == target_ip {
                    info!(&ctx, "ICMP packet to 192.168.1.12 detected and dropped");
                    return Err(TC_ACT_SHOT); // Drop the packet by returning TC_ACT_SHOT
                }
            }



            /*let source = u32::from_be(
                ctx.load(ETH_HDR_LEN + offset_of!(iphdr, saddr))
                    .map_err(|_| TC_ACT_OK)?,
            );
            info!(
                &ctx,
                "source IPv4: {:i}, {:x}, {:X}", source, source, source
            );*/
        }
        ETH_P_IPV6 => {
            let source = ctx
                .load::<[u8; 16]>(ETH_HDR_LEN + offset_of!(ipv6hdr, saddr))
                .map_err(|_| TC_ACT_OK)?;
            info!(&ctx, "source IPv6: {:i}", source);
        }
        _ => return Ok(TC_ACT_OK),
    }

    Ok(TC_ACT_OK)
}
 */
/*fn try_tc(ctx: TcContext) -> Result<i32, i32> {
    info!(&ctx, "received a packet");
    Ok(TC_ACT_PIPE)
}*/

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const ETH_P_ARP: u16 = 0x0806;
const IPPROTO_ICMP: u8 = 1; // ICMP protocol number
const IPPROTO_TCP: u8 = 6; // TCP protocol number
const IPPROTO_UDP: u8 = 17; // TCP protocol number
const EXTERNAL_IP:u32 = u32::from_le_bytes([192,168,1,11]);
const INTERNAL_IP:u32 = u32::from_le_bytes([192,168,58,1]);
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
const IP_HDR_LEN: usize = mem::size_of::<iphdr>();

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
