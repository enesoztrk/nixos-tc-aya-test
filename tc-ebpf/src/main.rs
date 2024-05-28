#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::*,
    macros::{classifier, map},
    maps::{PerCpuArray, RingBuf,HashMap},
    programs::TcContext,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};
use aya_log_ebpf::info;
use memoffset::offset_of;
use core::net::Ipv4Addr;
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod bindings;

use bindings::{ethhdr, iphdr, ipv6hdr};


//#[map]
//static DATA: RingBuf = RingBuf::with_max_entries(256 * 1024, 0); // 256 KB
#[map]
static BLOCKLIST: HashMap<u32, u32> = HashMap::with_max_entries(1000100, 0);

#[classifier]
pub fn tc_hashmap(ctx: TcContext) -> i32 {
#[cfg(all(feature = "block_ip", feature = "ingress"))]
    match try_tc_ingress_blockip(ctx) {
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
    let result = unsafe { BLOCKLIST.get(&address).is_some() };
    if result {
        info!(ctx, "Address {} is in the blocklist", address);
    } else {
        info!(ctx, "Address {} is not in the blocklist", address);
    }
    
    result
}
#[cfg(all(feature = "block_ip", feature = "ingress"))]
fn try_tc_ingress_blockip(ctx: TcContext) -> Result<i32, i32> {
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
    let source = u32::from_be(ipv4hdr.src_addr);

    let action = if block_ip(&ctx,source) {
        info!(&ctx, "Blocking packet to DEST {:i}", source);
        TC_ACT_SHOT
    } else {
        info!(&ctx, "Allowing packet to DEST {:i}", source);
        TC_ACT_PIPE
    };

    info!(&ctx, "Ingress-DEST {:i}, ACTION {}", source, action);

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

    let action = if block_ip(&ctx,dest) {
        info!(&ctx, "Blocking packet to DEST {:i}", dest);
        TC_ACT_SHOT
    } else {
        info!(&ctx, "Allowing packet to DEST {:i}", dest);
        TC_ACT_PIPE
    };
    info!(&ctx, "egress-DEST {:i}, ACTION {}", dest, action);

    Ok(action)
}



/* #[classifier]
pub fn tc(ctx: TcContext) -> i32 {
    match  { try_tc(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[classifier(name = "tc_ringbuf")]
pub fn tc_ringbuf(ctx: TcContext) -> i32 {
    match try_tc_ringbuf(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tc_ringbuf(ctx: TcContext) -> Result<i32, i32> {
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

const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
