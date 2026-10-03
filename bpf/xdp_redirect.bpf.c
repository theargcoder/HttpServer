#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <linux/udp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct
{
  __uint(type, BPF_MAP_TYPE_XSKMAP);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, 64);
} xsks_map SEC(".maps");

SEC("xdp")
int xdp_redirect_12345(struct xdp_md *ctx)
{
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  // we have to have something besides the header LOL
  if((data + sizeof(struct ethhdr)) > data_end)
    return XDP_DROP;

  data += 12; // skip MAC addresses

  __u16 header = bpf_ntohs(*(__u16 *)data);

  // VLAN header we gotta loop since they can be stacked
  if(header == ETH_P_8021Q || header == ETH_P_8021AD)
  {
    unsigned i = 0;
#pragma unroll
    for(; i < 8; i++)
    {
      if(data + 2 > data_end) //  Ether/Ver (2)
        return XDP_DROP;

      header = bpf_ntohs(*(__u16 *)data);

      if(header != ETH_P_8021Q && header != ETH_P_8021AD)
        break;

      if(data + 5 > data_end) // VLAN header (4) + extra (1) -- extra since it has to have payload
        return XDP_DROP;

      data += 4; // skip PCP/DEI/VID and skip Ether Type/Size straight into next header
    }

    if(i == 8) // 1'000'000'000 VLANs stacked ??? wtf let the kernel figure it out
      return XDP_PASS;
  }

  if(header < 1501) // 'raw' IEEE-802.3 frame
  {
    if(data + 11 > data_end) // len(2) + LLC (3) + OUI (3) + Type/Len (2) + extra(1) -- extra since it has to have payload
      return XDP_DROP;

    data += 2; // skip Lenth

    if(*((__u16 *)data) != 0xAAAA) // SNAP only traffic for TCP/UPD
      return XDP_PASS;

    data += 2; // skip DSAP and SSAP

    if(*(__u8 *)data != 0x03) // its not U format SNAP so let the kernel handle it
      return XDP_PASS;

    data += 1; // skip Control Byte

    if(bpf_htonl(*(__u32 *)data) >> 8U != 0) // it has an OUI then cannot be TCP/IP its propetary and == slop
      return XDP_PASS;

    data += 3; // skip OUI

    header = bpf_ntohs(*(__u16 *)data);
  }

  if(header == ETH_P_MPLS_UC || header == ETH_P_MPLS_MC) // this one is horrible, we have to loop :(
  {
    if(data + 2 > data_end)
      return XDP_DROP;

    data += 2; // skip header

    unsigned i = 0;
#pragma unroll
    for(; i < 8; i++)
    {
      if(data + 4 > data_end) // MPLS header (4) or drop
        return XDP_DROP;

      const __u32 mpls_header = bpf_ntohl(*(__u32 *)data);

      data += 4; // skip MPLS header (4)

      if(mpls_header & 0x00000100) // 8th bit in CPU order == 24th in network
        break;                     // found the bottom, now we point to payload
    }

    if(i == 8) // suspicious/strange amount of headers so we let the kernel do whatever with it
      return XDP_PASS;

    if(data + 1 > data_end)
      return XDP_DROP;

    const __u8 ip_ver = *(__u8 *)data >> 4;

    data -= 2; // this is to simulate like there was a Ether/Type header so IP parsers get the +2 happy

    if(ip_ver == 4) // IPv4
    {
      header = ETH_P_IP;
    }
    else if(ip_ver == 6) // IPv6
    {
      header = ETH_P_IPV6;
    }
    else
    {
      return XDP_PASS; // out of our reach
    }
  }

  // we care about Ethernet II - IPv4 AND IPv6 only
  if(header != ETH_P_IP && header != ETH_P_IPV6)
  {
    return XDP_PASS;
  }

  if(header == ETH_P_IP) // IPv4
  {
    if(data + 23 > data_end) // Ether/Type (2) + IPv4 header (20) + extra (1) -- IPv4 header only, skip
    {
      return XDP_PASS;
    }

    data += 2; // skip Ether/Type

    const __u8 ipv4_octet_0 = *(__u8 *)data;

    if((ipv4_octet_0 >> 4U) != 4 || (ipv4_octet_0 & 0b1111) != 5) // (Ether/Type was IPv4 and Version wasn't ??) AND (IHL is greater than standard)
    {
      return XDP_PASS; // let the kernel figure it out
    }

    data += 6; // skip Ver/IHL (1) and DSCP/ECN (1) + TotalLen (2) and Identification (2)

    const __u16 frag = bpf_ntohs(*(__u16 *)data);

    if(frag & 0x1FFF || frag & 0x2000) // our server doesn't support IP fragmentation
      return XDP_PASS;

    data += 3; // // Flags-Fragment Offset (2) and Time-to-live (1)

    const __u8 ipv4_octet_9 = *(__u8 *)data;
    if(ipv4_octet_9 != IPPROTO_TCP && ipv4_octet_9 != IPPROTO_UDP) // HTTP goes over TCP or UDP (as QUIC)
    {
      return XDP_PASS; // let the kernel figure it out
    }

    data += 11; // skip Protocol (1) and Checksum (2)  + Source Address (4) and Desination Address (4)

    // now data points to start of payload
  }
  else // IPv6
  {
    if(data + 43 > data_end) // Ether/Type (2) + IPv6 header (40) + extra (1) --- IPv6 header only, skip
    {
      return XDP_PASS;
    }
    data += 2; // skip Ether/Type (2)

    const __u8 ipv6_octet_0 = *(__u8 *)data;

    if((ipv6_octet_0 >> 4U) != 6) // Ether/Type was IPv6 and Version wasn't ??
    {
      return XDP_PASS; // let the kernel figure it out
    }

    data += 6; // skip version (1) + traffic class (1) + flow label (2) + skip payload length (2)

    const __u8 ipv6_octet_6 = *(__u8 *)data;

    // we drop hop-by-hop since they are a nightmare and no one uses them; what was the IEEE thinking jesus christ
    if(ipv6_octet_6 != IPPROTO_TCP && ipv6_octet_6 != IPPROTO_UDP) // HTTP goes over TCP or UDP (as QUIC) --- same as IPv4
    {
      return XDP_PASS; // let the kernel figure it out
    }

    data += 34; // skip Next Header (1) + Hop Limit (1) + Source Address (16) + Destination Address (16)
  }

  if(data + 5 > data_end) // TCP and UDP header have at least the port source and port destination (4) + extra (1) - skip
  {
    return XDP_PASS;
  }

  data += 2; // skip Source Port;

  const __u16 destination_port = bpf_ntohs(*(__u16 *)data);

  if(destination_port == 80 || destination_port == 443) // if its our HTTP/HTTPS traffic
  {
    const __u32 queue = ctx->rx_queue_index;
    return bpf_redirect_map(&xsks_map, queue, XDP_PASS);
  }

  return XDP_PASS;
}
