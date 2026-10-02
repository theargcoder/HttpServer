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

  __u16 header = *(__u16 *)data;

  // VLAN header we gotta loop since they can be stacked
  if(header == bpf_htons(ETH_P_8021Q) || header == bpf_htons(ETH_P_8021AD))
  {
    unsigned i = 0;
#pragma unroll
    for(; i < 4; i++)
    {
      if(data + 7 > data_end) // VLAN header (4) + Ether/Ver (2) + extra (1) -- extra since it has to have payload
        return XDP_DROP;

      header = *(__u16 *)data;

      if(header != bpf_htons(ETH_P_8021Q) && header != bpf_htons(ETH_P_8021AD))
        break;

      data += 4; // skip PCP/DEI/VID and skip Ether Type/Size straight into next header
    }

    if(i == 4) // 1'000'000'000 VLANs stacked ??? wtf let the kernel figure it out
      return XDP_PASS;
  }

  if(bpf_ntohs(header) < 1501) // 'raw' IEEE-802.3 frame
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

    header = *(__u16 *)data;
  }

  if(header == bpf_htons(ETH_P_MPLS_UC)) // this one is horrible, we have to loop :(
  {
    if(data + 2 > data_end)
      return XDP_DROP;

    data += 2; // skip header

    unsigned i = 0;
#pragma unroll
    for(; i < 8; i++)
    {
      if(data + 5 > data_end) // MPLS header (4) + extra (1) -- extra since it has to have payload
        return XDP_DROP;

      const __u32 mpls_header = bpf_htonl(*(__u32 *)data);

      data += 4; // skip MPLS header (4)

      if(mpls_header & 0x00000100) // 8th bit in CPU order == 24th in network
        break;                     // found the bottom, now we point to payload
    }

    if(i == 8) // suspicious/strange amount of headers so we let the kernel do whatever with it
      return XDP_PASS;

    const __u8 ip_ver = *(__u8 *)data >> 4;

    if(ip_ver == 4 || ip_ver == 6) // we only like IPv4 or IPv6
    {
      const __u32 queue = ctx->rx_queue_index;
      return bpf_redirect_map(&xsks_map, queue, XDP_PASS);
    }

    return XDP_PASS; // out of our reach
  }

  // we care about Ethernet II - IPv4 AND IPv6
  if(header == bpf_htons(ETH_P_IP) || header == bpf_htons(ETH_P_IPV6))
  {
    const __u32 queue = ctx->rx_queue_index;
    return bpf_redirect_map(&xsks_map, queue, XDP_PASS);
  }

  // we don't care about other messages so pass em to kernel
  return XDP_PASS;
}

/*
SEC("xdp")
int xdp_redirect_12345_old(struct xdp_md *ctx)
{
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct iphdr *iph = NULL;

  if(data + 1 > data_end)
    return XDP_PASS;

  // IPv4 packets start with version == 4.
  if(((*(__u8 *)data) >> 4) == 4)
  {
    iph = data;
  }
  else
  {
    struct ethhdr *eth = data;

    if((void *)(eth + 1) > data_end)
      return XDP_PASS;

    if(bpf_ntohs(eth->h_proto) != ETH_P_IP)
      return XDP_PASS;

    iph = (void *)(eth + 1);
  }

  if((void *)(iph + 1) > data_end)
    return XDP_PASS;

  if(iph->version != 4)
    return XDP_PASS;

  if(iph->ihl < 5)
    return XDP_PASS;

  if(iph->protocol != IPPROTO_UDP)
    return XDP_PASS;

  struct udphdr *udp = (void *)iph + (iph->ihl * 4);

  if((void *)(udp + 1) > data_end)
    return XDP_PASS;

  if(udp->dest != bpf_htons(12345))
    return XDP_PASS;

  const __u32 queue = ctx->rx_queue_index;

  // Only redirect if an XSK is installed for this queue.

  if(bpf_map_lookup_elem(&xsks_map, &queue))
    return bpf_redirect_map(&xsks_map, queue, XDP_PASS);

  return XDP_PASS;
}
*/
