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
