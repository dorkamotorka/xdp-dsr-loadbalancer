//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "parse_helpers.h"

#define NUM_BACKENDS 2 // Hardcoded number of backends
#define ETH_ALEN 6 // Octets in one ethernet addr
#define AF_INET 2 // Instead of including the whole sys/socket.h header

struct endpoint {
  __u32 ip;
};

struct four_tuple_t {
  __u32 src_ip;
  __u32 dst_ip;
  __u16 src_port;
  __u16 dst_port;
  __u8  protocol;
};

// Backend IPs and MAC addresses map
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, NUM_BACKENDS);
  __type(key, __u32);
  __type(value, struct endpoint);
} backends SEC(".maps");

// LB Real/Node IP
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct endpoint);
} load_balancer SEC(".maps");

// FNV-1a hash for load balancing (no need for routing table)
static __always_inline __u32 xdp_hash_tuple(struct four_tuple_t *tuple) {
  __u32 hash = 2166136261U;
  hash = (hash ^ tuple->src_ip) * 16777619U;
  hash = (hash ^ tuple->dst_ip) * 16777619U;
  hash = (hash ^ tuple->src_port) * 16777619U;
  hash = (hash ^ tuple->dst_port) * 16777619U;
  hash = (hash ^ tuple->protocol) * 16777619U;
  return hash;
}

static __always_inline void log_fib_error(int rc) {
  switch (rc) {
  case BPF_FIB_LKUP_RET_BLACKHOLE:
    bpf_printk("FIB lookup failed: BLACKHOLE route. Check 'ip route' – the "
               "destination may have a blackhole rule.");
    break;
  case BPF_FIB_LKUP_RET_UNREACHABLE:
    bpf_printk("FIB lookup failed: UNREACHABLE route. Kernel routing table "
               "explicitly marks this destination unreachable.");
    break;
  case BPF_FIB_LKUP_RET_PROHIBIT:
    bpf_printk("FIB lookup failed: PROHIBITED route. Forwarding is "
               "administratively blocked.");
    break;
  case BPF_FIB_LKUP_RET_NOT_FWDED:
    bpf_printk("FIB lookup failed: NOT_FORWARDED. Destination likely on the "
               "same subnet – try BPF_FIB_LOOKUP_DIRECT for on-link lookup.");
    break;
  case BPF_FIB_LKUP_RET_FWD_DISABLED:
    bpf_printk("FIB lookup failed: FORWARDING DISABLED. Enable it via 'sysctl "
               "-w net.ipv4.ip_forward=1' or IPv6 equivalent.");
    break;
  case BPF_FIB_LKUP_RET_UNSUPP_LWT:
    bpf_printk("FIB lookup failed: UNSUPPORTED LWT. The route uses a "
               "lightweight tunnel not supported by bpf_fib_lookup().");
    break;
  case BPF_FIB_LKUP_RET_NO_NEIGH:
    bpf_printk("FIB lookup failed: NO NEIGHBOR ENTRY. ARP/NDP unresolved – "
               "check 'ip neigh show' or ping the target to populate cache.");
    break;
  case BPF_FIB_LKUP_RET_FRAG_NEEDED:
    bpf_printk("FIB lookup failed: FRAGMENTATION NEEDED. Packet exceeds MTU; "
               "adjust packet size or enable PMTU discovery.");
    break;
  case BPF_FIB_LKUP_RET_NO_SRC_ADDR:
    bpf_printk(
        "FIB lookup failed: NO SOURCE ADDRESS. Kernel couldn’t choose a source "
        "IP – ensure the interface has an IP in the correct subnet.");
    break;
  default:
    bpf_printk("FIB lookup failed: rc=%d (unknown). Check routing and ARP/NDP "
               "configuration.",
               rc);
    break;
  }
}

static __always_inline int fib_lookup_v4_full(struct xdp_md *ctx,
                                              struct bpf_fib_lookup *fib,
                                              __u32 src, __u32 dst,
                                              __u16 tot_len) {
  // Zero and populate only what a full lookup needs
  __builtin_memset(fib, 0, sizeof(*fib));
  // Hardcode address family: AF_INET for IPv4
  fib->family = AF_INET;
  // Source IPv4 address used by the kernel for policy routing and source
  // address–based decisions
  fib->ipv4_src = src;
  // Destination IPv4 address (in network byte order)
  // The address we want to reach; used to find the correct egress route
  fib->ipv4_dst = dst;
  // Hardcoded Layer 4 protocol: TCP, UDP, ICMP
  fib->l4_protocol = IPPROTO_TCP;
  // Total length of the IPv4 packet (header + payload)
  fib->tot_len = tot_len;
  // Interface for the lookup
  fib->ifindex = ctx->ingress_ifindex;

  return bpf_fib_lookup(ctx, fib, sizeof(*fib), 0);
}

static __always_inline __u16 recalc_ip_checksum(struct iphdr *ip) {
  // Clear checksum
  ip->check = 0;

  // Compute incremental checksum difference over the header
  __u64 csum = bpf_csum_diff(0, 0, (unsigned int *)ip, sizeof(struct iphdr), 0);

// fold 64-bit csum to 16 bits (the “carry add” loop)
#pragma unroll
  for (int i = 0; i < 4; i++) {
    if (csum >> 16)
      csum = (csum & 0xffff) + (csum >> 16);
  }

  return ~csum;
}

SEC("xdp")
int xdp_load_balancer(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct hdr_cursor nh;
  nh.pos = data;

  // Parse Ethernet header to extract source and destination MAC address
  struct ethhdr *eth;
  int eth_type = parse_ethhdr(&nh, data_end, &eth);
  // For simplicity we only show IPv4 load-balancing
  if (eth_type != bpf_htons(ETH_P_IP)) {
    return XDP_PASS;
  }

  // Parse IP header to extract source and destination IP
  struct iphdr *ip;
  int ip_type = parse_iphdr(&nh, data_end, &ip);
  if ((void *)(ip + 1) > data_end) {
    return XDP_PASS;
  }

  // For simplicity only load-balance TCP traffic
  if (ip->protocol != IPPROTO_TCP) {
    return XDP_PASS;
  }

  // Parse TCP header to extract source and destination port
  struct tcphdr *tcp;
  int tcp_type = parse_tcphdr(&nh, data_end, &tcp);
  if ((void *)(tcp + 1) > data_end) {
    return XDP_PASS;
  }

  // We could technically load-balance all the traffic but
  // we only focus on port 8000 to not impact any other network traffic
  // in the playground
  if (bpf_ntohs(tcp->source) != 8000 && bpf_ntohs(tcp->dest) != 8000) {
    return XDP_PASS;
  }

  // Print source and destination IP/MAC addresses
  bpf_printk("IN: SRC IP %pI4 -> DST IP %pI4", &ip->saddr, &ip->daddr);
  bpf_printk("IN: SRC MAC %02x:%02x:%02x:%02x:%02x:%02x -> DST MAC "
             "%02x:%02x:%02x:%02x:%02x:%02x",
             eth->h_source[0], eth->h_source[1], eth->h_source[2],
             eth->h_source[3], eth->h_source[4], eth->h_source[5],
             eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3],
             eth->h_dest[4], eth->h_dest[5]);

  // Choose backend using simple hashing
  struct four_tuple_t four_tuple;
  four_tuple.src_ip = ip->saddr;
  four_tuple.dst_ip = ip->daddr;
  four_tuple.src_port = tcp->source;
  four_tuple.dst_port = tcp->dest;
  four_tuple.protocol = IPPROTO_TCP;
  __u32 key = xdp_hash_tuple(&four_tuple) % NUM_BACKENDS;
  struct endpoint *backend = bpf_map_lookup_elem(&backends, &key);
  if (!backend) {
    return XDP_ABORTED;
  }

  // Perform a FIB lookup
  struct bpf_fib_lookup fib = {};
  int rc = fib_lookup_v4_full(ctx, &fib, ip->daddr, backend->ip,
                              bpf_ntohs(ip->tot_len));
  if (rc != BPF_FIB_LKUP_RET_SUCCESS) {
    log_fib_error(rc);
    return XDP_ABORTED;
  }

  // Make room for the new outer IPv4 header (20 bytes) between ETH and inner IPv4
  int adj = bpf_xdp_adjust_head(ctx, 0 - (int)sizeof(struct iphdr));
  if (adj < 0) {
    bpf_printk("Failed to adjust packet head");
    return XDP_ABORTED;
  }

  // Recompute data pointers after adjusting headed
  void *new_data_end = (void *)(long)ctx->data_end;
  void *new_data = (void *)(long)ctx->data;

  // Re-parse Ethernet header
  struct ethhdr *new_eth = new_data;
  if ((void *)(new_eth + 1) > new_data_end) {
    return XDP_ABORTED;
  }

  // Outer IPv4 header lives right after Ethernet
  struct iphdr *outer = (void *)(new_eth + 1);
  if ((void *)(outer + 1) > new_data_end) {
    return XDP_ABORTED;
  }

  // Inner IPv4 header is now right after the new outer IP header
  struct iphdr *inner = (void *)(outer + 1);
  if ((void *)(inner + 1) > new_data_end) {
    return XDP_ABORTED;
  }

  // Backend needs to have a virtual IP on the lo (same one as load balancer)
  // DSR is layer 3 and will see the source IP is client, so it will respond
  // directly to client
  __builtin_memcpy(new_eth->h_source, fib.smac, ETH_ALEN);
  __builtin_memcpy(new_eth->h_dest, fib.dmac, ETH_ALEN);
  new_eth->h_proto = bpf_htons(ETH_P_IP);

  // Build OUTER IPv4 header
  __u16 inner_len = bpf_ntohs(inner->tot_len);
  __u16 outer_len = (__u16)(inner_len + sizeof(struct iphdr));
  outer->version = 4;
  outer->ihl = 5; // 20 bytes
  outer->tos = 0;
  outer->tot_len = bpf_htons(outer_len);
  outer->id = 0;
  outer->frag_off = 0;
  outer->ttl = 64;
  outer->protocol = IPPROTO_IPIP;
  __u32 lbkey = 0;
  struct endpoint *lb = bpf_map_lookup_elem(&load_balancer, &lbkey);
  if (!lb) {
    return XDP_ABORTED;
  }
  outer->saddr = lb->ip; // use LB real IP as outer source

  outer->daddr = backend->ip;  // Outer IP header destination IP == backend node real IP
  outer->check = 0;

  // Compute outer L3 checksum from scratch
  outer->check = recalc_ip_checksum(outer);

  // We don’t need to recalculate a Ethernet frame checksum after changing
  // Ethernet MACs because the Ethernet frame checksum (FCS) isn’t in the header
  // but instead is automatically recomputed by the NIC hardware when the packet
  // is transmitted.

  bpf_printk("[OUTER] OUT: SRC IP %pI4 -> DST IP %pI4", &outer->saddr, &outer->daddr);
  bpf_printk("[INNER] OUT: SRC IP %pI4 -> DST IP %pI4", &inner->saddr, &inner->daddr);
  bpf_printk("OUT: SRC MAC %02x:%02x:%02x:%02x:%02x:%02x -> DST MAC "
             "%02x:%02x:%02x:%02x:%02x:%02x",
             new_eth->h_source[0], new_eth->h_source[1], new_eth->h_source[2],
             new_eth->h_source[3], new_eth->h_source[4], new_eth->h_source[5],
             new_eth->h_dest[0], new_eth->h_dest[1], new_eth->h_dest[2], new_eth->h_dest[3],
             new_eth->h_dest[4], new_eth->h_dest[5]);

  // Return XDP_TX to transmit the modified packet back to the network
  return XDP_TX;
}

char _license[] SEC("license") = "GPL";
