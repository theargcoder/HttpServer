#pragma once

#include <net/if.h>

#include <linux/ethtool.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/sockios.h>
#include <linux/types.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <poll.h>

namespace TcpSocket
{
  inline constexpr unsigned SOCKET_ADDRESS = 443; // standard HTTPS port

  inline constexpr unsigned CHUNK_SIZE = 4096;                   // 4 KB
  inline constexpr unsigned CHUNK_COUNT = 4096;                  // 4 KB
  inline constexpr unsigned UMEM_LEN = CHUNK_SIZE * CHUNK_COUNT; // 16 MB

  inline constexpr unsigned RING_BUFFER_SIZE = 512;

  inline constexpr const char *NETWORK_INTERFACE = "wlp3s0";

  struct ring_ptrs
  {
    __u32 *rx, *tx, *fill, *completion;
  };

  class Socket
  {
  private:
    xdp_umem_reg umem_reg;
    xdp_mmap_offsets mmap_offsets{};

    ring_ptrs consumer, producer;
    xdp_desc *rx_ring, *tx_ring;
    __u64 *fill_ring, *completion_ring;

    sockaddr_xdp sock_addr;

    unsigned char *umem;
    int fd;

    unsigned ifindex;
    bool xdp_attached;

  public:
    Socket();
    ~Socket() noexcept;

    // can't copy sockets bro, singleton only
    Socket(const Socket &other) = delete;
    Socket &operator=(const Socket &other) = delete;

    // It can be moved tho!!
    Socket(Socket &&other) noexcept;
    Socket &operator=(Socket &&other) noexcept;

  public:
    void wait_for_a_packet();
  };

} // namespace TcpSocket
