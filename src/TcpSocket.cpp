#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <span>
#include <stdexcept>

#include "include/TcpSocket.hpp"

extern "C"
{
  extern const unsigned char _binary_xdp_redirect_bpf_o_start[];
  extern const unsigned char _binary_xdp_redirect_bpf_o_end[];
}

namespace
{
  void perror_and_throw(const char *STR)
  {
    perror(STR);
    throw std::runtime_error{ STR };
  }

  void load_xdp_program(const unsigned ifindex, const int xsk_fd)
  {
    // bpf_object *obj = bpf_object__open_file(TCP_SOCKET_BPF_OBJECT, nullptr);
    const auto *bpf_data = _binary_xdp_redirect_bpf_o_start;

    const auto bpf_size = static_cast<size_t>(_binary_xdp_redirect_bpf_o_end - _binary_xdp_redirect_bpf_o_start);

    bpf_object *obj = bpf_object__open_mem(bpf_data, bpf_size, nullptr);

    if(obj == nullptr)
    {
      perror_and_throw("TcpSocket::Socket()::load_xdp_program() - failed to load BPF object form this executable");
    }

    const long open_err = libbpf_get_error(obj);

    if(open_err != 0)
    {
      errno = static_cast<int>(-open_err);
      perror_and_throw("TcpSocket::Socket()::load_xdp_program() - failed to open BPF object");
    }

    if(const int err = bpf_object__load(obj); err != 0)
    {
      bpf_object__close(obj);

      perror_and_throw("TcpSocket::Socket() - failed to load BPF object");
    }

    bpf_map *xsks_map = bpf_object__find_map_by_name(obj, "xsks_map");

    if(xsks_map == nullptr)
    {
      bpf_object__close(obj);

      perror_and_throw("TcpSocket::Socket() - xsks_map not found");
    }

    const int xsks_map_fd = bpf_map__fd(xsks_map);

    if(xsks_map_fd < 0)
    {
      bpf_object__close(obj);

      perror_and_throw("TcpSocket::Socket() - invalid xsks_map FD");
    }

    // Our XSK is bound to queue 0.
    const __u32 queue = 0;

    // XSKMAP stores the FD of the AF_XDP socket from userspace. The kernel resolves it to the actual XSK.
    const auto value = static_cast<__u32>(xsk_fd);

    if(bpf_map_update_elem(xsks_map_fd, &queue, &value, BPF_ANY) == -1)
    {
      bpf_object__close(obj);

      perror_and_throw("TcpSocket::Socket() - failed to insert XSK into XSKMAP");
    }

    bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_redirect_12345");

    if(prog == nullptr)
    {
      bpf_object__close(obj);

      perror_and_throw("TcpSocket::Socket() - XDP program not found");
    }

    const int prog_fd = bpf_program__fd(prog);

    if(prog_fd < 0)
    {
      bpf_object__close(obj);

      perror_and_throw("TcpSocket::Socket() - invalid XDP program FD");
    }

    // Force XDP_SKB/generic mode. This is what we want for lo.
    constexpr auto xdp_flags = XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST;

    if(const int err = bpf_xdp_attach(static_cast<int>(ifindex), prog_fd, xdp_flags, nullptr); err < 0)
    {
      bpf_object__close(obj);

      perror_and_throw("TcpSocket::Socket() - failed to attach XDP program");
    }

    // The XDP program and its map are now referenced by the kernel's attached program, so the userspace ELF object can be closed.
    bpf_object__close(obj);
  }

  void prime_fill_ring(__u64 *fill_ring, __u32 *producer)
  {
    // RING_BUFFER_SIZE is 512, so we can only initially put 512 addresses into the FILL ring.
    for(__u32 i = 0; i < TcpSocket::RING_BUFFER_SIZE; ++i)
    {
      fill_ring[i] = static_cast<__u64>(i) * TcpSocket::CHUNK_SIZE;
    }

    // Publish all descriptors after writing them.
    __atomic_store_n(producer, TcpSocket::RING_BUFFER_SIZE, __ATOMIC_RELEASE);
  }

  using Packet = std::span<std::byte>;

  namespace Ethernet
  {
    constexpr std::uint16_t IP = 0x0800;
    constexpr std::uint16_t IPV6 = 0x86DD;
    constexpr std::uint16_t VLAN = 0x8100;
    constexpr std::uint16_t VLAN_8021AD = 0x88A8;
    constexpr std::uint16_t MPLS_UC = 0x8847;
    constexpr std::uint16_t MPLS_MC = 0x8848;
  } // namespace Ethernet

  namespace IP
  {
    constexpr std::uint8_t TCP = 6;
    constexpr std::uint8_t UDP = 17;
  } // namespace IP

  constexpr std::uint16_t HTTP = 80;
  constexpr std::uint16_t HTTPS = 443;

  [[nodiscard]]
  constexpr std::uint16_t load_be16(const std::byte *ptr) noexcept
  {
    return (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(ptr[0])) << 8U) | (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(ptr[1])));
  }

  [[nodiscard]]
  constexpr std::uint32_t load_be32(const std::byte *ptr) noexcept
  {
    return (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(ptr[0])) << 24U) | (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(ptr[1])) << 16U)
           | (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(ptr[2])) << 8U) | (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(ptr[3])));
  }

  [[nodiscard]]
  const std::byte *tcp_udp_header(Packet packet) noexcept
  {
    const std::byte *data = packet.data();
    const std::byte *end = data + packet.size();

    // Skip destination + source MAC.
    data += 12;

    std::uint16_t header = load_be16(data);

    if(header == Ethernet::VLAN || header == Ethernet::VLAN_8021AD)
    {
      for(std::size_t i = 0; i < 8; ++i)
      {
        header = load_be16(data);

        if(header != Ethernet::VLAN && header != Ethernet::VLAN_8021AD)
        {
          break;
        }

        // Skip TCI.
        data += 4;
      }
      // data now points at the next EtherType.
    }

    if(header < 1501)
    {
      data += 8; // Skip Length.(2) DSAP + SSAP (2) + Control byte (1) + OUI (3)

      // SNAP encapsulated EtherType.
      header = load_be16(data);
    }

    if(header == Ethernet::MPLS_UC || header == Ethernet::MPLS_MC)
    {
      // Skip the EtherType.
      data += 2;

      for(std::size_t i = 0; i < 8; ++i)
      {
        const std::uint32_t mpls_header = load_be32(data);

        // Skip MPLS label.
        data += 4;

        if(mpls_header & 0x00000100U)
          break;
      }

      const std::uint8_t ip_version = std::to_integer<std::uint8_t>(*data) >> 4U;

      header = ip_version == 4 ? Ethernet::IP : Ethernet::IPV6;
    }

    bool is_tcp = false;
    if(header == Ethernet::IP)
    {
      data += 2; // skip Ether/Type

      const __u8 ipv4_octet_0 = *(__u8 *)data;

      data += 6; // skip Ver/IHL (1) and DSCP/ECN (1) + TotalLen (2) and Identification (2)

      data += 3; // // Flags-Fragment Offset (2) and Time-to-live (1)

      const unsigned char ipv4_octet_9 = *reinterpret_cast<const unsigned char *>(data);

      is_tcp = ipv4_octet_9 == 6;

      data += 11; // skip Protocol (1) and Checksum (2)  + Source Address (4) and Desination Address (4)

      // now data points to start of payload
    }
    else
    {
      data += 2; // skip Ether/Type (2)

      data += 6; // skip version (1) + traffic class (1) + flow label (2) + skip payload length (2)

      const unsigned char ipv6_octet_6 = *reinterpret_cast<const unsigned char *>(data);

      is_tcp = ipv6_octet_6 == 6;

      data += 34; // skip Next Header (1) + Hop Limit (1) + Source Address (16) + Destination Address (16)
    }

    if(is_tcp)
    {
      // Need at least the fixed TCP header.
      if(data + 20 > end)
      {
        return nullptr;
      }

      const std::uint8_t data_offset = std::to_integer<std::uint8_t>(data[12]) >> 4U;

      const std::size_t tcp_header_len = static_cast<std::size_t>(data_offset) * 4U;

      // TCP header must be at least 20 bytes.
      if(tcp_header_len < 20)
      {
        return nullptr;
      }

      if(data + tcp_header_len > end)
      {
        return nullptr;
      }

      // THIS IS THE APPLICATION DATA *
      return data + tcp_header_len;
    }
    else
    {
      // UDP header is always 8 bytes.
      if(data + 8 > end)
      {
        return nullptr;
      }

      return data + 8;
    }
  }
} // namespace

namespace TcpSocket
{
  Socket::Socket(Socket && /*other*/) noexcept = default;
  Socket &Socket::operator=(Socket && /*other*/) noexcept = default;

  Socket::~Socket() noexcept
  {
    if(this->xdp_attached && this->ifindex != 0)
    {
      if(const int err = bpf_xdp_detach(static_cast<int>(this->ifindex), XDP_FLAGS_SKB_MODE, nullptr); err < 0)
      {
        // cant throw since desctructors in C++ have to be noexcept
        fprintf(stderr, "bpf_xdp_detach failed: %s\n", strerror(-err));
      }
    }

    if(this->umem)
    {
      free(this->umem);
    }

    if(fd != -1)
    {
      close(fd);
    }
  }

  Socket::Socket() : umem(nullptr), fd(-1), ifindex(0), xdp_attached(false)
  {
    if(posix_memalign(reinterpret_cast<void **>(&umem), 4096, UMEM_LEN) != 0)
    {
      perror_and_throw("TcpSocket::Socket() - posix_memalign failed");
    }

    fd = socket(AF_XDP, SOCK_RAW, 0);

    if(fd == -1)
    {
      perror_and_throw("TcpSocket::Socket() - socket creation failed");
    }

    if(this->umem == nullptr)
    {
      perror_and_throw("TcpSocket::Socket() - malloc failed");
    }

    this->umem_reg = { .addr = reinterpret_cast<__u64>(static_cast<void *>(this->umem)), .len = UMEM_LEN, .chunk_size = CHUNK_SIZE, .headroom = 0, .flags = 0 };

    if(setsockopt(fd, SOL_XDP, XDP_UMEM_REG, &this->umem_reg, sizeof(this->umem_reg)) == -1)
    {
      perror_and_throw("TcpSocket::Socket() - syscall for socket XDP UMEM failed");
    }

    for(const auto &opt : { XDP_RX_RING, XDP_TX_RING, XDP_UMEM_FILL_RING, XDP_UMEM_COMPLETION_RING })
    {
      if(setsockopt(fd, SOL_XDP, opt, &RING_BUFFER_SIZE, sizeof(RING_BUFFER_SIZE)) == -1)
      {
        perror_and_throw("TcpSocket::Socket() - syscall setsockopt for options for XDP socket failed");
      }
    }

    if(socklen_t mmap_offset_len = sizeof(this->mmap_offsets); getsockopt(fd, SOL_XDP, XDP_MMAP_OFFSETS, &this->mmap_offsets, &mmap_offset_len) == -1)
    {
      perror_and_throw("TcpSocket::Socket() - syscall setsockopt for XDP MMAP offsets failed");
    }

    void *mmap_rx = mmap(nullptr, this->mmap_offsets.rx.desc + RING_BUFFER_SIZE * sizeof(xdp_desc), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, XDP_PGOFF_RX_RING);
    void *mmap_tx = mmap(nullptr, this->mmap_offsets.tx.desc + RING_BUFFER_SIZE * sizeof(xdp_desc), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, XDP_PGOFF_TX_RING);
    void *mmap_fill = mmap(nullptr, this->mmap_offsets.fr.desc + RING_BUFFER_SIZE * sizeof(__u64), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, XDP_UMEM_PGOFF_FILL_RING);
    void *mmap_completion
        = mmap(nullptr, this->mmap_offsets.cr.desc + RING_BUFFER_SIZE * sizeof(__u64), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, XDP_UMEM_PGOFF_COMPLETION_RING);

    if(mmap_rx == MAP_FAILED || mmap_tx == MAP_FAILED || mmap_fill == MAP_FAILED || mmap_completion == MAP_FAILED)
    {
      perror_and_throw("TcpSocket::Socket() - ring buffer memory maps failed");
    }

    auto *rx_base = static_cast<std::byte *>(mmap_rx);
    auto *tx_base = static_cast<std::byte *>(mmap_tx);
    auto *fill_base = static_cast<std::byte *>(mmap_fill);
    auto *completion_base = static_cast<std::byte *>(mmap_completion);

    this->consumer.rx = reinterpret_cast<__u32 *>(rx_base + this->mmap_offsets.rx.consumer);
    this->producer.rx = reinterpret_cast<__u32 *>(rx_base + this->mmap_offsets.rx.producer);
    this->consumer.tx = reinterpret_cast<__u32 *>(tx_base + this->mmap_offsets.tx.consumer);
    this->producer.tx = reinterpret_cast<__u32 *>(tx_base + this->mmap_offsets.tx.producer);

    this->consumer.fill = reinterpret_cast<__u32 *>(fill_base + this->mmap_offsets.fr.consumer);
    this->producer.fill = reinterpret_cast<__u32 *>(fill_base + this->mmap_offsets.fr.producer);

    this->consumer.completion = reinterpret_cast<__u32 *>(completion_base + this->mmap_offsets.cr.consumer);
    this->producer.completion = reinterpret_cast<__u32 *>(completion_base + this->mmap_offsets.cr.producer);

    this->rx_ring = reinterpret_cast<xdp_desc *>(rx_base + this->mmap_offsets.rx.desc);
    this->tx_ring = reinterpret_cast<xdp_desc *>(tx_base + this->mmap_offsets.tx.desc);
    this->fill_ring = reinterpret_cast<__u64 *>(fill_base + this->mmap_offsets.fr.desc);
    this->completion_ring = reinterpret_cast<__u64 *>(completion_base + this->mmap_offsets.cr.desc);

    this->ifindex = if_nametoindex("lo");

    if(this->ifindex == 0)
    {
      perror_and_throw("TcpSocket::Socket() - if_nametoindex(lo) failed");
    }

    this->sock_addr = { .sxdp_family = AF_XDP, .sxdp_flags = 0, .sxdp_ifindex = this->ifindex, .sxdp_queue_id = 0, .sxdp_shared_umem_fd = static_cast<__u32>(this->fd) };

    prime_fill_ring(this->fill_ring, this->producer.fill);

    if(bind(this->fd, reinterpret_cast<const sockaddr *>(&this->sock_addr), sizeof(this->sock_addr)) == -1)
    {
      perror_and_throw("TcpSocket::Socket() - bind raw socket failed");
    }

    load_xdp_program(this->ifindex, this->fd);

    this->xdp_attached = true;
  };

  void Socket::wait_for_a_packet()
  {
    pollfd pfd{ .fd = this->fd, .events = POLLIN, .revents = 0 };

    for(;;)
    {
      const int ret = poll(&pfd, 1, -1);

      if(ret == -1)
      {
        if(errno == EINTR)
        {
          continue;
        }

        perror_and_throw("TcpSocket::wait_for_one_packet() - poll failed");
      }

      if(pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
      {
        throw std::runtime_error{ "TcpSocket::wait_for_one_packet() - poll reported socket error" };
      }

      const __u32 consumer_index = __atomic_load_n(this->consumer.rx, __ATOMIC_RELAXED);

      const __u32 producer_index = __atomic_load_n(this->producer.rx, __ATOMIC_ACQUIRE);

      if(consumer_index == producer_index)
      {
        continue;
      }

      const __u32 index = consumer_index & (RING_BUFFER_SIZE - 1);

      const xdp_desc desc = this->rx_ring[index];

      if(desc.addr >= UMEM_LEN || desc.len > UMEM_LEN - desc.addr)
      {
        throw std::runtime_error{ "TcpSocket::wait_for_one_packet() - invalid RX descriptor" };
      }

      auto *packet = this->umem + desc.addr;

      auto span = std::span<std::byte>(reinterpret_cast<std::byte *>(packet), desc.len);

      // XDP already filtered this packet before it ever reached us. so we return the Application data ptr
      const auto *beg_of_data = tcp_udp_header(span);

      printf("\n=== AF_XDP RX PACKET ===\n"
             "\tlength: %u\n"
             "\taddr:   %llu\n",
             desc.len, static_cast<unsigned long long>(desc.addr));

      // --------------------------------------------------------------
      // Full packet hex dump
      // ---------------------------------------------------------------
      const __u32 dump_len = desc.len < 64 ? desc.len : 64;

      printf("\nPACKET HEX:");

      for(__u32 i = 0; i < dump_len; ++i)
      {
        if(i % 16 == 0)
        {
          printf("\n%04x: ", i);
        }

        printf("%02x ", static_cast<unsigned>(std::to_integer<unsigned char>(span[i])));
      }

      printf("\n");

      // --------------------------------------------------------------
      // Application DATA
      // ---------------------------------------------------------------
      if(beg_of_data == nullptr)
      {
        printf("\nDATA:\n \tParser returned nullptr\n");
      }
      else
      {
        const auto *packet_begin = span.data();

        const auto *packet_end = packet_begin + span.size();

        const auto data_offset = static_cast<std::size_t>(beg_of_data - packet_begin);

        const auto data_length = static_cast<std::size_t>(packet_end - beg_of_data);

        printf("\n=== APPLICATION DATA ===\n"
               "\tOffset: %zu\n"
               "\tLength: %zu\n"
               "\tPtr:    %p\n",
               data_offset, data_length, static_cast<const void *>(beg_of_data));

        // Raw application payload. With your current test this should print: HELLO_FROM_AF_XDP
        printf("\nDATA STRING:\n");

        for(const std::byte byte : std::span{ beg_of_data, data_length })
        {
          printf("%c", static_cast<char>(std::to_integer<unsigned char>(byte)));
        }

        printf("\n");

        // Application payload hex dump.
        printf("\nDATA HEX:");

        for(std::size_t i = 0; i < data_length; ++i)
        {
          if(i % 16 == 0)
          {
            printf("\n%04zx: ", i);
          }

          printf("%02x ", static_cast<unsigned>(std::to_integer<unsigned char>(beg_of_data[i])));
        }

        printf("\n");
      }

      // --------------------------------------------------------------
      // Recycle this UMEM frame back onto the FILL ring.
      // ---------------------------------------------------------------
      const __u32 fill_producer = __atomic_load_n(this->producer.fill, __ATOMIC_RELAXED);

      this->fill_ring[fill_producer & (RING_BUFFER_SIZE - 1)] = desc.addr;

      __atomic_store_n(this->producer.fill, fill_producer + 1, __ATOMIC_RELEASE);

      // Tell the kernel that we consumed this RX descriptor.
      __atomic_store_n(this->consumer.rx, consumer_index + 1, __ATOMIC_RELEASE);

      return;
    }
  }

} // namespace TcpSocket
