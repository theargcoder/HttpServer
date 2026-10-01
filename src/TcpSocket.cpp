#include <cstdio>
#include <cstdlib>
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
        perror_and_throw("TcpSocket::wait_for_one_packet() - poll failed");
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

      const auto *packet = this->umem + desc.addr;

      printf("\n=== AF_XDP RX PACKET ===\n\tlength: %u\n\taddr:   %llu\n", desc.len, static_cast<unsigned long long>(desc.addr));

      const __u32 dump_len = desc.len < 64 ? desc.len : 64;

      for(__u32 i = 0; i < dump_len; ++i)
      {
        if(i % 16 == 0)
        {
          printf("\n%04x: ", i);
        }

        printf("%02x ", static_cast<unsigned>(packet[i]));
      }

      printf("\n\n");

      // Recycle this UMEM frame back onto the FILL ring.
      const __u32 fill_producer = __atomic_load_n(this->producer.fill, __ATOMIC_RELAXED);

      this->fill_ring[fill_producer & (RING_BUFFER_SIZE - 1)] = desc.addr;

      __atomic_store_n(this->producer.fill, fill_producer + 1, __ATOMIC_RELEASE);

      // Tell the kernel that we've consumed the RX descriptor.
      __atomic_store_n(this->consumer.rx, consumer_index + 1, __ATOMIC_RELEASE);

      return;
    }
  }

} // namespace TcpSocket
