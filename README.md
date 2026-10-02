# HttpServer
This is the repo for the HTTP/HTTPS server for my dev portafolio written in C++ and targeting Linux platforms only using Kernel's AF_XDP socket setting them up manually as well as loading manually the eBPF code into kernel. This is to maximize throughput and minimize latency.

## References for eBPF and XDP

[Low-Latency, Deterministic Networking with Standard Linux... Magnus Karlsson & Björn Töpel, Intel](https://www.youtube.com/watch?v=p61PlC9y62k&t=71s)

[eBPF: AF_XDP Socket Setup, eBPF Program and Options-Variations-Exceptions](https://docs.ebpf.io/linux/concepts/af_xdp/)

## References for eBPF Layer 2 code packet filtering 

> Note : There is a billion (sarcasm) layer 2 configurations but I tried to handle how 99% of normal traffic would arrive to a HTTP server in layer 2

[EtherTypes Definitions](https://en.wikipedia.org/wiki/EtherType)

[Ethernet Frames](https://en.wikipedia.org/wiki/Ethernet_frame)

[IEEE_802.1Q](https://en.wikipedia.org/wiki/IEEE_802.1Q)

[IEEE_802.2+ (LLC)](https://en.wikipedia.org/wiki/IEEE_802.2)

[IEEE_802.2+ (SNAP)](https://en.wikipedia.org/wiki/Subnetwork_Access_Protocol)

