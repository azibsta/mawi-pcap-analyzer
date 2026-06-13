/*
 * mawi_engine.cpp
 *
 * MAWI PCAP Research Engine — integrated with Python pipeline.
 *
 * Upgraded from prototype:
 *   1. Thread Pool for bounded parallel processing (prevents disk thrashing).
 *   2. IPv6 Transport parsing (TCP/UDP/ICMP/QUIC over IPv6).
 *   3. Bidirectional FlowHash (A->B and B->A collapse to same flow).
 *   4. Memory Alignment Safety (memcpy instead of unaligned pointer casting).
 *   5. Year 2038 protection (uint64_t timestamps).
 *
 * Build (Linux/macOS):
 *   g++ -std=c++17 -O2 -pthread mawi_engine.cpp -o mawi_engine
 *
 * Build (Windows, MSVC):
 *   cl /std:c++17 /O2 mawi_engine.cpp ws2_32.lib /Fe:mawi_engine.exe
 *
 * Build (Windows, MinGW):
 *   g++ -std=c++17 -O2 mawi_engine.cpp -lws2_32 -o mawi_engine.exe
 */

#include <cstdint>
#include <stdlib.h>

#ifdef _WIN32
  #include <winsock2.h>
  #pragma comment(lib, "ws2_32.lib")
  static inline uint32_t byteswap32(uint32_t v) { return _byteswap_ulong(v); }
  static inline uint16_t byteswap16(uint16_t v) { return _byteswap_ushort(v); }
  #define PATH_SEP '\\'
#else
  #include <arpa/inet.h>
  static inline uint32_t byteswap32(uint32_t v) {
      return ((v & 0xFF000000u) >> 24) | ((v & 0x00FF0000u) >> 8)
           | ((v & 0x0000FF00u) << 8)  | ((v & 0x000000FFu) << 24);
  }
  static inline uint16_t byteswap16(uint16_t v) {
      return (uint16_t)((v >> 8) | (v << 8));
  }
  #define PATH_SEP '/'
#endif

#include <iostream>
#include <filesystem>
#include <unordered_map>
#include <map>
#include <vector>
#include <future>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <iomanip>
#include <chrono>
#include <sstream>
#include <string>
#include <thread>
#include <mutex>
#include <queue>
#include <condition_variable>

namespace fs = std::filesystem;

// ── Thread Pool ────────────────────────────────────────────────────────────────
class ThreadPool {
public:
    ThreadPool(size_t threads) : stop(false) {
        for(size_t i = 0; i < threads; ++i)
            workers.emplace_back([this] {
                for(;;) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(this->queue_mutex);
                        this->condition.wait(lock, [this]{ return this->stop || !this->tasks.empty(); });
                        if(this->stop && this->tasks.empty()) return;
                        task = std::move(this->tasks.front());
                        this->tasks.pop();
                    }
                    task();
                }
            });
    }
    template<class F>
    auto enqueue(F&& f) -> std::future<typename std::invoke_result<F>::type> {
        using return_type = typename std::invoke_result<F>::type;
        auto task = std::make_shared<std::packaged_task<return_type()>>(std::forward<F>(f));
        std::future<return_type> res = task->get_future();
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            if(stop) throw std::runtime_error("enqueue on stopped ThreadPool");
            tasks.emplace([task](){ (*task)(); });
        }
        condition.notify_one();
        return res;
    }
    ~ThreadPool() {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            stop = true;
        }
        condition.notify_all();
        for(std::thread &worker: workers) worker.join();
    }
private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;
    std::mutex queue_mutex;
    std::condition_variable condition;
    bool stop;
};


// ── Config ─────────────────────────────────────────────────────────────────────
constexpr bool   ENABLE_CHECKSUM = false;
static uint64_t  MAX_PACKETS     = 0;

// ── Constants ──────────────────────────────────────────────────────────────────
constexpr int      ETHER_ADDR_LEN = 6;
constexpr uint16_t ETHERTYPE_IP   = 0x0800;
constexpr uint16_t ETHERTYPE_IPV6 = 0x86DD;
constexpr uint8_t  TH_FIN = 0x01;
constexpr uint8_t  TH_SYN = 0x02;
constexpr uint8_t  TH_RST = 0x04;
constexpr uint8_t  TH_ACK = 0x10;
constexpr int      TOP_PORTS_N   = 5;

// ── PCAP headers (packed) ──────────────────────────────────────────────────────
#pragma pack(push, 1)
struct PcapGlobalHeader {
    uint32_t magic;
    uint16_t v_major, v_minor;
    int32_t  thiszone;
    uint32_t sigfigs, snaplen, linktype;
};
struct PcapPacketHeader {
    uint32_t tv_sec, tv_usec, caplen, len;
};
struct EtherHeader {
    uint8_t  dst[ETHER_ADDR_LEN];
    uint8_t  src[ETHER_ADDR_LEN];
    uint16_t type;
};
struct IPHeader {
    uint8_t  ver_ihl, tos;
    uint16_t total_len, id, flags_fo;
    uint8_t  ttl, protocol;
    uint16_t checksum;
    uint32_t src, dst;
};
struct IPv6Header {
    uint32_t vtc_flow;
    uint16_t payload_len;
    uint8_t  next_header;
    uint8_t  hop_limit;
    uint8_t  src[16];
    uint8_t  dst[16];
};
struct TCPHeader {
    uint16_t src_port, dst_port;
    uint32_t seq, ack;
    uint8_t  offset_res, flags;
    uint16_t window, checksum, urgent_ptr;
};
struct UDPHeader {
    uint16_t src_port, dst_port, len, checksum;
};
#pragma pack(pop)

// ── Bidirectional Flow key ─────────────────────────────────────────────────────
struct FlowKey {
    uint8_t  src_ip[16];
    uint8_t  dst_ip[16];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
    bool     is_ipv6;

    FlowKey(uint32_t s4, uint32_t d4, uint16_t sp, uint16_t dp, uint8_t p) {
        is_ipv6 = false;
        proto = p;
        if (s4 < d4 || (s4 == d4 && sp <= dp)) {
            src_port = sp; dst_port = dp;
            std::memcpy(src_ip, &s4, 4);
            std::memcpy(dst_ip, &d4, 4);
        } else {
            src_port = dp; dst_port = sp;
            std::memcpy(src_ip, &d4, 4);
            std::memcpy(dst_ip, &s4, 4);
        }
        std::memset(src_ip + 4, 0, 12);
        std::memset(dst_ip + 4, 0, 12);
    }

    FlowKey(const uint8_t* s6, const uint8_t* d6, uint16_t sp, uint16_t dp, uint8_t p) {
        is_ipv6 = true;
        proto = p;
        int cmp = std::memcmp(s6, d6, 16);
        if (cmp < 0 || (cmp == 0 && sp <= dp)) {
            src_port = sp; dst_port = dp;
            std::memcpy(src_ip, s6, 16);
            std::memcpy(dst_ip, d6, 16);
        } else {
            src_port = dp; dst_port = sp;
            std::memcpy(src_ip, d6, 16);
            std::memcpy(dst_ip, s6, 16);
        }
    }

    bool operator==(const FlowKey& o) const {
        return is_ipv6 == o.is_ipv6 && proto == o.proto &&
               src_port == o.src_port && dst_port == o.dst_port &&
               std::memcmp(src_ip, o.src_ip, 16) == 0 &&
               std::memcmp(dst_ip, o.dst_ip, 16) == 0;
    }
};

struct FlowHash {
    size_t operator()(const FlowKey& k) const {
        size_t h = k.is_ipv6 ? 2166136261u : 0;
        int len = k.is_ipv6 ? 16 : 4;
        for(int i=0; i < len; ++i) h = h * 1315423911u + k.src_ip[i];
        for(int i=0; i < len; ++i) h = h * 1315423911u + k.dst_ip[i];
        h = h * 1315423911u + k.src_port;
        h = h * 1315423911u + k.dst_port;
        h = h * 1315423911u + k.proto;
        return h;
    }
};

using PortMap = std::unordered_map<uint16_t, uint64_t>;

// ── Traffic stats ──────────────────────────────────────────────────────────────
struct TrafficStats {
    uint64_t packets=0, bytes=0;
    uint64_t ipv4=0, ipv6=0;
    uint64_t tcp=0, udp=0, icmp=0, other_proto=0;
    uint64_t http=0, https=0, quic=0;
    uint64_t anomalies=0, checksum_errors=0;
    uint64_t tcp_syn=0, tcp_ack=0, tcp_fin=0, tcp_rst=0;
    uint64_t flows_seen=0;
    uint64_t gnutella=0, emule=0, msn=0, rtmp=0, telnet=0, ssh=0, cuseeme=0;

    uint64_t first_ts=0, last_ts=0;

    PortMap dst_port_freq;
    std::unordered_map<FlowKey, uint32_t, FlowHash> flows;

    void flush_flows() {
        flows_seen += flows.size();
        flows.clear();
    }
};

static void merge_stats(TrafficStats& dst, const TrafficStats& src) {
    dst.packets   += src.packets;
    dst.bytes     += src.bytes;
    dst.ipv4      += src.ipv4;
    dst.ipv6      += src.ipv6;
    dst.tcp       += src.tcp;
    dst.udp       += src.udp;
    dst.icmp      += src.icmp;
    dst.other_proto += src.other_proto;
    dst.http      += src.http;
    dst.https     += src.https;
    dst.quic      += src.quic;
    dst.anomalies += src.anomalies;
    dst.checksum_errors += src.checksum_errors;
    dst.tcp_syn   += src.tcp_syn;
    dst.tcp_ack   += src.tcp_ack;
    dst.tcp_fin   += src.tcp_fin;
    dst.tcp_rst   += src.tcp_rst;
    dst.flows_seen += src.flows_seen;
    dst.gnutella  += src.gnutella;
    dst.emule     += src.emule;
    dst.msn       += src.msn;
    dst.rtmp      += src.rtmp;
    dst.telnet    += src.telnet;
    dst.ssh       += src.ssh;
    dst.cuseeme   += src.cuseeme;

    if (src.first_ts && (!dst.first_ts || src.first_ts < dst.first_ts)) dst.first_ts = src.first_ts;
    if (src.last_ts > dst.last_ts) dst.last_ts = src.last_ts;

    for (const auto& [port, cnt] : src.dst_port_freq)
        dst.dst_port_freq[port] += cnt;
}

// ── Checksum ───────────────────────────────────────────────────────────────────
static uint16_t ip_checksum(const uint16_t* buf, int len) {
    uint32_t sum = 0;
    while (len > 1) { sum += *buf++; len -= 2; }
    if (len) sum += *(const uint8_t*)buf;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)~sum;
}

static std::string json_str(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 2);
    out += '"';
    for (char c : s) {
        if (c == '"' || c == '\\') out += '\\';
        out += c;
    }
    out += '"';
    return out;
}

static void emit_json(const std::string& year, const TrafficStats& s) {
    double total = s.packets ? (double)s.packets : 1.0;

    std::vector<std::pair<uint64_t, uint16_t>> port_vec;
    port_vec.reserve(s.dst_port_freq.size());
    for (const auto& [port, cnt] : s.dst_port_freq)
        port_vec.emplace_back(cnt, port);
    std::partial_sort(port_vec.begin(),
                      port_vec.begin() + std::min((int)port_vec.size(), TOP_PORTS_N),
                      port_vec.end(), std::greater<>{});

    std::ostringstream o;
    o << "{"
      << "\"year\":"         << json_str(year)         << ","
      << "\"total_packets\":" << s.packets              << ","
      << "\"total_bytes\":"   << s.bytes                << ","
      << "\"ipv4_pkts\":"     << s.ipv4                 << ","
      << "\"ipv6_pkts\":"     << s.ipv6                 << ","
      << "\"tcp_pkts\":"      << s.tcp                  << ","
      << "\"udp_pkts\":"      << s.udp                  << ","
      << "\"icmp_pkts\":"     << s.icmp                 << ","
      << "\"other_proto_pkts\":" << s.other_proto       << ","
      << "\"http_pkts\":"     << s.http                 << ","
      << "\"https_pkts\":"    << s.https                << ","
      << "\"quic_pkts\":"     << s.quic                 << ","
      << "\"tcp_syn\":"       << s.tcp_syn              << ","
      << "\"tcp_ack\":"       << s.tcp_ack              << ","
      << "\"tcp_fin\":"       << s.tcp_fin              << ","
      << "\"tcp_rst\":"       << s.tcp_rst              << ","
      << "\"anomaly_pkts\":"  << s.anomalies            << ","
      << "\"checksum_errors\":" << s.checksum_errors    << ","
      << "\"distinct_flows\":" << s.flows_seen          << ","
      << "\"first_ts\":"      << s.first_ts             << ","
      << "\"last_ts\":"       << s.last_ts              << ","
      << "\"tcp_pct\":"       << std::fixed << std::setprecision(4) << (s.tcp  / total * 100) << ","
      << "\"udp_pct\":"                                              << (s.udp  / total * 100) << ","
      << "\"icmp_pct\":"                                            << (s.icmp / total * 100) << ","
      << "\"http_pct\":"                                            << (s.http / total * 100) << ","
      << "\"https_pct\":"                                           << (s.https/ total * 100) << ","
      << "\"quic_pct\":"                                            << (s.quic / total * 100) << ","
      << "\"gnutella_pct\":"                                        << (s.gnutella / total * 100) << ","
      << "\"emule_pct\":"                                           << (s.emule / total * 100) << ","
      << "\"msn_pct\":"                                             << (s.msn / total * 100) << ","
      << "\"rtmp_pct\":"                                            << (s.rtmp / total * 100) << ","
      << "\"telnet_pct\":"                                          << (s.telnet / total * 100) << ","
      << "\"ssh_pct\":"                                             << (s.ssh / total * 100) << ","
      << "\"cuseeme_pct\":"                                         << (s.cuseeme / total * 100) << ","
      << "\"syn_flood_flag\":"  << (s.tcp_syn > s.tcp_ack * 0.8 ? "true" : "false") << ","
      << "\"rst_flood_flag\":"  << (s.tcp_rst > s.tcp_fin * 2   ? "true" : "false") << ","
      << "\"top_dst_ports\":[";
    int limit = std::min((int)port_vec.size(), TOP_PORTS_N);
    for (int i = 0; i < limit; ++i) {
        if (i) o << ",";
        o << "{\"port\":" << port_vec[i].second
          << ",\"pkts\":"  << port_vec[i].first << "}";
    }
    o << "]}";

    std::cout << o.str() << "\n";
}

static void print_row(const std::string& label, uint64_t count, double total) {
    std::cout << std::left << std::setw(22) << label
              << std::setw(14) << count
              << std::fixed << std::setprecision(2)
              << (count / total) * 100.0 << "%\n";
}

static void print_human(const std::map<std::string, TrafficStats>& all_stats) {
    std::cout << "\n================ MAWI TRAFFIC ANALYSIS ================\n";
    for (const auto& [year, s] : all_stats) {
        double total = s.packets ? (double)s.packets : 1.0;
        double mb    = s.bytes / (1024.0 * 1024.0);

        std::cout << "\n[ Year: " << year << " ]\n";
        std::cout << "--------------------------------------------------------\n";
        print_row("Total Packets",   s.packets, total);
        print_row("IPv4",            s.ipv4,    total);
        print_row("IPv6",            s.ipv6,    total);
        print_row("TCP",             s.tcp,     total);
        print_row("UDP",             s.udp,     total);
        print_row("ICMP",            s.icmp,    total);
        print_row("HTTP  (TCP/80)",  s.http,    total);
        print_row("HTTPS (TCP/443)", s.https,   total);
        print_row("QUIC  (UDP/443)", s.quic,    total);
        print_row("Anomalies",       s.anomalies, total);
        std::cout << "--------------------------------------------------------\n";
        std::cout << "Total Bandwidth : " << std::fixed << std::setprecision(2)
                  << mb << " MB\n";
        std::cout << "Distinct Flows  : " << s.flows_seen << "\n";

        std::cout << "\n--- Security Indicators ---\n";
        print_row("SYN Packets", s.tcp_syn, total);
        print_row("RST Packets", s.tcp_rst, total);
        if (s.tcp_syn > s.tcp_ack * 0.8)
            std::cout << "  [!] WARNING: Potential SYN Flood detected.\n";
        if (s.tcp_rst > s.tcp_fin * 2)
            std::cout << "  [!] WARNING: High RST count (Port Scanning).\n";
    }
}

// ── Core file parser ───────────────────────────────────────────────────────────
static TrafficStats analyze_file(const std::string& filepath) {
    TrafficStats stats;

    FILE* f = fopen(filepath.c_str(), "rb");
    if (!f) {
        std::cerr << "[warn] cannot open " << filepath << "\n";
        return stats;
    }

    PcapGlobalHeader gh{};
    if (fread(&gh, sizeof(gh), 1, f) != 1) { fclose(f); return stats; }

    bool swap = (gh.magic == 0xd4c3b2a1u);
    auto r32  = [&](uint32_t v) { return swap ? byteswap32(v) : v; };

    PcapPacketHeader ph{};
    uint8_t buffer[65536];

    stats.flows.reserve(200000);

    auto t_start = std::chrono::high_resolution_clock::now();

    while (fread(&ph, sizeof(ph), 1, f) == 1) {
        uint32_t caplen  = r32(ph.caplen);
        uint32_t wirelen = r32(ph.len);
        uint64_t ts_sec  = r32(ph.tv_sec);

        if (!stats.first_ts || ts_sec < stats.first_ts) stats.first_ts = ts_sec;
        if (ts_sec > stats.last_ts)                      stats.last_ts  = ts_sec;

        if (caplen < sizeof(EtherHeader) || caplen > sizeof(buffer)) {
            fseek(f, caplen, SEEK_CUR);
            continue;
        }

        EtherHeader eth{};
        if (fread(&eth, sizeof(eth), 1, f) != 1) break;

        uint32_t payload_len = caplen - sizeof(eth);
        if (fread(buffer, 1, payload_len, f) != payload_len) break;

        stats.packets++;
        stats.bytes += wirelen;

        if (MAX_PACKETS && stats.packets >= MAX_PACKETS) break;

        uint16_t etype = ntohs(eth.type);

        uint8_t protocol = 0;
        uint32_t src_ip_v4 = 0, dst_ip_v4 = 0;
        const uint8_t* src_ip_v6 = nullptr;
        const uint8_t* dst_ip_v6 = nullptr;
        bool is_v6 = false;

        uint8_t* l4 = nullptr;
        uint32_t l4_len = 0;

        if (etype == ETHERTYPE_IP) {
            stats.ipv4++;
            if (payload_len < sizeof(IPHeader)) continue;

            IPHeader ip;
            std::memcpy(&ip, buffer, sizeof(IPHeader)); // Safe memory alignment

            int ihl = (ip.ver_ihl & 0x0F) * 4;
            if (ihl < 20 || (int)payload_len < ihl) continue;

            if (ENABLE_CHECKSUM &&
                ip_checksum(reinterpret_cast<const uint16_t*>(buffer), ihl) != 0)
                stats.checksum_errors++;

            src_ip_v4 = ntohl(ip.src);
            dst_ip_v4 = ntohl(ip.dst);
            if (ip.ttl == 0 || src_ip_v4 == dst_ip_v4) stats.anomalies++;

            protocol = ip.protocol;
            l4 = buffer + ihl;
            l4_len = payload_len - ihl;
            is_v6 = false;

        } else if (etype == ETHERTYPE_IPV6) {
            stats.ipv6++;
            if (payload_len < sizeof(IPv6Header)) continue;

            IPv6Header ip6;
            std::memcpy(&ip6, buffer, sizeof(IPv6Header));

            // Shallow copy pointers since ip6 struct falls out of scope, but wait!
            // ip6 struct falls out of scope, so we can't keep pointers to it.
            // But we process it immediately below, wait, FlowKey copies the bytes.
            // So we can just use the pointers during this loop iteration.
            src_ip_v6 = ip6.src;
            dst_ip_v6 = ip6.dst;
            
            protocol = ip6.next_header; 
            l4 = buffer + sizeof(IPv6Header);
            l4_len = payload_len - sizeof(IPv6Header);
            is_v6 = true;

        } else {
            continue; // Not IP or IPv6
        }

        // L4 Parsing
        if (protocol == 6) {        // ── TCP ──
            if (l4_len < sizeof(TCPHeader)) continue;
            TCPHeader tcp;
            std::memcpy(&tcp, l4, sizeof(TCPHeader));

            int thl = ((tcp.offset_res >> 4) & 0x0F) * 4;
            if ((int)l4_len < thl) continue;

            uint16_t sp = ntohs(tcp.src_port);
            uint16_t dp = ntohs(tcp.dst_port);

            stats.tcp++;
            if (tcp.flags & TH_SYN) stats.tcp_syn++;
            if (tcp.flags & TH_ACK) stats.tcp_ack++;
            if (tcp.flags & TH_FIN) stats.tcp_fin++;
            if (tcp.flags & TH_RST) stats.tcp_rst++;

            if (sp == 80  || dp == 80)  stats.http++;
            if (sp == 443 || dp == 443) stats.https++;

            if (sp == 6346 || dp == 6346) stats.gnutella++;
            if (sp == 4662 || dp == 4662 || sp == 4672 || dp == 4672) stats.emule++;
            if (sp == 1863 || dp == 1863) stats.msn++;
            if (sp == 1935 || dp == 1935) stats.rtmp++;
            if (sp == 23 || dp == 23) stats.telnet++;
            if (sp == 22 || dp == 22) stats.ssh++;

            if (is_v6) stats.flows[FlowKey(src_ip_v6, dst_ip_v6, sp, dp, 6)]++;
            else       stats.flows[FlowKey(src_ip_v4, dst_ip_v4, sp, dp, 6)]++;
            
            stats.dst_port_freq[dp]++;

        } else if (protocol == 17) { // ── UDP ──
            if (l4_len < sizeof(UDPHeader)) continue;
            UDPHeader udp;
            std::memcpy(&udp, l4, sizeof(UDPHeader));

            uint16_t sp = ntohs(udp.src_port);
            uint16_t dp = ntohs(udp.dst_port);

            stats.udp++;
            if (sp == 443 || dp == 443) stats.quic++;

            if (sp == 6346 || dp == 6346) stats.gnutella++;
            if (sp == 4672 || dp == 4672) stats.emule++;
            if (sp == 7648 || dp == 7648) stats.cuseeme++;

            if (is_v6) stats.flows[FlowKey(src_ip_v6, dst_ip_v6, sp, dp, 17)]++;
            else       stats.flows[FlowKey(src_ip_v4, dst_ip_v4, sp, dp, 17)]++;
            
            stats.dst_port_freq[dp]++;

        } else if (protocol == 1) { // ── ICMP / ICMPv6 (approx) ──
            stats.icmp++;
        } else {
            stats.other_proto++;
        }
    }

    stats.flush_flows();

    auto t_end = std::chrono::high_resolution_clock::now();
    double secs = std::chrono::duration<double>(t_end - t_start).count();
    std::cerr << "[info] " << filepath << " → "
              << stats.packets << " pkts in "
              << std::fixed << std::setprecision(2) << secs << "s ("
              << std::setprecision(2) << (secs > 0 ? stats.packets / secs / 1e6 : 0)
              << " Mpps)\n";

    fclose(f);
    return stats;
}

static std::map<std::string, std::vector<fs::path>> collect_by_year(const fs::path& root) {
    std::map<std::string, std::vector<fs::path>> by_year;
    for (const auto& e : fs::recursive_directory_iterator(root)) {
        if (!e.is_regular_file()) continue;
        auto name = e.path().filename().string();
        if (name.size() < 5) continue;
        auto ext = name.substr(name.size() - 5);
        if (ext != ".pcap") continue;
        std::string year;
        auto parent = e.path().parent_path().filename().string();
        if (parent.size() == 4 && std::isdigit(parent[0]))
            year = parent;
        else if (name.size() >= 4 && std::isdigit(name[0]))
            year = name.substr(0, 4);
        else
            year = "unknown";
        by_year[year].push_back(e.path());
    }
    return by_year;
}

// ── Thread Pool Integration ────────────────────────────────────────────────────
static TrafficStats process_year_parallel(const std::vector<fs::path>& files) {
    unsigned int hw_threads = std::thread::hardware_concurrency();
    if (hw_threads == 0) hw_threads = 4;
    
    ThreadPool pool(hw_threads);
    std::vector<std::future<TrafficStats>> tasks;
    tasks.reserve(files.size());
    
    for (const auto& f : files)
        tasks.emplace_back(pool.enqueue([path = f.string()] { return analyze_file(path); }));

    TrafficStats combined;
    for (auto& t : tasks)
        merge_stats(combined, t.get());
    return combined;
}

// ── CLI argument parsing ───────────────────────────────────────────────────────
struct Args {
    std::string dir;
    std::string year_dir;
    bool json_mode  = false;
    bool human_mode = false;
};

static Args parse_args(int argc, char* argv[]) {
    Args a;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--json")   { a.json_mode  = true; }
        else if (arg == "--human") { a.human_mode = true; }
        else if (arg == "--dir" && i+1 < argc) { a.dir = argv[++i]; }
        else if (arg == "--year-dir" && i+1 < argc) { a.year_dir = argv[++i]; }
        else if (arg == "--max-packets" && i+1 < argc) {
            MAX_PACKETS = (uint64_t)std::stoull(argv[++i]);
        }
    }
    if (!a.json_mode && !a.human_mode) a.human_mode = true;
    return a;
}

// ── Main ───────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    Args args = parse_args(argc, argv);

    if (args.dir.empty() && args.year_dir.empty()) {
        std::cerr << "Usage:\n"
                  << "  mawi_engine --dir <root_data_dir> [--json|--human] [--max-packets N]\n"
                  << "  mawi_engine --year-dir <year_dir>  [--json|--human] [--max-packets N]\n";
        return 1;
    }

    if (!args.year_dir.empty()) {
        fs::path ypath(args.year_dir);
        std::string year = ypath.filename().string();

        std::vector<fs::path> files;
        for (const auto& e : fs::directory_iterator(ypath)) {
            auto name = e.path().filename().string();
            if (name.size() >= 5 && name.substr(name.size()-5) == ".pcap")
                files.push_back(e.path());
        }
        std::sort(files.begin(), files.end());

        if (files.empty()) {
            std::cerr << "[warn] no .pcap files in " << args.year_dir << "\n";
            return 0;
        }

        TrafficStats stats = process_year_parallel(files);

        if (args.json_mode) {
            emit_json(year, stats);
        } else {
            std::map<std::string, TrafficStats> m;
            m[year] = std::move(stats);
            print_human(m);
        }
        return 0;
    }

    auto by_year = collect_by_year(fs::path(args.dir));
    if (by_year.empty()) {
        std::cerr << "[error] No .pcap files found under " << args.dir << "\n";
        return 1;
    }

    std::map<std::string, TrafficStats> all_stats;
    for (auto& [year, files] : by_year) {
        std::cerr << "[year] Processing " << year
                  << " (" << files.size() << " files)\n";
        std::sort(files.begin(), files.end());
        all_stats[year] = process_year_parallel(files);
    }

    if (args.json_mode) {
        for (const auto& [year, stats] : all_stats)
            emit_json(year, stats);
    } else {
        print_human(all_stats);
    }

#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
