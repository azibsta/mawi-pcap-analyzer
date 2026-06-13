# Final Year Project: Long-Term Analysis of Internet Traffic Trends Using MAWI Backbone Dataset (2006–2025)

**Author:** Azib Bin Azendi

## 1. Introduction & Problem Statement
The Internet is in a state of constant evolution. Over the past two decades, internet architecture has undergone fundamental paradigm shifts, including the explosion of mobile devices, the transition to secure web traffic, and the adoption of modern protocols optimized for streaming and real-time data. However, the fundamental issue that this project addresses is the unavailability of scalable, longitudinal, backbone-level traffic analysis that tracks the development of Internet protocols throughout history.

### 1.1 Why is Longitudinal Traffic Analysis Important?
Analyzing traffic trends over a 20-year span is not merely an academic exercise; it is critical for the future of network engineering and cybersecurity:
- **Infrastructure Planning**: ISPs and backbone providers must understand macro-level shifts (such as the decline of TCP and the rise of UDP) to design next-generation routers and allocate bandwidth efficiently.
- **Evolving Cybersecurity Threats**: The rampant rise in encryption means that Deep Packet Inspection (DPI) and payload-based security appliances are becoming obsolete. Understanding header-level flow distributions is now the primary method for detecting anomalies, DDoS attacks, and unauthorized network probing.
- **Protocol Standardization**: Observing how new standards like IPv6 and QUIC are actually adopted in the wild (versus in theory) helps organizations like the IETF refine protocols. 

## 2. Project Objectives
This project has the following primary objectives:
1. To evaluate the change in traffic of the Internet backbone based on MAWI packet-level traces recorded between 2006 and 2025.
2. To analyze the time variation of protocol and transport-layer usage, paying special attention to the shift from plaintext to encrypted traffic.
3. To assess the use and expansion of new transport-based mechanisms, such as UDP-based encrypted protocols (e.g., QUIC), and their influence on the dominance of TCP.
4. To examine IPv6 traffic development and its integration with IPv4 at the backbone level.
5. To plan and deploy a scalable flow-based traffic analysis system utilizing hash-based aggregation for large-scale packet processing.

## 3. Project Scope & Limitations
### 3.1 Scope
- **Header-Level Analysis**: Only packet header data formats (Ethernet, IPv4/IPv6, TCP/UDP) are analyzed.
- **Flow Aggregation**: Flow-level aggregation is performed using a scalable hash-based algorithm mapped to transport-layer 5-tuples.
- **Offline Processing**: The system performs offline analysis of archived MAWI traces; it does not monitor live traffic in real time.

### 3.2 Limitations
- **No Payload Inspection**: The analysis is restricted to headers; it provides no visibility into application-level payloads due to pervasive encryption.
- **Single Node Perspective**: The dataset corresponds strictly to a single trans-Pacific backbone link (WIDE network) and may not reflect localized regional access-network behaviors.
- **Hash Collisions**: Flow aggregation via hashing introduces a negligible probability of collision, though this is statistically insignificant for macro-level analysis.

## 4. Methodology
The research follows an application-based, offline traffic analysis approach. To process the massive, anonymized 15-minute raw PCAP traces efficiently:
- **Backend Architecture**: A custom multi-threaded C++ engine (`mawi_engine.cpp`) was developed to perform rapid DPI on layer-3 and layer-4 headers.
- **Data Pipeline**: Python, utilizing Pandas and PyArrow, was employed to orchestrate the C++ engine, aggregate the metrics, and cache intermediate results into highly compressed Parquet files.
- **Visualization**: An interactive frontend dashboard was built using HTML, Tailwind CSS, and Chart.js to visually explore the output JSON datasets.

## 5. Results & Key Findings

### 5.1 The Decline of TCP and the Rise of UDP
Historically, TCP has dominated internet traffic due to its reliability. In **2006**, TCP accounted for **81.3%** of all packets, while UDP sat at 16.8%. However, by **2025**, TCP's share dropped significantly to **50.3%**. This decline correlates directly with the rise of modern multimedia streaming and the deployment of the UDP-based QUIC protocol by major tech entities. 

### 5.2 The Shift to Encrypted Web Traffic
The dataset maps the internet's transition from plaintext to secure communications.
- In **2006**, unencrypted HTTP dominated at **51.5%** of all bytes, with HTTPS practically non-existent at **0.7%**.
- The milestone of encryption overtaking plaintext occurred around **2017**, where encrypted traffic surpassed the 50% threshold globally.
- By **2025**, HTTP traffic plummeted to **16.6%**, while HTTPS and general encrypted traffic stabilized over 22%. 

### 5.3 The Emergence of Web3.0 (QUIC Protocol)
QUIC (HTTP/3 over UDP) represents a paradigm shift in web transport.
- **Pre-2015**: QUIC traffic was non-existent.
- **2017**: QUIC officially surpassed 1% of total traffic.
- **2025**: QUIC adoption reached nearly **4.6%** of global backbone bytes, demonstrating a steady migration away from traditional TCP-based HTTP/2 architectures.

### 5.4 IPv6 Adoption
The analysis tracks the massive deployment of the IPv6 addressing system. In **2006**, the backbone routed a mere 59,458 IPv6 packets during the 15-minute capture window. By **2015**, this exploded to over 10 million packets, and reached **17.8 million** packets by **2025**, highlighting the modernization of global infrastructure.

## 6. Conclusion
The MAWI dataset provides invaluable insights into the shifting landscape of internet architecture. The analysis confirms a clear trend: the internet is becoming significantly more secure (via pervasive encryption) and latency-optimized (via the transition from TCP to UDP-based protocols). The custom-built C++ and Python pipeline demonstrated extreme efficiency and scalability in parsing decades of raw PCAP data without relying on payload decryption. This provides a robust framework for future real-time traffic analysis and backbone infrastructure planning.
