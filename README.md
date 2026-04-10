# C++ DNS Sinkhole

A lightweight, high-performance DNS sinkhole and ad blocker written entirely from scratch in C++. This project acts as a local DNS server that intercepts network traffic, blocking advertisements, tracking scripts, and telemetry before they reach your devices.

## Features

* **Custom DNS Forwarding:** Acts as a proxy for legitimate requests, forwarding raw UDP packets to an upstream DNS provider (e.g., 8.8.8.8) and returning the real IP addresses to the client.
* **Instantaneous Blocking:** Spoofs DNS responses for blacklisted domains, resolving them to `0.0.0.0` with a low Time-To-Live (TTL) to prevent browsers from caching the blocked state permanently.
* **O(1) Complexity Lookups:** Utilizes a hash table (`std::unordered_set`) for domain matching. It can load and process massive community blocklists (e.g., Steven Black's hosts with 150,000+ entries) with minimal RAM usage and near-zero lookup latency.
* **Dynamic File Loading:** Reads blocklists from a local `blocklist.txt` file at startup. It automatically sanitizes inputs by stripping carriage returns (Windows `\r` formatting) and ignoring commented lines.

## How It Works

The application operates in user space and binds a datagram socket to UDP port 53. 

1. **Interception:** A client device on the network asks for the IP address of a domain (e.g., `ads.doubleclick.net`).
2. **Parsing:** The C++ server extracts the requested domain name from the raw binary DNS query packet.
3. **Evaluation:** The domain is checked against the pre-loaded hash table.
4. **Action (Block):** If the domain is found in the blocklist, the server modifies the DNS header flags, appends a standard DNS Answer Section containing `0.0.0.0`, and sends it back to the client. The client's browser immediately fails to connect to the ad server, saving bandwidth and processing power.
5. **Action (Allow):** If the domain is not in the blocklist, the server opens a temporary client socket, forwards the exact original buffer to an upstream DNS server, awaits the response, and relays it back to the local client.

## Prerequisites

* A Linux environment (e.g., Raspberry Pi OS, Ubuntu, Rocky Linux)
* `g++` compiler
* Root privileges (mandatory for binding to the restricted port 53)

## Installation and Usage

1. Clone this repository.
2. Create a `blocklist.txt` file in the project root directory. You can populate it with community-driven lists. For example, to download a parsed list of domains:
   ```bash
   curl -s [https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts](https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts) | grep '^0\.0\.0\.0' | awk '{print $2}' > blocklist.txt
   ```
3. Compile the source code:
   ```bash
   g++ bloker.cpp -o bloker
   ```
4. Run the executable with administrative privileges:
   ```bash
   sudo ./bloker
   ```
5. Point your client devices (Windows, Android, iOS) to use the IP address of your Linux machine as their sole Primary DNS server.

## Limitations

* **Same-Domain Ads:** As a DNS-level blocker (Layer 3/4), this tool cannot block advertisements that are served from the exact same domain as the primary content (e.g., YouTube video ads). For full protection, use this in conjunction with a browser-based extension like uBlock Origin.
* **Single-Threaded:** Designed and optimized for home network environments.

## Roadmap / Future Improvements

* **Multithreading & Asynchronous Processing:** Transitioning from a single-threaded blocking architecture to a multithreaded model (e.g., using thread pools or Linux `epoll`). This will allow the sinkhole to handle thousands of concurrent DNS requests from multiple devices simultaneously without blocking the main event loop.
* **Automated Blocklist Updates (Cronjob):** Implementing a scheduled shell script via `cron` to automatically download the latest community blocklists on a daily or weekly basis. The script will seamlessly restart the service or send a signal to reload the hash table in memory, ensuring continuous protection against newly registered ad domains without manual intervention.
