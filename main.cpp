#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <unordered_set>

void insert_list(const std::string &filename,
                 std::unordered_set<std::string> &blacklist) {
  std::ifstream file(filename);
  if (!file.is_open()) {
    std::cerr << "Warning: the file could not be opened " << filename
              << std::endl;
    return;
  }
  std::string line;
  int count = 0;

  while (std::getline(file, line)) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    if (line.empty() || line[0] == '#') {
      continue;
    }
    blacklist.insert(line);
    count++;
  }
  std::cout << "Loaded " << count
            << " of blocked domains from file: " << filename << std::endl;
  file.close();
}

std::string read_dns(const char *buffer, int bytes_received) {
  if (bytes_received <= 12) {
    return "";
  }
  int offset = 12;
  std::string domain = "";

  while (offset < bytes_received && buffer[offset] != 0) {
    int fragment_length = buffer[offset];
    offset++;

    if (offset + fragment_length > bytes_received) {
      return "Parsing error";
    }
    for (int j = 0; j < fragment_length; j++) {
      domain += buffer[offset];
      offset++;
    }
    domain += ".";
  }
  if (!domain.empty()) {
    domain.pop_back();
  }
  return domain;
}

int main() {
  std::unordered_set<std::string> blacklist;
  std::cout << "Loading blocked domains..." << std::endl;
  auto start = std::chrono::high_resolution_clock::now();
  insert_list("blocklist.txt", blacklist);

  auto stop = std::chrono::high_resolution_clock::now();
  auto duration =
      std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);

  int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    std::cerr << "Error while creating socket!" << std::endl;
    return 1;
  }
  std::cout << "Socket created successfully" << std::endl;
  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(53);

  if (bind(sockfd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) <
      0) {
    std::cerr << "Error while binding port" << std::endl;
    return 1;
  }
  char buffer[512];
  struct sockaddr_in client_addr;
  socklen_t client_len = sizeof(client_addr);

  while (true) {
    int bytes_received = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                                  (struct sockaddr *)&client_addr, &client_len);
    if (bytes_received > 0) {
      std::string query = read_dns(buffer, bytes_received);

      if (!query.empty()) {
        if (query.find("in-addr.arpa") == std::string::npos) {
          if (blacklist.find(query) != blacklist.end()) {
            char response[512];
            memcpy(response, buffer, bytes_received);
            int response_len = bytes_received;

            response[2] |= 0x80;
            response[3] |= 0x00;

            response[6] = 0x00;
            response[7] = 0x01;

            // 0xC00C - "the same domain that came in" for DNS
            response[response_len++] = 0xc0;
            response[response_len++] = 0x0c;

            // an A record (ipv4) == 0x0001
            response[response_len++] = 0x00;
            response[response_len++] = 0x01;

            // CLass: Internet == 0x0001
            response[response_len++] = 0x00;
            response[response_len++] = 0x01;
            // TTL : 2 seconds: response[response_len++] = 0x00;
            response[response_len++] = 0x00;
            response[response_len++] = 0x00;
            response[response_len++] = 0x02;

            // 4 bytes of data:
            response[response_len++] = 0x00;
            response[response_len++] = 0x04;

            // Finally - The address: 0.0.0.0
            response[response_len++] = 0x00;
            response[response_len++] = 0x00;
            response[response_len++] = 0x00;
            response[response_len++] = 0x00;

            sendto(sockfd, response, response_len, 0,
                   (struct sockaddr *)&client_addr, client_len);
            std::cout << "blocked domain: " << query << std::endl;

          } else {
            int upstream_sock = socket(AF_INET, SOCK_DGRAM, 0);
            struct timeval tv;
            tv.tv_sec = 2;
            tv.tv_usec = 0;
            setsockopt(upstream_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

            struct sockaddr_in upstream_addr;
            memset(&upstream_addr, 0, sizeof(upstream_addr));
            upstream_addr.sin_family = AF_INET;
            upstream_addr.sin_port = htons(53);
            inet_pton(AF_INET, "8.8.8.8", &upstream_addr.sin_addr);
            sendto(upstream_sock, buffer, bytes_received, 0,
                   (struct sockaddr *)&upstream_addr, sizeof(upstream_addr));
            char upstream_buffer[1024];
            struct sockaddr_in from_upstream;
            socklen_t from_upstream_len = sizeof(from_upstream);
            int upstream_bytes = recvfrom(
                upstream_sock, upstream_buffer, sizeof(upstream_buffer), 0,
                (struct sockaddr *)&from_upstream, &from_upstream_len);

            if (upstream_bytes > 0) {
              sendto(sockfd, upstream_buffer, upstream_bytes, 0,
                     (struct sockaddr *)&client_addr, client_len);

            } else {
              std::cout << "Error: Timeout or lack of answer from 8.8.8.8"
                        << std::endl;
            }
            close(upstream_sock);
          }
        }
      }
    }
  }
  close(sockfd);
  return 0;
}
