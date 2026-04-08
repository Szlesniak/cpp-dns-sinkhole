#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <unordered_set>

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
  std::unordered_set<std::string> blacklist = {"ads.google.com", "wp.pl"};
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
            std::cout << "Blocking ad domain:" << query << std::endl;

          } else {
            std::cout << "Passing clear domain: " << query << std::endl;
          }
        }
      }
    }
  }
  close(sockfd);
  return 0;
}
