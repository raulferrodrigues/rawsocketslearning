#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include "raw.h"
#include "pthread.h"

#define HOST_LIMIT 50
#define HEARTBEAT_TICK 10
#define TTL_TICK 1
#define TTL_RESET 15

char this_name[NAME_SIZE];

char this_mac[6];
char bcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
// char dst_mac[6] = {0x00, 0x00, 0x00, 0x22, 0x22, 0x22};
// char src_mac[6] = {0x00, 0x00, 0x00, 0x33, 0x33, 0x33};
char ifName[IFNAMSIZ];

struct host_ttl connected_hosts[HOST_LIMIT];

void print_connected_hosts()
{
  printf("Connected hosts:\n");
  for (int i = 0; i < HOST_LIMIT; i++)
  {
    if (connected_hosts[i].ttl > 0)
    {

      printf(
          "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x %s\n",
          (unsigned char)connected_hosts[i].mac[0],
          (unsigned char)connected_hosts[i].mac[1],
          (unsigned char)connected_hosts[i].mac[2],
          (unsigned char)connected_hosts[i].mac[3],
          (unsigned char)connected_hosts[i].mac[4],
          (unsigned char)connected_hosts[i].mac[5],
          connected_hosts[i].hostname);
    }
  }
}

void *heartbeat(void *p)
{
  struct ifreq if_idx, if_mac, ifopts;
  struct sockaddr_ll socket_address;
  int sockfd, numbytes;

  uint8_t raw_buffer[ETH_LEN];
  struct eth_frame_s *raw = (struct eth_frame_s *)&raw_buffer;

  /* Open RAW socket */
  if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
    perror("socket");

  /* Set interface to promiscuous mode */
  strncpy(ifopts.ifr_name, ifName, IFNAMSIZ - 1);
  ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
  ifopts.ifr_flags |= IFF_PROMISC;
  ioctl(sockfd, SIOCSIFFLAGS, &ifopts);

  /* Get the index of the interface */
  memset(&if_idx, 0, sizeof(struct ifreq));
  strncpy(if_idx.ifr_name, ifName, IFNAMSIZ - 1);
  if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
    perror("SIOCGIFINDEX");
  socket_address.sll_ifindex = if_idx.ifr_ifindex;
  socket_address.sll_halen = ETH_ALEN;

  /* Get the MAC address of the interface */
  memset(&if_mac, 0, sizeof(struct ifreq));
  strncpy(if_mac.ifr_name, ifName, IFNAMSIZ - 1);
  if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
    perror("SIOCGIFHWADDR");
  memcpy(this_mac, if_mac.ifr_hwaddr.sa_data, 6);

  /* fill the Ethernet frame header */
  memcpy(raw->ethernet.dst_addr, bcast_mac, 6);
  memcpy(raw->ethernet.src_addr, this_mac, 6);
  raw->ethernet.eth_type = htons(ETHER_TYPE);

  /* fill mxp data */
  raw->packet.type = HEARTBEAT;
  strncpy(raw->packet.src_name, this_name, 3);
  memset(raw->packet.payload, 0, PAYLOAD_SIZE);

  while (1)
  {
    sleep(HEARTBEAT_TICK);

    /* Send it.. */
    memcpy(socket_address.sll_addr, bcast_mac, 6);
    if (sendto(sockfd, raw_buffer, sizeof(struct eth_hdr_s) + sizeof(struct mxp_packet), 0, (struct sockaddr *)&socket_address, sizeof(struct sockaddr_ll)) < 0)
      printf("Send failed\n");

    print_connected_hosts();
  }
}

int sendRaw(enum mtype type, char *data)
{
  struct ifreq if_idx, if_mac, ifopts;
  struct sockaddr_ll socket_address;
  int sockfd, numbytes;

  uint8_t raw_buffer[ETH_LEN];
  struct eth_frame_s *raw = (struct eth_frame_s *)&raw_buffer;

  /* Open RAW socket */
  if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
    perror("socket");

  /* Set interface to promiscuous mode */
  strncpy(ifopts.ifr_name, ifName, IFNAMSIZ - 1);
  ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
  ifopts.ifr_flags |= IFF_PROMISC;
  ioctl(sockfd, SIOCSIFFLAGS, &ifopts);

  /* Get the index of the interface */
  memset(&if_idx, 0, sizeof(struct ifreq));
  strncpy(if_idx.ifr_name, ifName, IFNAMSIZ - 1);
  if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
    perror("SIOCGIFINDEX");
  socket_address.sll_ifindex = if_idx.ifr_ifindex;
  socket_address.sll_halen = ETH_ALEN;

  /* Get the MAC address of the interface */
  memset(&if_mac, 0, sizeof(struct ifreq));
  strncpy(if_mac.ifr_name, ifName, IFNAMSIZ - 1);
  if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
    perror("SIOCGIFHWADDR");
  memcpy(this_mac, if_mac.ifr_hwaddr.sa_data, 6);

  /* fill the Ethernet frame header */
  memcpy(raw->ethernet.dst_addr, bcast_mac, 6);
  memcpy(raw->ethernet.src_addr, this_mac, 6);
  raw->ethernet.eth_type = htons(ETHER_TYPE);

  /* fill mxp data */
  raw->packet.type = type;
  strncpy(raw->packet.src_name, this_name, 3);
  memset(raw->packet.payload, 0, PAYLOAD_SIZE);
  if (data != NULL)
  {
    memcpy(raw->packet.payload, data, PAYLOAD_SIZE);
  }

  /* Send it.. */
  memcpy(socket_address.sll_addr, bcast_mac, 6);
  if (sendto(sockfd, raw_buffer, sizeof(struct eth_hdr_s) + sizeof(struct mxp_packet), 0, (struct sockaddr *)&socket_address, sizeof(struct sockaddr_ll)) < 0)
    printf("Send failed\n");

  return 0;
}

void heartbeat_handler(char hostname[NAME_SIZE], char mac[6])
{
  for (int i = 0; i < HOST_LIMIT; i++)
  {
    if (!strcmp(connected_hosts[i].hostname, hostname))
    {
      connected_hosts[i].ttl = TTL_RESET;
      return;
    }
  }

  for (int i = 0; i < HOST_LIMIT; i++)
  {
    if (connected_hosts[i].ttl == -1)
    {
      struct host_ttl host;
      strcpy(host.hostname, hostname);
      memcpy(host.mac, mac, 6);
      host.ttl = TTL_RESET;
      connected_hosts[i] = host;
      return;
    }
  }
}

void *host_manager(void *p)
{
  while (1)
  {
    sleep(1);

    for (int i = 0; i < HOST_LIMIT; i++)
    {
      if (connected_hosts[i].ttl > 0)
      {
        connected_hosts[i].ttl -= -1;
      }

      if (connected_hosts[i].ttl == 0)
      {
        struct host_ttl host;
        strcpy(host.hostname, "");
        strcpy(host.mac, "");
        host.ttl = -1;
        connected_hosts[i] = host;
      }
    }
  }
}

void *recvRaw(void *param)
{
  struct ifreq ifopts;
  int sockfd, numbytes;
  char *p;

  uint8_t raw_buffer[ETH_LEN];
  struct eth_frame_s *raw = (struct eth_frame_s *)&raw_buffer;

  /* Open RAW socket */
  if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
    perror("socket");

  /* Set interface to promiscuous mode */
  strncpy(ifopts.ifr_name, ifName, IFNAMSIZ - 1);
  ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
  ifopts.ifr_flags |= IFF_PROMISC;
  ioctl(sockfd, SIOCSIFFLAGS, &ifopts);

  /* End of configuration. Now we can receive data using raw sockets. */

  while (1)
  {
    numbytes = recvfrom(sockfd, raw_buffer, ETH_LEN, 0, NULL, NULL);
    if (raw->ethernet.eth_type == ntohs(ETHER_TYPE))
    {
      char mxp_type[12] = "";
      switch (raw->packet.type)
      {
      case 0:
        strcpy(mxp_type, "START");
        break;
      case 1:
        strcpy(mxp_type, "HEARTBEAT");
        heartbeat_handler(raw->packet.src_name, raw->ethernet.src_addr);
        break;
      case 2:
        strcpy(mxp_type, "TALK");
        break;
      default:
        strcpy(mxp_type, "ERR");
        break;
      };

      printf("Packet received source: , mxp_type: %s, payload: %s\n", mxp_type, raw->packet.payload);
    }
  }
}

int sendStart()
{
  return sendRaw(START, NULL);
}

int sendTalk(char *data)
{
  return sendRaw(TALK, data);
}

int main(int argc, char *argv[])
{
  /* Get interface name */
  if (argc > 1)
    strcpy(ifName, argv[1]);
  else
    exit(1);

  if (argc > 2)
    strcpy(this_name, argv[2]);
  else
    exit(1);

  for (int i = 0; i < HOST_LIMIT; i++)
  {
    struct host_ttl host;
    strcpy(host.hostname, "");
    strcpy(host.mac, "");
    host.ttl = -1;
    connected_hosts[i] = host;
  }
  pthread_t rec_th, hb_th;

  pthread_create(&rec_th, NULL, recvRaw, NULL);
  pthread_create(&hb_th, NULL, heartbeat, NULL);
  sendStart();

  pthread_join(rec_th, NULL);
  pthread_join(hb_th, NULL);
}
