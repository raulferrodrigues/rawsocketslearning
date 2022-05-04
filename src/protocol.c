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

char this_mac[6];
char bcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
char dst_mac[6] = {0x00, 0x00, 0x00, 0x22, 0x22, 0x22};
char src_mac[6] = {0x00, 0x00, 0x00, 0x33, 0x33, 0x33};
char ifName[IFNAMSIZ];

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
      printf("got a packet, %d bytes\n", numbytes);
      continue;
    }
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

  /* fill t1 data */
  raw->packet.type = type;
  strncpy(raw->src, "PC1", 3);
  if (data != NULL)
  {
    memcpy(raw->packet.payload, data, sizeof(raw->packet.payload));
  }

  /* Send it.. */
  memcpy(socket_address.sll_addr, bcast_mac, 6);
  if (sendto(sockfd, raw_buffer, sizeof(struct eth_hdr_s) + sizeof(struct miguel_xavier_protocol), 0, (struct sockaddr *)&socket_address, sizeof(struct sockaddr_ll)) < 0)
    printf("Send failed\n");

  return 0;
}

int sendStart()
{
  return sendRaw(START, NULL);
}

int sendHB()
{
  return sendRaw(HEARTBEAT, NULL);
}

int sendTalk(char *data)
{
  return sendRaw(TALK, data);
}

int main(int argc, char *argv[])
{
  pthread_t th;

  /* Get interface name */
  if (argc > 1)
    strcpy(ifName, argv[1]);
  else
    strcpy(ifName, DEFAULT_IF);

  pthread_create(&th, NULL, recvRaw, NULL);

  sendStart();

  pthread_join(&th, NULL);
}
