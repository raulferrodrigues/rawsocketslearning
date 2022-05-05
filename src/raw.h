#include <stdint.h>

#define ETH_LEN 1518
#define ETHER_TYPE 0x8888
#define DEFAULT_IF "ens33"

#define NAME_SIZE 8
#define PAYLOAD_SIZE 32

enum mtype
{
	START,
	HEARTBEAT,
	TALK
};

struct mxp_packet
{
	enum mtype type;
	char src_name[NAME_SIZE];
	char dst_name[NAME_SIZE];
	char payload[PAYLOAD_SIZE];
};

struct eth_hdr_s
{
	uint8_t dst_addr[6];
	uint8_t src_addr[6];
	uint16_t eth_type;
};

struct eth_frame_s
{
	struct eth_hdr_s ethernet;
	struct mxp_packet packet;
};

struct host_ttl
{
	char hostname[NAME_SIZE];
	char mac[6];
	int ttl;
};
