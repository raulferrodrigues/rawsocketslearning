#include <stdint.h>

#define ETH_LEN 1518
#define ETHER_TYPE 0x8888
#define DEFAULT_IF "enp5s0"

enum mtype
{
	START,
	HEARTBEAT,
	TALK
};

struct miguel_xavier_protocol
{
	enum mtype type;
	char dst_name[32];
	char payload[32];
};

struct eth_hdr_s
{
	uint8_t dst_addr[6];
	uint8_t src_addr[6];
	uint16_t eth_type;
};

struct eth_frame_s
{
	char src[4];
	struct eth_hdr_s ethernet;
	struct miguel_xavier_protocol packet;
};
