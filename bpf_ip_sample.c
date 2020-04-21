#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <linux/filter.h>

#define OP_LDH (BPF_LD  | BPF_H   | BPF_ABS)
#define OP_LDB (BPF_LD  | BPF_B   | BPF_ABS)
#define OP_JEQ (BPF_JMP | BPF_JEQ | BPF_K)
#define OP_RET (BPF_RET | BPF_K)

static struct sock_filter bpfcode[4] = {
	{ 0x28, 0, 0, 0x0000000c },
	{ 0x15, 0, 1, 0x00000800 },
	{ 0x6, 0, 0, 0x00040000 },
	{ 0x6, 0, 0, 0x00000000 },
};

int main(int argc, char **argv)
{
	int sock;
	int n;
	char buf[2000];
	struct sockaddr_ll addr;
	struct packet_mreq mreq;
	struct iphdr *ip;
	char saddr_str[INET_ADDRSTRLEN], daddr_str[INET_ADDRSTRLEN];
	char *proto_str;
	char *name;
	struct sock_fprog bpf = { 4, bpfcode };

	if (argc != 2) {
		printf("Usage: %s ifname\n", argv[0]);
		return 1;
	}

	name = argv[1];

	sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock < 0) {
		perror("socket");
		return 1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sll_ifindex = if_nametoindex(name);
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);


	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf))) {
		perror("setsockopt ATTACH_FILTER");
		return 1;
	}

	memset(&mreq, 0, sizeof(mreq));
	mreq.mr_type = PACKET_MR_PROMISC;
	mreq.mr_ifindex = if_nametoindex(name);

	if (setsockopt(sock, SOL_PACKET,
				PACKET_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq))) {
		perror("setsockopt MR_PROMISC");
		return 1;
	}

	for (;;) {
		n = recv(sock, buf, sizeof(buf), 0);
		if (n < 1) {
			perror("recv");
			return 0;
		}
	}

	return 0;
}
