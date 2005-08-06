
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>

#include <libnfnetlink_log/libnfnetlink_log.h>

static int print_pkt(struct nfattr *tb[])
{
	if (tb[NFULA_PACKET_HDR-1]) {
		struct nfulnl_msg_packet_hdr *ph =
					NFA_DATA(tb[NFULA_PACKET_HDR-1]);
		printf("hw_protocol=0x%04x hook=%u ", 
			ntohs(ph->hw_protocol), ph->hook);
	}

	if (tb[NFULA_MARK-1]) {
		u_int32_t mark = 
			ntohl(*(u_int32_t *)NFA_DATA(tb[NFULA_MARK-1]));
		printf("mark=%u ", mark);
	}

	if (tb[NFULA_IFINDEX_INDEV-1]) {
		u_int32_t ifi = ntohl(*(u_int32_t *)NFA_DATA(tb[NFULA_IFINDEX_INDEV-1]));
		printf("indev=%u ", ifi);
	}
	if (tb[NFULA_IFINDEX_OUTDEV-1]) {
		u_int32_t ifi = ntohl(*(u_int32_t *)NFA_DATA(tb[NFULA_IFINDEX_OUTDEV-1]));
		printf("outdev=%u ", ifi);
	}
	if (tb[NFULA_IFINDEX_PHYSINDEV-1]) {
		u_int32_t ifi = ntohl(*(u_int32_t *)NFA_DATA(tb[NFULA_IFINDEX_PHYSINDEV-1]));
		printf("physindev=%u ", ifi);
	}
	if (tb[NFULA_IFINDEX_PHYSOUTDEV-1]) {
		u_int32_t ifi = ntohl(*(u_int32_t *)NFA_DATA(tb[NFULA_IFINDEX_PHYSOUTDEV-1]));
		printf("physoutdev=%u ", ifi);
	}
	if (tb[NFULA_PREFIX-1]) {
		char *prefix = NFA_DATA(tb[NFULA_PREFIX-1]);
		printf("prefix=\"%s\" ", prefix);
	}
	if (tb[NFULA_PAYLOAD-1]) {
		printf("payload_len=%d\n", NFA_PAYLOAD(tb[NFULA_PAYLOAD-1]));
	}

	fputc('\n', stdout);
	return 0;
}

static int cb(struct nfulnl_g_handle *gh, struct nfgenmsg *nfmsg,
		struct nfattr *nfa[], void *data)
{
	print_pkt(nfa);
}


int main(int argc, char **argv)
{
	struct nfulnl_handle *h;
	struct nfulnl_g_handle *qh;
	struct nfulnl_g_handle *qh100;
	struct nfnl_handle *nh;
	int rv, fd;
	char buf[4096];

	h = nfulnl_open();
	if (!h)
		exit(1);

	nfulnl_unbind_pf(h, AF_INET);
	nfulnl_bind_pf(h, AF_INET);
	qh = nfulnl_bind_group(h, 0);
	qh100 = nfulnl_bind_group(h, 100);
	nfulnl_set_mode(qh, NFULNL_COPY_PACKET, 0xffff);

	nh = nfulnl_nfnlh(h);
	fd = nfnl_fd(nh);
#if 1
	nfulnl_callback_register(qh, &cb, NULL);
#endif

	while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
		struct nlmsghdr *nlh;
		printf("pkt received (len=%u)\n", rv);

#if 0
		for (nlh = nfnl_get_msg_first(nh, buf, rv);
		     nlh; nlh = nfnl_get_msg_next(nh, buf, rv)) {
			struct nfattr *tb[NFULA_MAX];
			struct nfgenmsg *nfmsg;

			printf("msg received: ");
			nfnl_parse_hdr(nh, nlh, &nfmsg);
			rv = nfnl_parse_attr(tb, NFULA_MAX, NFM_NFA(NLMSG_DATA(nlh)), nlh->nlmsg_len-NLMSG_ALIGN(sizeof(struct nfgenmsg)));
			if (rv < 0) {
				printf("error during parse: %d\n", rv);
				break;
			}
			print_pkt(tb);
		}
#else
		nfulnl_handle_packet(h, buf, rv);
#endif
	}

	nfulnl_unbind_group(qh100);
	nfulnl_unbind_group(qh);
	nfulnl_unbind_pf(h, AF_INET);

	nfulnl_close(h);

	exit(0);
}
