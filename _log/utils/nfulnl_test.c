
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
#if 0
	if (tb[NFULA_IFINDEX_PHYSINDEV-1]) {
		u_int32_t ifi = ntohl(*(u_int32_t *)NFA_DATA(tb[NFULA_IFINDEX_PHYSINDEV-1]));
		printf("physindev=%u ", ifi);
	}
	if (tb[NFULA_IFINDEX_PHYSOUTDEV-1]) {
		u_int32_t ifi = ntohl(*(u_int32_t *)NFA_DATA(tb[NFULA_IFINDEX_PHYSOUTDEV-1]));
		printf("physoutdev=%u ", ifi);
	}
#endif
	if (tb[NFULA_PREFIX-1]) {
		char *prefix = NFA_DATA(tb[NFULA_PREFIX-1]);
		printf("prefix=\"%s\" ", prefix);
	}
	if (tb[NFULA_PAYLOAD-1]) {
		printf("payload_len=%d ", NFA_PAYLOAD(tb[NFULA_PAYLOAD-1]));
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
	if (!h) {
		fprintf(stderr, "error during nfulnl_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_log handler for AF_INET (if any)\n");
	if (nfulnl_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error nfulnl_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_log to AF_INET\n");
	if (nfulnl_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfulnl_bind_pf()\n");
		exit(1);
	}
	printf("binding this socket to group 0\n");
	qh = nfulnl_bind_group(h, 0);
	if (!qh) {
		fprintf(stderr, "no handle for grup 0\n");
		exit(1);
	}

	printf("binding this socket to group 100\n");
	qh100 = nfulnl_bind_group(h, 100);
	if (!qh100) {
		fprintf(stderr, "no handle for group 100\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfulnl_set_mode(qh, NFULNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet copy mode\n");
		exit(1);
	}

	nh = nfulnl_nfnlh(h);
	fd = nfnl_fd(nh);

	printf("registering callback for group 0\n");
	nfulnl_callback_register(qh, &cb, NULL);

	printf("going into main loop\n");
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
		/* handle messages in just-received packet */
		nfulnl_handle_packet(h, buf, rv);
#endif
	}

	printf("unbinding from group 100\n");
	nfulnl_unbind_group(qh100);
	printf("unbinding from group 0\n");
	nfulnl_unbind_group(qh);

#ifdef INSANE
	/* norally, applications SHOULD NOT issue this command,
	 * since it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfulnl_unbind_pf(h, AF_INET);
#endif

	printf("closing handle\n");
	nfulnl_close(h);

	exit(0);
}
