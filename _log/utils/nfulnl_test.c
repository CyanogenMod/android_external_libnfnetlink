
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>

#include <libnfnetlink_log/libnfnetlink_log.h>

int main(int argc, char **argv)
{
	struct nfulnl_handle h;
	struct nfulnl_g_handle qh;
	struct nfulnl_g_handle qh100;
	int rv;
	char buf[4096];

	rv = nfulnl_open(&h);
	if (rv < 0)
		exit(rv);

	nfulnl_unbind_pf(&h, AF_INET);
	nfulnl_bind_pf(&h, AF_INET);
	nfulnl_bind_group(&h, &qh, 0);
	nfulnl_bind_group(&h, &qh100, 100);
	nfulnl_set_mode(&qh, NFULNL_COPY_PACKET, 0xffff);

	while (recv(h.nfnlh.fd, buf, sizeof(buf), 0) >= 0) {
		printf("pkt received\n");
	}

	nfulnl_unbind_group(&qh100);
	nfulnl_unbind_group(&qh);
	nfulnl_unbind_pf(&h, AF_INET);

	nfulnl_close(&h);

	exit(0);
}
