/* libnfnetlink.h: Header file for generic netfilter netlink interface
 *
 * (C) 2002 Harald Welte <laforge@gnumonks.org>
 */

#ifndef __LIBNFNETLINK_H
#define __LIBNFNETLINK_H

#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/nfnetlink.h>

#define NFNL_BUFFSIZE		8192

struct nfnl_handle {
	int			fd;
	struct sockaddr_nl	local;
	struct sockaddr_nl	peer;
	u_int8_t		subsys_id;
	u_int32_t		seq;
	u_int32_t		dump;
};

/* get a new library handle */
extern int nfnl_open(struct nfnl_handle *nfnlh, u_int8_t subsys_id,
		     unsigned int subscriptions);
extern int nfnl_close(struct nfnl_handle *nfnlh);

int nfnl_send(struct nfnl_handle *nfnlh, struct nlmsghdr *n);


void nfnl_fill_hdr(struct nfnl_handle *nfnlh,
		   struct nlmsghdr *nlh, int len,
		   u_int8_t family,
		   u_int16_t msg_type,
		   u_int16_t msg_flags);

int nfnl_listen(struct nfnl_handle *nfnlh,
		int (*handler)(struct sockaddr_nl *, struct nlmsghdr *n,
			       void *), void *jarg);




/* nfnl attribute handling functions */
int nfnl_addattr_l(struct nlmsghdr *n, int maxlen, int type, void *data,
		   int alen);
int nfnl_addattr32(struct nlmsghdr *n, int maxlen, int type,
		   u_int32_t data);
int nfnl_nfa_addattr_l(struct nfattr *nfa, int maxlen, int type, void *data,
		       int alen);
int nfnl_nfa_addattr32(struct nfattr *nfa, int maxlen, int type, 
		       u_int32_t data);
int nfnl_parse_attr(struct nfattr *tb[], int max, struct nfattr *nfa, int len);

void nfnl_dump_packet(struct nlmsghdr *nlh, int received_len, char *desc);

#endif /* __LIBNFNETLINK_H */
