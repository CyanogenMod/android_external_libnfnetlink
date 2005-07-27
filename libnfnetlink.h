/* libnfnetlink.h: Header file for generic netfilter netlink interface
 *
 * (C) 2002 Harald Welte <laforge@gnumonks.org>
 */

#ifndef __LIBNFNETLINK_H
#define __LIBNFNETLINK_H

#include <linux/types.h>
#include <sys/socket.h>	/* for sa_family_t */
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>

#define NLMSG_TAIL(nlh) \
	(((void *) (nlh)) + NLMSG_ALIGN((nlh)->nlmsg_len))

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
extern int nfnl_open(struct nfnl_handle *, u_int8_t, unsigned int);
extern int nfnl_close(struct nfnl_handle *);
extern int nfnl_send(struct nfnl_handle *, struct nlmsghdr *);
extern int nfnl_sendmsg(const struct nfnl_handle *, const struct msghdr *msg,
			unsigned int flags);
extern int nfnl_sendiov(const struct nfnl_handle *nfnlh,
			const struct iovec *iov, unsigned int num,
			unsigned int flags);

extern void nfnl_fill_hdr(struct nfnl_handle *, struct nlmsghdr *,
			  unsigned int, u_int8_t, u_int16_t, u_int16_t,
			  u_int16_t);

extern struct nfattr *nfnl_parse_hdr(struct nfnl_handle *nfnlh, 
				     const struct nlmsghdr *nlh,
				     struct nfgenmsg **genmsg);

extern int nfnl_listen(struct nfnl_handle *,
                      int (*)(struct sockaddr_nl *, struct nlmsghdr *, void *),
                      void *);

extern int nfnl_talk(struct nfnl_handle *, struct nlmsghdr *, pid_t,
                     unsigned, struct nlmsghdr *,
                     int (*)(struct sockaddr_nl *, struct nlmsghdr *, void *),
                     void *);

/* nfnl attribute handling functions */
extern int nfnl_addattr_l(struct nlmsghdr *, int, int, void *, int);
extern int nfnl_addattr32(struct nlmsghdr *, int, int, u_int32_t);
extern int nfnl_nfa_addattr_l(struct nfattr *, int, int, void *, int);
extern int nfnl_nfa_addattr32(struct nfattr *, int, int, u_int32_t);
extern int nfnl_parse_attr(struct nfattr **, int, struct nfattr *, int);
#define nfnl_parse_nested(tb, max, nfa) \
	nfnl_parse_attr((tb), (max), NFA_DATA((nfa)), NFA_PAYLOAD((nfa)))
#define nfnl_nest(nlh, bufsize, type) 				\
({	struct nfattr *__start = NLMSG_TAIL(nlh);		\
	nfnl_addattr_l(nlh, bufsize, type, NULL, 0); 		\
	__start; })
#define nfnl_nest_end(nlh, tail) 				\
({	(tail)->nfa_len = (void *) NLMSG_TAIL(nlh) - (void *) tail; })

extern void nfnl_build_nfa_iovec(struct iovec *iov, struct nfattr *nfa, 
				 u_int16_t type, u_int32_t len,
				 unsigned char *val);

extern void nfnl_dump_packet(struct nlmsghdr *, int, char *);
#endif /* __LIBNFNETLINK_H */
