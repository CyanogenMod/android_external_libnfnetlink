/* libnfnetlink_log.h: Header file for the Netfilter Userspace Log library.
 *
 * (C) 2005 by Harald Welte <laforge@gnumonks.org>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 */

#ifndef __LIBNFNETLINK_LOG_H
#define __LIBNFNETLINK_LOG_H

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_log.h>
#include <libnfnetlink/libnfnetlink.h>


struct nfulnl_handle
{
	struct nfnl_handle nfnlh;
};

struct nfulnl_g_handle
{
	struct nfulnl_handle *h;
	u_int16_t id;
};

struct ctnl_msg_handler {
	int type;
	int (*handler)(struct sockaddr_nl *, struct nlmsghdr *, void *arg);
};

extern int nfulnl_open(struct nfulnl_handle *h);
extern int nfulnl_close(struct nfulnl_handle *h);

extern int nfulnl_bind_pf(struct nfulnl_handle *h, u_int16_t pf);
extern int nfulnl_unbind_pf(struct nfulnl_handle *h, u_int16_t pf);

extern int nfulnl_bind_group(struct nfulnl_handle *h,
			     struct nfulnl_g_handle *qh, u_int16_t num);
extern int nfulnl_unbind_group(struct nfulnl_g_handle *qh);

extern int nfulnl_set_mode(struct nfulnl_g_handle *qh,
			  u_int8_t mode, unsigned int len);
extern int nfulnl_set_timeout(struct nfulnl_g_handle *gh, u_int32_t timeout);
extern int nfulnl_set_qthresh(struct nfulnl_g_handle *gh, u_int32_t qthresh);
extern int nfulnl_set_nlbufsiz(struct nfulnl_g_handle *gh, u_int32_t nlbufsiz);
#endif	/* __LIBNFNETLINK_LOG_H */
