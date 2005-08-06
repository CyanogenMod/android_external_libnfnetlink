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

struct nfulnl_handle;
struct nfulnl_g_handle;

extern struct nfnl_handle *nfulnl_nfnlh(struct nfulnl_handle *h);

typedef nfulnl_callback(struct nfulnl_g_handle *gh, struct nfgenmsg *nfmsg,
			struct nfattr *nfa[], void *data);


extern struct nfulnl_handle *nfulnl_open(void);
extern int nfulnl_close(struct nfulnl_handle *h);

extern int nfulnl_bind_pf(struct nfulnl_handle *h, u_int16_t pf);
extern int nfulnl_unbind_pf(struct nfulnl_handle *h, u_int16_t pf);

extern struct nfulnl_g_handle *nfulnl_bind_group(struct nfulnl_handle *h,
						 u_int16_t num);
extern int nfulnl_unbind_group(struct nfulnl_g_handle *gh);

extern int nfulnl_set_mode(struct nfulnl_g_handle *gh,
			  u_int8_t mode, unsigned int len);
extern int nfulnl_set_timeout(struct nfulnl_g_handle *gh, u_int32_t timeout);
extern int nfulnl_set_qthresh(struct nfulnl_g_handle *gh, u_int32_t qthresh);
extern int nfulnl_set_nlbufsiz(struct nfulnl_g_handle *gh, u_int32_t nlbufsiz);

extern int nfulnl_callback_register(struct nfulnl_g_handle *gh, 
				    nfulnl_callback *cb, void *data);
extern int nfulnl_handle_packet(struct nfulnl_handle *h, char *buf, int len);

#endif	/* __LIBNFNETLINK_LOG_H */
