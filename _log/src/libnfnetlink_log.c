/* libnfqnetlink.c: generic library for access to nf_queue
 *
 * (C) 2005 by Harald Welte <laforge@gnumonks.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 
 *  as published by the Free Software Foundation
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_log.h>
#include "libnfnetlink_log.h"

#define HEADER_LEN	(NLMSG_LENGTH(sizeof(struct nlmsghdr))	\
			 +NLMSG_LENGTH(sizeof(struct nfgenmsg)))

/***********************************************************************
 * low level stuff 
 ***********************************************************************/

int nfulnl_open(struct nfulnl_handle *h)
{
	int err;

	memset(h, 0, sizeof(*h));

	err = nfnl_open(&h->nfnlh, NFNL_SUBSYS_ULOG, 0);
	if (err < 0)
		return err;

	return 0;
}

int nfulnl_close(struct nfulnl_handle *h)
{
	return nfnl_close(&h->nfnlh);
}

/* build a NFULNL_MSG_CONFIG message */
static int
__build_send_cfg_msg(struct nfulnl_handle *h, u_int8_t command,
		     u_int16_t queuenum, u_int8_t pf)
{
	char buf[HEADER_LEN+NFA_LENGTH(sizeof(struct nfulnl_msg_config_cmd))];
	struct nfulnl_msg_config_cmd cmd;
	struct nlmsghdr *nmh = (struct nlmsghdr *) buf;

	nfnl_fill_hdr(&h->nfnlh, nmh, 0, pf, queuenum,
		      NFULNL_MSG_CONFIG, NLM_F_REQUEST|NLM_F_ACK);

	cmd.command = command;
	nfnl_addattr_l(nmh, sizeof(buf), NFULA_CFG_CMD, &cmd, sizeof(cmd));

	return nfnl_send(&h->nfnlh, nmh);
}

/* bind nf_queue from a specific protocol family */
int nfulnl_bind_pf(struct nfulnl_handle *h, u_int16_t pf)
{
	return __build_send_cfg_msg(h, NFULNL_CFG_CMD_PF_BIND, 0, pf);
}

/* unbind nf_queue from a specific protocol family */
int nfulnl_unbind_pf(struct nfulnl_handle *h, u_int16_t pf)
{
	return __build_send_cfg_msg(h, NFULNL_CFG_CMD_PF_UNBIND, 0, pf);
}

/* bind this socket to a specific queue number */
int nfulnl_bind_group(struct nfulnl_handle *h,
		       struct nfulnl_g_handle *gh, u_int16_t num)
{
	gh->h = h;
	gh->id = num;

	return __build_send_cfg_msg(h, NFULNL_CFG_CMD_BIND, num, 0);
}

/* unbind this socket from a specific queue number */
int nfulnl_unbind_group(struct nfulnl_g_handle *gh)
{
	int ret = __build_send_cfg_msg(gh->h, NFULNL_CFG_CMD_UNBIND, gh->id, 0);
	if (ret == 0)
		gh->h = NULL;

	return ret;
}

int nfulnl_set_mode(struct nfulnl_g_handle *gh,
		   u_int8_t mode, u_int32_t range)
{
	char buf[HEADER_LEN
		+NFA_LENGTH(sizeof(struct nfulnl_msg_config_mode))];
	struct nfulnl_msg_config_mode params;
	struct nlmsghdr *nmh = (struct nlmsghdr *) buf;

	nfnl_fill_hdr(&gh->h->nfnlh, nmh, 0, AF_UNSPEC, gh->id,
		      NFULNL_MSG_CONFIG, NLM_F_REQUEST|NLM_F_ACK);

	params.copy_range = htonl(range);	/* copy_range is short */
	params.copy_mode = mode;
	nfnl_addattr_l(nmh, sizeof(buf), NFULA_CFG_MODE, &params,
		       sizeof(params));

	return nfnl_send(&gh->h->nfnlh, nmh);
}

int nfulnl_set_timeout(struct nfulnl_g_handle *gh, u_int32_t timeout)
{
	char buf[HEADER_LEN+NFA_LENGTH(sizeof(u_int32_t))];
	struct nlmsghdr *nmh = (struct nlmsghdr *) buf;

	nfnl_fill_hdr(&gh->h->nfnlh, nmh, 0, AF_UNSPEC, gh->id,
		      NFULNL_MSG_CONFIG, NLM_F_REQUEST|NLM_F_ACK);

	nfnl_addattr32(nmh, sizeof(buf), NFULA_CFG_TIMEOUT, htonl(timeout));

	return nfnl_send(&gh->h->nfnlh, nmh);
}

int nfulnl_set_qthresh(struct nfulnl_g_handle *gh, u_int32_t qthresh)
{
	char buf[HEADER_LEN+NFA_LENGTH(sizeof(u_int32_t))];
	struct nlmsghdr *nmh = (struct nlmsghdr *) buf;

	nfnl_fill_hdr(&gh->h->nfnlh, nmh, 0, AF_UNSPEC, gh->id,
		      NFULNL_MSG_CONFIG, NLM_F_REQUEST|NLM_F_ACK);

	nfnl_addattr32(nmh, sizeof(buf), NFULA_CFG_QTHRESH, htonl(qthresh));

	return nfnl_send(&gh->h->nfnlh, nmh);
}

int nfulnl_set_nlbufsiz(struct nfulnl_g_handle *gh, u_int32_t nlbufsiz)
{
	char buf[HEADER_LEN+NFA_LENGTH(sizeof(u_int32_t))];
	struct nlmsghdr *nmh = (struct nlmsghdr *) buf;

	nfnl_fill_hdr(&gh->h->nfnlh, nmh, 0, AF_UNSPEC, gh->id,
		      NFULNL_MSG_CONFIG, NLM_F_REQUEST|NLM_F_ACK);

	nfnl_addattr32(nmh, sizeof(buf), NFULA_CFG_NLBUFSIZ, htonl(nlbufsiz));

	return nfnl_send(&gh->h->nfnlh, nmh);
}

