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
#include <libnfnetlink/libnfnetlink.h>
#include <libnfnetlink_log/libnfnetlink_log.h>

struct nfulnl_handle
{
	struct nfnl_handle nfnlh;
	struct nfulnl_g_handle *gh_list;
};

struct nfulnl_g_handle
{
	struct nfulnl_g_handle *next;
	struct nfulnl_handle *h;
	u_int16_t id;

	nfulnl_callback *cb;
	void *data;
};

int nfulnl_errno;

/***********************************************************************
 * low level stuff 
 ***********************************************************************/

static void del_gh(struct nfulnl_g_handle *gh)
{
	struct nfulnl_g_handle *cur_gh, *prev_gh = NULL;

	for (cur_gh = gh->h->gh_list; cur_gh; cur_gh = cur_gh->next) {
		if (cur_gh == gh) {
			if (prev_gh)
				prev_gh->next = gh->next;
			else
				gh->h->gh_list = gh->next;
			return;
		}
		prev_gh = cur_gh;
	}
}

static void add_gh(struct nfulnl_g_handle *gh)
{
	gh->next = gh->h->gh_list;
	gh->h->gh_list = gh;
}

static struct nfulnl_g_handle *find_gh(struct nfulnl_handle *h, u_int16_t group)
{
	struct nfulnl_g_handle *gh;

	for (gh = h->gh_list; gh; gh = gh->next) {
		if (gh->id == group)
			return gh;
	}
	return NULL;
}

static int __nfulnl_rcv_cmd(struct nlmsghdr *nlh, struct nfattr *nfa[],
			    void *data)
{
	struct nfulnl_handle *h = data;

	/* FIXME: implement this */
	return 0;
}

/* build a NFULNL_MSG_CONFIG message */
static int
__build_send_cfg_msg(struct nfulnl_handle *h, u_int8_t command,
		     u_int16_t queuenum, u_int8_t pf)
{
	char buf[NFNL_HEADER_LEN
		+NFA_LENGTH(sizeof(struct nfulnl_msg_config_cmd))];
	struct nfulnl_msg_config_cmd cmd;
	struct nlmsghdr *nmh = (struct nlmsghdr *) buf;

	nfnl_fill_hdr(&h->nfnlh, nmh, 0, pf, queuenum,
		      NFULNL_MSG_CONFIG, NLM_F_REQUEST|NLM_F_ACK);

	cmd.command = command;
	nfnl_addattr_l(nmh, sizeof(buf), NFULA_CFG_CMD, &cmd, sizeof(cmd));

	return nfnl_talk(&h->nfnlh, nmh, 0, 0, NULL, NULL, NULL);
}

static int __nfulnl_rcv_pkt(struct nlmsghdr *nlh, struct nfattr *nfa[],
			    void *data)
{
	struct nfgenmsg *nfmsg = NLMSG_DATA(nlh);
	struct nfulnl_handle *h = data;
	u_int16_t group = ntohs(nfmsg->res_id);
	struct nfulnl_g_handle *gh = find_gh(h, group);

	if (!gh)
		return -ENODEV;

	if (!gh->cb)
		return -ENODEV;

	return gh->cb(gh, nfmsg, nfa, gh->data);
}

static struct nfnl_callback cmd_cb = {
	.call 		= &__nfulnl_rcv_cmd,
	.attr_count 	= NFULA_CFG_MAX,
};

static struct nfnl_callback pkt_cb = {
	.call 		= &__nfulnl_rcv_pkt,
	.attr_count 	= NFULA_MAX,
};

/* public interface */

struct nfnl_handle *nfulnl_nfnlh(struct nfulnl_handle *h)
{
	return &h->nfnlh;
}

int nfulnl_fd(struct nfulnl_handle *h)
{
	return nfnl_fd(nfulnl_nfnlh(h));
}

struct nfulnl_handle *nfulnl_open(void)
{
	struct nfulnl_handle *h;
	int err;

	h = malloc(sizeof(*h));
	if (!h)
		return NULL;

	memset(h, 0, sizeof(*h));

	err = nfnl_open(&h->nfnlh, NFNL_SUBSYS_ULOG, NFULNL_MSG_MAX, 0);
	if (err < 0) {
		nfulnl_errno = err;
		goto out_free;
	}

	cmd_cb.data = h;
	err = nfnl_callback_register(&h->nfnlh, NFULNL_MSG_CONFIG, &cmd_cb);
	if (err < 0) {
		nfulnl_errno = err;
		goto out_close;
	}
	pkt_cb.data = h;
	err = nfnl_callback_register(&h->nfnlh, NFULNL_MSG_PACKET, &pkt_cb);
	if (err < 0) {
		nfulnl_errno = err;
		goto out_close;
	}

	return h;
out_close:
	nfnl_close(&h->nfnlh);
out_free:
	free(h);
	return NULL;
}

int nfulnl_callback_register(struct nfulnl_g_handle *gh, nfulnl_callback *cb,
			     void *data)
{
	gh->data = data;
	gh->cb = cb;

	return 0;
}

int nfulnl_handle_packet(struct nfulnl_handle *h, char *buf, int len)
{
	return nfnl_handle_packet(&h->nfnlh, buf, len);
}

int nfulnl_close(struct nfulnl_handle *h)
{
	return nfnl_close(&h->nfnlh);
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
struct nfulnl_g_handle *
nfulnl_bind_group(struct nfulnl_handle *h, u_int16_t num)
{
	struct nfulnl_g_handle *gh;
	
	if (find_gh(h, num))
		return NULL;
	
	gh = malloc(sizeof(*gh));
	if (!gh)
		return NULL;

	memset(gh, 0, sizeof(*gh));
	gh->h = h;
	gh->id = num;

	if (__build_send_cfg_msg(h, NFULNL_CFG_CMD_BIND, num, 0) < 0) {
		free(gh);
		return NULL;
	}

	add_gh(gh);
	return gh;
}

/* unbind this socket from a specific queue number */
int nfulnl_unbind_group(struct nfulnl_g_handle *gh)
{
	int ret = __build_send_cfg_msg(gh->h, NFULNL_CFG_CMD_UNBIND, gh->id, 0);
	if (ret == 0) {
		del_gh(gh);
		free(gh);
	}

	return ret;
}

int nfulnl_set_mode(struct nfulnl_g_handle *gh,
		   u_int8_t mode, u_int32_t range)
{
	char buf[NFNL_HEADER_LEN
		+NFA_LENGTH(sizeof(struct nfulnl_msg_config_mode))];
	struct nfulnl_msg_config_mode params;
	struct nlmsghdr *nmh = (struct nlmsghdr *) buf;

	nfnl_fill_hdr(&gh->h->nfnlh, nmh, 0, AF_UNSPEC, gh->id,
		      NFULNL_MSG_CONFIG, NLM_F_REQUEST|NLM_F_ACK);

	params.copy_range = htonl(range);	/* copy_range is short */
	params.copy_mode = mode;
	nfnl_addattr_l(nmh, sizeof(buf), NFULA_CFG_MODE, &params,
		       sizeof(params));

	return nfnl_talk(&gh->h->nfnlh, nmh, 0, 0, NULL, NULL, NULL);
}

int nfulnl_set_timeout(struct nfulnl_g_handle *gh, u_int32_t timeout)
{
	char buf[NFNL_HEADER_LEN+NFA_LENGTH(sizeof(u_int32_t))];
	struct nlmsghdr *nmh = (struct nlmsghdr *) buf;

	nfnl_fill_hdr(&gh->h->nfnlh, nmh, 0, AF_UNSPEC, gh->id,
		      NFULNL_MSG_CONFIG, NLM_F_REQUEST|NLM_F_ACK);

	nfnl_addattr32(nmh, sizeof(buf), NFULA_CFG_TIMEOUT, htonl(timeout));

	return nfnl_talk(&gh->h->nfnlh, nmh, 0, 0, NULL, NULL, NULL);
}

int nfulnl_set_qthresh(struct nfulnl_g_handle *gh, u_int32_t qthresh)
{
	char buf[NFNL_HEADER_LEN+NFA_LENGTH(sizeof(u_int32_t))];
	struct nlmsghdr *nmh = (struct nlmsghdr *) buf;

	nfnl_fill_hdr(&gh->h->nfnlh, nmh, 0, AF_UNSPEC, gh->id,
		      NFULNL_MSG_CONFIG, NLM_F_REQUEST|NLM_F_ACK);

	nfnl_addattr32(nmh, sizeof(buf), NFULA_CFG_QTHRESH, htonl(qthresh));

	return nfnl_talk(&gh->h->nfnlh, nmh, 0, 0, NULL, NULL, NULL);
}

int nfulnl_set_nlbufsiz(struct nfulnl_g_handle *gh, u_int32_t nlbufsiz)
{
	char buf[NFNL_HEADER_LEN+NFA_LENGTH(sizeof(u_int32_t))];
	struct nlmsghdr *nmh = (struct nlmsghdr *) buf;
	int status;

	nfnl_fill_hdr(&gh->h->nfnlh, nmh, 0, AF_UNSPEC, gh->id,
		      NFULNL_MSG_CONFIG, NLM_F_REQUEST|NLM_F_ACK);

	nfnl_addattr32(nmh, sizeof(buf), NFULA_CFG_NLBUFSIZ, htonl(nlbufsiz));

	status = nfnl_talk(&gh->h->nfnlh, nmh, 0, 0, NULL, NULL, NULL);

	/* we try to have space for at least 10 messages in the socket buffer */
	if (status >= 0)
		nfnl_rcvbufsiz(&gh->h->nfnlh, 10*nlbufsiz);

	return status;
}
