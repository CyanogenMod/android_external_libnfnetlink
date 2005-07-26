/* libnfnetlink.c: generic library for communication with netfilter
 *
 * (C) 2001 by Jay Schulist <jschlst@samba.org>
 * (C) 2002-2005 by Harald Welte <laforge@gnumonks.org>
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com)
 *
 * this software may be used and distributed according to the terms
 * of the gnu general public license, incorporated herein by reference.
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>

#include <sys/socket.h>

#include "libnfnetlink.h"

#define nfnl_error(format, args...) \
	fprintf(stderr, "%s: " format "\n", __FUNCTION__, ## args)

#ifdef _NFNL_DEBUG
#define nfnl_debug_dump_packet nfnl_dump_packet
#else
#define nfnl_debug_dump_packet(a, b, ...)
#endif

void nfnl_dump_packet(struct nlmsghdr *nlh, int received_len, char *desc)
{
	void *nlmsg_data = NLMSG_DATA(nlh);
	struct nfattr *nfa = NFM_NFA(NLMSG_DATA(nlh));
	int len = NFM_PAYLOAD(nlh);

	printf("%s called from %s\n", __FUNCTION__, desc);
	printf("  nlmsghdr = %p, received_len = %u\n", nlh, received_len);
	printf("  NLMSG_DATA(nlh) = %p (+%td bytes)\n", nlmsg_data,
	       (nlmsg_data - (void *)nlh));
	printf("  NFM_NFA(NLMSG_DATA(nlh)) = %p (+%td bytes)\n",
		nfa, ((void *)nfa - (void *)nlh));
	printf("  nlmsg_type = %u, nlmsg_len = %u, nlmsg_seq = %u "
		"nlmsg_flags = 0x%x\n", nlh->nlmsg_type, nlh->nlmsg_len,
		nlh->nlmsg_seq, nlh->nlmsg_flags);

	while (NFA_OK(nfa, len)) {
		printf("    nfa@%p: nfa_type=%u, nfa_len=%u\n",
			nfa, nfa->nfa_type, nfa->nfa_len);
		nfa = NFA_NEXT(nfa,len);
	}
}

/**
 * nfnl_open - open a netlink socket
 *
 * nfnlh: libnfnetlink handle to be allocated by user
 * subsys_id: which nfnetlink subsystem we are interested in
 * subscriptions: netlink groups we want to be subscribed to
 *
 */
int nfnl_open(struct nfnl_handle *nfnlh, u_int8_t subsys_id,
	      u_int32_t subscriptions)
{
	int err;
	unsigned int addr_len;
	
	memset(nfnlh, 0, sizeof(*nfnlh));
	nfnlh->fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
	if (nfnlh->fd < 0) {
		nfnl_error("socket(netlink): %s", strerror(errno));
		return nfnlh->fd;
	}

	nfnlh->local.nl_family = AF_NETLINK;
	nfnlh->local.nl_groups = subscriptions;

	nfnlh->peer.nl_family = AF_NETLINK;

	err = bind(nfnlh->fd, (struct sockaddr *)&nfnlh->local,
		   sizeof(nfnlh->local));
	if (err < 0) {
		nfnl_error("bind(netlink): %s", strerror(errno));
		return err;
	}

	addr_len = sizeof(nfnlh->local);
	err = getsockname(nfnlh->fd, (struct sockaddr *)&nfnlh->local, 
			  &addr_len);
	if (addr_len != sizeof(nfnlh->local)) {
		nfnl_error("Bad address length (%u != %zd)", addr_len,
			   sizeof(nfnlh->local));
		return -1;
	}
	if (nfnlh->local.nl_family != AF_NETLINK) {
		nfnl_error("Badd address family %d", nfnlh->local.nl_family);
		return -1;
	}
	nfnlh->seq = time(NULL);
	nfnlh->subsys_id = subsys_id;

	return 0;
}

/**
 * nfnl_close - close netlink socket
 *
 * nfnlh: libnfnetlink handle
 *
 */
int nfnl_close(struct nfnl_handle *nfnlh)
{
	return close(nfnlh->fd);
}

/**
 * nfnl_send - send a nfnetlink message through netlink socket
 *
 * nfnlh: libnfnetlink handle
 * n: netlink message
 */
int nfnl_send(struct nfnl_handle *nfnlh, struct nlmsghdr *n)
{
	nfnl_debug_dump_packet(n, n->nlmsg_len+sizeof(*n), "nfnl_send");

	return sendto(nfnlh->fd, n, n->nlmsg_len, 0, 
		      (struct sockaddr *)&nfnlh->peer, sizeof(nfnlh->peer));
}

int nfnl_sendmsg(const struct nfnl_handle *nfnlh, const struct msghdr *msg,
		 unsigned int flags)
{
	return sendmsg(nfnlh->fd, msg, flags);
}

int nfnl_sendiov(const struct nfnl_handle *nfnlh, const struct iovec *iov,
		 unsigned int num, unsigned int flags)
{
	struct msghdr msg;

	msg.msg_name = (struct sockaddr *) &nfnlh->peer;
	msg.msg_namelen = sizeof(nfnlh->peer);
	msg.msg_iov = (struct iovec *) iov;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;

	return nfnl_sendmsg(nfnlh, &msg, flags);
}

/**
 * nfnl_fill_hdr - fill in netlink and nfnetlink header
 *
 * nfnlh: libnfnetlink handle
 * nlh: netlink header to be filled in
 * len: length of _payload_ bytes (not including nfgenmsg)
 * family: AF_INET / ...
 * res_id: resource id
 * msg_type: nfnetlink message type (without subsystem)
 * msg_flags: netlink message flags
 *
 * NOTE: the nlmsghdr must point to a memory region of at least
 * the size of struct nlmsghdr + struct nfgenmsg
 *
 */
void nfnl_fill_hdr(struct nfnl_handle *nfnlh,
		    struct nlmsghdr *nlh, unsigned int len, 
		    u_int8_t family,
		    u_int16_t res_id,
		    u_int16_t msg_type,
		    u_int16_t msg_flags)
{
	struct nfgenmsg *nfg = (struct nfgenmsg *) 
					((void *)nlh + sizeof(*nlh));

	nlh->nlmsg_len = NLMSG_LENGTH(len+sizeof(*nfg));
	nlh->nlmsg_type = (nfnlh->subsys_id<<8)|msg_type;
	nlh->nlmsg_flags = msg_flags;
	nlh->nlmsg_pid = 0;
	nlh->nlmsg_seq = ++nfnlh->seq;

	nfg->nfgen_family = family;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = htons(res_id);
}

/**
 * nfnl_listen: listen for one or more netlink messages
 *
 * nfnhl: libnfnetlink handle
 * handler: callback function to be called for every netlink message
 * jarg: opaque argument passed on to callback
 *
 */
int nfnl_listen(struct nfnl_handle *nfnlh,
		int (*handler)(struct sockaddr_nl *, struct nlmsghdr *n,
			       void *), void *jarg)
{
	struct sockaddr_nl nladdr;
	char buf[NFNL_BUFFSIZE];
	struct iovec iov;
	int remain;
	struct nlmsghdr *h;
	struct nlmsgerr *msgerr;

	struct msghdr msg = {
		(void *)&nladdr, sizeof(nladdr),
		&iov, 1,
		NULL, 0,
		0
	};

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);

	while (1) {
		remain = recvmsg(nfnlh->fd, &msg, 0);
		if (remain < 0) {
			if (errno == EINTR)
				continue;
			/* Bad file descriptor */
			if (errno == EBADF)
				break;
			nfnl_error("recvmsg overrun");
			continue;
		}
		if (remain == 0) {
			nfnl_error("EOF on netlink");
			return -1;
		}
		if (msg.msg_namelen != sizeof(nladdr)) {
			nfnl_error("Bad sender address len (%d)",
				   msg.msg_namelen);
			return -1;
		}

		for (h = (struct nlmsghdr *)buf; remain >= sizeof(*h);) {
			int err;
			int len = h->nlmsg_len;
			int l = len - sizeof(*h);

			if (l < 0 || len > remain) {
				if (msg.msg_flags & MSG_TRUNC) {
					nfnl_error("MSG_TRUNC");
					return -1;
				}
				nfnl_error("Malformed msg (len=%d)", len);
				return -1;
			}

			/* end of messages reached, let's return */
			if (h->nlmsg_type == NLMSG_DONE)
				return 0;

			/* Break the loop if success is explicitely
			 * reported via NLM_F_ACK flag set */
			if (h->nlmsg_type == NLMSG_ERROR) {
				msgerr = NLMSG_DATA(h);
				return msgerr->error;
			}

			err = handler(&nladdr, h, jarg);
			if (err < 0)
				return err;
		
			/* FIXME: why not _NEXT macros, etc.? */
			//h = NLMSG_NEXT(h, remain);
			remain -= NLMSG_ALIGN(len);
			h = (struct nlmsghdr *)((char *)h + NLMSG_ALIGN(len));
		}
		if (msg.msg_flags & MSG_TRUNC) {
			nfnl_error("MSG_TRUNC");
			continue;
		}
		if (remain) {
			nfnl_error("remnant size %d", remain);
			return -1;
		}
	}

	return 0;
}

int nfnl_talk(struct nfnl_handle *nfnlh, struct nlmsghdr *n, pid_t peer,
	      unsigned groups, struct nlmsghdr *answer,
	      int (*junk)(struct sockaddr_nl *, struct nlmsghdr *n, void *),
	      void *jarg)
{
	char buf[NFNL_BUFFSIZE];
	struct sockaddr_nl nladdr;
	struct nlmsghdr *h;
	unsigned int seq;
	int status;
	struct iovec iov = {
		(void *)n, n->nlmsg_len
	};
	struct msghdr msg = {
		(void *)&nladdr, sizeof(nladdr),
		&iov, 1,
		NULL, 0,
		0
	};

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = peer;
	nladdr.nl_groups = groups;

	n->nlmsg_seq = seq = ++nfnlh->seq;
	/* FIXME: why ? */
	if (!answer)
		n->nlmsg_flags |= NLM_F_ACK;

	status = sendmsg(nfnlh->fd, &msg, 0);
	if (status < 0) {
		nfnl_error("sendmsg(netlink) %s", strerror(errno));
		return -1;
	}
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);

	while (1) {
		status = recvmsg(nfnlh->fd, &msg, 0);
		if (status < 0) {
			if (errno == EINTR)
				continue;
			nfnl_error("recvmsg over-run");
			continue;
		}
		if (status == 0) {
			nfnl_error("EOF on netlink");
			return -1;
		}
		if (msg.msg_namelen != sizeof(nladdr)) {
			nfnl_error("Bad sender address len %d",
				   msg.msg_namelen);
			return -1;
		}

		for (h = (struct nlmsghdr *)buf; status >= sizeof(*h); ) {
			int len = h->nlmsg_len;
			int l = len - sizeof(*h);
			int err;

			if (l < 0 || len > status) {
				if (msg.msg_flags & MSG_TRUNC) {
					nfnl_error("Truncated message\n");
					return -1;
				}
				nfnl_error("Malformed message: len=%d\n", len);
				return -1; /* FIXME: libnetlink exits here */
			}

			if (h->nlmsg_pid != nfnlh->local.nl_pid ||
			    h->nlmsg_seq != seq) {
				if (junk) {
					err = junk(&nladdr, h, jarg);
					if (err < 0)
						return err;
				}
				continue;
			}

			if (h->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err = NLMSG_DATA(h);
				if (l < sizeof(struct nlmsgerr))
					nfnl_error("ERROR truncated\n");
				else {
					errno = -err->error;
					if (errno == 0) {
						if (answer)
							memcpy(answer, h, h->nlmsg_len);
						return 0;
					}
					perror("CTNETLINK answers");
				}
				return -1;
			}
			if (answer) {
				memcpy(answer, h, h->nlmsg_len);
				return 0;
			}

			nfnl_error("Unexpected reply!\n");

			status -= NLMSG_ALIGN(len);
			h = (struct nlmsghdr *)((char *)h + NLMSG_ALIGN(len));
		}
		if (msg.msg_flags & MSG_TRUNC) {
			nfnl_error("Messages truncated\n");
			continue;
		}
		if (status) {
			nfnl_error("Remnant of size %d\n", status);
			exit(1);
		}
	}
}

/**
 * nfnl_addattr_l - Add variable length attribute to nlmsghdr
 *
 * n: netlink message header to which attribute is to be added
 * maxlen: maximum length of netlink message header
 * type: type of new attribute
 * data: content of new attribute
 * alen: attribute length
 *
 */
int nfnl_addattr_l(struct nlmsghdr *n, int maxlen, int type, void *data,
		   int alen)
{
	int len = NFA_LENGTH(alen);
	struct nfattr *nfa;

	if ((NLMSG_ALIGN(n->nlmsg_len) + len) > maxlen) {
		nfnl_error("%d greater than maxlen (%d)\n",
			   NLMSG_ALIGN(n->nlmsg_len) + len, maxlen);
		return -1;
	}

	nfa = NLMSG_TAIL(n);
	nfa->nfa_type = type;
	nfa->nfa_len = len;
	memcpy(NFA_DATA(nfa), data, alen);
	n->nlmsg_len = (NLMSG_ALIGN(n->nlmsg_len) + NFA_ALIGN(len));
	return 0;
}

/**
 * nfnl_nfa_addattr_l - Add variable length attribute to struct nfattr 
 *
 * nfa: struct nfattr
 * maxlen: maximal length of nfattr buffer
 * type: type for new attribute
 * data: content of new attribute
 * alen: length of new attribute
 *
 */
int nfnl_nfa_addattr_l(struct nfattr *nfa, int maxlen, int type, void *data,
		       int alen)
{
	struct nfattr *subnfa;
	int len = NFA_LENGTH(alen);

	if ((NFA_OK(nfa, nfa->nfa_len) + len) > maxlen)
		return -1;

	subnfa = (struct nfattr *)(((char *)nfa) + NFA_OK(nfa, nfa->nfa_len));
	subnfa->nfa_type = type;
	subnfa->nfa_len = len;
	memcpy(NFA_DATA(subnfa), data, alen);
	nfa->nfa_len = (NLMSG_ALIGN(nfa->nfa_len) + len);

	return 0;
}


/**
 * nfnl_nfa_addattr32 - Add u_int32_t attribute to struct nfattr 
 *
 * nfa: struct nfattr
 * maxlen: maximal length of nfattr buffer
 * type: type for new attribute
 * data: content of new attribute
 *
 */
int nfnl_nfa_addattr32(struct nfattr *nfa, int maxlen, int type, 
		       u_int32_t data)
{

	return nfnl_nfa_addattr_l(nfa, maxlen, type, &data, sizeof(data));
}

/**
 * nfnl_addattr32 - Add u_int32_t attribute to nlmsghdr
 *
 * n: netlink message header to which attribute is to be added
 * maxlen: maximum length of netlink message header
 * type: type of new attribute
 * data: content of new attribute
 *
 */
int nfnl_addattr32(struct nlmsghdr *n, int maxlen, int type,
		   u_int32_t data)
{
	return nfnl_addattr_l(n, maxlen, type, &data, sizeof(data));
}

/**
 * nfnl_parse_attr - Parse a list of nfattrs into a pointer array
 *
 * tb: pointer array, will be filled in (output)
 * max: size of pointer array
 * nfa: pointer to list of nfattrs
 * len: length of 'nfa'
 *
 */
int nfnl_parse_attr(struct nfattr *tb[], int max, struct nfattr *nfa, int len)
{
	while (NFA_OK(nfa, len)) {
		if (nfa->nfa_type <= max)
			tb[nfa->nfa_type-1] = nfa;
                nfa = NFA_NEXT(nfa,len);
	}
	if (len)
		nfnl_error("deficit (%d) len (%d).\n", len, nfa->nfa_len);

	return 0;
}

/**
 * nfnl_build_nfa_iovec - Build two iovec's from tag, length and value
 *
 * iov: pointer to array of two 'struct iovec' (caller-allocated)
 * nfa: pointer to 'struct nfattr' (caller-allocated)
 * type: type (tag) of attribute
 * len: length of value
 * val: pointer to buffer containing 'value'
 *
 */ 
void nfnl_build_nfa_iovec(struct iovec *iov, struct nfattr *nfa, 
			  u_int16_t type, u_int32_t len, unsigned char *val)
{
	iov[0].iov_base = nfa;
	iov[0].iov_len = sizeof(*nfa);
	iov[1].iov_base = val;
	iov[1].iov_len = NFA_ALIGN(len);
}
