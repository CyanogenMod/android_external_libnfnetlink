
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#include <sys/socket.h>

#include "libnfnetlink.h"

#define nfnl_error(format, args...) \
	fprintf(stderr, __FUNCTION__ ": " format "\n", ## args)

int nfnl_open(struct nfnl_handle *nfnlh, u_int8_t subsys_id,
	      u_int32_t subscriptions)
{
	int err, addr_len;
	
	memset(nfnlh, 0, sizeof(*nfnlh));
	nfnlh->fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
	if (nfnlh->fd < 0) {
		nfnl_error("socket(netlink): %s", strerror(errno));
		return nfnlh->fd;
	}

	nfnlh->local.nl_family = AF_NETLINK;
	nfnlh->local.nl_groups = subscriptions;

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
		nfnl_error("Bad address length (%d != %d)", addr_len,
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

int nfnl_close(struct nfnl_handle *nfnlh)
{
	if (nfnlh->fd)
		close(nfnlh->fd);

	return 0;
}

int nfnl_send(struct nfnl_handle *nfnlh, struct nlmsghdr *n)
{
	struct sockaddr_nl nladdr;

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;

	return sendto(nfnlh->fd, n, n->nlmsg_len, 0, 
		      (struct sockaddr *)&nladdr, sizeof(nladdr));
}

void nfnl_fill_hdr(struct nfnl_handle *nfnlh,
		    struct nlmsghdr *nlh, int len, 
		    u_int8_t family,
		    u_int16_t msg_type,
		    u_int16_t msg_flags)
{
	struct nfgenmsg *nfg = (struct nfgenmsg *) 
					((void *)nlh + sizeof(*nlh));

	nlh->nlmsg_len = NLMSG_LENGTH(len);
	nlh->nlmsg_type = (nfnlh->subsys_id<<8)|msg_type;
	nlh->nlmsg_flags = msg_flags;
	nlh->nlmsg_pid = 0;
	nlh->nlmsg_seq = ++nfnlh->seq;

	nfg->nfgen_family = family;

}

int nfnl_listen(struct nfnl_handle *nfnlh,
		int (*handler)(struct sockaddr_nl *, struct nlmsghdr *n,
			       void *), void *jarg)
{
	struct sockaddr_nl nladdr;
	char buf[NFNL_BUFFSIZE];
	struct iovec iov;
	int remain;
	struct nlmsghdr *h;

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

			err = handler(&nladdr, h, jarg);
			if (err < 0)
				return err;
		
			/* FIXME: why not _NEXT macros, etc.? */
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

#if 0
int nfnl_talk(struct nfnl_handle *nfnlh, struct nlmsghdr *n, pid_t peer,
	      unsigned groups, struct nlmsghdr *answer,
	      int (*junk)(struct sockaddr_nl *, struct nlmsghdr *n, void *),
	      void *jarg)
{
	char buf[CTNL_BUFFSIZE];
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

	status = snedmsg(nfnlh->fd, &msg, 0);
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

		for (h = (struct nlmsghdr *)buf; status >= sizeof(*h)) {
			int len = h->nlmsg_len;
			int l = len - sizeof(*h);
			int err;

				

}
#endif

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

	nfa = (struct nfattr *)(((char *)n) + NLMSG_ALIGN(n->nlmsg_len));
	nfa->nfa_type = type;
	nfa->nfa_len = len;
	memcpy(NFA_DATA(nfa), data, alen);
	n->nlmsg_len = (NLMSG_ALIGN(n->nlmsg_len) + len);

	return 0;
}

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
			tb[nfa->nfa_type] = nfa;
                nfa = NFA_NEXT(nfa,len);
	}
	if (len)
		nfnl_error("deficit (%d) len (%d).\n", len, nfa->nfa_len);

	return 0;
}
