#ifndef _UMMSANDBOX_H_
#define _UMSANDBOX_H_
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>

#define IOCTLLENMASK      0x07ffffff
#define IOCTL_R           0x10000000
#define IOCTL_W           0x20000000
#define AF_MAXMAX (AF_MAX + 2)
#define PF_ALL PF_MAXMAX+1
#define PF_ALLIP PF_MAXMAX+2
#define DEFAULT_NET_PATH "/dev/net/default"

typedef void (* voidfun)(void *arg);

struct umsandbox;


struct fsentry {
	char *name;
	struct fsentry *subdir;
	loff_t (*getputfun)(int op,char *value,int size,struct umsandbox *mh,int tag,char *path);
	int tag;
};

struct umsandbox_operations {
	struct fsentry root;
	void (*init) (char *path, unsigned long flags, char *args,struct umsandbox *mh);
	void (*fini) (struct umsandbox *mh);
};


/*
 *     UMNET: (MULTI) Virtual Stack management
 *     Copyright (C) 2008  Renzo Davoli <renzo@cs.unibo.it>
 *
 *     This program can be distributed under the terms of the GNU GPLv2.
 *     See the file COPYING.LIB.
 */

#ifndef _UMNET_H_
#define _UMNET_H_
#include <stdint.h>
#include "module.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#define AF_MAXMAX (AF_MAX + 2)

#define IOCTLLENMASK      0x07ffffff
#define IOCTL_R           0x10000000
#define IOCTL_W           0x20000000

#define UMNET_DEBUG       (1 << 29)

struct umnet;

#if 0
struct net_info {

	/* File handle. It usually set up in msocket and then
	 * available for all other operations */
	uint64_t fh;

	/* nethandle for management */
	struct umnet *nethandle;
};
#endif

struct umnet_operations {
	//int (*getattr) (struct stat64 *, struct umnet *nethandle);
	//int (*fgetattr) (struct stat64 *, struct net_info *);
	//int (*chmod) (mode_t, struct umnet *nethandle);
	//int (*chown) (uid_t, gid_t, struct umnet *nethandle);
	//int (*access) (int, struct umnet *nethandle);
  //int (*open) (char, net_t, struct net_info *);
	int (*msocket) (int, int, int, struct umnet *);
	int (*bind) (int, const struct sockaddr *, socklen_t);
	int (*connect) (int, const struct sockaddr *, socklen_t);
	int (*listen) (int, int);
	int (*accept) (int, struct sockaddr *, socklen_t *);
	int (*getsockname) (int, struct sockaddr *, socklen_t *);
	int (*getpeername) (int, struct sockaddr *, socklen_t *);
	ssize_t (*send) (int, const void *, size_t, int) ;
	ssize_t (*recv) (int, const void *, size_t, int);
	ssize_t (*sendto) (int, const void *, size_t, int, const struct sockaddr *, socklen_t);
	ssize_t (*recvfrom) (int, void *, size_t, int, struct sockaddr *, socklen_t *);
	ssize_t (*recvmsg)(int, struct msghdr *, int);
	ssize_t (*sendmsg)(int, const struct msghdr *, int);
	int (*setsockopt) (int, int, int, const void *, socklen_t);
	int (*getsockopt) (int, int, int, void *, socklen_t *);
	ssize_t (*read) (int, void *, size_t);
	ssize_t (*write) (int, const void *, size_t);
	int (*ioctl) (int, int, void *);
	int (*close) (int);
	int (*fcntl) (int, int, long);

	int (*supported_domain) (int);
	int (*event_subscribe) (voidfun cb, void *arg, int fd, int how);

	int (*ioctlparms) (int, int req, struct umnet *nethandle);
	int (*init) (char *source, char *mountpoint, unsigned long flags, char *args, struct umnet *nethandle);
	int (*fini) (struct umnet *nethandle);
};

/* MOUNT ARG MGMT */
struct netargitem {
	char *arg;
	void (*fun)();
};
void netargs(char *opts, struct netargitem *netargtab, int netargsize, void *arg);

void umnet_setprivatedata(struct umnet *nethandle, void *privatedata);
void *umnet_getprivatedata(struct umnet *nethandle);

#if 0
void umnet_setmode(struct umnet *nethandle, mode_t mode);
mode_t umnet_getmode(struct umnet *nethandle);
#endif
#endif /* _UMNET_H_ */

/* MOUNT ARG MGMT
struct miscargitem {
	char *arg;
	void (*fun)();
};
*/
/*
void miscargs(char *opts, struct miscargitem *miscargtab, int miscargsize, void *arg);

struct ummisc *searchmisc_sc(int scno);
void *misc_getdl(struct ummisc *mh);

void ummisc_setprivatedata(struct ummisc *mischandle,void *privatedata);
void *ummisc_getprivatedata(struct ummisc *mischandle);
*/
//void ummisc_setmode(struct ummisc *mischandle, mode_t mode);
//mode_t ummisc_getmode(struct ummisc *mischandle);
#endif /* _UMSANDBOX_H_ */
