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
