/*
 * *
 *  * umsandbox.c
 *   *
 *    * Copyright 2012 phra
 *     *
 *      * This program is free software; you can redistribute it and/or modify
 *       * it under the terms of the GNU General Public License as published by
 *        * the Free Software Foundation; either version 2 of the License, or
 *         * (at your option) any later version.
 *          *
 *           * This program is distributed in the hope that it will be useful,
 *            * but WITHOUT ANY WARRANTY; without even the implied warranty of
 *             * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *              * GNU General Public License for more details.
 *               *
 *                * You should have received a copy of the GNU General Public License
 *                 * along with this program; if not, write to the Free Software
 *                  * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *                   * MA 02110-1301, USA.
 *                    *
 *                     *
 * * * * * * * * * * * * */


#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <linux/net.h>
#include <string.h>
#include <asm/ioctls.h>
#include <linux/net.h>
#include <linux/sockios.h>
#include <linux/if.h>
#include <sys/utsname.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <asm/ioctls.h>
#include <linux/net.h>
#include <linux/sockios.h>
#include <linux/if.h>
#include <stdarg.h>
#include <pthread.h>
#include <assert.h>
#include "libummod.h"
#include "module.h"
#include "utils.h"

#include "umsandbox.h"

#define BUFSTDIN 16
#define MAX_FD 128
#define WHITE 1
#define BLACK 2

#define puliscipuntatore(p) memset(p,0,sizeof(*p))
#define puliscistruct(s) memset(&s,0,sizeof(s))
#define pulisciarray(a) memset(a,0,sizeof(a))
#define likely(x) __builtin_expect((x),1)
#define unlikely(x) __builtin_expect((x),0)


static struct service s;
VIEWOS_SERVICE(s);
struct ht_elem* htuname,* htfork,* htvfork,* htclone,* htopen,* htsocket;
char connections[MAX_FD];
pthread_mutex_t mutexconnect;



typedef struct unique {
    struct sockaddr addr;
    struct unique* next;
} lista_t;

lista_t whitelist, blacklist;

static inline lista_t* __crea(struct sockaddr* addr){
    lista_t* new = malloc(sizeof(lista_t));
    assert(new);
    puliscipuntatore(new);
    new->addr = *addr;
    return new;
}

static void addaddr(struct sockaddr* saddr, lista_t* sentinella){
    uint16_t family = saddr->sa_family;
    if (family == AF_INET || family == AF_INET6) {
        lista_t* new = __crea(saddr);
        new->next = sentinella->next;
        sentinella->next = new;
    }
}

static int sockaddrcmp(struct sockaddr* s1, struct sockaddr* s2){
    uint16_t family = s1->sa_family;
    if (s1->sa_family == s2->sa_family){
        switch(family){
            case AF_INET:
                return memcmp(&((struct sockaddr_in*)s1)->sin_addr, &((struct sockaddr_in*)s2)->sin_addr,sizeof(*s1));
            case AF_INET6:
                return memcmp(&((struct sockaddr_in6*)s1)->sin6_addr, &((struct sockaddr_in6*)s2)->sin6_addr,sizeof(*s1));
        }
        return -1;
    }
}

static lista_t* _lookforaddr(struct sockaddr* target, lista_t* sentinella){
    lista_t* iter = sentinella;
    while (iter->next != NULL){
        iter = iter->next;
        if (iter->addr.sa_family == target->sa_family) {
            switch(iter->addr.sa_family){
                case AF_INET:
                case AF_INET6:
                    if (sockaddrcmp(&iter->addr, target)) return iter;
            }
        }
    }
    return NULL;
}

static int lookforaddr(struct sockaddr* target){
    lista_t* white,* black;
    white = _lookforaddr(target,&whitelist);
    black = _lookforaddr(target,&blacklist);
    if (unlikely(black && white)){
        printf("lookforaddr: indirizzo sia nella whitelist sia nella blacklist.\n");
        fflush(stdout);
        exit(-1);
    }
    if (black) return BLACK;
    else if (white) return WHITE;
    else return 0;
}
/*
static long ioctlparms(int fd,int req){
    return 0;
    switch (req) {
        case FIONREAD:
            return sizeof(int) | IOCTL_W;
        case FIONBIO:
            return sizeof(int) | IOCTL_R;
        case SIOCGIFCONF:
            return sizeof(struct ifconf) | IOCTL_R | IOCTL_W;
        case SIOCGSTAMP:
            return sizeof(struct timeval) | IOCTL_W;
        case SIOCGIFTXQLEN:
            return sizeof(struct ifreq) | IOCTL_R | IOCTL_W;
        case SIOCGIFFLAGS:
        case SIOCGIFADDR:
        case SIOCGIFDSTADDR:
        case SIOCGIFBRDADDR:
        case SIOCGIFNETMASK:
        case SIOCGIFMETRIC:
        case SIOCGIFMEM:
        case SIOCGIFMTU:
        case SIOCGIFHWADDR:
            return sizeof(struct ifreq) | IOCTL_R | IOCTL_W;
        case SIOCSIFFLAGS:
        case SIOCSIFADDR:
        case SIOCSIFDSTADDR:
        case SIOCSIFBRDADDR:
        case SIOCSIFNETMASK:
        case SIOCSIFMETRIC:
        case SIOCSIFMEM:
        case SIOCSIFMTU:
        case SIOCSIFHWADDR:
        case SIOCGIFINDEX:
            return sizeof(struct ifreq) | IOCTL_R;
        default:
			return 0;
    }
}*/

static long ioctlparms(int fd, int req)
{
	switch (req) { 
		case FIONREAD:
			return sizeof(int) | IOCTL_W;
		case FIONBIO:
			return sizeof(int) | IOCTL_R;
		case SIOCGIFCONF:
			return sizeof(struct ifconf) | IOCTL_R | IOCTL_W;
		case SIOCGSTAMP:
			return sizeof(struct timeval) | IOCTL_W;
		case SIOCGIFTXQLEN:
			return sizeof(struct ifreq) | IOCTL_R | IOCTL_W;
		case SIOCGIFFLAGS:
		case SIOCGIFADDR:
		case SIOCGIFDSTADDR:
		case SIOCGIFBRDADDR:
		case SIOCGIFNETMASK:
		case SIOCGIFMETRIC:
		case SIOCGIFMEM:
		case SIOCGIFMTU:
		case SIOCGIFHWADDR:
			return sizeof(struct ifreq) | IOCTL_R | IOCTL_W;
		case SIOCSIFFLAGS:
		case SIOCSIFADDR:
		case SIOCSIFDSTADDR:
		case SIOCSIFBRDADDR:
		case SIOCSIFNETMASK:
		case SIOCSIFMETRIC:
		case SIOCSIFMEM:
		case SIOCSIFMTU:
		case SIOCSIFHWADDR:
		case SIOCGIFINDEX:
			return sizeof(struct ifreq) | IOCTL_R;
		default:
			return 0;
	}
}

static struct umnet *umnet_getdefstack(int id, int domain)
{

		struct ht_elem *hte=ht_search(CHECKPATH,DEFAULT_NET_PATH,
				strlen(DEFAULT_NET_PATH),&s);
		if (hte)
			return ht_get_private_data(hte);
		else
			return NULL;

}

static int checksocket(int type, void *arg, int arglen,
		struct ht_elem *ht)
{
	int *family=arg;
	struct umnet *mc=umnet_getdefstack(um_mod_getumpid(),*family);
	//printk("checksocket %d %d %p\n",um_mod_getumpid(),*family,mc);
	if (mc==NULL) {
		char *defnetstr=ht_get_private_data(ht);
		if (defnetstr)
		 return defnetstr[*family];
		else
			return 0;
	} else {
		return 1;
	}
}

static int my_fork(void){
    errno=ENOMEM;
    return -1;
}

static int my_open(const char *pathname, int flags, mode_t mode){
    errno=EACCES;
    return -1;
}

static int my_uname(struct utsname *buf){
    /*errno=EINVAL;
      return -1;*/

    if (uname(buf) >= 0) {
        strcpy(buf->sysname,"sandbox_module");
        strcpy(buf->nodename,"sandbox_module");
        strcpy(buf->release,"sandbox_module");
        strcpy(buf->version,"sandbox_module");
        strcpy(buf->machine,"sandbox_module");
        //strcpy(buf->domainname,"mymodule");
        return 0;
    } else return -1;

}

static int mysocket(int domain, int type, int protocol){
	int ret = socket(domain, type, protocol);
	printf("socket #%d -> ",ret);
	switch(domain){
		case AF_LOCAL:
			printf("socket locale. (%d)\n",AF_LOCAL);
			connections[ret] = 'L';
			break;
		case AF_INET:
			printf("socket inet4. (%d)\n",AF_INET);
			connections[ret] = '4';
			break;
		case AF_INET6:
			printf("socket inet6. (%d)\n",AF_INET6);
			connections[ret] = '6';
			break;
		case AF_PACKET:
			printf("socket af_packet. (%d)\n",AF_PACKET);
		default:
			printf("altro socket richiesto (%d %d %d).\n",domain, type, protocol);
	}
	return ret;
}

static int myclose(int fd){
    int ret = close(fd);
    printf("myclose: fd=%d, ret=%d.\n",fd,ret);
    connections[fd] = (char)0;
    return ret;
}

/*TODO: ricordare scelta accept/reject*/
static int myconnect(int sockfd, struct sockaddr *addr, socklen_t addrlen){ 
	char ip[INET6_ADDRSTRLEN],response = 'n';
	uint16_t family = addr->sa_family;
	struct sockaddr* saddr = addr;
	/*new*/	
	switch (lookforaddr(saddr)) {
		case BLACK: goto failure;
		case WHITE: goto success;
        case 0:
        default:
                break;
	}
	/*endnew*/
	switch(family){
		case AF_INET:
			inet_ntop(AF_INET, &(((struct sockaddr_in *)addr)->sin_addr),ip,INET_ADDRSTRLEN);
			break;
		case AF_INET6:
			inet_ntop(AF_INET, &(((struct sockaddr_in6 *)addr)->sin6_addr),ip,INET6_ADDRSTRLEN);
			break;
	}
	if (family == AF_INET || family == AF_INET6) {
		static char buf[BUFSTDIN];
		int i = 0;
        memset(buf,0,BUFSTDIN);
		printf("rilevato un tentativo di connect verso l'ip %s: vuoi permetterla? (y/n/Y/N) ",ip);
		fgets(buf,BUFSTDIN,stdin);
		sscanf(buf,"%c",&response);
        switch(response){
            case 'Y': addaddr(addr,&whitelist);
            case 'y': goto success;
            case 'N': addaddr(addr,&blacklist);
            case 'n':
            default:
failure:			errno = EACCES;
                    return -1;
        }
    }
success:return connect(sockfd,addr,addrlen);	
}

static int mybind(int sockfd, const struct sockaddr *addr, socklen_t addrlen){
    char ip[INET6_ADDRSTRLEN],response,buf[BUFSTDIN];
    uint16_t port, family = addr->sa_family;
    printf("bind su fd #%d , family %d \n",sockfd,family);
    switch(family){
        case AF_INET:
            inet_ntop(AF_INET, &(((struct sockaddr_in *)addr)->sin_addr),ip,INET_ADDRSTRLEN);
            port = ntohs(((struct sockaddr_in *)addr)->sin_port);
            break;
        case AF_INET6:
            inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)addr)->sin6_addr),ip,INET6_ADDRSTRLEN);
            port = ntohs(((struct sockaddr_in6 *)addr)->sin6_port);
            break;
        default:
            memset(ip,0,INET6_ADDRSTRLEN*sizeof(char));
    }
    if (family == AF_INET || family == AF_INET6){
        printf("rilevato un tentativo di bind sulla porta %d: vuoi permetterla? (y/n)", port);
        pulisciarray(buf);
        fgets(buf,BUFSTDIN,stdin);
        sscanf(buf,"%c",&response);
        if (response == 'y') return bind(sockfd, addr, addrlen);
        errno=EACCES;
        return -1;
    }
    else return bind(sockfd,addr,addrlen);
}

static int myaccept(int sockfd, struct sockaddr *addr, socklen_t *addrlen){
    errno=EACCES;
    return -1;
}



static uint32_t hash4(char *s) {
	uint32_t result=0;
	uint32_t wrap=0;
	while (*s) {
		wrap = result >> 24;
		result <<= 8;
		result |= (*s ^ wrap);
		s++;
	}
	return result;
}

static void defnet_update (char *defnetstr,
		char plusminus, int family)
{
	if (family > 0 && family < AF_MAXMAX) {
		switch (plusminus) {
			case '+' : defnetstr[family]=0; break;
			case '-' : defnetstr[family]=1; break;
		}
	}
}
/*
void *viewos_init(char *args)
{
	char *defnetstr = NULL;
	if (args && *args) {
		char *str, *token, *saveptr;
		char plusminus='-';
		int i;
		defnetstr = calloc(1,AF_MAXMAX);
		if (args[0] == '+' || (args[0] == '-' && args[1] == 0)) {
			for (i=0; i<AF_MAXMAX; i++)
				defnet_update(defnetstr,'-',i);
		} else {
			for (i=0; i<AF_MAXMAX; i++)
				defnet_update(defnetstr,'+',i);
		}
		for (str=args;
				(token=strtok_r(str, ",", &saveptr))!=NULL;str=NULL) {
			//printf("option %s\n",token);
			if (*token=='+' || *token=='-') {
				plusminus=*token;
				token++;
			}
			switch (hash4(token)) {
				case 0x00000000:
				case 0x00616c6c: for (i=0; i<AF_MAXMAX; i++)
													 defnet_update(defnetstr,plusminus,i);
												 break;
				case 0x00000075:
				case 0x756e6978: defnet_update(defnetstr,plusminus,AF_UNIX); break;
				case 0x00000034:
				case 0x69707634: defnet_update(defnetstr,plusminus,AF_INET); break;
				case 0x00000036:
				case 0x69707636: defnet_update(defnetstr,plusminus,AF_INET6); break;
				case 0x0000006e:
				case 0x6c070b1f: defnet_update(defnetstr,plusminus,AF_NETLINK); break;
				case 0x00000070:
				case 0x636b1515: defnet_update(defnetstr,plusminus,AF_PACKET); break;
				case 0x00000062:
				case 0x031a117e: defnet_update(defnetstr,plusminus,AF_BLUETOOTH); break;
				case 0x00000069:
				case 0x69726461: defnet_update(defnetstr,plusminus,AF_IRDA); break;
				case 0x00006970: defnet_update(defnetstr,plusminus,AF_INET);
												 defnet_update(defnetstr,plusminus,AF_INET6);
												 defnet_update(defnetstr,plusminus,AF_NETLINK);
												 defnet_update(defnetstr,plusminus,AF_PACKET);
												 break;
				default: if (*token == '#') {
									 int family=atoi(token+1);
									 if (family > 0 && family < AF_MAXMAX)
										 defnet_update(defnetstr,plusminus,family);
									 else
										 printk("umnet: unknown protocol \"%s\"\n",token);
								 } else
									 printk("umnet: unknown protocol \"%s\"\n",token);
								 break;
			}
		}
	}
	return ht_tab_add(CHECKSOCKET,NULL,0,&s,checksocket,defnetstr);
}

//TODO: vedere buffer in entrata/uscita di read/write
*/

/*
   void *viewos_init(char *args)
   {
   return ht_tab_add(CHECKSOCKET,NULL,0,&s,NULL,NULL);
   }
   
*/
static int sockioctl(int d, int request, void *arg)
{
	if (request == SIOCGIFCONF) {
		int rv;
		void *save;
		struct ifconf *ifc=(struct ifconf *)arg;
		save=ifc->ifc_buf;
		ioctl(d,request,arg);
		ifc->ifc_buf=malloc(ifc->ifc_len);
		um_mod_umoven((long) save,ifc->ifc_len,ifc->ifc_buf);
		rv=ioctl(d,request,arg);
		if (rv>=0)
			um_mod_ustoren((long) save,ifc->ifc_len,ifc->ifc_buf);
		free(ifc->ifc_buf);
		ifc->ifc_buf=save;
		return rv;
	}
	return ioctl(d,request,arg);
}

static long umnet_ctl(int type, char *sender, va_list ap)
{
	int id, ppid, max;

	switch(type)
	{
		case MC_PROC | MC_ADD:
			id = va_arg(ap, int);
			ppid = va_arg(ap, int);
			max = va_arg(ap, int);
			/*printk("umnet_addproc %d %d %d\n",id,ppid,max);*/
			return umnet_addproc(id, ppid, max);

		case MC_PROC | MC_REM:
			id = va_arg(ap, int);
			/*printk("umnet_delproc %d\n",id);*/
			return umnet_delproc(id);

		default:
			return -1;
	}
}

/*
void *viewos_init(char *args)
{
	int socktype=AF_INET;
	return ht_tab_add(CHECKSOCKET,&socktype,sizeof(int),&s,NULL,NULL);
}
*/

static long sock_event_subscribe(void (* cb)(), void *arg, int fd, int how){
    return um_mod_event_subscribe(cb,arg,fd,how);
}
/*
void viewos_fini(void *data){
    struct ht_elem *proc_ht=data;
    ht_tab_del(proc_ht);
}*/

static void __attribute__ ((constructor)) init (void) {
    int nruname=__NR_uname;
    int nrfork = __NR_fork;
    int nrvfork = __NR_vfork;
    int nrclone = __NR_clone;
    int nropen = __NR_open;
    memset(connections,0,MAX_FD*sizeof(char));
    pthread_mutex_init(&mutexconnect,NULL);
    puliscistruct(whitelist);
    puliscistruct(blacklist);
    memset(&s,0,sizeof(s));

    //MCH_ZERO(&(s.ctlhs));
    printk("Sandbox init\n");
    s.name="umsandbox";
	s.description="socket syscall (AF_INET) are executed server side";
	s.ioctlparms=ioctlparms;
	s.syscall=(sysfun *)calloc(scmap_scmapsize,sizeof(sysfun));
	s.socket=(sysfun *)calloc(scmap_sockmapsize,sizeof(sysfun));
	s.virsc=(sysfun *)calloc(scmap_virscmapsize,sizeof(sysfun));
	s.ctl = umnet_ctl;

	MCH_ZERO(&(s.ctlhs));
	MCH_SET(MC_PROC, &(s.ctlhs));
	//MCH_SET(MC_PROC, &(s.ctlhs));
	//SERVICESYSCALL(s, mount, mount);
	//SERVICESYSCALL(s, umount2, umount2);
	printk("1\n");
	SERVICEVIRSYSCALL(s, msocket, msocket);
		printk("2\n");
	SERVICESOCKET(s, bind, bind);
	SERVICESOCKET(s, connect, connect);
	SERVICESOCKET(s, listen, listen);
	SERVICESOCKET(s, accept, accept);
	SERVICESOCKET(s, getsockname, getsockname);
	SERVICESOCKET(s, getpeername, getpeername);
	SERVICESOCKET(s, send, send);
	SERVICESOCKET(s, recv, recv);

	SERVICESOCKET(s, sendto, sendto);
	SERVICESOCKET(s, recvfrom, recvfrom);
	SERVICESOCKET(s, sendmsg, sendmsg);
	SERVICESOCKET(s, recvmsg, recvmsg);
	SERVICESOCKET(s, getsockopt, getsockopt);
	SERVICESOCKET(s, setsockopt, setsockopt);
	SERVICESYSCALL(s, read, read);
	SERVICESYSCALL(s, write, write);
	SERVICESYSCALL(s, close, close);
	printk("3\n");
	SERVICESYSCALL(s, lstat, lstat);
	SERVICESYSCALL(s, fcntl, fcntl64);
	SERVICESYSCALL(s, access, access);
	SERVICESYSCALL(s, chmod, chmod);
	SERVICESYSCALL(s, lchown, lchown);
	SERVICESYSCALL(s, ioctl, ioctl);
	s.event_subscribe=sock_event_subscribe;
	printk("4\n");
    htuname=ht_tab_add(CHECKSC,&nruname,sizeof(int),&s,NULL,NULL);
    int socktype=AF_INET;
	htsocket = ht_tab_add(CHECKSOCKET,&socktype,sizeof(int),&s,NULL,NULL);
	printk("5\n");
    
    //htopen=ht_tab_add(CHECKPATH,&nropen,sizeof(int),&s,NULL,NULL);
    /*htfork=ht_tab_add(CHECKSC,&nrfork,sizeof(int),&s,NULL,NULL);
      htvfork=ht_tab_add(CHECKSC,&nrvfork,sizeof(int),&s,NULL,NULL);
      htclone=ht_tab_add(CHECKSC,&nrclone,sizeof(int),&s,NULL,NULL);*/
}

static void __attribute__ ((destructor)) fini (void){
    ht_tab_del(htuname);
    //ht_tab_del(htopen);
    ht_tab_del(htsocket);
    /*ht_tab_del(htfork);
      ht_tab_del(htvfork);
      ht_tab_del(htclone);*/
    printk("Sandbox fini\n");
}
