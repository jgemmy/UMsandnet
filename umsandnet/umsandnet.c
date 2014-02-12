/*
 **   UMsandnet module for UMview.
 * *   Copyright (C) 2014 phra
 *  *
 *   *   This program is free software; you can redistribute it and/or modify
 *    *   it under the terms of the GNU General Public License, version 2, as
 *     *   published by the Free Software Foundation, or (at your opinion)
 *      *   any later version.
 *       *
 *        *   This program is distributed in the hope that it will be useful,
 *         *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *          *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *           *   GNU General Public License for more details.
 *            *
 *             *   You should have received a copy of the GNU General Public License
 *              *   along with this program; if not, write to the Free Software Foundation,
 *               *   Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA.
 *                *
 * * * * * * * * * */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <time.h>
#include <pthread.h>
#include <sys/mount.h>
#include <linux/net.h>
#include <sys/utsname.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <sys/time.h>
#include <signal.h>
#include "module.h"
#include "libummod.h"

#define TRUE 1
#define FALSE 0
#define printf printk

#define BUFSTDIN 16
#define PATHLEN 256
#define MAX_FD 128
#define WHITE 1
#define BLACK 2

struct ht_elem* htuname,* htsocket;
char permitall = 0;
char allowall = 0;
char rawaccess = 0;
char permitallbind = 0;

#define puliscipuntatore(p) memset(p,0,sizeof(*p))
#define puliscistruct(s) memset(&s,0,sizeof(s))
#define likely(x) __builtin_expect((x),1)
#define unlikely(x) __builtin_expect((x),0)


static struct service s;
VIEWOS_SERVICE(s)

/**
 * debug function.
 * \return 1
 */
static int print(int type, void *arg, int arglen, struct ht_elem *ht) {
#ifdef DEBUG
    printk("[DEBUG] type = %d, arg = %lu, arglen = %d, ht = %lu\n", type, arg, arglen, ht);
#endif
    return 1;
}

typedef struct unique {
    struct sockaddr addr;
    struct unique* next;
} lista_t;

lista_t whitelist, blacklist;

/**
 * create a new element of the list.
 * \param addr address to add.
 * \return pointer to the new element
 */
static inline lista_t* __crea(struct sockaddr* addr) {
    lista_t* new = malloc(sizeof(lista_t));
    assert(new);
    puliscipuntatore(new);
    new->addr = *addr;
    return new;
}

/**
 * add new element to a list.
 * \param saddr address to add.
 * \param sentinella sentinel of the list.
 */
static void addaddr(struct sockaddr* saddr, lista_t* sentinella) {
    uint16_t family = saddr->sa_family;
    if (family == AF_INET || family == AF_INET6) {
        lista_t* new = __crea(saddr);
        new->next = sentinella->next;
        sentinella->next = new;
#ifdef DEBUG
        printk("addaddr ok\n");
#endif
    }
}

/**
 * compare two sockaddr structures.
 * \param s1 pointer to first sockaddr
 * \param s2 pointer to second sockaddr
 * \return 0 if they are equals. 
 */

static int sockaddrcmp(struct sockaddr* s1, struct sockaddr* s2) {
    uint16_t family = s1->sa_family;
    if (s1->sa_family == s2->sa_family) {
        switch(family) {
        case AF_INET:
            return memcmp(&((struct sockaddr_in*)s1)->sin_addr, &((struct sockaddr_in*)s2)->sin_addr,sizeof(struct in_addr));
        case AF_INET6:
            return memcmp(&((struct sockaddr_in6*)s1)->sin6_addr, &((struct sockaddr_in6*)s2)->sin6_addr,sizeof(struct in6_addr));
        }
    }
    return 1;
}

/**
 * look for an address in a specific list.
 * \param target address to look for
 * \param sentinella sentinel of the list
 * \return pointer to found element, else NULL
 */

static lista_t* _lookforaddr(struct sockaddr* target, lista_t* sentinella) {
    lista_t* iter = sentinella;
#ifdef DEBUG
    printk("_LOOKFORADDR\n");
#endif
    while (iter->next != NULL) {
        iter = iter->next;
        if (iter->addr.sa_family == target->sa_family) {
            switch(iter->addr.sa_family) {
            case AF_INET:
            case AF_INET6:
                if (!sockaddrcmp(&iter->addr, target)) return iter;
            }
        } else continue;
    }
    return NULL;
}

/**
 * look for an address in the blacklist and whitelist.
 * \param target address to look for
 * \return an int to indicate a list or 0 if not found
 */

static int lookforaddr(struct sockaddr* target) {
    lista_t* white,* black;
    white = _lookforaddr(target,&whitelist);
    black = _lookforaddr(target,&blacklist);
    if (unlikely(black && white)) {
        printk("lookforaddr error: address is in both lists..\n");
        fflush(stdout);
        exit(-1);
    } else if (black) return BLACK;
    else if (white) return WHITE;
    else return 0;
}

/**
 * uname() substitute.
 * \param buf pointer to user buffer.
 * \return 0 if no errors, else -1
 */

static int myuname(struct utsname *buf) {
#ifdef DEBUG
    printk("MYUNAME\n");
#endif
    if (uname(buf) >= 0) {
        strcpy(buf->sysname,"sandnet_module");
        strcpy(buf->nodename,"sandnet_module");
        strcpy(buf->release,"sandnet_module");
        strcpy(buf->version,"sandnet_module");
        strcpy(buf->machine,"sandnet_module");
        return 0;
    } else return -1;

}

/**
 * wrapper of msocket(). it asks if allow or not creation of sockets.
 * \param path path to the network stack.
 * \param domain domain of the socket
 * \param type type of the socket
 * \protocol protocol of the socket
 * \return new socket's fd or -1 if errors
 */

static int mymsocket(char* path, int domain, int type, int protocol) {
    int ret;
    if (unlikely((domain == PF_PACKET) || (((domain == PF_INET) || (domain == PF_INET6)) && (type == SOCK_RAW)))) {
        if (rawaccess == 2) {
            errno = EACCES;
            return -1;
        }
        if (!rawaccess) {
            char buf[BUFSTDIN];
            char response;
            memset(buf,0,BUFSTDIN);
            printk("low level socket required w/ path = %s, domain %d, type = %d, proto = %d, do you want to allow access to it? (Y/y/n/N)?\n",
                   path == NULL? "NULL" : path, domain, type, protocol);
            fgets(buf,BUFSTDIN,stdin);
            sscanf(buf,"%c",&response);
            switch(response) {
            case 'Y':
                rawaccess = 1;
                break;
            case 'y':
                break;
            case 'n':
                errno = EACCES;
                return -1;
                break;
            case 'N':
                rawaccess = 2;
                errno = EACCES;
                return -1;
                break;
            }
        }
    }
    switch(domain) {
    case PF_LOCAL:
#ifdef DEBUG
        printk("msocket PF_LOCAL and path = %s, domain %d, type = %d, proto = %d\n",
               path == NULL? "NULL" : path, domain, type, protocol);
#endif
        break;
    case PF_INET:
#ifdef DEBUG
        if (likely(type != SOCK_RAW)) printk("msocket inet4.\n");
#endif
        break;
    case PF_INET6:
#ifdef DEBUG
        if (likely(type != SOCK_RAW)) printk("msocket inet6.\n");
#endif
        break;
    case PF_PACKET:
        break;
    default:
#ifdef DEBUG
        printk("other socket required (%d %d %d).\n",domain, type, protocol);
#endif
        break;
    }
    ret = msocket(path, domain, type, protocol);
#ifdef DEBUG
    printk("msocket returned #%d\n",ret);
    fflush(stdout);
    fflush(stderr);
#endif
    return ret;
}

static int myclose(int fd) {
    int ret = close(fd);
#ifdef DEBUG
    printk("myclose: fd=%d, ret=%d.\n",fd,ret);
#endif
    return ret;
}

/**
 * wrapper of connect(). it asks to allow or not connect to requested IP.
 * \param sockfd file descriptor of the socket
 * \param addr pointer of sockaddr structure of the remote endpoint
 * \param addrlen lenght of the sockaddr structure
 * \return 0 if success, -1 else
 */

static int myconnect(int sockfd, struct sockaddr *addr, socklen_t addrlen) {
#ifdef DEBUG
    printk("%d MYCONNECT (sockfd =  %d, addr = %lu, addrlen = %d\n", um_mod_getsyscallno(),sockfd, addr, (int) addrlen);
#endif
    char ip[INET6_ADDRSTRLEN],response = 'n';
    uint16_t family = addr->sa_family;
    struct sockaddr* saddr = addr;
    int ret = -2;
    memset(ip,0,INET6_ADDRSTRLEN*sizeof(char));
    switch(family) {
    case AF_INET:
        inet_ntop(AF_INET, &(((struct sockaddr_in *)addr)->sin_addr),ip,INET_ADDRSTRLEN);
        break;
    case AF_INET6:
        inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)addr)->sin6_addr),ip,INET6_ADDRSTRLEN);
        break;
    }
    switch (lookforaddr(saddr)) {
    case BLACK:
        goto failure;
    case WHITE:
        goto success;
    case 0:
    default:
        break;
    }
    if (permitall) goto success;
    if (family == AF_INET || family == AF_INET6) {
        char buf[BUFSTDIN];
        memset(buf,0,BUFSTDIN);
        printk("connect(%d) to IP =  %s detected: do you want to allow it? (A/Y/y/n/N) ",sockfd,ip);
        fgets(buf,BUFSTDIN,stdin);
        sscanf(buf,"%c",&response);
        switch(response) {
        case 'A':
            permitall = 1;
            goto success;
        case 'Y':
            addaddr(addr,&whitelist);
        case 'y':
            goto success;
        case 'N':
            addaddr(addr,&blacklist);
        case 'n':
        default:
failure:
            printk("CONNECT REJECTED\n");
            errno = EACCES;
            return -1;
        }
    }
success:
    ret = connect(sockfd,addr,addrlen);
    if (likely(ret == 0)) {
        if (family == PF_INET || family == PF_INET6)
            printk("CONNECT SUCCESS : %s\n",ip);
    }
#ifdef DEBUG
    else
        printk("CONNECT FAILURE : %s\n",ip);
#endif
    return ret;
}

/**
 * wrapper of bind(). it asks to allow bind() on requested port.
 * \param sockfd file descriptor of the socket
 * \param addr pointer to sockaddr of local endpoint
 * \param addrlen lenght of the sockaddr structure
 * \return 0 if success, else -1
 */

static int mybind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    char ip[INET6_ADDRSTRLEN],response = 'n',buf[BUFSTDIN];
    uint16_t port, family = addr->sa_family;
#ifdef DEBUG
    printk("bind on fd #%d , family %d \n",sockfd,family);
#endif
    memset(ip,0,INET6_ADDRSTRLEN*sizeof(char));
    switch(family) {
    case AF_INET:
        inet_ntop(AF_INET, &(((struct sockaddr_in *)addr)->sin_addr),ip,INET_ADDRSTRLEN);
        port = ntohs(((struct sockaddr_in *)addr)->sin_port);
        break;
    case AF_INET6:
        inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)addr)->sin6_addr),ip,INET6_ADDRSTRLEN);
        port = ntohs(((struct sockaddr_in6 *)addr)->sin6_port);
        break;
    }
    if (!permitallbind && (family == AF_INET || family == AF_INET6)) {
        int ret;
        printk("bind(fd = %d) on port %d detected: do you want to allow it? (Y/y/n)\n", sockfd, port);
        memset(buf,0,BUFSTDIN);
        fgets(buf,BUFSTDIN,stdin);
        sscanf(buf,"%c",&response);
        switch (response) {
        case 'Y':
            permitallbind = 1;
        case 'y':
            ret = bind(sockfd, addr, addrlen);
#ifdef DEBUG
            printk("bind returns %d\n",ret);
#endif
            return ret;
        case 'n':
        default:
            errno=EACCES;
            return -1;
        }

    } else return bind(sockfd,addr,addrlen);
}

/**
 * wrapper of accept().
 * \param sockfd file descriptor of the socket
 * \param addr pointer to sockaddr structure buffer of the remote endpoint
 * \param addrlen lenght of the sockaddr structure
 * \return 0 on success, else -1
 */

static int myaccept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
#ifdef DEBUG
    printk("myaccept\n");
#endif
    return accept(sockfd,addr,addrlen);
}

/**
 * wrapper of listen().
 * \param sockfd file descriptor of the socket
 * \param backlog maximum length to which the queue of pending connections may grow
 * \return 0 on success, else -1
 */

static int mylisten(int sockfd, int backlog) {
#ifdef DEBUG
    printk("mylisten\n");
#endif
    return listen(sockfd, backlog);
}

/**
 * wrapper of read().
 * \param fd file descriptor of the socket
 * \param buf pointer to user buffer
 * \param count lenght of the buffer
 * \return number of read bytes.
 */
ssize_t myread(int fd, void *buf, size_t count) {
#ifdef DEBUG
    printk("MYREAD for %d bytes\n",count);
    fflush(stdout);
    fflush(stderr);
#endif
    return read(fd,buf,count);
}

/**
 * wrapper of write().
 * \param fd file descriptor of the socket
 * \param buf pointer to user buffer
 * \param count lenght of the buffer
 * \return number of written bytes.
 */
ssize_t mywrite(int fd, const void *buf, size_t count) {
#ifdef DEBUG
    printk("MYWRITE\n");
    fflush(stdout);
    fflush(stderr);
#endif
    return write(fd,buf,count);
}

/**
 * wrapper of recv().
 * \param sockfd file descriptor of the socket
 * \param buf pointer to user buffer
 * \param len lenght of the buffer
 * \param flags flags of recv()
 * \return number of received bytes 
 */
ssize_t myrecv(int sockfd, void *buf, size_t len, int flags) {
#ifdef DEBUG
    printk("MYRECV\n");
    fflush(stdout);
    fflush(stderr);
#endif
    return recv(sockfd,buf,len,flags);
}

/**
 * wrapper of send().
 * \param sockfd file descriptor of the socket
 * \param buf pointer to user buffer
 * \param len lenght of the buffer
 * \param flags flags of send()
 * \return number of sended bytes 
 */

ssize_t mysend(int sockfd, const void *buf, size_t len, int flags) {
#ifdef DEBUG
    printk("MYSEND\n");
    fflush(stdout);
    fflush(stderr);
#endif
    return send(sockfd,buf,len,flags);
}

static long myioctlparms(int fd, int req) {
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
    case SIOCGIFINDEX:
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
        return sizeof(struct ifreq) | IOCTL_R;
    default:
        return 0;
    }
}

static int myioctl(int d, int request, void *arg) {
#ifdef DEBUG
    printk("MYIOCTL\n");
#endif
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

void viewos_fini(void *arg) {
    printk("umsandnet_fini\n");
    return;
}

void *viewos_init(char *args) {
    printk("umsandnet_init\n");
    return NULL;
}

/**
 * entrypoint of the module.
 */

static void
__attribute__ ((constructor))
init (void) {
    int nruname=__NR_uname;
    memset(&s,0,sizeof(s));
    s.name="umsandnet";
    s.description="umsandnet";
    s.syscall=(sysfun *)calloc(scmap_scmapsize,sizeof(sysfun));
    s.socket=(sysfun *)calloc(scmap_sockmapsize,sizeof(sysfun));
    s.virsc=(sysfun *)calloc(scmap_virscmapsize,sizeof(sysfun));
    SERVICESYSCALL(s, uname, myuname);
    MCH_ZERO(&(s.ctlhs));
    SERVICEVIRSYSCALL(s, msocket, mymsocket);
    SERVICESOCKET(s, connect, myconnect);
    SERVICESOCKET(s, bind, mybind);
    SERVICESOCKET(s, listen, mylisten);
    SERVICESOCKET(s, accept, myaccept);
    SERVICESOCKET(s, getsockopt, getsockopt);
    SERVICESOCKET(s, setsockopt, setsockopt);
    SERVICESOCKET(s, getsockname, getsockname);
    SERVICESOCKET(s, getpeername, getpeername);
    SERVICESOCKET(s, recv, recv);
    SERVICESOCKET(s, send, send);
    SERVICESOCKET(s, recvfrom, recvfrom);
    SERVICESOCKET(s, sendto, sendto);
    SERVICESOCKET(s, sendmsg, sendmsg);
    SERVICESOCKET(s, recvmsg, recvmsg);
    SERVICESOCKET(s, shutdown, shutdown);
    SERVICESYSCALL(s, read, myread);
    SERVICESYSCALL(s, write, mywrite);
    SERVICESYSCALL(s, close, myclose);
    SERVICESYSCALL(s, ioctl, myioctl);
    htsocket = ht_tab_add(CHECKSOCKET,NULL,0,&s,print,NULL);
    htuname=ht_tab_add(CHECKSC,&nruname,sizeof(int),&s,NULL,NULL);
    s.ioctlparms = (sysfun) myioctlparms;
    s.event_subscribe = (sysfun)um_mod_event_subscribe;
}

/**
 * exitpoint of the module
 */
static void
__attribute__ ((destructor))
fini (void) {
    ht_tab_invalidate(htsocket);
    ht_tab_del(htsocket);
    ht_tab_invalidate(htuname);
    ht_tab_del(htuname);
    free(s.syscall);
    free(s.socket);
    free(s.virsc);
    printk(KERN_NOTICE "umsandnet fini\n");
}

