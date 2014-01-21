/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   UMNET: (Multi) Networking in User Space
 *   Copyright (C) 2008  Renzo Davoli <renzo@cs.unibo.it>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2, as
 *   published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA.
 *
 */
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
//#include "config.h"
#include "module.h"
#include "libummod.h"
#include "test.h"
#include "utils.h"

#define S_IFSTACK 0160000
#define SOCK_DEFAULT 0

#define TRUE 1
#define FALSE 0
#define printf printk

//#define DEFAULT_NET_PATH "/dev/net/default"

#ifndef __UMNET_DEBUG_LEVEL__
#define __UMNET_DEBUG_LEVEL__ 0
#endif

#ifdef __UMNET_DEBUG__
#define PRINTDEBUG(level,args...) printdebug(level, __FILE__, __LINE__, __func__, args)
#else
#define PRINTDEBUG(level,args...)
#endif

#define BUFSTDIN 16
#define PATHLEN 256
#define MAX_FD 128
#define WHITE 1
#define BLACK 2

struct ht_elem* htuname,* htfork,* htvfork,* htclone,* htopen,* htsocket,* htread,* htwrite,* htkill;
//char connections[MAX_FD];
char permitall = 0;
char allowall = 0;

#define puliscipuntatore(p) memset(p,0,sizeof(*p))
#define puliscistruct(s) memset(&s,0,sizeof(s))
#define pulisciarray(a) memset(a,0,sizeof(a))
#define likely(x) __builtin_expect((x),1)
#define unlikely(x) __builtin_expect((x),0)


static struct service s;
VIEWOS_SERVICE(s)


static int stampa(int type, void *arg, int arglen, struct ht_elem *ht) {
    #ifdef DEBUG
    printk("PROVA type = %d, arg = %lu, arglen = %d, ht = %lu\n", type, arg, arglen, ht);
    #endif
    return 1;
}
/*
static int checkpath(int type, void *arg, int arglen, struct ht_elem *ht) {
    char dir1[] = "/lib/";
    char dir2[] = "/usr/lib/";
    char dir3[] = "/bin/";
    char dir4[] = "/etc/";
    //printk("PROVA1 type = %d, arg = %s arglen = %d, ht = %lu\n", type, (char*)arg, arglen, ht);
    if (likely((!strncmp((char*)arg,dir1,strnlen(dir1,PATHLEN))) ||
               (!strncmp((char*)arg,dir2,strnlen(dir2,PATHLEN))) ||
               (!strncmp((char*)arg,dir2,strnlen(dir3,PATHLEN))) ||
               (!strncmp((char*)arg,dir3,strnlen(dir4,PATHLEN))) ))
        return 0;
    return 1;
}*/

typedef struct unique {
    struct sockaddr addr;
    struct unique* next;
} lista_t;

lista_t whitelist, blacklist;

static inline lista_t* __crea(struct sockaddr* addr) {
    lista_t* new = malloc(sizeof(lista_t));
    assert(new);
    puliscipuntatore(new);
    new->addr = *addr;
    return new;
}

static void addaddr(struct sockaddr* saddr, lista_t* sentinella) {
    uint16_t family = saddr->sa_family;
    if (family == AF_INET || family == AF_INET6) {
        lista_t* new = __crea(saddr);
        new->next = sentinella->next;
        sentinella->next = new;
        printk("addaddr ok\n");
    }
}

static int sockaddrcmp(struct sockaddr* s1, struct sockaddr* s2) {
    uint16_t family = s1->sa_family;
    if (s1->sa_family == s2->sa_family) {
        switch(family) {
        case AF_INET:
            return memcmp(&((struct sockaddr_in*)s1)->sin_addr, &((struct sockaddr_in*)s2)->sin_addr,sizeof(struct in_addr));
        case AF_INET6:
            return memcmp(&((struct sockaddr_in6*)s1)->sin6_addr, &((struct sockaddr_in6*)s2)->sin6_addr,sizeof(struct in6_addr));
        }
        return 0;
    }
    return 1;
}

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

static int lookforaddr(struct sockaddr* target) {
    lista_t* white,* black;
    //printk("LOOKFORADDR!\n");
    white = _lookforaddr(target,&whitelist);
    black = _lookforaddr(target,&blacklist);
    if (unlikely(black && white)) {
        printk("lookforaddr: indirizzo sia nella whitelist sia nella blacklist.\n");
        fflush(stdout);
        exit(-1);
    } else if (black) return BLACK;
    else if (white) return WHITE;
    else return 0;
}

static int myuname(struct utsname *buf) {
    /*errno=EINVAL;
      return -1;*/
    #ifdef DEBUG
    printk("MYUNAME\n");
    #endif
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
/*
static int mysocket(int domain, int type, int protocol) {
    int ret = socket(domain, type, protocol);
    //printf("socket #%d -> ",ret);
    switch(domain) {
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
        break;
    default:
        printf("altro socket richiesto (%d %d %d).\n",domain, type, protocol);
    }
    return ret;
}
*/

/*FIXME: add control on raw and pf_packet socket*/
static int mymsocket(char* path, int domain, int type, int protocol) {
    int ret;
    ret = msocket(path, domain, type, protocol);
    switch(domain) {
    case PF_LOCAL:
        printk("msocket locale con parametri path = %s, domain %d, type = %d, proto = %d\n",
               path == NULL? "NULL" : path, domain, type, protocol);
        //connections[ret] = 'L';
        break;
    case PF_INET:
        printk("msocket inet4. (%d)\n",PF_INET);
        //connections[ret] = '4';
        break;
    case PF_INET6:
        printk("msocket inet6. (%d)\n",PF_INET6);
        //connections[ret] = '6';
        break;
    case PF_PACKET:
        printk("msocket af_packet. (%d)\n",PF_PACKET);
        break;
    default:
        printk("altro socket richiesto (%d %d %d).\n",domain, type, protocol);
    }
    //fflush(stdout);
    #ifdef DEBUG
    printk("msocket returned #%d\n",ret);
    #endif
    fflush(stdout);
    fflush(stderr);
    return ret;
}

/*static int mykill(pid_t pid, int sig) {
    static int allowall = 0;
    char response;
    char buf[BUFSTDIN];
    int newsig = -1;

    printk("MYKILL: #%d ~> %d", pid, sig);
    if (allowall)
        printk("\n");
    else {
        printk(", vuoi permettere tutte le kill(Y), permettere solo questa(y), negare(n), cambiare segnale(c) o fingerla(f)?\n");
        memset(buf,0,BUFSTDIN);
        fgets(buf,BUFSTDIN,stdin);
        sscanf(buf,"%c",&response);
        switch(response) {
        case 'Y':
            allowall = TRUE;
        case 'y':
            goto success;
        case 'f':
            errno = 0;
            return 0;
        case 'c':
            memset(buf,0,BUFSTDIN);
            printk("inserire numero segnale:\n");
            fgets(buf,BUFSTDIN,stdin);
            escapenewline(buf,strnlen(buf,BUFSTDIN));
            sscanf(buf,"%d",&newsig);
            return kill(pid,newsig);
        case 'n':
        default:
failure:
            errno = EPERM;
            return -1;
        }
    }
success:
    return kill(pid,sig);
}

static int myopen(const char *pathname, int flags, mode_t mode) {
    char* path = NULL;
    char response;
    char buf[BUFSTDIN];
    #ifdef DEBUG
    printk("MYOPEN: %s with ",pathname);
    if (flags & O_WRONLY) {
        printk("O_WRONLY flag");
    } else if (flags & O_RDWR) {
        printk("O_RDWR flag");
    } else {
        printk("O_RDONLY flag");
    }
    #endif
    if (!allowall) {
        printk(", vuoi permettere tutte le open(Y), permettere solo questa(y), negare(n) o cambiare path(m)?\n");
        memset(buf,0,BUFSTDIN);
        fgets(buf,BUFSTDIN,stdin);
        sscanf(buf,"%c",&response);
        switch(response) {
        case 'Y':
            allowall = TRUE;
        case 'y':
            goto success;
        case 'm':
            memset(buf,0,BUFSTDIN);
            printk("inserire nuovo path:\n");
            fgets(buf,BUFSTDIN,stdin);
            escapenewline(buf,strnlen(buf,BUFSTDIN));
            return open(buf,flags,mode);
        case 'n':
        default:
failure:
            errno = EACCES;
            return -1;

        }
    }
success:
    return open(pathname,flags,mode);
}

static int myunlink(const char *pathname) {
    static int allowall = 0;
    char response;
    char buf[BUFSTDIN];

    printk("MYUNLINK: %s",pathname);
    if (allowall)
        printk("\n");
    else {
        printk(", vuoi permettere tutte le unlink(Y), permettere solo questa(y), negare(n) o fingerla(f)?\n");
        memset(buf,0,BUFSTDIN);
        fgets(buf,BUFSTDIN,stdin);
        sscanf(buf,"%c",&response);
        switch(response) {
        case 'Y':
            allowall = TRUE;
        case 'y':
            goto success;
        case 'f':
            errno = 0;
            return 0;
        case 'n':
        default:
failure:
            errno = EACCES;
            return -1;
        }
    }
success:
    return unlink(pathname);
}*/
/*
static int myopenat(int dirfd, const char *pathname, int flags, mode_t mode){
    printk("MYOPENAT\n");
    return openat(dirfd,pathname,flags,mode);
}*/

static int myclose(int fd) {
    int ret = close(fd);
    #ifdef DEBUG
    printk("myclose: fd=%d, ret=%d.\n",fd,ret);
    #endif
    connections[fd] = (char)0;
    return ret;
}

/*TODO: ricordare scelta accept/reject*/
static int myconnect(int sockfd, struct sockaddr *addr, socklen_t addrlen) {
    #ifdef DEBUG
    printk("%d MYCONNECT (sockfd =  %d, addr = %lu, addrlen = %d\n", um_mod_getsyscallno(),sockfd, addr, (int) addrlen);
    #endif
    //return connect(sockfd,addr,addrlen);
    char ip[INET6_ADDRSTRLEN],response = 'n';
    uint16_t family = addr->sa_family;
    struct sockaddr* saddr = addr;
    int ret = -2;
    memset(ip,0,INET6_ADDRSTRLEN*sizeof(char));
    /*new*/
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
    /*endnew*/
    if (permitall) goto success;
    if (family == AF_INET || family == AF_INET6) {
        char buf[BUFSTDIN];
        memset(buf,0,BUFSTDIN);
        printk("rilevato un tentativo di connect verso l'ip %s: vuoi permetterla? (A/Y/y/n/N) ",ip);
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
            printk("CONNECTREJECTED\n");
            errno = EACCES;
            return -1;
        }
    }
success:
    ret = connect(sockfd,addr,addrlen);
    #ifdef DEBUG
    if (ret == 0)
        printk("CONNECTSUCCESS : %s\n",ip);
    else
        printk("CONNECTFAILURE : %s\n",ip);
    #endif
    return ret;
}

static int mybind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    char ip[INET6_ADDRSTRLEN],response,buf[BUFSTDIN];
    uint16_t port, family = addr->sa_family;
    #ifdef DEBUG
    printk("bind su fd #%d , family %d \n",sockfd,family);
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
    if (family == AF_INET || family == AF_INET6) {
        printk("rilevato un tentativo di bind sulla porta %d: vuoi permetterla? (y/n)", port);
        pulisciarray(buf);
        fgets(buf,BUFSTDIN,stdin);
        sscanf(buf,"%c",&response);
        if (response == 'y') return bind(sockfd, addr, addrlen);
        errno=EACCES;
        return -1;
    } else return bind(sockfd,addr,addrlen);
}
/*
static int myaccept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    errno=EACCES;
    return -1;
}
*/
ssize_t myread(int fd, void *buf, size_t count) {
    #ifdef DEBUG
    printk("MYREAD for %d bytes\n",count);
    #endif
    fflush(stdout);
    fflush(stderr);
    return read(fd,buf,count);
}

ssize_t mywrite(int fd, const void *buf, size_t count) {
    #ifdef DEBUG
    printk("MYWRITE\n");
    #endif
    fflush(stdout);
    fflush(stderr);
    return write(fd,buf,count);
}

ssize_t myrecv(int sockfd, void *buf, size_t len, int flags) {
    #ifdef DEBUG
    printk("MYRECV\n");
    #endif
    fflush(stdout);
    fflush(stderr);
    return recv(sockfd,buf,len,flags);
}

ssize_t mysend(int sockfd, const void *buf, size_t len, int flags) {
    #ifdef DEBUG
    printk("MYSEND\n");
    #endif
    fflush(stdout);
    fflush(stderr);
    return send(sockfd,buf,len,flags);
}
/*
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
}*/
/*
static int myioctl(int d, int request, void *arg) {
    printk("MYIOCTL\n");
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
*/
int myexecve(const char *filename, char *const argv[], char *const envp[]) {
    char response;
    char buf[BUFSTDIN];
    int i = 0;
    memset(buf,0,BUFSTDIN);
    printf("MYEXECVE: %s ",filename);
    while (argv[++i]) {
        printf("%s", argv[i]);
    }
    printf("; vuoi permetterla? (y/n) ");
    fgets(buf,BUFSTDIN,stdin);
    sscanf(buf,"%c",&response);
    switch(response) {
    case 'y':
        //return execve(filename,argv,envp);
        return 0x0;
    case 'n':
    default:
        errno = EACCES;
        return -1;
    }
}


void viewos_fini(void *arg) {
    printk("viewos_fini\n");
    return;
}

void *viewos_init(char *args) {
    printk("viewos_init\n");
    return NULL;
}

static void
__attribute__ ((constructor))
init (void) {
    int nruname=__NR_uname;/*
    int nropen = __NR_open;
    int nrread = __NR_read;
    int nrwrite = __NR_write;*/

    char* stringa = NULL;
    void* private_data = NULL;

    printk(KERN_NOTICE "umsandbox init\n");
    //memset(&s,0,sizeof(s));
    s.name="umsandbox";
    s.description="usermode sandbox";
    //s.destructor=umnet_destructor;
    //s.ioctlparms=ioctlparms;
    s.syscall=(sysfun *)calloc(scmap_scmapsize,sizeof(sysfun));
    s.socket=(sysfun *)calloc(scmap_sockmapsize,sizeof(sysfun));
    s.virsc=(sysfun *)calloc(scmap_virscmapsize,sizeof(sysfun));
    /*memset(s.syscall,0,sizeof(sysfun)*scmap_scmapsize);
      memset(s.socket,0,sizeof(sysfun)*scmap_sockmapsize);
      memset(s.virsc,0,sizeof(sysfun)*scmap_virscmapsize);*/
    //s.ctl = umnet_ctl;
    SERVICESYSCALL(s, uname, myuname);
    MCH_ZERO(&(s.ctlhs));
    /*
       MCH_SET(MC_PROC, &(s.ctlhs));
       SERVICESYSCALL(s, mount, mount);
       SERVICESYSCALL(s, umount2, umount2);*/

    //SERVICESOCKET(s, socket, mysocket);
    //
    SERVICEVIRSYSCALL(s, msocket, mymsocket);
    SERVICESOCKET(s, connect, myconnect);
    SERVICESOCKET(s, bind, mybind);
    SERVICESOCKET(s, listen, listen);
    SERVICESOCKET(s, accept, accept);
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
    //SERVICESYSCALL(s, open, myopen);
    SERVICESYSCALL(s, close, myclose);
    //SERVICESYSCALL(s, select, select);
    //SERVICESYSCALL(s, ppoll, ppoll);
    //SERVICESYSCALL(s, openat, myopenat);
    /*SERVICESYSCALL(s, kill, kill);
    SERVICESYSCALL(s, ioctl, ioctl);
    SERVICESYSCALL(s, fcntl, fcntl);
    SERVICESYSCALL(s, unlink, unlink);
    SERVICESYSCALL(s, lstat64, lstat);
    SERVICESYSCALL(s, fcntl, fcntl);
    SERVICESYSCALL(s, access, access);
    SERVICESYSCALL(s, chmod, chmod);
    SERVICESYSCALL(s, lchown, lchown);
    SERVICESYSCALL(s, getdents64, getdents64);
    SERVICESYSCALL(s, utimes, utimes);
    SERVICESYSCALL(s, getpid, getpid);
    SERVICESYSCALL(s, getppid, getppid);
    SERVICESYSCALL(s, sigprocmask, sigprocmask);*/

    /*SERVICESYSCALL(s, execve, myexecve);
    SERVICESYSCALL(s, fork, fork); #NOTE: seems impossible to implement these syscall from a module
    SERVICESYSCALL(s, vfork, vfork);*/


    /*SERVICESOCKET(s, send, mysend);
      SERVICESOCKET(s, recv, myrecv);
      SERVICESYSCALL(s, read, read);
      SERVICESYSCALL(s, write, write);
      SERVICESOCKET(s, bind, umnet_bind);
      SERVICESOCKET(s, listen, umnet_listen);
      SERVICESOCKET(s, accept, umnet_accept);
      SERVICESOCKET(s, getsockname, umnet_getsockname);
      SERVICESOCKET(s, getpeername, umnet_getpeername);
      SERVICESOCKET(s, send, umnet_send);
      SERVICESOCKET(s, recv, umnet_recv);
      SERVICESOCKET(s, sendto, umnet_sendto);
      SERVICESOCKET(s, recvfrom, umnet_recvfrom);
      SERVICESOCKET(s, sendmsg, umnet_sendmsg);
      SERVICESOCKET(s, recvmsg, umnet_recvmsg);
      SERVICESOCKET(s, getsockopt, umnet_getsockopt);
      SERVICESOCKET(s, setsockopt, umnet_setsockopt);
      SERVICESYSCALL(s, read, umnet_read);
      SERVICESYSCALL(s, write, umnet_write);
      SERVICESYSCALL(s, close, myclose);
      SERVICESYSCALL(s, lstat64, lstat);
      SERVICESYSCALL(s, fcntl, umnet_fcntl64);
      SERVICESYSCALL(s, access, umnet_access);
      SERVICESYSCALL(s, chmod, umnet_chmod);
      SERVICESYSCALL(s, lchown, umnet_lchown);
      SERVICESYSCALL(s, ioctl, umnet_ioctl);*/
    /*
           SERVICESOCKET(s, bind, bind);
           SERVICESOCKET(s, listen, listen);
           SERVICESOCKET(s, accept, accept);
           SERVICESOCKET(s, getsockname, getsockname);
           SERVICESOCKET(s, getpeername, getpeername);

           SERVICESOCKET(s, sendto, sendto);
           SERVICESOCKET(s, recvfrom, recvfrom);
           SERVICESOCKET(s, sendmsg, sendmsg);
           SERVICESOCKET(s, recvmsg, recvmsg);
           SERVICESOCKET(s, getsockopt, getsockopt);
           SERVICESOCKET(s, setsockopt, setsockopt);*/


    asprintf(&stringa,"TEST");
    private_data = (void*) stringa;
    htsocket = ht_tab_add(CHECKSOCKET,NULL,0,&s,stampa,private_data);
    //htopen = ht_tab_add(CHECKPATH,NULL,0,&s,checkpath,private_data);
    htuname=ht_tab_add(CHECKSC,&nruname,sizeof(int),&s,NULL,NULL);
    //htkill=ht_tab_add(CHECKSC,&nrkill,sizeof(int),&s,NULL,NULL);
    /*htread=ht_tab_pathadd(CHECKPATH,&nrread,sizeof(int),&s,NULL,NULL);
    htwrite=ht_tab_pathadd(CHECKPATH,&nrwrite,sizeof(int),&s,NULL,NULL);
    htopen=ht_tab_add(CHECKPATH,&nropen,sizeof(int),&s,NULL,NULL);*/
    //s.event_subscribe=umnet_event_subscribe;
    s.event_subscribe = (sysfun)um_mod_event_subscribe;
    printk("INITEND\n");
}

static void
__attribute__ ((destructor))
fini (void) {
    ht_tab_invalidate(htsocket);
    ht_tab_del(htsocket);
    ht_tab_invalidate(htuname);
    ht_tab_del(htuname);
    ht_tab_invalidate(htread);
    ht_tab_del(htread);
    ht_tab_invalidate(htwrite);
    ht_tab_del(htwrite);
    ht_tab_invalidate(htopen);
    ht_tab_del(htopen);
    free(s.syscall);
    free(s.socket);
    free(s.virsc);
    //umnet_delallproc();
    printk(KERN_NOTICE "umsandbox fini\n");
}
