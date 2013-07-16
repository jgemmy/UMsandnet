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

static long ioctlparms(int fd,int req){
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

static int sockioctl(int d, int request, void *arg){
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
    switch(domain){
        case AF_LOCAL:
            printf("#%d socket locale. (%d)\n",ret,AF_LOCAL);
            connections[ret] = 'L';
            break;
        case AF_INET:
            printf("#%d socket inet4. (%d)\n",ret,AF_INET);
            connections[ret] = '4';
            break;
        case AF_INET6:
            printf("#%d socket inet6. (%d)\n",ret,AF_INET6);
            connections[ret] = '6';
            break;
        case AF_PACKET:
            printf("#%d socket af_packet. (%d)\n",ret,AF_PACKET);
        default:
            printf("#%d altro socket richiesto (%d %d %d).\n",ret,domain, type, protocol);
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
    int ret = -1;
    struct sockaddr* saddr = addr;
    switch (lookforaddr(saddr)) {
        case BLACK: goto failure;
        case WHITE: goto success;
    }
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
success:
    ret = connect(sockfd,addr,addrlen);	
    printf("connect returned %d\n",ret);
    if (ret == -1) printf("errno = %s",strerror(errno));
    return ret;
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

//TODO: vedere buffer in entrata/uscita di read/write


/*
   void *viewos_init(char *args)
   {
   return ht_tab_add(CHECKSOCKET,NULL,0,&s,NULL,NULL);
   }
   */

static long sock_event_subscribe(void (* cb)(), void *arg, int fd, int how){
    return um_mod_event_subscribe(cb,arg,fd,how);
}

void viewos_fini(void *data){
    struct ht_elem *proc_ht=data;
    ht_tab_del(proc_ht);
}

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

    printk("Sandbox init\n");
    s.name="umsandbox";
    s.description="Sandbox Module";
    s.ioctlparms=ioctlparms;
    s.syscall=(sysfun *)calloc(scmap_scmapsize,sizeof(sysfun));
    s.socket=(sysfun *)calloc(scmap_sockmapsize,sizeof(sysfun));
    SERVICESOCKET(s, uname, my_uname);
    SERVICESOCKET(s, socket, mysocket);
    SERVICESOCKET(s, bind, bind);
    SERVICESOCKET(s, connect, myconnect);
    SERVICESOCKET(s, listen, listen);
    SERVICESOCKET(s, accept, accept);
    SERVICESOCKET(s, getsockname, getsockname);
    SERVICESOCKET(s, getpeername, getpeername);
    SERVICESOCKET(s, send, send);
    SERVICESOCKET(s, recv, recv);
    SERVICESOCKET(s, sendto, sendto);
    SERVICESOCKET(s, recvfrom, recvfrom);
    SERVICESOCKET(s, shutdown, shutdown);
    SERVICESOCKET(s, setsockopt, setsockopt);
    SERVICESOCKET(s, getsockopt, getsockopt);
    SERVICESOCKET(s, sendmsg, sendmsg);
    SERVICESOCKET(s, recvmsg, recvmsg);
    SERVICESYSCALL(s, read, read);
    SERVICESYSCALL(s, write, write);
    SERVICESYSCALL(s, close, myclose);
#ifdef __NR_fcntl64
    SERVICESYSCALL(s, fcntl, fcntl64);
#else
    SERVICESYSCALL(s, fcntl, fcntl);
#endif
    SERVICESYSCALL(s, ioctl, sockioctl);
    s.event_subscribe=sock_event_subscribe;
    /*SERVICESYSCALL(s, fork, my_fork);
      SERVICESYSCALL(s, vfork, my_fork);
      SERVICESYSCALL(s, clone, my_fork);*/

    htuname=ht_tab_add(CHECKSC,&nruname,sizeof(int),&s,NULL,NULL);
    //htopen=ht_tab_add(CHECKPATH,&nropen,sizeof(int),&s,NULL,NULL);
    htsocket=ht_tab_add(CHECKSOCKET,NULL,0,&s,NULL,NULL);
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
