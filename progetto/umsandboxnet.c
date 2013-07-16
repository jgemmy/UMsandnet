/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   UMNETNATIVE: Virtual Native Network
 *    Copyright (C) 2008  Renzo Davoli <renzo@cs.unibo.it>
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/net.h>
#include <linux/net.h>
#include <linux/sockios.h>
#include <linux/if.h>

#include "umsandnew.h"

static int umnetnative_ioctlparms(int fd, int req, struct umnet *nethandle)
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

int umnetnative_msocket (int domain, int type, int protocol,
		struct umnet *nethandle){
	return msocket(NULL,domain, type, protocol);
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


static int mysocket1(int domain, int type, int protocol){
	int ret, erno;
	printf("mysocket1: inserire un valore di ritorno e errno.\n");
	scanf("%d",&ret);
	scanf("%d",&erno);
	printf("hai inserito i seguenti valori: rv=%d, erno=%d.\n",ret,erno);
	return socket(domain, type, protocol);
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







int umnetnative_init (char *source, char *mountpoint, unsigned long flags, char *args, struct umnet *nethandle) {
	return 0;
}

int umnetnative_fini (struct umnet *nethandle){
	return 0;
}

int um_mod_event_subscribe(void (* cb)(), void *arg, int fd, int how);

static int umnetnative_ioctl(int d, int request, void *arg)
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

struct umnet_operations umnet_ops={
	.msocket=umnetnative_msocket,
	.bind=bind,
	.connect=connect,
	//connect=myconnect;
	.listen=listen,
	.accept=accept,
	//.accept=myaccept;
	.getsockname=getsockname,
	.getpeername=getpeername,
	.send=send,
	.sendto=sendto,
	.recvfrom=recvfrom,
	.sendmsg=sendmsg,
	.recvmsg=recvmsg,
	.getsockopt=getsockopt,
	.setsockopt=setsockopt,
	.read=read,
	.write=write,
	.ioctl=umnetnative_ioctl,
	.close=close,
	.fcntl=(void *)fcntl,
	.ioctlparms=umnetnative_ioctlparms,
	.init=umnetnative_init,
	.fini=umnetnative_fini,
	.event_subscribe=um_mod_event_subscribe
};

