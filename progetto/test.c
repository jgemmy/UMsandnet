#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include "module.h"

static struct service s;
VIEWOS_SERVICE(s);
struct ht_elem *htuname;

static int my_uname(struct utsname *buf) {
    if (uname(buf) >= 0) {
        strcpy(buf->nodename,"mymodule");
        return 0;
    } else return -1;
}

static void __attribute__ ((constructor)) init (void) {
    int nruname=__NR_uname;
    printk("Second module (uname) init\n");
    s.name="umsandbox";
    s.description="Uname Module";
    s.syscall=(sysfun *)calloc(scmap_scmapsize,sizeof(sysfun));
    s.socket=(sysfun *)calloc(scmap_sockmapsize,sizeof(sysfun));
    SERVICESYSCALL(s, uname, my_uname);
    htuname=ht_tab_add(CHECKSC,&nruname,sizeof(int),&s,NULL,NULL);
}

static void __attribute__ ((destructor)) fini (void) {
    ht_tab_del(htuname);
    printk("Second module (uname) fini\n");
}

