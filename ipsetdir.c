#define _DEFAULT_SOURCE

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <string.h>
#include <strings.h>

#include <sys/inotify.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define EVENT_SIZE  ( sizeof (struct inotify_event) )
#define EVENT_BUF_LEN     ( 64 * ( EVENT_SIZE + 16 ) )

#include <libipset/ipset_lib.h>

/****************************/

#define W_DIR_MAX 32
char *w_dirs[W_DIR_MAX] = { NULL, };
int   w_dirs_wd[W_DIR_MAX];
int w_dir_last = 0;

char pid_file[256]="";
int pid_file_ok = 0;

char *w_dir = NULL, *w_set = NULL, *w_type="hash:ip";

volatile int work = 1;
int debug = 0;


static int is_ip(char *str) {
  char a_buf[16];
  return inet_pton(AF_INET,str,a_buf) || inet_pton(AF_INET6,str,a_buf);
}

static void fix_char(char *str) {
  for(;str && *str;str++) {
	if(*str == '_') *str = ':';
  }
}

static int check_exist_ipset(char *setname) {
char *arg[6];
int r;

ipset_parse_file(NULL,0,"/dev/zero");
arg[0]="ipset";
arg[1]="save";
arg[2]=setname;
arg[3]=NULL;
r = ipset_parse_commandline(3,arg);
if(r < 0)
        ipset_session_reset();
ipset_session_fdclose();
return r == 0;
}

static int ipset_parse_cmd(char *cmd,char *setname,char *setarg) {
char *arg[5],*sa,*sn;
int r;

arg[0]="ipset";
arg[1]=cmd;
sn = arg[2]= strdup(setname);
sa = arg[3]= setarg && *setarg ? strdup(setarg) : NULL;
arg[4]=NULL;
r = ipset_parse_commandline(arg[3] ? 4:3,arg);
if(r < 0)
        ipset_session_reset();
if(sn) free(sn);
if(sa) free(sa);
return r;
}

static void create_ipset(char *setname,char *add) {

int r = ipset_parse_cmd("create",setname,add);
if(r < 0) {
	fprintf(stderr,"cant create set %s\n",setname);
	exit(1);
}
}

static void flush_ipset(char *setname) {

int r = ipset_parse_cmd("flush",setname,NULL);
if(r < 0) {
	fprintf(stderr,"cant flush set %s\n",setname);
	exit(1);
}
}


static int test_ipset(char *setname,char *addr) {
int r = ipset_parse_cmd("test",setname,addr);

return r >= 0;
}

static int add_ipset(char *setname,char *addr) {
int r;

r = ipset_parse_cmd("del",setname,addr);

r = ipset_parse_cmd("add",setname,addr);
if(r < 0) {
	fprintf(stderr,"cant add ip %s set %s\n",addr,setname);
}
return r >= 0;
}

static int del_ipset(char *setname,char *addr) {
int r;

if(!test_ipset(setname,addr)) {
	fprintf(stderr,"nonexist ip %s set %s\n",addr,setname);
	return 1;
}
r = ipset_parse_cmd("del",setname,addr);
if(r < 0) {
	fprintf(stderr,"cant del ip %s set %s\n",addr,setname);
}
return r >= 0;
}

static void event_handler(char *f_name,int del) {
  char a_buf[64];
	strncpy(a_buf,f_name,sizeof(a_buf)-1);
	fix_char(a_buf);
	if(!is_ip(a_buf)) {
		if(debug)
			fprintf(stderr,"Invalid ip %s\n",a_buf);
		return;
	}

	if(del) {
		if(!del_ipset(w_set,a_buf))
			fprintf(stderr,"%s del err\n", a_buf);
		else if(debug)
			fprintf(stderr,"%s deleted\n", a_buf);
	} else {
		if(!add_ipset(w_set,a_buf))
			fprintf(stderr,"%s add err\n", a_buf);
		else if(debug)
			fprintf(stderr,"%s added\n", a_buf);
	}
}

static int is_file(char *file,char *dir) {
struct stat st;
char full_name[512];
char slash = dir && *dir ? dir[strlen(dir)-1] != '/': 0;

snprintf(full_name,sizeof(full_name)-1,"%s%s%s",dir && *dir ? dir:"", slash ? "/":"",file);
if(stat(full_name,&st) < 0) return 0;
return  S_ISREG(st.st_mode);
}

static int create_pidfile(char *pfile) {
int fd;
ssize_t n;
char buf[64];
fd = creat(pfile,0644);
if(fd < 0) return 1;
snprintf(buf,sizeof(buf)-1,"%d\n",getpid());
n = write(fd,buf,strlen(buf));
fd = close(fd);
pid_file_ok = fd == 0 && n == strlen(buf);
return pid_file_ok == 0;
}

static int is_valid_pidfile(char *pfile) {
int fd;
ssize_t n;
char buf[64];
struct stat st;

fd = open(pfile,O_RDONLY);
if(fd < 0) 
	return create_pidfile(pfile);
bzero(buf,sizeof(buf));
n = read(fd,buf,sizeof(buf)-1);
close(fd);
if(n > 0) {
	int pid;
	if(sscanf(buf,"%d",&pid) == 1) {
		snprintf(buf,sizeof(buf)-1,"/proc/%d",pid);
		if(stat(buf,&st) < 0)
			return create_pidfile(pfile);
	}
	return 1;
}
return create_pidfile(pfile);
}

void prepare_ipset_dir(char *dir,char *set) {
struct dirent **namelist;
int n;

n = scandir(dir, &namelist, NULL, alphasort);
if(n < 0) {
	perror("scandir");
	exit(1);
}
if(debug) fprintf(stderr,"Lookup dir %s\n",dir);
while( --n >= 0) {
	if(namelist[n]->d_name[0] != '.') {
		if(is_file(namelist[n]->d_name,dir)) 
			event_handler(namelist[n]->d_name,0);
	}
	free(namelist[n]);
}
free(namelist);
ipset_session_reset();
}

static void reread_w_dirs(void) {
int i;
flush_ipset(w_set);
for(i=0; i < w_dir_last; i++) {
	prepare_ipset_dir(w_dirs[i],w_set);
}
}

static char *find_wd(int wd) {
int i;
for(i=0; i < w_dir_last; i++) {
	if(w_dirs_wd[i] == wd) 
		return w_dirs[i];
}
return NULL;
}

void help(void) {
fprintf(stderr,"%s [-d] [-F] [-f] [-p pidfile] [-t ipset_type] -s ipset_name dir [dir ...]\n","ipsetdir");
fprintf(stderr," -d - debug\n -F - no daemonize\n -f - flush set on exit\n"
		" -p pidfile - use PID file. Default: /run/ipset_dir_<setname>.pid\n"
		" -t ipset_type - type of ipset. default hash:ip\n -s ipset_name - ipset name\n");
exit(0);
}

char event_buff[EVENT_BUF_LEN];

void my_signals(int s) {
if(s == SIGHUP) {
	reread_w_dirs();
} else {
	work = 0;
}
}

int main(int argc,char **argv) {

struct inotify_event * event;
int i,fd,wd,len,c;
int set_flush = 0, dodaemon = 1;
int del;

	if(ipset_init_lib()) {
		fprintf(stderr,"Initialize ipset library failed.\n");
		exit(1);
	}
	while((c=getopt(argc,argv,"dFp:s:t:")) != -1) {
	switch(c) {
	  case 'd': debug++; break;
	  case 'f': set_flush = 1; break;
	  case 'F': dodaemon = 0; break;
	  case 'p': strncpy(pid_file,optarg,sizeof(pid_file)-1); break;
	  case 's': w_set = strdup(optarg); break;
	  case 't': w_type = strdup(optarg); break;
	  default: help();
	}
	}

	if(!w_set || !argv[optind]) {
		help();
	}
	if(!pid_file[0]) {
		snprintf(pid_file,sizeof(pid_file)-1,"/run/ipset_dir_%s.pid",w_set);
	}
	if(is_valid_pidfile(pid_file)) {
		fprintf(stderr,"Found valid PID file %s\n",pid_file);
		exit(1);
	}

	if(!check_exist_ipset(w_set))
		create_ipset(w_set,w_type);

	flush_ipset(w_set);

	fd = inotify_init();
	if ( fd < 0 ) {
		perror("inotify_init");
		exit(1);
	}

	for(i = optind; i < argc; i++) {
		w_dir = strdup(argv[i]);
		if(w_dir_last+1 >= W_DIR_MAX) {
			fprintf(stderr,"Too many watch dirs\n");
			break;
		}
		w_dirs[w_dir_last] = w_dir;
		
		prepare_ipset_dir(w_dir,w_set);
		wd = inotify_add_watch( fd, w_dir, IN_CLOSE_WRITE|IN_DELETE|IN_MOVED_FROM|IN_MOVED_TO );
		if(wd < 0) {
			perror("inotify_add_watch");
			exit(1);
		}
		w_dirs_wd[w_dir_last++] = wd;
		if(debug)
			fprintf(stderr,"Add watch dir %s\n",w_dir);
	}
	if(dodaemon) {
		if(daemon(1,0) < 0) {
			perror("daemon");
			exit(1);
		}
		if(create_pidfile(pid_file)) {
			perror("create pidfile");
			exit(1);
		}
	}
	signal(SIGHUP,my_signals);
	signal(SIGINT,my_signals);
	signal(SIGTERM,my_signals);
	signal(SIGQUIT,my_signals);
	siginterrupt(SIGHUP,1);
	siginterrupt(SIGINT,1);
	siginterrupt(SIGTERM,1);
	siginterrupt(SIGQUIT,1);

	while(work) {
		len = read(fd,event_buff,sizeof(event_buff));
		if(len < 0 && errno == EINTR) {
			if(debug) fprintf(stderr,"EINTR\n");
			continue;
		}
		if(len < 0) break;
		if(len < EVENT_SIZE) break;
		if(debug) fprintf(stderr,"Read %d from events FD\n",len);

		for(i = 0; i < len; i += EVENT_SIZE + event->len) {
			event = (struct inotify_event *)(&event_buff[i]);
			if(!event->len || EVENT_SIZE + event->len + i > len) break;
			del = event->mask & (IN_DELETE|IN_MOVED_FROM);
			w_dir = find_wd(event->wd);
			if(debug)
				fprintf(stderr,"Dir:%s File:%s Event:%s\n",
						w_dir,event->name,
						del ? "DEL":"ADD");
			if(is_file(event->name,w_dir) || del)
				event_handler(event->name,del);
		}
	}
	if(set_flush)
		flush_ipset(w_set);
	if(pid_file_ok)
		unlink(pid_file);
	if(debug)
		fprintf(stderr,"Exit\n");
	exit(0);
}

