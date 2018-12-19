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
#include <poll.h>
#include <time.h>

#include <openssl/sha.h>

#define EVENT_SIZE  ( sizeof (struct inotify_event) )
#define EVENT_BUF_LEN     ( 64 * ( EVENT_SIZE + 16 ) )
#define ARRAY_LEN(a)	(sizeof(a)/sizeof(a[0]))


#include "ipset_ui/ipset_ui.h"

/****************************/

#define W_DIR_MAX 32
char *w_dirs[W_DIR_MAX] = { NULL, };
int   w_dirs_wd[W_DIR_MAX];
int w_dir_last = 0;

char pid_file[256]="";
int pid_file_ok = 0;

char *w_dir = NULL, *w_set = NULL, *w_type="hash:ip";

struct ipset_session *session = NULL;

volatile int work = 1;
int debug = 0;
static time_t last_wakeup = 0;

#define N_PEERS 8
#define N_LIST 8

struct peer {
		struct sockaddr_in	pa;
		struct sockaddr_in	la;
		int					psock;
		int					ssock;
		time_t				ptime;
		int					master;
		int					seq;
};

struct app_cfg {
		int		ping;
		struct pollfd fds[N_LIST+1];
		int		n_list;
		int		n_peer;
		int		n_master;
		struct sockaddr_in list[N_LIST];
		struct peer peers[N_PEERS];
		char	key[32];
		int		key_len;
		uint32_t port;
} CFG;

struct one_string {
    struct one_string *next;
    size_t      len; // length of origin string
    char		x; // for compare
	char        data[0];
};

typedef struct one_string one_string_t ;

one_string_t *LIST = NULL;

static int event_handler(char *f_name,int del);

static void fix_char(char *str) {
  for(;str && *str;str++) {
	if(*str == '_') *str = ':';
	if(*str == '%') *str = '/';
	if(*str == '^') *str = '/';
  }
}
/*
 * pidfile
 */
// create_pidfile,is_valid_pidfile  {{{{
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
//}}}}

/*
 * SHA1
 */
// l_crypt {{{{

void SHA1_digest(uint8_t *d, SHA_CTX *c) {
	SHA_CTX c1;
	c1 = *c;
	SHA1_Final(d,&c1);
}

#if 0
void print_hex(uint8_t *d,size_t len) {
  int i;
  for(i=0; i < len; i++) {
	uint8_t c = d[i] & 0xff;
	if(c >= ' ' && c < 127) 
		  fprintf(stderr,"%c",c);
		else
		  fprintf(stderr,"\\%02x",d[i] & 0xff);
  }
  fprintf(stderr,"\n");
}
#endif

int l_crypt(uint8_t *src, size_t len, uint32_t salt, uint8_t *key, size_t keylen) {
SHA_CTX c;
uint8_t hash[SHA_DIGEST_LENGTH];
int i,j;

if(!key || !*key || !keylen) return len;

SHA1_Init(&c);
SHA1_Update(&c,key,keylen);
SHA1_Update(&c,&salt,4);
//fprintf(stderr,"src: "); print_hex(src,len);
for(i=0,j=0; i < len; i++) {
	if(j == SHA_DIGEST_LENGTH) j = 0;
	if(!j) {
		if(i) SHA1_Update(&c,key,keylen);
		SHA1_digest(hash,&c);
	}
	src[i] ^= hash[j];
	j++;
}
//fprintf(stderr,"dst: "); print_hex(src,len);
return i;
}
//}}}}
/*
 * ipset functions
 */

enum ipset_type_id {
		UNKNOWN_IPSET,
		HASH_IP,
		HASH_MAC,
		HASH_NET,
		LAST_IPSET
} w_type_id = UNKNOWN_IPSET;

static char *known_settypes[] = {
		[HASH_IP] = "hash:ip",
		[HASH_MAC] = "hash:mac",
		[HASH_NET] = "hash:net",
};

static void print_known_settypes(void) {
	enum ipset_type_id t;
	fprintf(stderr,"Known types: ");
	for(t = UNKNOWN_IPSET; (int)t < ARRAY_LEN(known_settypes); t++) {
		if(known_settypes[t]) fprintf(stderr," %s",known_settypes[t]);
	}
	fprintf(stderr,"\n");
}

static int set_ip_type() {
	enum ipset_type_id t;
	for(t = UNKNOWN_IPSET; (int)t < ARRAY_LEN(known_settypes); t++) {
		if(known_settypes[t] && !strcasecmp(known_settypes[t],w_type)) {
			w_type_id = t;
			return 1;
		}
	}
	return 0;
}

// alloc_one_string add_to_list del_from_list {{{{
static one_string_t *alloc_one_string(const char *str,size_t len) {
    one_string_t *r;

    if(!str) return NULL;
    if(!len) len = strlen(str);
    if(!len) return NULL;

    r = (one_string_t *)malloc(sizeof(one_string_t)+len+1);
    if(!r) return r;
    r->next = NULL;
    r->len = len;
	r->x = 0;
    memcpy(r->data,str,len+1);
    return r;
}

void add_to_list(char *str) {
	one_string_t *t;
	one_string_t *r;

	for(t = LIST; t; t = t->next) {
		if(!strcmp(str,t->data)) {
			if(!t->x) fprintf(stderr,"Add: string '%s' exist\n",str);
			t->x = 0;
			return;
		}
	}

	r = alloc_one_string(str,0);
	if(!r) return;
	r->next = LIST;
	LIST = r;
}

void del_from_list(char *str) {
	one_string_t *t,*p;
	for(p = NULL,t = LIST; t; t = t->next) {
		if(!strcmp(str,t->data)) {
			if(!p) {
				LIST = t->next;
			} else {
				p->next = t->next;
			}
			free(t);
			return;
		}
		p = t;
	}
	fprintf(stderr,"Delete: string '%s' not exist\n",str);
}
// }}}}

static int valid_ipv4(struct sockaddr_in *a) {
	uint32_t i = htonl(a->sin_addr.s_addr);
	if((i & 0xF0000000ul) == 0xF0000000ul) {
		fprintf(stderr,"Can't use reserved address\n");
		return 0;
	}
	if((i & 0xF0000000ul) == 0xE0000000ul) {
		fprintf(stderr,"Can't use multicast address\n");
		return 0;
	}
	if((i & 0xFF000000ul) == 0x0ul) {
		fprintf(stderr,"Can't use network 0.0.0.0/8\n");
		return 0;
	}
	return 1;
}

int net_config(char *fc) {
struct sockaddr_in *sa;
char cbuf[256],*cmd,*arg1;
int i;

	FILE *f = fopen(fc,"r");
	if(!f) {
		perror("open:");
		exit(1);
	}

	while(fgets(cbuf,sizeof(cbuf)-1,f)) {
		if(cbuf[0] == '#') continue;
		if(cbuf[0] == '\n') continue;
		cmd = strchr(cbuf,'\n');
		if(cmd) *cmd = '\0';
		cmd = strtok(cbuf," \t");
		if(!cmd) {
			fprintf(stderr,"Invalid config string '%s'\n",cbuf);
			exit(1);
		}
		arg1 = strtok(NULL," \t");
		if(!arg1) {
			fprintf(stderr,"Invalid config string '%s'\n",cmd);
			exit(1);
		}
		if(!strcmp(cmd,"key:")) {
			if(CFG.key[0]) {
				fprintf(stderr,"Double key\n");
				exit(1);
			}
			strncpy(CFG.key,arg1,sizeof(CFG.key)-1);
			CFG.key_len = strlen(CFG.key);
			continue;
		}
		if(!strcmp(cmd,"port:")) {
			if(CFG.port) {
				fprintf(stderr,"Double port\n");
				exit(1);
			}
			CFG.port = strtoul(arg1,NULL,0);
			if(!CFG.port || CFG.port > 65535) {
				fprintf(stderr,"Bad port! port: 1..65535\n");
				exit(1);
			}
			CFG.port = htons(CFG.port);
			continue;
		}
		if(!strcmp(cmd,"ping:")) {
			if(CFG.ping) {
				fprintf(stderr,"Double ping\n");
				exit(1);
			}
			CFG.ping = strtoul(arg1,NULL,0);
			if(!CFG.ping || CFG.ping > 600) {
				fprintf(stderr,"Bad ping! ping: 1..600\n");
				exit(1);
			}
			continue;
		}
		if(!strcmp(cmd,"peer:") || !strcmp(cmd,"master:")) {
			struct peer *P;
			char *arg2;
			if(CFG.n_peer >= 16) {
				fprintf(stderr,"Too many peers\n");
				exit(1);
			}
			arg2 = strtok(NULL," \t");
			P = &CFG.peers[CFG.n_peer];
			if(!inet_pton(AF_INET,arg1,&P->pa.sin_addr)) {
				fprintf(stderr,"Bad peer ipv4 %s\n",arg1);
				exit(1);
			}
			if(!valid_ipv4(&P->pa)) {
				exit(1);
			}
			P->pa.sin_family = AF_INET;
			P->pa.sin_port = CFG.port;
			if(!strcmp(cmd,"master:")) {
				P->master = 1;
				CFG.n_master++;
			}
			P->seq = 0;
			P->ssock = -1;
			if(arg2) {
				if(!inet_pton(AF_INET,arg2,&P->la.sin_addr)) {
					fprintf(stderr,"Bad local peer ipv4 %s\n",arg2);
					exit(1);
				}
				P->ssock = -2;
			}
			CFG.n_peer++;
			continue;
		}
		if(!strcmp(cmd,"list:")) {
			if(CFG.n_list >= 16) {
				fprintf(stderr,"Too many list\n");
				exit(1);
			}
			sa = &CFG.list[CFG.n_list];
			bzero((char *)sa,sizeof(CFG.list[0]));
			if(!inet_pton(AF_INET,arg1,&sa->sin_addr)) {
				fprintf(stderr,"Bad list ipv4 address %s\n",arg1);
				exit(1);
			}
			if(!valid_ipv4(sa)) {
				exit(1);
			}
			sa->sin_family = AF_INET;
			sa->sin_port = CFG.port;
			CFG.n_list++;
			continue;
		}

		fprintf(stderr,"Bad config option: '%s'\n",cmd);
		exit(1);
	}
	fclose(f);

	if(!CFG.ping) CFG.ping=10;
	if(!CFG.port) {
			fprintf(stderr,"Error: missing port\n");
			exit(1);
	}

	for(i=0; i < CFG.n_list; i++) {
		int sock = socket(PF_INET,SOCK_DGRAM,0);
		if(sock < 0) {
				perror("socket");
				exit(1);
		}
		sa = &CFG.list[i];
		if(bind(sock,(struct sockaddr *)sa,sizeof(*sa))) {
		   perror("BIND"); exit(1);
	    }
		CFG.fds[i+1].fd = sock;
		CFG.fds[i+1].events = POLLIN | POLLERR | POLLHUP | POLLNVAL;
	}
	for(i=0; i < CFG.n_peer; i++) {
		if(CFG.n_list == 0) {
			fprintf(stderr,"Error: no listen address\n");
			exit(1);
		}
		if(CFG.peers[i].ssock != -2) {
			CFG.peers[i].ssock = CFG.fds[1].fd;
		} else {
			int j;
			struct sockaddr_in *la = &CFG.peers[i].la;
			for(j=0; j < CFG.n_list; j++) {
				sa = &CFG.list[j];
				if(!memcmp((char *)&sa->sin_addr,(char *)&la->sin_addr,sizeof(sa->sin_addr))) {
					CFG.peers[i].ssock = CFG.fds[j+1].fd;
				}
			}
			if(CFG.peers[i].ssock < 0) {
				fprintf(stderr,"Error: local address %s not found\n",inet_ntoa(la->sin_addr));
				exit(1);
			}
		}
	}

return 0;
}

static char *net_buf = NULL;

void send_all(int fd,struct sockaddr_in *sa, time_t ct) {
	char *buf = net_buf;
	int p,max=65536-16;
	one_string_t *t;
	
	*(time_t *)&buf[0] = ct;
	memcpy(&buf[4],"ALL ",4);
	*(uint32_t *)&buf[8] = 0;
	p = 12;
	for(t = LIST; t; t = t->next) {
		if(p + t->len+1 >= max) break;
		memcpy(&buf[p],t->data,t->len+1);
		p += t->len+1;
	}
	l_crypt((uint8_t*)(net_buf+4),p-4,ct,(uint8_t *)CFG.key,CFG.key_len);
	sendto(fd,net_buf,p,0,(struct sockaddr *)sa,sizeof(*sa));
}

void send_diff(char *str,int del) {
	char *buf = net_buf;
	struct sockaddr_in *sa;
	int i,p,l;

	time_t tm = time(NULL);
	l = strlen(str)+1;

	for(i = 0; i < CFG.n_peer; i++) {
		if(CFG.peers[i].ptime < tm - (CFG.ping*5)/2) continue;

		*(time_t *)&buf[0] = tm;
		memcpy(&buf[4],"EVNT",4);
		*(uint32_t *)&buf[8] = ++CFG.peers[i].seq;
		p = 12;
		buf[p++] = del ? '-':'+';
		memcpy(&buf[p],str,l);
		p += l;
		sa = &CFG.peers[i].pa;
		l_crypt((uint8_t *)(net_buf+4),p-4,tm,(uint8_t *)CFG.key,CFG.key_len);
		if(debug)
		  fprintf(stderr,"Send peer %d: %s %s\n", i,
						  del ? "DEL":"ADD", str);
		sendto(CFG.peers[i].psock,net_buf,p,0,
						(struct sockaddr *)sa,sizeof(struct sockaddr_in));
	}
}

static void mark_all(void) {
	one_string_t *t;
	for(t=LIST; t; t = t->next) {
		if(debug)
			fprintf(stderr,"Mark '%s'\n",&t->data[0]);
		t->x = 1;
	}
}

static void delete_marked(void) {
	one_string_t *t,*p;
	p = NULL;
	t = LIST;
	while( t ) {
		if(t->x) {
			if(debug)
				fprintf(stderr,"Delete '%s'\n",&t->data[0]);
			event_handler(&t->data[0],2);
			if(p) {
				p->next = t->next;
				free(t);
				t = p->next;
				continue;
			} else {
				LIST = t->next;
				free(t);
				t = LIST;
				continue;
			}
		}
		p = t;
		t = t->next;
	}
}

static void recv_all(char *buf,int len) {
	int p,l;
	int max = 65536-16;
	if(len < 12) {
			return;
	}
	p = 12;
	mark_all();
	while(p < max && p < len) {
		l = strlen(&buf[p]);
		if(!l || p+l > len) break;
		if(debug)
			fprintf(stderr,"ADD %s\n",&buf[p]);
		event_handler(&buf[p],0);
		p += l+1;
	}
	delete_marked();
}

static void recv_diff(char *buf,int len,int peer) {
	int p,l;
	int max = 65536-16;
	if(len < 12) {
		return;
	}
	p = 12;
	while(p < max && p < len) {
		l = strlen(&buf[p]);
		if(!l) break;
		if(debug)
		  fprintf(stderr,"%s %s\n", buf[p] == '-' ? "DEL":"ADD",
						&buf[p+1]);
		event_handler(&buf[p+1],buf[p] == '-');
		p += l+1;
	}
}

static void net_event(int i) {
	char buf[512];
	struct sockaddr_in ra;
	struct sockaddr_in *sa;
	int l,n;
	uint32_t ct;
	socklen_t ral;

	if(0 && debug)
		fprintf(stderr,"Listen:%d event:%x\n",i-1,CFG.fds[i].revents);

	if(CFG.fds[i].revents & POLLIN) {
		ral = sizeof(ra);
		l=recvfrom(CFG.fds[i].fd,buf,sizeof(buf),0,(struct sockaddr *)&ra,&ral);
		if(l < 0) { perror("recv"); return;}
		for(n = 0; n < CFG.n_peer; n++) {
			sa = &CFG.peers[n].pa;
			if(!memcmp((char *)&sa->sin_addr,(char *)&ra.sin_addr,sizeof(ra.sin_addr))) {
				CFG.peers[n].psock = CFG.fds[i].fd;
				break;
			}
		}
		if(debug && 0)
			fprintf(stderr,"from %s:%d peer:%d len:%d\n",
							inet_ntoa(ra.sin_addr),htons(ra.sin_port),n,l);
		if(n >= CFG.n_peer) {
			fprintf(stderr,"Unknown peer\n");
			return;
		}
		if(l < 12) return;
		ct = *(uint32_t *)&buf[0];
		l_crypt((uint8_t*)&buf[4],l-4,ct,(uint8_t *)CFG.key,CFG.key_len);

		if(CFG.n_master == 0) {
			if(l == 12) {
				if(!strncmp(&buf[4],"INIT",4)) {
					fprintf(stderr,"Peer %d: INIT!\n",n);
					send_all(CFG.fds[i].fd,&ra,ct-3);
					CFG.peers[n].seq = 1;
				}
				if(!strncmp(&buf[4],"PING",4)) {
					uint32_t rseq = *(uint32_t *)&buf[8];
					fprintf(stderr,"Peer %d: PING seq %u\n",n,rseq);
					strncpy(&buf[4],"PONG",4);
					ct -= 3;
					*(uint32_t *)&buf[0] = ct;
					*(uint32_t *)&buf[8] = ++CFG.peers[n].seq;
					l_crypt((uint8_t *)&buf[4],l-4,ct,(uint8_t *)CFG.key,CFG.key_len);
					sendto(CFG.fds[i].fd,buf,l,0,(struct sockaddr *)&ra,ral);
				}
				CFG.peers[n].ptime = time(NULL);
				CFG.peers[n].ssock = CFG.fds[i].fd;
			}
		} else {
			uint32_t rseq = *(uint32_t *)&buf[8];
			if(!memcmp(&buf[4],"ALL ",4)) {
				fprintf(stderr,"Peer %d: ALL info\n",n);
				recv_all(buf,l);	
				if(CFG.peers[n].master == 1) CFG.peers[n].master = 2;
				CFG.peers[n].seq = 1;
			}
			if(!memcmp(&buf[4],"PONG",4)) {
				if(CFG.peers[n].seq != rseq) {
					CFG.peers[n].master = 1;
					last_wakeup = 0;
					fprintf(stderr,"Peer %d: PONG! seq %u:%u BAD! reINIT\n",n,rseq,CFG.peers[n].seq);
					CFG.peers[n].seq = 0;
				} else
					fprintf(stderr,"Peer %d: PONG! seq %u OK\n",n,rseq);
			}
			if(!memcmp(&buf[4],"EVNT",4)) {
				fprintf(stderr,"Peer %d: EVNT! seq %u:%u\n",n,rseq,CFG.peers[n].seq);
				if(CFG.peers[n].seq+1 != rseq) {
					CFG.peers[n].master = 1;
					last_wakeup = 0;
				} else {
					recv_diff(buf,l,n);
					CFG.peers[n].seq++;
				}
			}
		}
	} else {
		fprintf(stderr,"event %x\n",CFG.fds[i].revents);
	}

	CFG.fds[i].revents = 0;
}

static void net_wakeup_master() {
	char sbuf[64];
	struct sockaddr_in *sa;
	int i;
	time_t tm = time(NULL);
	if(last_wakeup && tm - last_wakeup < CFG.ping) return;
	last_wakeup = tm;

	if(CFG.n_list <= 1) return;

	for(i=0; i < CFG.n_peer; i++) {
		if(!CFG.peers[i].master) continue;
		sa = &CFG.peers[i].pa;
		*(time_t *)&sbuf[0] = tm;
		if(CFG.peers[i].master == 1) {
			if(debug)
				fprintf(stderr,"Master:%s send INIT\n",inet_ntoa(sa->sin_addr));
			strcpy(&sbuf[4],"INIT");
			*(uint32_t *)&sbuf[8] = CFG.peers[i].seq; // 0
			l_crypt((uint8_t *)&sbuf[4],8,tm,(uint8_t *)CFG.key,CFG.key_len);
			sendto(CFG.peers[i].ssock,sbuf,12,0,(struct sockaddr *)sa,sizeof(*sa));
		} else {
			if(debug)
				fprintf(stderr,"Master:%s send PING seq %u\n",inet_ntoa(sa->sin_addr),CFG.peers[i].seq+1);
			strcpy(&sbuf[4],"PING");

			*(uint32_t *)&sbuf[8] = ++CFG.peers[i].seq; // > 0
			l_crypt((uint8_t *)&sbuf[4],8,tm,(uint8_t *)CFG.key,CFG.key_len);
			sendto(CFG.peers[i].ssock,sbuf,12,0,(struct sockaddr *)sa,sizeof(*sa));
		}
	}
}

static int event_handler(char *f_name,int del) {
  char a_buf[64];
  int e;
  int ret = 0;
	strncpy(a_buf,f_name,sizeof(a_buf)-1);
	fix_char(a_buf);
	if(!ipset_validate(session,w_set,a_buf)) {
		if(debug)
			fprintf(stderr,"Invalid address %s\n",a_buf);
		return ret;
	}
	e = ipset_test(session,w_set,a_buf);
	if(del) {
		if(e) {
			if(!ipset_del(session,w_set,a_buf))
				fprintf(stderr,"%s del err\n", a_buf);
			else { if(debug)
				fprintf(stderr,"%s deleted\n", a_buf);
				if(CFG.n_master == 0)
						send_diff(a_buf,1);
				ret = 1;
			}
		} else if (debug) fprintf(stderr,"%s not exist\n", a_buf);
		if(del == 1)
				del_from_list(a_buf);
	} else {
		if(!e) {
			if(!ipset_add(session,w_set,a_buf))
				fprintf(stderr,"%s add err\n", a_buf);
			else { if(debug)
				fprintf(stderr,"%s added\n", a_buf);
				if(CFG.n_master == 0)
						send_diff(a_buf,0);
				ret = 1;
			}
		} else if (debug) fprintf(stderr,"%s exist\n", a_buf);
		add_to_list(a_buf);
	}
	return ret;
}

static int is_file(char *file,char *dir) {
struct stat st;
char full_name[512];
char slash = dir && *dir ? dir[strlen(dir)-1] != '/': 0;

snprintf(full_name,sizeof(full_name)-1,"%s%s%s",dir && *dir ? dir:"", slash ? "/":"",file);
if(stat(full_name,&st) < 0) return 0;
return  S_ISREG(st.st_mode);
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
ipset_session_restart(&session);
}

static void reread_w_dirs(void) {
int i;
ipset_flush(session,w_set);
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
fprintf(stderr,"%s [-d] [-F] [-f] [-p pidfile] [-t ipset_type] [-c netconfig ] -s ipset_name dir [dir ...]\n","ipsetdir");
fprintf(stderr," -d - debug\n -F - no daemonize\n -f - flush set on exit\n"
		" -p pidfile - use PID file. Default: /run/ipset_dir_<setname>.pid\n"
		" -s ipset_name - ipset name\n"
		" -t ipset_type - type of ipset. default hash:ip\n    "
		);
print_known_settypes();
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
char *fconfig = NULL;
int i,fd,wd,len,c;
int set_flush = 0, dodaemon = 1;
int del;
char est[128];

	bzero((char *)&CFG,sizeof(CFG));
	ipset_load_types();
#if IPSET_PROTOCOL == 7
	session = ipset_session_init(NULL,NULL);
#else
	session = ipset_session_init(printf);
#endif

	if(!session) {
		fprintf(stderr,"Initialize ipset library failed.\n");
		exit(1);
	}
	while((c=getopt(argc,argv,"dFp:s:t:c:")) != -1) {
	switch(c) {
	  case 'd': debug++; break;
	  case 'f': set_flush = 1; break;
	  case 'F': dodaemon = 0; break;
	  case 'p': strncpy(pid_file,optarg,sizeof(pid_file)-1); break;
	  case 's': w_set = strdup(optarg); break;
	  case 't': w_type = strdup(optarg); break;
	  case 'c': fconfig = strdup(optarg); break;
	  default: help();
	}
	}

	if(fconfig) {
		if(net_config(fconfig)) {
			fprintf(stderr,"Bad network configuration\n");
			exit(1);
		}
	}
	net_buf = malloc(65536-16);
	if(!net_buf) {
			perror("malloc net_buf");
			exit(1);
	}
	if(!w_set || !argv[optind]) 
		help();
	
	if(!pid_file[0])
		snprintf(pid_file,sizeof(pid_file)-1,"/run/ipset_dir_%s.pid",w_set);

	if(is_valid_pidfile(pid_file)) {
		fprintf(stderr,"Found valid PID file %s\n",pid_file);
		exit(1);
	}
	if(!set_ip_type()) {
		fprintf(stderr,"Unknown type '%s'\n",w_type);
		print_known_settypes();
		exit(1);
	}
	if(!ipset_exist(session,w_set,est,sizeof(est)-1))
		ipset_create(session,w_set,w_type,NULL,0);
	else if(strcmp(est,w_type)) {
		fprintf(stderr,"ipset %s have type %s != %s\n",w_set,est,w_type);
		exit(1);
	}

	ipset_flush(session,w_set);

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

	CFG.fds[0].fd = fd;
	CFG.fds[0].events = POLLIN | POLLOUT | POLLERR | POLLHUP | POLLNVAL;
	CFG.n_list++;

	if(!CFG.n_master && !CFG.n_peer) CFG.ping = 600;

	while(work) {
		if(CFG.n_master) {
			net_wakeup_master();
		}
		len = poll(CFG.fds, CFG.n_list, CFG.ping*1000);
		if(!len) continue;
		if(len < 0 && errno == EINTR) {
			if(debug) fprintf(stderr,"EINTR\n");
			continue;
		}
		if(CFG.fds[0].revents) {
				len = read(fd,event_buff,sizeof(event_buff));
				if(len < 0 && errno == EINTR) {
					if(debug) fprintf(stderr,"EINTR\n");
					continue;
				}
				if(len < 0) break;
				if(len < EVENT_SIZE) break;
//				if(debug) fprintf(stderr,"Read %d from events FD\n",len);

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
		for(i=1; i < CFG.n_list; i++) {
			if(!CFG.fds[i].revents) continue;
			net_event(i);
		}
	}
	if(set_flush)
		ipset_flush(session,w_set);
	if(pid_file_ok)
		unlink(pid_file);
	if(debug)
		fprintf(stderr,"Exit\n");
	exit(0);
}


/*
 * vim: set ts=4:foldmethod=marker:foldmarker={{{{,}}}}:
 */
