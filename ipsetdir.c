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
int   w_dir_last = 0;

char pid_file[256]="";
int pid_file_ok = 0;
int init_set = 0;
char *w_dir = NULL, *w_set = NULL, *w_type="hash:ip";

struct ipset_session *session = NULL;

static volatile int work = 1;
static int debug = 0;
#define DBG_CFG		0x1
#define DBG_IPSET	0x2
#define DBG_NET		0x4
#define DBG_SYNC	0x8
#define DBG_INO		0x10
#define DBG_NET2	0x20

static int net_buf_size = 4000; // must be > 1024
static char *net_buf = NULL;
static volatile int restarted = 0;

#define MAX_SEQ_NUM 64
#define N_PEERS 8
#define N_LIST 8

struct peer {
		struct sockaddr_in	pa;
		struct sockaddr_in	la;
		int					psock;
		int					ssock;
		time_t				ptime;
		int					master; // 2 - All data received, 1 - wait events
		int					seq; // 0 - init state
		char				key[32];
		int					key_len;
		uint32_t			port;
};

struct app_cfg {
		int					ping;
		struct sockaddr_in	list[N_LIST];
		struct pollfd		fds[N_LIST+1];
		int					n_list;
		int					n_peer;
		int					n_master;
		struct peer			peers[N_PEERS];
		char				key[32];
		int					key_len;
		uint32_t			port;
} CFG;

struct one_string {
    struct one_string 	   *next;
    size_t			 		len; // length of origin string
    char					old; // for compare
	char					data[0];
};

typedef struct one_string one_string_t ;

one_string_t LIST = { .next = NULL, .len = 0 };

#define OP_ADD 0
#define OP_DEL 1
#define DO_IPSET 1
#define NO_IPSET 0
static int ipset_op(char *f_name,int op);

static inline int is_master(void) {
		return CFG.n_master == 0 && CFG.n_peer;
}
static inline int is_peer(void) {
		return CFG.n_master;
}

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
	r->old = 0;
    memcpy(r->data,str,len+1);
    return r;
}

int add_to_list(char *str) {
	one_string_t *t;
	one_string_t *r;

	for(t = LIST.next; t; t = t->next) {
		if(!strcmp(str,t->data)) {
			if(!t->old) fprintf(stderr,"Add: string '%s' exist\n",str);
			t->old = 0;
			return 0;
		}
	}

	r = alloc_one_string(str,0);
	if(!r) return 0;
	r->next = LIST.next;
	LIST.next = r;
	return 1;
}

void del_from_list(char *str) {
	one_string_t *t,*p;
	for(p = &LIST,t = LIST.next; t; p = t, t = t->next) {
		if(!strcmp(str,t->data)) {
			p->next = t->next;
			free(t);
			return;
		}
	}
	fprintf(stderr,"Delete: string '%s' not exist\n",str);
}
// }}}}

// valid_ipv4() , parse_ipv4_port() {{{{
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

static void parse_ipv4_port(char *arg1,struct sockaddr_in *sa,int port) {
	char *pp;
	int pport;

		bzero((char *)sa,sizeof(*sa));
		pp = strchr(arg1,':');
		if(pp) *pp = 0;
		if(!inet_pton(AF_INET,arg1,&sa->sin_addr)) {
			fprintf(stderr,"Bad peer ipv4 %s\n",arg1);
			exit(1);
		}
		if(!valid_ipv4(sa)) {
			fprintf(stderr,"invalid ipv4 %s\n",arg1);
			exit(1);
		}
		pport = port;
		if(pp) {
			pport = strtol(pp+1,NULL,10);
			if(pport < 1 || pport > 0xffff) {
				fprintf(stderr,"invalid port %s for %s\n",pp+1,arg1);
				exit(1);
			}
			pport = htons(pport);
		}
		sa->sin_family = AF_INET;
		sa->sin_port = pport;
		if(pp) *pp = ':';
		if(debug & DBG_CFG) fprintf(stderr,"%s: string %s host %s port %u\n",__func__,
						arg1,inet_ntoa(sa->sin_addr),htons(sa->sin_port));

}
// }}}}

static int all_listen_have_port(void) {
    int no_port = 0,i;
    for(i=0; i < CFG.n_list; i++) {
        if(!CFG.list[i].sin_port) no_port++;
	}
	return no_port == 0;
}

static void fix_ports(void) {
	int i;
    for(i=0; i < CFG.n_list; i++) {
        if(!CFG.list[i].sin_port) {
			if(!CFG.port) {
				fprintf(stderr,"port undefined\n");
				exit(1);
			}
			CFG.list[i].sin_port = CFG.port;
		}
	}
    for(i=0; i < CFG.n_peer; i++) {
        if(!CFG.peers[i].pa.sin_port) {
			if(!CFG.port) {
				fprintf(stderr,"port undefined\n");
				exit(1);
			}
			CFG.peers[i].pa.sin_port = CFG.port;
		}

		if(!CFG.peers[i].la.sin_family) {
			CFG.peers[i].la = CFG.list[0];
			if(CFG.n_list > 1) {
				fprintf(stderr,"Warning: set local address %s:%d ",inet_ntoa(CFG.peers[i].la.sin_addr),
								htons(CFG.peers[i].la.sin_port));
				fprintf(stderr,"for peer %s:%d\n",inet_ntoa(CFG.peers[i].pa.sin_addr),
								htons(CFG.peers[i].pa.sin_port));
			}
		}
	}
}

static void fix_keys(void) {
	int i;
    for(i=0; i < CFG.n_peer; i++) {
        if(!CFG.peers[i].key_len) {
			CFG.peers[i].key_len  = CFG.key_len;
			strncpy(CFG.peers[i].key,CFG.key,sizeof(CFG.peers[0].key)-1);
		}
	}
}
static int find_listen(struct sockaddr_in *la) {
	int j;
	struct sockaddr_in *sa;

	for(j=0; j < CFG.n_list; j++) {
		sa = &CFG.list[j];
		if(!memcmp((char *)&sa->sin_addr,(char *)&la->sin_addr,sizeof(sa->sin_addr))) {
			return j;
		}
	}
	return -1;
}
static void add_listen(char *arg1) {
	struct sockaddr_in ta;

	bzero((char *)&ta,sizeof(ta));
	parse_ipv4_port(arg1,&ta,CFG.port);

	if(find_listen(&ta) >= 0) return;

	if(CFG.n_list >= N_LIST) {
		fprintf(stderr,"Too many list\n");
		exit(1);
	}
	CFG.list[CFG.n_list] = ta;;
	CFG.n_list++;
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
			struct sockaddr_in ta;

			if(CFG.n_peer >= N_PEERS) {
				fprintf(stderr,"Too many peers\n");
				exit(1);
			}
			P = &CFG.peers[CFG.n_peer];
			P->seq = 0;
			P->ssock = -1;

			parse_ipv4_port(arg1,&ta,CFG.port);
			for(i=0; i < CFG.n_peer; i++) {
				if(ta.sin_addr.s_addr == CFG.peers[i].pa.sin_addr.s_addr &&
					ta.sin_port == CFG.peers[i].pa.sin_port) break;
			}
			if(i < CFG.n_peer) {
				fprintf(stderr,"dup master/peer %s\n",arg1);
				continue;
			}
			P->pa = ta;

			while((arg2 = strtok(NULL," \t")) != NULL) {
				if(!strncmp(arg2,"local:",6)) {
					arg2 += 6;
					parse_ipv4_port(arg2,&P->la,CFG.port);
					add_listen(arg2);
				} else if(!strncmp(arg2,"key:",4)) {
					arg2 += 4;
					strncpy(P->key,arg2,sizeof(P->key)-1);
					P->key_len = strlen(P->key);
				} else {		
					fprintf(stderr,"%s unknown\n",arg2);
					exit(1);
				}
			}

			if(!strcmp(cmd,"master:")) {
				P->master = 1;
				CFG.n_master++;
			}
			CFG.n_peer++;
			continue;
		}
		if(!strcmp(cmd,"listen:")) {
			add_listen(arg1);
			continue;
		}

		fprintf(stderr,"Bad config option: '%s'\n",cmd);
		exit(1);
	}
	fclose(f);

	if(!CFG.ping) CFG.ping=10;
	if(!all_listen_have_port() && !CFG.port) {
			fprintf(stderr,"Error: missing port\n");
			exit(1);
	}
	fix_ports();
	if(!CFG.n_list && CFG.n_peer) {
			fprintf(stderr,"Error: missing listen for master/peer\n");
			exit(1);
	}
	if(CFG.n_list && !CFG.n_peer && !CFG.n_master) {
			fprintf(stderr,"Error: missing master: or peer:\n");
			exit(1);
	}
	if(CFG.n_peer && CFG.n_master > 0 && CFG.n_master != CFG.n_peer) {
			fprintf(stderr,"Error: cant master and peer!\n");
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
	fix_keys();
	for(i=0; i < CFG.n_peer; i++) {
		int j;
		struct sockaddr_in *la = &CFG.peers[i].la;

		if(!la->sin_family)
			*la = CFG.list[0];

		for(j=0; j < CFG.n_list; j++) {
			sa = &CFG.list[j];
			if(!memcmp((char *)&sa->sin_addr,(char *)&la->sin_addr,sizeof(sa->sin_addr))) {
				CFG.peers[i].ssock = CFG.fds[j+1].fd;
			}
		}
		if(CFG.peers[i].ssock < 0) {
			fprintf(stderr,"Error: local address %s not listen\n",inet_ntoa(la->sin_addr));
			exit(1);
		}
	}

return 0;
}

static void dump_peers(void) {
	int i;
	for(i=0; i < CFG.n_peer; i++) {
		struct sockaddr_in *la = &CFG.peers[i].pa;

		fprintf(stderr,"Peer[%d]: %s:%d ",i, inet_ntoa(la->sin_addr),htons(la->sin_port));
		la = &CFG.peers[i].la;
		fprintf(stderr,"local: %s:%d key:%s\n",
						inet_ntoa(la->sin_addr),htons(la->sin_port),CFG.peers[i].key);
	}
}
static uint32_t csum(const uint8_t *buf,size_t len) {
	uint32_t r=0;
	int i;
	for(i=0; i < len; i++) {
//		fprintf(stderr,"%c",buf[i] >= ' ' && buf[i] < 128 ? buf[i]:'?');
		r += (uint32_t)buf[i];
	}
//	fprintf(stderr,"=%08x\n",r);
	return r;
}

void send_all(int fd,struct sockaddr_in *sa, time_t ct, char *key, size_t key_len) {
	char *buf = net_buf;
	int p,max = net_buf_size,seg = 0;
	one_string_t *t;

	*(time_t *)&buf[0] = ct;
	memcpy(&buf[8],"ALL ",4);
	*(uint32_t *)&buf[12] = 1;
	p = 16;
	for(t = LIST.next; t; t = t->next) {
		if(p + t->len+1 >= max) {
			memcpy(&buf[8],"ALL",3);
			buf[11] = seg ? '1':'0';
			*(uint32_t *)&buf[12] = 1;
			*(uint32_t *)&buf[4] = csum((uint8_t*)(buf+8),p-8);
			l_crypt((uint8_t*)(buf+8),p-8,ct,(uint8_t *)key,key_len);
			sendto(fd,buf,p,0,(struct sockaddr *)sa,sizeof(*sa));
			fprintf(stderr,"ALL0 %d\n",p);
			p = 16;
			*(time_t *)&buf[0] = ct;
			memcpy(&buf[8],"ALL2",4);
			*(uint32_t *)&buf[12] = 1;
			seg++;
		}
		memcpy(&buf[p],t->data,t->len+1);
		p += t->len+1;
	}
	*(uint32_t *)&buf[4] = csum((uint8_t*)(buf+8),p-8);
	fprintf(stderr,"%4.4s %d\n",&buf[8],p);
	l_crypt((uint8_t*)(buf+8),p-8,ct,(uint8_t *)key,key_len);
	sendto(fd,buf,p,0,(struct sockaddr *)sa,sizeof(*sa));
}

void send_diff(char *str,int op) {
	char *buf = net_buf;
	struct sockaddr_in *sa;
	int i,p,l;

	time_t tm = time(NULL);
	l = strlen(str)+1;

	for(i = 0; i < CFG.n_peer; i++) {
		if(CFG.peers[i].ptime < tm - (CFG.ping*5)/2) continue;

		*(time_t *)&buf[0] = tm;
		memcpy(&buf[8],"EVNT",4);
		*(uint32_t *)&buf[12] = ++CFG.peers[i].seq;
		p = 16;
		buf[p++] = op == OP_DEL ? '-':'+';
		memcpy(&buf[p],str,l);
		p += l;
		sa = &CFG.peers[i].pa;
		*(uint32_t *)&buf[4] = csum((uint8_t*)(buf+8),p-8);
		l_crypt((uint8_t *)(buf+8),p-8,tm,(uint8_t *)CFG.peers[i].key,CFG.peers[i].key_len);
		if(debug & DBG_NET)
			fprintf(stderr,"Send peer %d: %s %s\n", i, op == OP_DEL ? "DEL":"ADD", str);
		sendto(CFG.peers[i].psock,buf,p,0,
						(struct sockaddr *)sa,sizeof(struct sockaddr_in));
	}
}

static void mark_old(void) {
	one_string_t *t;
	for(t=LIST.next; t; t = t->next) {
		if(debug & 0) fprintf(stderr,"Mark '%s'\n",&t->data[0]);
		t->old = 1;
	}
}

static void delete_old(int do_ipset) {
	one_string_t *t,*p;
	for(t = LIST.next,p = &LIST; t; ) {
		if(t->old) {
			if(debug & DBG_SYNC)
				fprintf(stderr,"Delete old '%s'\n",&t->data[0]);
			if(do_ipset == DO_IPSET) 
				ipset_op(&t->data[0],OP_DEL);
			p->next = t->next;
			free(t);
			t = p->next;
		} else {
			p = t;
			t = t->next;
		}
	}
}

static void reload_ipset_list(char *wset) {
	char *l1,*ld;
	int xl = strlen(w_set)+1;
	ipset_list(&session,w_set,1);
	mark_old();
	l1 = strtok(ipset_list_mem_data,"\n");
	while((ld = strtok(NULL,"\n")) != NULL) {
		l1 = strstr(ld,w_set);
		if(l1) {
			l1 += xl;
			add_to_list(l1);
		}
	}
	if(ipset_list_mem_data) {
		free(ipset_list_mem_data);
		ipset_list_mem_data = NULL;
	}
	delete_old(NO_IPSET);
}

static void recv_all(char *buf,int len,int start,int end) {
	int p,l;
	int max = net_buf_size;
	if(len < 16) {
			return;
	}
	p = 16;
	if(start)
		mark_old();
	while(p < max && p < len) {
		l = strlen(&buf[p]);
		if(!l || p+l > len) break;
		if(debug & DBG_SYNC)
			fprintf(stderr,"ADD %s\n",&buf[p]);
		if(ipset_op(&buf[p],OP_ADD))
			add_to_list(&buf[p]);
		p += l+1;
	}
	if(end)
		delete_old(DO_IPSET);
}

static void recv_diff(char *buf,int len,int peer) {
	int p,l;
	int max = net_buf_size;
	int op;

	if(len < 16)
		return;

	p = 16;
	while(p < max && p < len) {
		l = strlen(&buf[p]);
		if(!l) break;
		if(buf[p] == '-') {
			op = OP_DEL;
			p++;
			l--;
		} else if(buf[p] == '+') {
			op = OP_ADD;
			p++;
			l--;
		} else {
			op = OP_ADD;
		}
		if(debug & DBG_SYNC)
		  fprintf(stderr,"%s %s\n", op == OP_DEL ? "DEL":"ADD", &buf[p]);
		if(op == OP_DEL) {
			if(ipset_op(&buf[p],OP_DEL))
				del_from_list(&buf[p]);
		} else {
			if(ipset_op(&buf[p],OP_ADD))
				add_to_list(&buf[p]);
		}
		p += l+1;
	}
}

static void net_event(int i) {
	char *buf;
	struct sockaddr_in ra;
	struct sockaddr_in *sa;
	int l,n;
	uint32_t ct;
	uint32_t rseq;
	socklen_t ral;

	if(debug & DBG_NET)
		fprintf(stderr,"Listen:%d event:%x\n",i,CFG.fds[i].revents);

	ral = sizeof(ra);
	buf = net_buf;
	l=recvfrom(CFG.fds[i].fd,buf,net_buf_size,0,(struct sockaddr *)&ra,&ral);
	if(l < 0) { perror("recv"); return;}

	for(n = 0; n < CFG.n_peer; n++) {
		sa = &CFG.peers[n].pa;
		if(!memcmp((char *)&sa->sin_addr,(char *)&ra.sin_addr,sizeof(ra.sin_addr))) {
			CFG.peers[n].psock = CFG.fds[i].fd;
			break;
		}
	}
	if(debug & DBG_NET2)
		fprintf(stderr,"from %s:%d peer:%d len:%d\n",
						inet_ntoa(ra.sin_addr),htons(ra.sin_port),n,l);
	if(n >= CFG.n_peer) {
		if(debug & DBG_NET) fprintf(stderr,"Unknown peer\n");
		return;
	}
	if(l < 16) return;
	ct = *(uint32_t *)&buf[0];
	l_crypt((uint8_t*)&buf[8],l-8,ct,(uint8_t *)CFG.peers[n].key,CFG.peers[n].key_len);

	if(csum((uint8_t*)&buf[8],l-8) != *(uint32_t *)&buf[4]) {
		if(debug & DBG_NET) fprintf(stderr,"Bad csum! calc %08x != %08x\n",
						csum((uint8_t*)&buf[8],l-8), *(uint32_t *)&buf[4]);
		return;
	}

	rseq = *(uint32_t *)&buf[12];

	if(is_master()) {
		if(CFG.fds[i].fd != CFG.peers[n].ssock)
				if(debug & DBG_NET) fprintf(stderr,"Peer %d: socket fd %d != %d\n",n,
								CFG.fds[i].fd, CFG.peers[n].ssock);
		if(l == 16) {
			ct -= 3; // ?
			if(!strncmp(&buf[8],"INIT",4)) {
				if(debug & DBG_NET)
					fprintf(stderr,"Peer %d: INIT!\n",n);
				send_all(CFG.peers[n].ssock, &ra, ct, CFG.peers[n].key,CFG.peers[n].key_len);
				CFG.peers[n].seq = 1;
			} else
			if(!strncmp(&buf[8],"PING",4)) {
				if(debug & DBG_NET)
					fprintf(stderr,"Peer %d: PING seq %u:%u\n",n,rseq,CFG.peers[n].seq);
				if(rseq != CFG.peers[n].seq) {
					if(debug & DBG_NET)
						fprintf(stderr,"Peer %d: reINIT!\n",n);
					send_all(CFG.peers[n].ssock, &ra, ct, CFG.peers[n].key,CFG.peers[n].key_len);
					CFG.peers[n].seq = 1;
				} else {
					*(uint32_t *)&buf[0] = ct;
					memcpy(&buf[8],"PONG",4);
					*(uint32_t *)&buf[12] = ++CFG.peers[n].seq;
					*(uint32_t *)&buf[4] = csum((uint8_t*)(buf+8),l-8);
					l_crypt((uint8_t *)&buf[8],l-8,ct,(uint8_t *)CFG.peers[n].key,CFG.peers[n].key_len);
					sendto(CFG.peers[n].ssock, buf,l,0,(struct sockaddr *)&ra,ral);
				}
			} else {
				if(debug & DBG_NET) fprintf(stderr,"Unknown command\n");
				return;
			}
			CFG.peers[n].ptime = time(NULL);
			// CFG.peers[n].ssock = CFG.fds[i].fd;
		}
	} else { // peer
		if(!memcmp(&buf[8],"ALL",3)) {
			if(debug & DBG_NET)
				fprintf(stderr,"Peer %d: %4.4s info\n",n,&buf[8]);
			if(buf[11] == '0') {
				recv_all(buf,l,1,0);
			} else if(buf[11] == '1') {
				recv_all(buf,l,0,0);
			} else if(buf[11] == '2') {
				recv_all(buf,l,0,1);
			} else if(buf[11] == ' ') {
				recv_all(buf,l,1,1);
			}
			CFG.peers[n].seq = 1;
			CFG.peers[n].ptime = time(NULL);
		} else {
			if(CFG.peers[n].seq+1 != rseq) {
				if(debug & DBG_NET)
					fprintf(stderr,"Peer %d: %.4s seq %u:%u BAD! reINIT\n",
								n,&buf[4],rseq,CFG.peers[n].seq);
				CFG.peers[n].ptime = 0;
				CFG.peers[n].seq = 0;
				return;
			}
			if(!memcmp(&buf[8],"PONG",4)) {
				if(debug & DBG_NET) fprintf(stderr,"Peer %d: PONG! seq %u OK\n",n,rseq);
			} else if(!memcmp(&buf[8],"EVNT",4)) {
				if(debug & DBG_NET) fprintf(stderr,"Peer %d: EVNT! seq %u OK\n",n,rseq);
				recv_diff(buf,l,n);
			} else {
				if(debug & DBG_NET) fprintf(stderr,"Peer %d: unknown command!\n",n);
				return;
			}
			CFG.peers[n].seq++;
			CFG.peers[n].ptime = time(NULL);
		}
	}
}

static void net_wakeup_master() {
	char sbuf[64];
	struct sockaddr_in *sa;
	int i;
	time_t tm = time(NULL);

	if(!CFG.n_list) return;

	for(i=0; i < CFG.n_peer; i++) {
		if(!CFG.peers[i].master) continue; // ?

		if(CFG.peers[i].ptime && CFG.peers[i].ptime + CFG.ping > tm) continue;

		sa = &CFG.peers[i].pa;
		*(time_t *)&sbuf[0] = tm;
		if(CFG.peers[i].seq == 0 || CFG.peers[i].seq > MAX_SEQ_NUM) {
			if(debug & DBG_NET)
				fprintf(stderr,"Master:%s send INIT\n",inet_ntoa(sa->sin_addr));
			memcpy(&sbuf[8],"INIT",4);
			*(uint32_t *)&sbuf[12] = CFG.peers[i].seq; // 0
			*(uint32_t *)&sbuf[4] = csum((uint8_t*)(sbuf+8),8);
			l_crypt((uint8_t *)&sbuf[8],8,tm,(uint8_t *)CFG.peers[i].key,CFG.peers[i].key_len);
			sendto(CFG.peers[i].ssock,sbuf,16,0,(struct sockaddr *)sa,sizeof(*sa));
		} else {
			if(debug & DBG_NET)
				fprintf(stderr,"Master:%s send PING seq %u\n",inet_ntoa(sa->sin_addr),CFG.peers[i].seq);
			memcpy(&sbuf[8],"PING",4);

			*(uint32_t *)&sbuf[12] = CFG.peers[i].seq; // > 0
			*(uint32_t *)&sbuf[4] = csum((uint8_t*)(sbuf+8),8);
			l_crypt((uint8_t *)&sbuf[8],8,tm,(uint8_t *)CFG.peers[i].key,CFG.peers[i].key_len);
			sendto(CFG.peers[i].ssock,sbuf,16,0,(struct sockaddr *)sa,sizeof(*sa));
		}
	}
}

static int ipset_op(char *f_name, int op) {
  char a_buf[64];
  int e;
  int ret = 0;
	strncpy(a_buf,f_name,sizeof(a_buf)-1);
	fix_char(a_buf);
	if(!ipset_validate(session,w_set,a_buf)) {
		if(debug & DBG_IPSET)
			fprintf(stderr,"Invalid address %s\n",a_buf);
		return ret;
	}
	e = ipset_test(session,w_set,a_buf);
	if(op == OP_DEL) {
		if(e) {
			if(!ipset_del(session,w_set,a_buf)) {
				fprintf(stderr,"%s del err\n", a_buf);
			} else { 
				if(debug & DBG_IPSET)
					fprintf(stderr,"%s deleted from set\n", a_buf);
				ret = 1;
			}
		} else {
			if (debug & DBG_IPSET) fprintf(stderr,"%s not exist\n", a_buf);
			ret = 1;
		}
	} else { // OP_ADD
		if(!e) {
			if(!ipset_add(session,w_set,a_buf)) {
				fprintf(stderr,"%s add err\n", a_buf);
			} else { 
				if(debug & DBG_IPSET)
					fprintf(stderr,"%s added to set\n", a_buf);
				ret = 1;
			}
		} else {
			if (debug & DBG_IPSET) fprintf(stderr,"%s exist\n", a_buf);
			ret = 1;
		}
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
if(debug & DBG_INO) fprintf(stderr,"Lookup dir %s\n",dir);
while( --n >= 0) {
	if(namelist[n]->d_name[0] != '.') {
		if(is_file(namelist[n]->d_name,dir)) 
			if(ipset_op(namelist[n]->d_name,OP_ADD))
				add_to_list(namelist[n]->d_name);
	}
	free(namelist[n]);
}
free(namelist);

//ipset_session_restart(&session);
}

static void reread_w_dirs(void) {
int i;
restarted = 1;
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
fprintf(stderr,"%s [-d] [-F] [-f] [-p pidfile] [-t ipset_type] [-c netconfig ] -s ipset_name [dir ...]\n","ipsetdir");
fprintf(stderr," -d dbglvl - debug\n -F - no daemonize\n -f - flush set on exit\n"
		" -p pidfile - use PID file. Default: /run/ipset_dir_<setname>.pid\n"
		" -s ipset_name - ipset name\n"
		" -D            - Dump peer/master info and exit\n"
		" -d dbglvl     - debug level (bitmap):\n"
		"                   0x1 - cfg,  0x02 - ipset, 0x4 - network,\n"
		"                   0x8 - sync, 0x10 - inotify\n"
		" -t ipset_type - type of ipset. default hash:ip\n    "
		);
print_known_settypes();
exit(0);
}

char event_buff[EVENT_BUF_LEN];

void my_signals(int s) {
if(s == SIGHUP || s == SIGINT) {
	reread_w_dirs();
} else {
	work = 0;
}
}

int main(int argc,char **argv) {

struct inotify_event * event;
char *fconfig = NULL;
int i,fd,wd,len,c;
int set_flush = 0, dodaemon = 1, do_dump_peer = 0;
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
	while((c=getopt(argc,argv,"DFp:s:t:c:d:")) != -1) {
	 switch(c) {
	  case 'D': do_dump_peer++; break;
	  case 'd': debug = strtol(optarg,NULL,0); break;
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
	if(net_buf_size < 256) {
		fprintf(stderr,"net_buf_size too small!\n");
		abort();
	}
	if(do_dump_peer) {
			dump_peers();
			exit(0);
	}
	net_buf = malloc(net_buf_size+1);
	if(!net_buf) {
			perror("malloc net_buf");
			exit(1);
	}
	if(!w_set || (is_master() && !argv[optind]))
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


	fd = inotify_init();
	if ( fd < 0 ) {
		perror("inotify_init");
		exit(1);
	}

	if(is_peer()) {
		reload_ipset_list(w_set);
	} else { // master or single
		ipset_flush(session,w_set);
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
			if(debug & DBG_INO)
				fprintf(stderr,"Add watch dir %s\n",w_dir);
		}
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
	CFG.fds[0].revents = 0;

	if(!CFG.n_master && !CFG.n_peer) CFG.ping = 600;
	restarted = 1;
	while(work) {
		if(is_master() && restarted) { // On start: send to peer all info
			uint32_t ct = (uint32_t)time(NULL);
			restarted = 0;
			for(i=0; i < CFG.n_peer; i++) {
				CFG.peers[i].seq = 1;
				send_all(CFG.peers[i].ssock, &CFG.peers[i].pa, ct,
								CFG.peers[i].key,CFG.peers[i].key_len);
			}
		}
		if(is_peer())
				net_wakeup_master();

		len = poll(CFG.fds, CFG.n_list + 1, CFG.ping*1000);
		if(!len) continue;
		if(len < 0 && errno == EINTR) {
			if(debug) fprintf(stderr,"EINTR\n");
			continue;
		}
		if(CFG.fds[0].revents) {
				int op;
				len = read(fd,event_buff,sizeof(event_buff));
				if(len < 0 && errno == EINTR) {
					if(debug) fprintf(stderr,"EINTR\n");
					continue;
				}
				if(len < 0) break;
				if(len < EVENT_SIZE) break;

				for(i = 0; i < len; i += EVENT_SIZE + event->len) {
					event = (struct inotify_event *)(&event_buff[i]);
					if(!event->len || EVENT_SIZE + event->len + i > len) break;
					op = event->mask & (IN_DELETE|IN_MOVED_FROM) ? OP_DEL:OP_ADD;
					w_dir = find_wd(event->wd);
					if(debug & DBG_INO) fprintf(stderr,"Dir:%s File:%s Event:%s\n",
								w_dir,event->name,op == OP_DEL ? "DEL":"ADD");
					if(op == OP_DEL) {
							if(ipset_op(event->name,op)) {
								del_from_list(event->name);
								send_diff(event->name,op);
							}
					} else { // OP_ADD
						if(is_file(event->name,w_dir))
							if(ipset_op(event->name,op)) {
								add_to_list(event->name);
								send_diff(event->name,op);
							}
					}
				}
				CFG.fds[0].revents = 0;
		}
		for(i=1; i <= CFG.n_list; i++) {
			if(CFG.fds[i].revents) {
				if(CFG.fds[i].revents & POLLIN) net_event(i);
				CFG.fds[i].revents = 0;
			}
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
