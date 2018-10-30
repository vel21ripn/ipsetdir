
#define _DEFAULT_SOURCE

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "ipset_ui.h"

#define STREQ(a, b)             (strcmp(a, b) == 0)

int ipset_session_restart(struct ipset_session **session) {
if(*session)
		ipset_session_fini(*session);
*session = ipset_session_init(printf);
return *session != NULL;
}

int ipset_exist(struct ipset_session *session,char *setname,char *buf,size_t bufsize) {
	int ret;
	static uint32_t restore_line=0;

	ipset_session_report_reset(session);
	ipset_data_reset(ipset_session_data(session));

	ret = ipset_parse_setname(session, IPSET_SETNAME, setname);
	if(ret >= 0)
	        ret = ipset_cmd(session, IPSET_CMD_HEADER , restore_line);
	if(ret >= 0 && buf && bufsize) {
	        const char *sn = ipset_data_get(ipset_session_data(session),IPSET_OPT_TYPENAME);
	        strncpy(buf,sn ? sn : "",bufsize);
	} else {
	        if(buf) *buf = 0;
	}

	return ret == 0;
}


/* copy from ipset/src/{ipset.c,ui.c} */

static bool do_parse(const struct ipset_arg *arg, bool family)
{
	return !((family == true) ^ (arg->opt == IPSET_OPT_FAMILY));
}

static bool
ipset_match_option(const char *arg, const char * const name[])
{

        /* Skip two leading dashes */
        if (arg[0] == '-' && arg[1] == '-')
                arg++, arg++;

        return STREQ(arg, name[0]) ||
               (name[1] != NULL && STREQ(arg, name[1]));
}

static int
call_parser(struct ipset_session *session,int *argc, char *argv[], const struct ipset_type *type,
            enum ipset_adt cmd, bool family)
{
int i=0,j,ret = -1;
const struct ipset_arg *arg;
const char *optstr;

	while (*argc > i) {
		ret = -1;
		for (j = 0; type->cmd[cmd].args[j] != IPSET_ARG_NONE; j++) {
			arg = ipset_keyword(type->cmd[cmd].args[j]);
			if (!(ipset_match_option(argv[i], arg->name))) continue;
			ret = 0;
			optstr = argv[i++];

			if(arg->has_arg == IPSET_MANDATORY_ARG && *argc - i < 1) {
				return -1;
			}

			if(arg->has_arg == IPSET_OPTIONAL_ARG) {
				if (*argc - i >= 1) {
					if (do_parse(arg, family)) {
						ret = ipset_call_parser(session, arg, argv[i]);
						if (ret < 0)  return ret;
					}
					i++;
					continue;
				}
			}
			if (do_parse(arg, family)) {
				ret = ipset_call_parser(session, arg, optstr);
				if (ret < 0)  return ret;
			}
		}
	}
	if (!family) *argc = 0;

	return ret;

}
/* end of copy */

int ipset_create(struct ipset_session *session,char *setname,char *stype, 
				char **optargs, int nopts) {
	int ret;
	const struct ipset_type *type = NULL;
	static uint32_t restore_line=0;
	int argc;

	ipset_session_report_reset(session);
	ipset_data_reset(ipset_session_data(session));

	do {
		ret = ipset_parse_setname(session, IPSET_SETNAME, setname);
		if(ret < 0) break;
		ret = ipset_parse_typename(session, IPSET_OPT_TYPENAME, stype);
		if(ret < 0) break;

		type = ipset_type_get(session, IPSET_CMD_CREATE);

		if(!type) break;
		if(optargs) {
			for(argc = 0;optargs[argc] && argc < nopts; argc++);

			ret = call_parser(session, &argc, optargs, type, IPSET_CREATE, true);
			if(ret < 0) break;
			ret = call_parser(session, &argc, optargs, type, IPSET_CREATE, false);
			if(ret < 0) break;
		}

		ret = ipset_cmd(session, IPSET_CMD_CREATE , restore_line);
	} while(0);

	return ret == 0;
}

int ipset_rename(struct ipset_session *session,char *setname,char *newname,int swap) {
	int ret;
	static uint32_t restore_line=0;

	ipset_session_report_reset(session);
	ipset_data_reset(ipset_session_data(session));

	do {
		ret = ipset_parse_setname(session, IPSET_SETNAME, setname);
		if(ret < 0) break;
		ret = ipset_parse_setname(session, IPSET_OPT_SETNAME2, newname);
		if(ret < 0) break;

		ret = ipset_cmd(session, swap ? IPSET_CMD_SWAP:IPSET_CMD_RENAME , restore_line);
	} while(0);

	return ret == 0;
}

int ipset_flush(struct ipset_session *session,char *setname) {
	int ret;
	static uint32_t restore_line=0;

	ipset_session_report_reset(session);
	ipset_data_reset(ipset_session_data(session));

	ret = ipset_parse_setname(session, IPSET_SETNAME, setname);
	if(ret >= 0)
		ret = ipset_cmd(session, IPSET_CMD_FLUSH , restore_line);

	return ret == 0;
}

int ipset_destroy(struct ipset_session *session,char *setname) {
	int ret;
	static uint32_t restore_line=0;

	ipset_session_report_reset(session);
	ipset_data_reset(ipset_session_data(session));

	ret = ipset_parse_setname(session, IPSET_SETNAME, setname);
	if(ret >= 0)
		ret = ipset_cmd(session, IPSET_CMD_DESTROY , restore_line);

	return ret == 0;
}

static int _ipset_print_file(const char *fmt, ...)
{
     int len;
     va_list args;

	 printf("ipset_print_file>");
     va_start(args, fmt);
     len = vfprintf(stdout, fmt, args);
     va_end(args);

     return len;
}

int ipset_list(struct ipset_session **session,char *setname) {
	int ret;
	static uint32_t restore_line=0;

	ipset_session_restart(session);

	ret = ipset_parse_setname(*session, IPSET_SETNAME, setname);
	ipset_session_outfn(*session, _ipset_print_file);
	if(ret >= 0)
		ret = ipset_cmd(*session, IPSET_CMD_LIST , restore_line);

	ipset_session_restart(session);

	return ret == 0;
}

int ipset_save(struct ipset_session **session,char *setname) {
	int ret;
	static uint32_t restore_line=0;

	ipset_session_restart(session);

	ret = ipset_parse_setname(*session, IPSET_SETNAME, setname);
	ipset_session_outfn(*session, _ipset_print_file);
	if(ret >= 0)
		ret = ipset_cmd(*session, IPSET_CMD_SAVE , restore_line);

	ipset_session_restart(session);

	return ret == 0;
}

static int _ipset_adt_verbose = 0;

static int _ipset_adt(struct ipset_session *session,int cmd,char *setname,char *buf) {
	int ret;
	static uint32_t restore_line=0;
	const struct ipset_type *type = NULL;
	int set_cmd = cmd & ~0xC000;

	cmd |= _ipset_adt_verbose;
	ipset_session_report_reset(session);
	ipset_data_reset(ipset_session_data(session));

	ret = ipset_parse_setname(session, IPSET_SETNAME, setname);

	type = ret >= 0 ? ipset_type_get(session, set_cmd) : NULL;

	if(type) {
		ret = ipset_parse_elem(session, type->last_elem_optional, buf);
		if(cmd & 0x8000) {
			if(cmd & 0x4000) 
				printf("VALIDATE(%s,%s) = %s\n", setname,buf,ret == 0 ? "OK":"ERR");
			return ret == 0;
		}
		if(ret >= 0)
			ret = ipset_cmd(session, set_cmd, restore_line);
		if(ret < 0)
			ipset_session_report_reset(session);
	}
	if(cmd & 0x4000) printf("%s(%s,%s) = %s\n",
			set_cmd == IPSET_CMD_TEST ? "test":(set_cmd == IPSET_CMD_ADD ? "add":"del"),
			setname,buf,ret == 0 ? "OK":"ERR");
	return ret == 0;
}

int ipset_test(struct ipset_session *session,char *setname,char *buf) {
	return _ipset_adt(session,IPSET_CMD_TEST,setname,buf);
}
int ipset_add(struct ipset_session *session,char *setname,char *buf) {
	return _ipset_adt(session,IPSET_CMD_ADD,setname,buf);
}
int ipset_del(struct ipset_session *session,char *setname,char *buf) {
	return _ipset_adt(session,IPSET_CMD_DEL,setname,buf);
}
int ipset_validate(struct ipset_session *session,char *setname,char *buf) {
	return _ipset_adt(session,IPSET_CMD_TEST | 0x8000,setname,buf);
}

#ifdef IPSET_LIB_TEST
int main(int argc,char **argv) {
int t = 0;
char est[128];
char *w_set = "AAA", *w_type="hash:ip", *w_set2 = "AAA1", *w_set3="AAM", *w_type3="hash:mac";

struct ipset_session *session;

_ipset_adt_verbose = 0x4000;
ipset_load_types();
session = ipset_session_init(printf);

if(!session) abort();
if(!ipset_session_restart(&session)) abort();
if(!ipset_session_restart(&session)) abort();

if(ipset_exist(session,w_set,NULL,0)) {
	printf("set '%s' exist! Can't continue\n",w_set);
	exit(1);
}
if(ipset_exist(session,w_set2,NULL,0)) {
	printf("set %s exist! Can't continue\n",w_set2);
	exit(1);
}

printf("create %s %d\n",w_set,
		ipset_create(session,w_set,w_type,NULL,0));
if(!ipset_exist(session,w_set,est,sizeof(est)-1)) {
	printf("not exist %s\n",w_set);
	exit(1);
}
printf("Set '%s' type %s\n",w_set,est);

if(!ipset_exist(session,w_set3,NULL,0)) {
	ipset_create(session,w_set3,w_type3,NULL,0);
}
ipset_add(session,w_set3,"00:11:22:33:44:55");
ipset_test(session,w_set3,"00:11:22:33:44:55");
ipset_validate(session,w_set3,"00:11:22:33:44:zz");

for(t=0; t < 3; t++) {
	printf("%d\n",t);
	ipset_test(session,w_set,"10.0.0.121");
	if(t == 1)
		ipset_add(session,w_set,"10.0.0.122");
	if(t == 2)
		ipset_add(session,w_set,"10.0.0.122");

	ipset_test(session,w_set,"10.0.0.122");
	ipset_test(session,w_set,"10.0.0.123");
}
ipset_validate(session,w_set,"10.0.0.123");
ipset_validate(session,w_set,"10.0.0.123a");

if(!ipset_exist(session,w_set,est,sizeof(est)-1)) {
	printf("not exist %s - OK\n",w_set);
}

if(!ipset_exist(session,w_set2,est,sizeof(est)-1)) {
	printf("not exist %s -OK\n",w_set2);
}

printf("rename %s %d\n",w_set,ipset_rename(session,w_set,w_set2,0));
if(ipset_exist(session,w_set,NULL,0)) {
	printf("exist %s\n",w_set);
	exit(1);
}

if(!ipset_exist(session,w_set2,NULL,0)) {
	printf("not exist %s\n",w_set);
	exit(1);
}

ipset_test(session,w_set2,"10.0.0.124");
ipset_add( session,w_set2,"10.0.0.124");
ipset_test(session,w_set2,"10.0.0.124");

printf("save %s %d\n",w_set2,ipset_save(&session,w_set2));
printf("save %s %d\n",w_set ,ipset_save(&session,w_set));
printf("save %s %d\n",w_set2,ipset_save(&session,w_set2));

printf("flush %s %d\n",w_set2,ipset_flush(session,w_set2));
ipset_test(session,w_set2,"10.0.0.124");
printf("zap  %s %d\n",w_set2,ipset_destroy(session,w_set2));

ipset_session_fini(session);
exit(0);
}
#endif /*  IPSET_LIB_TEST  */

/*
 * vim: set ts=4:foldmethod=marker:foldmarker={{{{,}}}}:
 */
