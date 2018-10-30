
#include <libipset/types.h>
#include <libipset/session.h>
#include <libipset/parse.h>

int ipset_session_restart(struct ipset_session **session);
int ipset_exist(struct ipset_session *session,char *setname,char *buf,size_t bufsize);
int ipset_create(struct ipset_session *session,char *setname,char *stype,
			char **optargs, int nopts);
int ipset_rename(struct ipset_session *session,char *setname,char *newname,int swap);
int ipset_flush(struct ipset_session *session,char *setname);
int ipset_destroy(struct ipset_session *session,char *setname);
int ipset_list(struct ipset_session **session,char *setname);
int ipset_save(struct ipset_session **session,char *setname);
int ipset_validate(struct ipset_session *session,char *setname,char *buf);
int ipset_test(struct ipset_session *session,char *setname,char *buf);
int ipset_add(struct ipset_session *session,char *setname,char *buf);
int ipset_del(struct ipset_session *session,char *setname,char *buf);

