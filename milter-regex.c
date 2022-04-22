/* $Id: milter-regex.c,v 1.22 2019/12/12 14:43:01 dhartmei Exp $ */

/*
 * Copyright (c) 2003-2019 Daniel Hartmeier
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    - Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    - Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

static const char rcsid[] = "$Id: milter-regex.c,v 1.22 2019/12/12 14:43:01 dhartmei Exp $";

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pthread.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define SYSLOG_NAMES
#include <syslog.h>
#include <unistd.h>
#ifdef __linux__
#include <stdbool.h>
#endif
#include <libmilter/mfapi.h>

#include "eval.h"

extern void	 die(const char *);
extern int	 parse_ruleset(const char *, struct ruleset **, char *,
		    size_t);

static const char	*rule_file_name = "/etc/milter-regex.conf";
static int		 debug = 0;
static unsigned		 maxlines = 0;
static pthread_mutex_t	 mutex;

struct context {
	struct ruleset	*rs;
	int		*res;
	char		 buf[2048];	/* longer body lines are wrapped */
	unsigned	 pos;		/* write position within buf */
	char		 host_name[128];
	char		 host_addr[64];
	char		 helo[128];
	char		 env_from[128];
	char		 env_rcpt[2048];
	char		 hdr_from[128];
	char		 hdr_to[128];
	char		 hdr_subject[128];
	char		*quarantine;
	unsigned	 lines;
};

static sfsistat		 setreply(SMFICTX *, struct context *,
			    const struct action *);
static struct ruleset	*get_ruleset(void);
static sfsistat		 cb_connect(SMFICTX *, char *, _SOCK_ADDR *);
static sfsistat		 cb_helo(SMFICTX *, char *);
static sfsistat		 cb_envfrom(SMFICTX *, char **);
static sfsistat		 cb_envrcpt(SMFICTX *, char **);
static sfsistat		 cb_header(SMFICTX *, char *, char *);
static sfsistat		 cb_eoh(SMFICTX *);
static sfsistat		 cb_body(SMFICTX *, u_char *, size_t);
static sfsistat		 cb_eom(SMFICTX *);
static sfsistat		 cb_close(SMFICTX *);
static void		 usage(const char *);
static void		 msg(int, struct context *, const char *, ...);

#define USER		"_milter-regex"
#define OCONN		"unix:/var/spool/milter-regex/sock"
#define RCODE_REJECT	"554"
#define RCODE_TEMPFAIL	"451"
#define XCODE_REJECT	"5.7.1"
#define XCODE_TEMPFAIL	"4.7.1"
#define	MAXRS		16

/* Define what sendmail macros should be queried in what context (phase)
 * with smfi_getsymval(). Whether sendmail actually provides specific
 * values depends on configuration of confMILTER_MACROS_*
 */
struct {
	const char *phase;
	const char *name;
} macro[] = {
	{ "connect", "{daemon_name}" },
	{ "connect", "{if_name}" },
	{ "connect", "{if_addr}" },
	{ "connect", "j" },
	{ "connect", "_" },
	{ "helo", "{tls_version}" },
	{ "helo", "{cipher}" },
	{ "helo", "{cipher_bits}" },
	{ "helo", "{cert_subject}" },
	{ "helo", "{cert_issuer}" },
	{ "helo", "{verify}" },
	{ "envfrom", "i" },
	{ "envfrom", "{tls_version}" },
	{ "envfrom", "{cipher}" },
	{ "envfrom", "{cipher_bits}" },
	{ "envfrom", "{cert_subject}" },
	{ "envfrom", "{cert_issuer}" },
	{ "envfrom", "{verify}" },
	{ "envfrom", "{auth_type}" },
	{ "envfrom", "{auth_authen}" },
	{ "envfrom", "{auth_ssf}" },
	{ "envfrom", "{auth_author}" },
	{ "envfrom", "{mail_mailer}" },
	{ "envfrom", "{mail_host}" },
	{ "envfrom", "{mail_addr}" },
	{ "envrcpt", "{rcpt_mailer}" },
	{ "envrcpt", "{rcpt_host}" },
	{ "envrcpt", "{rcpt_addr}" },
	{ NULL, NULL }
};

#if __linux__ || __sun__
#define	ST_MTIME st_mtime
extern size_t	 strlcat(char *, const char *, size_t);
extern size_t	 strlcpy(char *, const char *, size_t);
#else
#define	ST_MTIME st_mtimespec
#endif

static void
mutex_lock(void)
{
	if (pthread_mutex_lock(&mutex))
		die("pthread_mutex_lock");
}

static void
mutex_unlock(void)
{
	if (pthread_mutex_unlock(&mutex))
		die("pthread_mutex_unlock");
}

#ifdef __sun__
int
daemon(int nochdir, int noclose)
{
	pid_t pid;
	int fd;

	if ((pid = fork()) < 0) {
		perror("fork");
		return (1);
	} else if (pid > 0)
		_exit(0);
	if ((pid = setsid()) == -1) {
		perror("setsid");
		return (1);
	}
	if ((pid = fork()) < 0) {
		perror("fork");
		return (1);
	} else if (pid > 0)
		_exit(0);
	if (!nochdir && chdir("/")) {
		perror("chdir");
		return (1);
	}
	if (!noclose) {
		dup2(fd, fileno(stdout));
		dup2(fd, fileno(stderr));
		dup2(open("/dev/null", O_RDONLY, 0), fileno(stdin));
	}
	return (0);
}
#endif

static sfsistat
setreply(SMFICTX *ctx, struct context *context, const struct action *action)
{
	int result = SMFIS_CONTINUE;

	switch (action->type) {
	case ACTION_REJECT:
		msg(LOG_NOTICE, context, "REJECT: %s, HELO: %s, FROM: %s, "
		    "RCPT: %s, From: %s, To: %s, Subject: %s", action->msg,
		    context->helo, context->env_from, context->env_rcpt,
		    context->hdr_from, context->hdr_to, context->hdr_subject);
		result = SMFIS_REJECT;
		break;
	case ACTION_TEMPFAIL:
		msg(LOG_NOTICE, context, "TEMPFAIL: %s, HELO: %s, FROM: %s, "
		    "RCPT: %s, From: %s, To: %s, Subject: %s", action->msg,
		    context->helo, context->env_from, context->env_rcpt,
		    context->hdr_from, context->hdr_to, context->hdr_subject);
		result = SMFIS_TEMPFAIL;
		break;
	case ACTION_QUARANTINE:
		if (context->quarantine != NULL)
			free(context->quarantine);
		context->quarantine = strdup(action->msg);
		break;
	case ACTION_DISCARD:
		msg(LOG_NOTICE, context, "DISCARD, HELO: %s, FROM: %s, "
		    "RCPT: %s, From: %s, To: %s, Subject: %s",
		    context->helo, context->env_from, context->env_rcpt,
		    context->hdr_from, context->hdr_to, context->hdr_subject);
		result = SMFIS_DISCARD;
		break;
	case ACTION_ACCEPT:
		msg(LOG_INFO, context, "ACCEPT, HELO: %s, FROM: %s, "
		    "RCPT: %s, From: %s, To: %s, Subject: %s",
		    context->helo, context->env_from, context->env_rcpt,
		    context->hdr_from, context->hdr_to, context->hdr_subject);
		result = SMFIS_ACCEPT;
		break;
	}
	if (action->type == ACTION_REJECT &&
	    smfi_setreply(ctx, RCODE_REJECT, XCODE_REJECT,
	    (char *)action->msg) != MI_SUCCESS)
		msg(LOG_ERR, context, "smfi_setreply");
	if (action->type == ACTION_TEMPFAIL &&
	    smfi_setreply(ctx, RCODE_TEMPFAIL, XCODE_TEMPFAIL,
	    (char *)action->msg) != MI_SUCCESS)
		msg(LOG_ERR, context, "smfi_setreply");
	return (result);
}

static struct ruleset *
get_ruleset(void)
{
	static struct ruleset *rs[MAXRS] = {};
	static int cur = 0;
	static time_t last_check = 0;
	static struct stat sbo;
	time_t t = time(NULL);
	int load = 0;

	mutex_lock();
	if (!last_check)
		memset(&sbo, 0, sizeof(sbo));
	if (t - last_check >= 10) {
		struct stat sb;

		last_check = t;
		memset(&sb, 0, sizeof(sb));
		if (stat(rule_file_name, &sb))
			msg(LOG_ERR, NULL, "get_ruleset: stat: %s: %s",
			    rule_file_name, strerror(errno));
		else if (memcmp(&sb.ST_MTIME, &sbo.ST_MTIME,
		    sizeof(sb.ST_MTIME))) {
			memcpy(&sbo.ST_MTIME, &sb.ST_MTIME,
			    sizeof(sb.ST_MTIME));
			load = 1;
		}
	}
	if (load || rs[cur] == NULL) {
		int i;
		char err[8192];

		msg(LOG_DEBUG, NULL, "loading new configuration file");
		for (i = 0; i < MAXRS; ++i)
			if (rs[i] != NULL && rs[i]->refcnt == 0) {
				msg(LOG_DEBUG, NULL, "freeing unused ruleset "
				    "%d/%d", i, MAXRS);
				free_ruleset(rs[i]);
				rs[i] = NULL;
			}
		for (i = 0; i < MAXRS; ++i)
			if (rs[i] == NULL)
				break;
		if (i == MAXRS)
			msg(LOG_ERR, NULL, "all rulesets are in use, cannot "
			    "load new one", MAXRS);
		else if (parse_ruleset(rule_file_name, &rs[i], err,
		    sizeof(err)) || rs[i] == NULL)
			msg(LOG_ERR, NULL, "parse_ruleset: %s", err);
		else {
			msg(LOG_INFO, NULL, "configuration file %s loaded "
			    "successfully", rule_file_name);
			cur = i;
		}
	}
	mutex_unlock();
	return (rs[cur]);
}

static struct action *
check_macros(SMFICTX *ctx, struct context *context, const char *phase)
{
	struct action *action;
	int i;
	const char *v;

	for (i = 0; macro[i].phase != NULL; ++i) {
		if (strcmp(macro[i].phase, phase))
			continue;
		if ((v = smfi_getsymval(ctx, (char *)macro[i].name)) == NULL)
			v = "";
		msg(LOG_DEBUG, context, "macro %s = %s", macro[i].name, v);
		if ((action = eval_cond(context->rs, context->res, COND_MACRO,
		    macro[i].name, v)) != NULL)
			return (action);
	}
	return (NULL);
}

static sfsistat
cb_connect(SMFICTX *ctx, char *name, _SOCK_ADDR *sa)
{
	struct context *context;
	struct action *action;

	context = calloc(1, sizeof(*context));
	if (context == NULL) {
		msg(LOG_ERR, NULL, "cb_connect: calloc: %s", strerror(errno));
		return (SMFIS_ACCEPT);
	}
	context->rs = get_ruleset();
	if (context->rs == NULL) {
		free(context);
		msg(LOG_ERR, NULL, "cb_connect: get_ruleset");
		return (SMFIS_ACCEPT);
	}
	context->res = calloc(context->rs->maxidx, sizeof(*context->res));
	if (context->res == NULL) {
		free(context);
		msg(LOG_ERR, NULL, "cb_connect: calloc: %s", strerror(errno));
		return (SMFIS_ACCEPT);
	}
	if (smfi_setpriv(ctx, context) != MI_SUCCESS) {
		free(context->res);
		free(context);
		msg(LOG_ERR, NULL, "cb_connect: smfi_setpriv");
		return (SMFIS_ACCEPT);
	}
	context->rs->refcnt++;

	strlcpy(context->host_name, name, sizeof(context->host_name));
	strlcpy(context->host_addr, "unknown", sizeof(context->host_addr));
	if (sa) {
		switch (sa->sa_family) {
		case AF_INET: {
			struct sockaddr_in *sin = (struct sockaddr_in *)sa;

			if (inet_ntop(AF_INET, &sin->sin_addr.s_addr,
			    context->host_addr, sizeof(context->host_addr)) ==
			    NULL)
				msg(LOG_ERR, NULL, "cb_connect: inet_ntop: %s",
				    strerror(errno));
			break;
		}
		case AF_INET6: {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;

			if (inet_ntop(AF_INET6, &sin6->sin6_addr,
			    context->host_addr, sizeof(context->host_addr)) ==
			    NULL)
				msg(LOG_ERR, NULL, "cb_connect: inet_ntop: %s",
				    strerror(errno));
			break;
		}
		}
	}
	msg(LOG_DEBUG, context, "cb_connect('%s', '%s')",
	    context->host_name, context->host_addr);
	if ((action = check_macros(ctx, context, "connect")) != NULL) {
		/* can't really do this, delay */
		/*return (setreply(ctx, context, action)); */
	}
	return (SMFIS_CONTINUE);
}

static sfsistat
cb_helo(SMFICTX *ctx, char *arg)
{
	struct context *context;
	const struct action *action;

	if ((context = (struct context *)smfi_getpriv(ctx)) == NULL) {
		msg(LOG_ERR, NULL, "cb_helo: smfi_getpriv");
		return (SMFIS_ACCEPT);
	}
	strlcpy(context->helo, arg, sizeof(context->helo));
	msg(LOG_DEBUG, context, "cb_helo('%s')", arg);
	/* multiple HELO imply RSET in sendmail */
	/* evaluate connect arguments here, because we can't call */
	/* setreply from cb_connect */
	eval_clear(context->rs, context->res, COND_CONNECT);
	if ((action = eval_cond(context->rs, context->res, COND_CONNECT,
	    context->host_name, context->host_addr)) != NULL)
		return (setreply(ctx, context, action));
	if ((action = eval_end(context->rs, context->res, COND_CONNECT,
	    COND_MACRO)) !=
	    NULL)
		return (setreply(ctx, context, action));
	if ((action = check_macros(ctx, context, "helo")) != NULL)
		return (setreply(ctx, context, action));
	eval_clear(context->rs, context->res, COND_HELO);
	if ((action = eval_cond(context->rs, context->res, COND_HELO,
	    arg, NULL)) != NULL)
		return (setreply(ctx, context, action));
	if ((action = eval_end(context->rs, context->res, COND_HELO,
	    COND_MACRO)) != NULL)
		return (setreply(ctx, context, action));
	return (SMFIS_CONTINUE);
}

static sfsistat
cb_envfrom(SMFICTX *ctx, char **args)
{
	struct context *context;
	const struct action *action;

	if ((context = (struct context *)smfi_getpriv(ctx)) == NULL) {
		msg(LOG_ERR, NULL, "cb_envfrom: smfi_getpriv");
		return (SMFIS_ACCEPT);
	}
	/* multiple MAIL FROM indicate separate messages */
	eval_clear(context->rs, context->res, COND_ENVFROM);
	if (*args != NULL) {
		msg(LOG_DEBUG, context, "cb_envfrom('%s')", *args);
		strlcpy(context->env_from, *args, sizeof(context->env_from));
		if ((action = eval_cond(context->rs, context->res, COND_ENVFROM,
		    *args, NULL)) != NULL)
			return (setreply(ctx, context, action));
	}
	if ((action = eval_end(context->rs, context->res, COND_ENVFROM,
	    COND_MACRO)) != NULL)
		return (setreply(ctx, context, action));
	if ((action = check_macros(ctx, context, "envfrom")) != NULL)
		return (setreply(ctx, context, action));
	return (SMFIS_CONTINUE);
}

static sfsistat
cb_envrcpt(SMFICTX *ctx, char **args)
{
	struct context *context;
	const struct action *action;

	if ((context = (struct context *)smfi_getpriv(ctx)) == NULL) {
		msg(LOG_ERR, NULL, "cb_envrcpt: smfi_getpriv");
		return (SMFIS_ACCEPT);
	}
	/* multiple RCPT TO: possible */
	eval_clear(context->rs, context->res, COND_ENVRCPT);
	if (*args != NULL) {
		msg(LOG_DEBUG, context, "cb_envrcpt('%s')", *args);
		if (context->env_rcpt[0])
			strlcat(context->env_rcpt, " ",
			    sizeof(context->env_rcpt));
		strlcat(context->env_rcpt, *args, sizeof(context->env_rcpt));
		if ((action = eval_cond(context->rs, context->res, COND_ENVRCPT,
		    *args, NULL)) != NULL)
			return (setreply(ctx, context, action));
	}
	if ((action = eval_end(context->rs, context->res, COND_ENVRCPT,
	    COND_MACRO)) != NULL)
		return (setreply(ctx, context, action));
	if ((action = check_macros(ctx, context, "envrcpt")) != NULL)
		return (setreply(ctx, context, action));
	return (SMFIS_CONTINUE);
}

static sfsistat
cb_header(SMFICTX *ctx, char *name, char *value)
{
	struct context *context;
	const struct action *action;

	if ((context = (struct context *)smfi_getpriv(ctx)) == NULL) {
		msg(LOG_ERR, context, "cb_header: smfi_getpriv");
		return (SMFIS_ACCEPT);
	}
	msg(LOG_DEBUG, context, "cb_header('%s', '%s')", name, value);
	if ((action = eval_end(context->rs, context->res, COND_MACRO,
	    COND_HEADER)) != NULL)
		return (setreply(ctx, context, action));
	if (!strcasecmp(name, "From"))
		strlcpy(context->hdr_from, value, sizeof(context->hdr_from));
	else if (!strcasecmp(name, "To"))
		strlcpy(context->hdr_to, value, sizeof(context->hdr_to));
	else if (!strcasecmp(name, "Subject"))
		strlcpy(context->hdr_subject, value,
		    sizeof(context->hdr_subject));
	if ((action = eval_cond(context->rs, context->res, COND_HEADER,
	    name, value)) != NULL)
		return (setreply(ctx, context, action));
	return (SMFIS_CONTINUE);
}

static sfsistat
cb_eoh(SMFICTX *ctx)
{
	struct context *context;
	const struct action *action;

	if ((context = (struct context *)smfi_getpriv(ctx)) == NULL) {
		msg(LOG_ERR, NULL, "cb_eoh: smfi_getpriv");
		return (SMFIS_ACCEPT);
	}
	msg(LOG_DEBUG, context, "cb_eoh()");
	memset(context->buf, 0, sizeof(context->buf));
	context->pos = 0;
	if ((action = eval_end(context->rs, context->res, COND_HEADER,
	    COND_BODY)) != NULL)
		return (setreply(ctx, context, action));
	return (SMFIS_CONTINUE);
}

static sfsistat
cb_body(SMFICTX *ctx, u_char *chunk, size_t size)
{
	struct context *context;

	if ((context = (struct context *)smfi_getpriv(ctx)) == NULL) {
		msg(LOG_ERR, NULL, "cb_body: smfi_getpriv");
		return (SMFIS_ACCEPT);
	}
	for (; size > 0; size--, chunk++) {
		context->buf[context->pos] = *chunk;
		if (context->buf[context->pos] == '\n' ||
		    context->pos == sizeof(context->buf) - 1) {
			const struct action *action;

			if (context->pos > 0 &&
			    context->buf[context->pos - 1] == '\r')
				context->buf[context->pos - 1] = 0;
			else
				context->buf[context->pos] = 0;
			context->pos = 0;
			if (maxlines && context->lines++ > maxlines)
				continue;
			msg(LOG_DEBUG, context, "cb_body('%s')", context->buf);
			if ((action = eval_cond(context->rs, context->res,
			    COND_BODY, context->buf, NULL)) != NULL)
				return (setreply(ctx, context, action));
		} else
			context->pos++;
	}
	return (SMFIS_CONTINUE);
}

static sfsistat
cb_eom(SMFICTX *ctx)
{
	struct context *context;
	const struct action *action;
	int result = SMFIS_ACCEPT;

	if ((context = (struct context *)smfi_getpriv(ctx)) == NULL) {
		msg(LOG_ERR, NULL, "cb_eom: smfi_getpriv");
		return (SMFIS_ACCEPT);
	}
	msg(LOG_DEBUG, context, "cb_eom()");
	if ((action = eval_end(context->rs, context->res, COND_BODY,
	    COND_MAX)) != NULL)
		result = setreply(ctx, context, action);
	else
		msg(LOG_DEBUG, context, "ACCEPT, HELO: %s, FROM: %s, "
		    "RCPT: %s, From: %s, To: %s, Subject: %s",
		    context->helo, context->env_from, context->env_rcpt,
		    context->hdr_from, context->hdr_to, context->hdr_subject);
	if (context->quarantine != NULL) {
		msg(LOG_NOTICE, context, "QUARANTINE: %s, HELO: %s, FROM: %s, "
		    "RCPT: %s, From: %s, To: %s, Subject: %s", action->msg,
		    context->helo, context->env_from, context->env_rcpt,
		    context->hdr_from, context->hdr_to, context->hdr_subject);
		if (smfi_quarantine(ctx, context->quarantine) != MI_SUCCESS)
			msg(LOG_ERR, context, "cb_eom: smfi_quarantine");
	}
	context->pos = context->hdr_from[0] = context->hdr_to[0] =
	    context->hdr_subject[0] = 0;
	if (context->quarantine != NULL) {
		free(context->quarantine);
		context->quarantine = NULL;
	}
	return (result);
}

static sfsistat
cb_close(SMFICTX *ctx)
{
	struct context *context;

	context = (struct context *)smfi_getpriv(ctx);
	msg(LOG_DEBUG, context, "cb_close()");
	if (context != NULL) {
		smfi_setpriv(ctx, NULL);
		free(context->res);
		if (context->quarantine != NULL)
			free(context->quarantine);
		context->rs->refcnt--;
		free(context);
	}
	return (SMFIS_CONTINUE);
}

struct smfiDesc smfilter = {
	"milter-regex",	/* filter name */
	SMFI_VERSION,	/* version code -- do not change */
	SMFIF_QUARANTINE, /* flags */
	cb_connect,	/* connection info filter */
	cb_helo,	/* SMTP HELO command filter */
	cb_envfrom,	/* envelope sender filter */
	cb_envrcpt,	/* envelope recipient filter */
	cb_header,	/* header filter */
	cb_eoh,		/* end of header */
	cb_body,	/* body block */
	cb_eom,		/* end of message */
	NULL,		/* message aborted */
	cb_close,	/* connection cleanup */
	NULL,		/* unrecognized or unimplemented command filter */
	NULL,		/* SMTP DATA command filter */
	NULL		/* negotiation callback */
};

static void
msg(int priority, struct context *context, const char *fmt, ...)
{
	va_list ap;
	char msg[8192];

	va_start(ap, fmt);
	if (context != NULL)
		snprintf(msg, sizeof(msg), "%s [%s]: ", context->host_name,
		    context->host_addr);
	else
		msg[0] = 0;
	vsnprintf(msg + strlen(msg), sizeof(msg) - strlen(msg), fmt, ap);
	if (debug)
		printf("syslog: %s\n", msg);
	else
		syslog(priority, "%s", msg);
	va_end(ap);
}

static void
usage(const char *argv0)
{
	fprintf(stderr, "usage: %s [-dt] [-c config] [-f facility] "
	    "[-j dirname] [-l loglevel] [-m number] [-p pipe] [-r pid-file] "
	    "[-u user] [-G group] [-P mode] [-U user]\n", argv0);
	exit(1);
}

void
die(const char *reason)
{
	msg(LOG_ERR, NULL, "die: %s", reason);
	smfi_stop();
	sleep(60);
	/* not reached, smfi_stop() kills thread */
	abort();
}

int
main(int argc, char **argv)
{
	int ch, maskpri = LOG_INFO;
	const char *oconn = OCONN;
	const char *pid_file_name = NULL;
	const char *user = USER;
	const char *jail = NULL;
	sfsistat r = MI_FAILURE;
	const char *ofile = NULL;
	const char *pgroup = NULL;
	const char *puser = NULL;
	mode_t pperm = 0600;
	int facility = LOG_DAEMON;
	int test_ruleset = 0;
	FILE *f = NULL;

	while ((ch = getopt(argc, argv, "c:df:j:l:m:p:r:tu:G:P:U:")) != -1) {
		switch (ch) {
		case 'c':
			rule_file_name = optarg;
			break;
		case 'd':
			debug = 1;
			break;
		case 'f': {
			int i;

			for (i = 0; facilitynames[i].c_name != NULL; ++i)
				if (!strcmp(facilitynames[i].c_name, optarg)) {
					facility = facilitynames[i].c_val;
					break;
				}
			break;
		}
		case 'j':
			jail = optarg;
			break;
		case 'l':
			maskpri = atoi(optarg);
			break;
		case 'm':
			maxlines = atoi(optarg);
			break;
		case 'p':
			oconn = optarg;
			break;
		case 't':
			test_ruleset = 1;
			break;
		case 'r':
			pid_file_name = optarg;
			break;
		case 'u':
			user = optarg;
			break;
		case 'G':
			pgroup = optarg;
			break;
		case 'P':
			pperm = strtol(optarg, (char **)NULL, 8);
			break;
		case 'U':
			puser = optarg;
			break;
		default:
			usage(argv[0]);
		}
	}
	if (argc != optind) {
		fprintf(stderr, "unknown command line argument: %s ...",
		    argv[optind]);
		usage(argv[0]);
	}

	tzset();
	openlog("milter-regex", LOG_PID | LOG_NDELAY, facility);
	setlogmask(LOG_UPTO(maskpri));

	if (!strncmp(oconn, "unix:", 5))
		ofile = oconn + 5;
	else if (!strncmp(oconn, "local:", 6))
		ofile = oconn + 6;
	else if (!strchr(oconn, ':'))
		ofile = oconn;

	if (jail != NULL && (chroot(jail) || chdir("/"))) {
		perror("chroot");
		return (1);
	}

	if (test_ruleset) {
		return (get_ruleset() == NULL ? 1 : 0);
	}

	if (smfi_setconn((char *)oconn) != MI_SUCCESS) {
		fprintf(stderr, "smfi_setconn: %s: failed\n", oconn);
		goto done;
	}

	if (smfi_register(smfilter) != MI_SUCCESS) {
		fprintf(stderr, "smfi_register: failed\n");
		goto done;
	}

	if (pid_file_name != NULL) {
		umask(0133);
		if ((f = fopen(pid_file_name, "w")) == NULL) {
			fprintf(stderr, "fopen: %s: %s\n", pid_file_name,
			    strerror(errno));
			return (1);
		}
	}

	umask(0777);
	if (smfi_opensocket(true) != MI_SUCCESS) {
		fprintf(stderr, "smfi_opensocket: failed\n");
		goto done;
	}

	/* modify socket file ownership and permissions, drop privileges */
	if (!getuid()) {
		struct passwd *pw;
		struct group *gr;
		uid_t uid = -1;
		gid_t gid = -1;

		if (ofile != NULL && puser != NULL) {
			if ((pw = getpwnam(puser)) == NULL) {
				fprintf(stderr, "getpwnam: %s: %s\n", puser,
				    strerror(errno));
				return (1);
			}
			uid = pw->pw_uid;
		}
		if (ofile != NULL && pgroup != NULL) {
			if ((gr = getgrnam(pgroup)) == NULL) {
				fprintf(stderr, "getgrnam: %s: %s\n", pgroup,
				    strerror(errno));
				return (1);
			}
			gid = gr->gr_gid;
		}
		if ((uid != -1 || gid != -1) && chown(ofile, uid, gid)) {
			fprintf(stderr, "chown: %s: %s\n", ofile,
			    strerror(errno));
			return (1);
		}
		if (ofile != NULL && chmod(ofile, pperm)) {
			fprintf(stderr, "chmod: %s: %s\n", ofile,
			    strerror(errno));
			return (1);
		}
		if ((pw = getpwnam(user)) == NULL) {
			fprintf(stderr, "getpwnam: %s: %s\n", user,
			    strerror(errno));
			return (1);
		}
		if (setgroups(1, &pw->pw_gid)) {
			perror("setgroups");
			return (1);
		}
		if (setgid(pw->pw_gid)) {
			perror("setgid");
			return (1);
		}
		if (setuid(pw->pw_uid)) {
			perror("setuid");
			return (1);
		}
	}

	if (pthread_mutex_init(&mutex, 0)) {
		fprintf(stderr, "pthread_mutex_init\n");
		goto done;
	}

	if (eval_init(ACTION_ACCEPT)) {
		fprintf(stderr, "eval_init: failed\n");
		goto done;
	}

	/* daemonize (detach from controlling terminal) */
	if (!debug && daemon(0, 0)) {
		perror("daemon");
		goto done;
	}

	if (f != NULL) {
		fprintf(f, "%d", (int)getpid());
		fclose(f);
	}

	msg(LOG_INFO, NULL, "started: %s", rcsid);
	r = smfi_main();
	if (r != MI_SUCCESS)
		msg(LOG_ERR, NULL, "smfi_main: terminating due to error");
	else
		msg(LOG_INFO, NULL, "smfi_main: terminating without error");

done:
	return (r);
}
