/********************************************
 * vi: set ts=4 sw=4
 * Hallock
 * pam_gmirror module
 *
 * $Id$
 * Copyright (C) 2008-2011, vitki.net
 *
 */

#include <sys/file.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define PAM_SM_AUTH

#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>

#include "pgm-defs.h"
#include "pgm-hashes.c"
#include "pgm-logging.c"
#include "pgm-etcgroup.c"
#include "pgm-user.c"
#include "pgm-rules.c"
#include "pgm-sess.c"
#include "pgm-nscd.c"

static hash_t ignored;

static int
alloc_hashes(pam_handle_t *pamh)
{
	if ((ignored = hash_alloc(pamh)) == NULL)
		return PAM_BUF_ERR;
	if (   alloc_session_hashes(pamh) == PAM_SUCCESS
		&& alloc_rule_hashes(pamh) == PAM_SUCCESS
		&& alloc_etcgroup_memory(pamh) == PAM_SUCCESS
		&& alloc_user_hashes(pamh) == PAM_SUCCESS)
		return PAM_SUCCESS;
	return PAM_BUF_ERR;
}

static void
free_hashes(pam_handle_t *pamh)
{
	hash_free(pamh, ignored);
	ignored = NULL;
	free_session_hashes(pamh);
	free_rule_hashes(pamh);
	free_etcgroup_memory(pamh);
	free_user_hashes(pamh);
	free_hash_memory(pamh);
	mg_free_memory(pamh);
}

/* ======== analyze user ======== */

static int
get_skin_name(pam_handle_t *pamh, char *name, int namelen)
{
	const char *fname = "/proc/cmdline";
	char buf[BUFLEN];
	int len;
	FILE *fcmd;
	char *s;

	*name = '\0';
	if (namelen < 2)
		return -1;

	fcmd = fopen(fname, "r");
	if (fcmd == NULL) {
		logit(pamh, LOG_ERR, "cannot read %s", fname);
		return -1;
	}

	while (fscanf(fcmd, " %s ", buf) == 1) {
		buf[BUFLEN - 1] = 0;
		if (strncmp(buf, "skin=", 5) == 0) {
			s = buf + 5;
			while (*s != '\0' && *s != '\r' && *s != '\n' && !isspace(*s))
				s++;
			len = s - buf;
			if (len < namelen)
				namelen = len;
			if (namelen > 0)
				memcpy(name, buf, namelen);
			name[namelen] = '\0';
			logit(pamh, LOG_DEBUG, "current skin is \"%s\"", name);
			break;
		}
	}

	fclose(fcmd);
	return 0;
}

static int
apply_logon_rules (pam_handle_t *pamh, const char *user)
{
	int applied, iter;
	char *group, *member;
	int gid;
	void *unused;
	hash_t set, copy, disable_set;
	lgroup_t *gptr;
	int in_local, in_final, is_managed;
	char cur_skin[64];
	char buf[BUFLEN];
	struct group *gr, gr_buf;
	int retval;
	char gid_str[12];

	/* disable by skin */
	disable_set = NULL;
	get_skin_name(pamh, cur_skin, sizeof(cur_skin) - 1);
	if (*cur_skin != '\0')
		disable_set = hash_get(pamh, disable, cur_skin);
	logit(pamh, LOG_DEBUG, "set for skin \"%s\" is %p", cur_skin, disable_set);

	iter = 0;

	/* apply inclusions */
	hash_clear(pamh, ignored);
	do {
		iter++;
		applied = 0;
		if (show_debug) {
			logit(pamh, LOG_DEBUG, "inclusion iteration %d:", iter);
			HASH_LOOP(user_groups, member, unused) {
				logit(pamh, LOG_DEBUG, "    member \"%s\"", member);
			} HASH_ENDLOOP;
		}

		HASH_LOOP(user_groups, group, unused) {
			if (!hash_get(pamh, ignored, group)
					&& (set = hash_get(pamh, include, group)) != NULL) {
				HASH_LOOP(set, member, unused) {
					hash_put(pamh, user_groups, member, SET1);
					logit(pamh, LOG_DEBUG,
						" ...and group \"%s\" includes \"%s\"", group, member);
				} HASH_ENDLOOP;
				applied++;
				hash_put(pamh, ignored, group, SET1);
			}
		} HASH_ENDLOOP;
	} while (applied > 0);

	/* apply associations */
	hash_clear(pamh, ignored);
	do {
		iter++;
		applied = 0;
		if (show_debug) {
			logit(pamh, LOG_DEBUG, "association iteration %d:", iter);
			HASH_LOOP(user_groups, member, unused) {
				logit(pamh, LOG_DEBUG, "    member \"%s\"", member);
			} HASH_ENDLOOP;
		}

		HASH_LOOP(user_groups, group, unused) {
			if (!hash_get(pamh, ignored, group)
					&& (set = hash_get(pamh, assoc, group)) != NULL) {
				HASH_LOOP(set, member, unused) {
					if (hash_put(pamh, user_groups, member, SET1) == 0)
						applied++;
					logit(pamh, LOG_DEBUG,
						" ...and group \"%s\" associates \"%s\"", group, member);
				} HASH_ENDLOOP;
				hash_put(pamh, ignored, group, SET1);
			}
		} HASH_ENDLOOP;
	} while (applied > 0);

	/* apply exclusions */
	hash_clear(pamh, ignored);
	do {
		iter++;
		applied = 0;
		if (show_debug) {
			logit(pamh, LOG_DEBUG, "exclusion iteration %d:", iter);
			HASH_LOOP(user_groups, member, unused) {
				logit(pamh, LOG_DEBUG, "    member \"%s\"", member);
			} HASH_ENDLOOP;
		}

		copy = hash_copy(pamh, user_groups);
		HASH_LOOP(user_groups, group, unused) {
			if ((set = hash_get(pamh, exclude, group)) != NULL) {
				HASH_LOOP(set, member, unused) {
					if (hash_remove(pamh, copy, member) == 0)
						applied++;
					logit(pamh, LOG_DEBUG,
						" ...and group \"%s\" excludes \"%s\"", group, member);
				} HASH_ENDLOOP;
			}
		} HASH_ENDLOOP;
		hash_free(pamh, user_groups);
		user_groups = copy;
	} while (0);

	/* apply skin disabler */
	if (disable_set != NULL) {
		HASH_LOOP(disable_set, member, unused) {
			if (hash_remove(pamh, user_groups, member) == 0)
				applied++;
			logit(pamh, LOG_DEBUG, " ...and skin \"%s\" excludes \"%s\"",
					cur_skin, member);
		} HASH_ENDLOOP;
	}

	/* find group ids for user groups */
	logit(pamh, LOG_DEBUG, "user group ids:");
	copy = hash_copy(pamh, user_groups);
	HASH_LOOP(user_groups, group, unused) {
		gid = (int) hash_get(pamh, all_groups, group);
		if (gid == 0) {
			if (pamh == NULL) {
				gr = NULL;
				retval = getgrnam_r(group, &gr_buf, buf, BUFLEN, &gr);
			} else {
				gr = pam_modutil_getgrnam(pamh, group);
				retval = gr == NULL ? errno : 0;
			}
			if (gr != NULL) {
				gid = (int) gr->gr_gid;
				hash_put(pamh, all_groups, group, (void *) gid);
				sprintf(gid_str, "%d", (int) gid);
				hash_put(pamh, group_gids, gid_str, mg_strdup(pamh, group));
			}
		}
		if (gid == 0) {
			logit(pamh, LOG_ERR, "cannot determine gid for user group \"%s\"", group);
		} else {
			hash_put(pamh, copy, group, (void *) gid);
			logit(pamh, LOG_DEBUG, "    %d", gid);
		}
	} HASH_ENDLOOP;
	hash_free(pamh, user_groups);
	user_groups = copy;

	/* find local groups to act on */
	applied = 0;
	HASH_LOOP(etc_groups, group, gptr) {
		is_managed = group_is_managed(pamh, group);
		in_final = hash_get(pamh, user_groups, group) != NULL;
		in_local = hash_get(pamh, gptr->members, user) != NULL;
		if (is_managed && in_final && !in_local) {
			hash_put(pamh, gptr->members, user, SET1);
			gptr->modify = mod_add;
			applied++;
			logit(pamh, LOG_INFO, "add \"%s\" to \"%s\"", user, group);
		} else if (is_managed && in_local && !in_final) {
			hash_remove(pamh, gptr->members, user);
			gptr->modify = mod_remove;
			applied++;
			logit(pamh, LOG_INFO, "remove \"%s\" from \"%s\"", user, group);
		} else {
			gptr->modify = mod_none;
		}
	} HASH_ENDLOOP;

	logit(pamh, LOG_DEBUG, "%d logon changes will be applied", applied);
	return applied;
}

static int
apply_logoff (pam_handle_t *pamh, const char *user)
{
	char *group;
	lgroup_t *gptr;
	int applied = 0;

	HASH_LOOP(etc_groups, group, gptr) {
		gptr->modify = mod_none;
		if (gptr->managed && hash_get(pamh, gptr->members, user)) {
			logit(pamh, LOG_INFO, "will remove \"%s\" from \"%s\"", user, group);
			hash_remove(pamh, gptr->members, user);
			gptr->modify = mod_remove;
			applied++;
		}
	} HASH_ENDLOOP;

	logit(pamh, LOG_DEBUG, "%d logoff changes will be applied", applied);
	return applied;
}

static int
run_logoff_helper (pam_handle_t *pamh, const char *user)
{
	const char *prog = LOGOFF_HELPER;
	char *argv[5];
	char *verbosity;
	int retval;

	if (show_debug)
		verbosity = "debug";
	else if (show_info)
		verbosity = "info";
	else
		verbosity = "err";
	argv[0] = (char *) prog;
	argv[1] = "logoff";
	argv[2] = (char *) user;
	argv[3] = verbosity;
	argv[4] = NULL;

	retval = run_program(pamh, prog, argv, user);
	return retval;
}

static int
set_user_gids (pam_handle_t *pamh, const char *user, int method)
{
	int max_gids, ngids, size_gids, i, warned;
	gid_t gid, *gids;
	char buf[BUFLEN], ermes[ERMESLEN];
	char *s, *group;
	lgroup_t *gptr;

	if (method != 1 && getuid() == 0) {
		logit(pamh, LOG_DEBUG, "no need to reset groups");
		return PAM_SUCCESS;
	}

	max_gids = sysconf(_SC_NGROUPS_MAX);
	if (max_gids <= 0) {
		logit(pamh, LOG_ERR, "cannot determine NGROUPS_MAX: %s",
				strerror_r(errno, ermes, ERMESLEN));
		return PAM_AUTH_ERR;
	}
	size_gids = max_gids * sizeof(gid_t);
	gids = (gid_t *) mg_malloc(pamh, size_gids);
	if (gids == NULL) {
		logit(pamh, LOG_ERR, "cannot allocate memory for group ids");
		return PAM_BUF_ERR;
	}

	ngids = getgroups(max_gids, gids);
	if (ngids < 0) {
		logit(pamh, LOG_ERR, "getgroups failed: %s",
				strerror_r(errno, ermes, ERMESLEN));
		mg_free(pamh, gids, size_gids);
		return PAM_AUTH_ERR;
	}
	if (show_debug) {
		s = buf;
		for (i = 0; i < ngids; i++) {
			if (i > 0)
				mg_strcatc(s, ',');
			s += sprintf(s, "%d", gids[i]);
		}
		*s = '\0';
		logit(pamh, LOG_DEBUG,
				"get \"%s\" group ids (max=%d num=%d): %s",
				user, max_gids, ngids, buf);
	}

	warned = 0;
	HASH_LOOP(etc_groups, group, gptr) {
		if (gptr->managed) {
			gid = gptr->gid;
			if (hash_get(pamh, gptr->members, user)) {
				for (i = 0; i < ngids; i++) {
					if (gids[i] == gid)
						break;
				}
				if (i == ngids) {
					if (ngids < max_gids) {
						gids[ngids++] = gptr->gid;
					} else if (warned == 0) {
						logit(pamh, LOG_ERR,
							"cannot add more groups: limit reached");
						warned = 1;
					}
				}
			} else {
				i = 0;
				while (i < ngids) {
					if (gids[i] == gid) {
						ngids--;
						if (i < ngids) {
							memcpy(&gids[i], &gids[i+1],
									(ngids - i) * sizeof(gid_t));
						}
					} else {
						i++;
					}
				}
			}
		}
	} HASH_ENDLOOP;

	if (show_debug || show_info) {
		s = buf;
		for (i = 0; i < ngids; i++) {
			if (i > 0)
				mg_strcatc(s, ',');
			s += sprintf(s, "%d", gids[i]);
		}
		*s = '\0';
		logit(pamh, LOG_INFO,
			"set \"%s\" group ids (num=%d): %s", user, ngids, buf);
	}

	if (setgroups(ngids, gids) < 0) {
		logit(pamh, LOG_ERR, "setgroups failed: %s",
				strerror_r(errno, ermes, ERMESLEN));
		return PAM_AUTH_ERR;
	}

	mg_free(pamh, gids, size_gids);
	return PAM_SUCCESS;
}

static int
handle_logon (pam_handle_t *pamh, const char *user, int curr_uid)
{
	int ret, count, method;
	if ((ret = update_logon_count(pamh, user, 1, &count)) != PAM_SUCCESS)
		return ret;
	if ((ret = check_user_id(pamh, user, curr_uid)) != PAM_SUCCESS)
		return ret;
	if ((ret = load_etc_groups(pamh)) != PAM_SUCCESS)
		return ret;
	if ((ret = get_user_groups(pamh, user, &method)) != PAM_SUCCESS)
		return ret;
	if ((ret = parse_rules(pamh, 1)) != PAM_SUCCESS)
		return ret;
	count = apply_logon_rules(pamh, user);
	if (method == 1)
		set_user_gids(pamh, user, method);
	if (count == 0)
		return PAM_SUCCESS;
	ret = save_etc_groups(pamh);
	update_nscd(pamh);
	return ret;
}

static int
handle_logoff (pam_handle_t *pamh, const char *user, int curr_uid)
{
	int ret, count, method;
	if ((ret = update_logon_count(pamh, user, 0, &count)) != PAM_SUCCESS)
		return ret;
	if (count > 0) {
		logit(pamh, LOG_INFO, "\"%s\" still has %d logons to do", user, count);
		return PAM_SUCCESS;
	}
	if ((ret = check_user_id(pamh, user, curr_uid)) != PAM_SUCCESS)
		return ret;
	if ((ret = load_etc_groups(pamh)) != PAM_SUCCESS)
		return ret;
	if ((ret = get_user_groups(pamh, user, &method)) != PAM_SUCCESS)
		return ret;
	if ((ret = parse_rules(pamh, 0)) != PAM_SUCCESS)
		return ret;
	if ((count = apply_logoff(pamh, user)) == 0 && !ALWAYS_RUN_HELPER)
		return PAM_SUCCESS;
	if (geteuid() != 0 || ALWAYS_RUN_HELPER)
		return run_logoff_helper(pamh, user);
	if (count == 0)
		return PAM_SUCCESS;
	ret = save_etc_groups(pamh);
	update_nscd(pamh);
	return ret;
}

static int
handle_pam_options(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int i;

	show_debug = show_info = 0;
	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "debug") == 0)
			show_debug = 1;
		else if (strcmp(argv[i], "info") == 0)
			show_info = 1;
	}
	return 0;
}

static int
handle_call (pam_handle_t *pamh, const char *user, int logon, int ruid)
{
	int retval;
	sem_t *sem;

	if (logon == 0 && (geteuid() != 0 || ALWAYS_RUN_HELPER)) {
		retval = run_logoff_helper(pamh, user);
	} else {
		/* serialize access to internal structures */
		retval = PAM_AUTH_ERR;
		sem = mg_lock(pamh);
		if (sem != SEM_FAILED) {
			/* do the job */
			alloc_hashes(pamh);
			if (logon)
				retval = handle_logon(pamh, user, ruid);
			else
				retval = handle_logoff(pamh, user, ruid);
			free_hashes(pamh);
			mg_unlock(pamh, sem);
		}
	}

	return retval;
}

static int
handle_pam_call(pam_handle_t *pamh, int flags, int logon, const char *who)
{
	const char *user = NULL;
	int retval;
	struct passwd *pw;

	if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS
		|| user == NULL || *user == '\0'
		|| (pw = pam_modutil_getpwnam(pamh, user)) == NULL)
	{
		logit(pamh, LOG_ERR, "cannot determine the user's name");
		return PAM_USER_UNKNOWN;
	}

	/* not applied to root */
	if (pw->pw_uid == 0)
		return PAM_SUCCESS;

	retval = handle_call(pamh, user, logon, 0);

	logit(pamh, LOG_INFO, "%s logon=%d user=%s uid=%d euid=%d retval=%d",
			who, logon, user, (int)getuid(), (int)geteuid(), retval);
	return retval;
}

/* --- public authentication management functions --- */

PAM_EXTERN int
pam_sm_authenticate (pam_handle_t *pamh UNUSED, int flags UNUSED,
		     int argc UNUSED, const char **argv UNUSED)
{
	return PAM_IGNORE;
}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int logon, retval;
	handle_pam_options(pamh, flags, argc, argv);
	if (flags & PAM_ESTABLISH_CRED) {
		logon = entry_logon_sess;
	} else if (flags & PAM_DELETE_CRED) {
		logon = entry_logoff;
	} else {
		logit(pamh, LOG_DEBUG, "ignoring call (flags=0x%x)", flags);
		return PAM_SUCCESS;
	}
	retval = handle_pam_call(pamh, flags, logon, "setcred");
	if (retval != PAM_SUCCESS)
		retval = PAM_IGNORE;
	return retval;
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	handle_pam_options(pamh, flags, argc, argv);
	handle_pam_call(pamh, flags, entry_logon_sess, "open_sess");
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	handle_pam_options(pamh, flags, argc, argv);
	handle_pam_call(pamh, flags, entry_logoff, "close_sess");
	return PAM_SUCCESS;
}

/* end of module definition */

#ifdef PAM_STATIC
/* static module data */

struct pam_module _pam_gmirror_modstruct = {
	"pam_gmirror",
	pam_sm_authenticate,
	pam_sm_setcred,
	NULL,
	pam_sm_open_session,
	pam_sm_close_session,
	NULL
};
#endif

#ifdef TEST_MAIN
int
main (int argc, char **argv)
{
	pam_handle_t *pamh = NULL;
	char *user = "root";
	char *action = "logon";
	char *odbg = "";
	int logon, retval;

	if (argc < 4) {
		printf("usage: pam_mirrorgroups user logon|logoff debug|info|quiet\n");
		return 1;
	}
	user = argv[1];
	action = argv[2];
	odbg = argv[3];
	logon = (strcmp(action, "logon") == 0);
	show_debug = (strcmp(odbg, "debug") == 0);
	show_info = (strcmp(odbg, "info") == 0);
	console = 1;
	logit(pamh, LOG_DEBUG, "user=\"%s\"", user);

	retval = handle_call(pamh, user, logon, 0);

	logit(pamh, LOG_INFO, "retval=0x%x", retval);
	return 0;
}
#endif /* TEST_MAIN */

