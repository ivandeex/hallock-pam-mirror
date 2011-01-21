/********************************************
 * vi: set ts=4 sw=4
 * Hallock
 * pam_gmirror module
 *
 * $Id$
 * Copyright (C) 2008-2011, vitki.net
 *
 */

#ifndef PGM_USER_C
#define PGM_USER_C

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <stdarg.h>
#include <syslog.h>
#include <string.h>

#include <pwd.h>
#include <grp.h>

#include "pgm-logging.c"
#include "pgm-hashes.c"
#include "pgm-etcgroup.c"

static hash_t all_groups, user_groups, group_gids;
static int user_uid, user_gid;

static int
alloc_user_hashes(pam_handle_t *pamh)
{
	all_groups = hash_alloc(pamh);
	user_groups = hash_alloc(pamh);
	group_gids = hash_alloc(pamh);
	if (all_groups == NULL || user_groups == NULL || group_gids == NULL)
		return PAM_BUF_ERR;
	else
		return PAM_SUCCESS;
}

static void
free_user_hashes(pam_handle_t *pamh)
{
	char *name, *gid_str;
	HASH_LOOP(group_gids, gid_str, name) {
		mg_free(pamh, name, 0);
	} HASH_ENDLOOP;
	hash_free(pamh, group_gids);
	hash_free(pamh, all_groups);
	hash_free(pamh, user_groups);
	group_gids = all_groups = user_groups = NULL;
}

static int
check_user_id (pam_handle_t *pamh, const char *user, int curr_uid)
{
	struct passwd *pw, pw_buf;
	char buf[BUFLEN], ermes[ERMESLEN];
	int retval;

	if (pamh == NULL) {
		retval = getpwnam_r(user, &pw_buf, buf, BUFLEN, &pw);
	} else {
		pw = pam_modutil_getpwnam(pamh, user);
		retval = pw == NULL ? errno : 0;
	}
	if (pw == NULL) {
		logit(pamh, LOG_ERR, "user \"%s\" not found: %s",
				user, strerror_r(retval, ermes, ERMESLEN));
		return PAM_USER_UNKNOWN;
	}

	user_uid = pw->pw_uid;
	user_gid = pw->pw_gid;

	/* verify user id */
	if (user_uid == 0) {
		logit(pamh, LOG_DEBUG, "will not change root groups");
		memset(buf, '\0', BUFLEN);
		return PAM_IGNORE;
	}
	if (curr_uid != 0 && user_uid != curr_uid) {
		logit(pamh, LOG_INFO, "user id mismatch: %d <> %d", user_uid, curr_uid);
		memset(buf, '\0', BUFLEN);
		return PAM_USER_UNKNOWN;
	}

	return PAM_SUCCESS;
}

static int
get_user_groups(pam_handle_t *pamh, const char *user, int *method)
{
	struct group *gr, gr_buf;
	char buf[BUFLEN], ermes[ERMESLEN];
	int i, j, retval, ngroups, size;
	char *group;
	char gid_str[12];
	gid_t *gids, gid;
	lgroup_t *gptr;

	/* find all secondary groups containing this user */
	*method = 0;

	/* first method - get current user groups - fails on fedora 7 */
	ngroups = getgroups(0, NULL);
	if (ngroups > 0) {
		size = (ngroups + 1) * sizeof(gid_t);
		if ((gids = mg_malloc(pamh, size)) == NULL) {
			logit(pamh, LOG_ERR, "cannot allocate space for groups");
			ngroups = 0;
		} else if ((retval = getgroups(ngroups, gids)) < 0) {
			logit(pamh, LOG_ERR, "getgroups() failed: %s",
					strerror_r(errno, ermes, ERMESLEN));
			ngroups = 0;
		} else {
			/* find info for primary group too */
			gids[ngroups] = user_gid;
			/* find info for secondary groups */
			for (i = 0; i <= ngroups; i++) {
				/* avoid duplicate requests */
				for (j = 0; j < i; j++) {
					if (gids[j] == gids[i])
						break;
				}
				if (j < i)
					continue;
				/* request group id */
				gid = gids[i];
				if (pamh == NULL) {
					gr = NULL;
					retval = getgrgid_r(gid, &gr_buf, buf, BUFLEN, &gr);
				} else {
					gr = pam_modutil_getgrgid(pamh, gid);
					retval = gr == NULL ? errno : 0;
				}
				if (gr == NULL) {
					logit(pamh, LOG_ERR,
						"secondary group id %d not found: %s",
						(int)gid, strerror_r(retval, ermes, ERMESLEN));
					continue;
				}
				group = gr->gr_name;
				hash_put(pamh, user_groups, group, SET1);
				hash_put(pamh, all_groups, group, (void *) gid);
				sprintf(gid_str, "%d", (int) gid);
				hash_put(pamh, group_gids, gid_str, mg_strdup(pamh, group));
				logit(pamh, LOG_DEBUG, "group \"%s\" id %d", group, (int) gid);
			}
			/* memorize group ids for local groups */
			HASH_LOOP(etc_groups, group, gptr) {
				gid = gr->gr_gid;
				hash_put(pamh, all_groups, group, (void *) gid);
				sprintf(gid_str, "%d", (int) gid);
				hash_put(pamh, group_gids, gid_str, mg_strdup(pamh, group));
			} HASH_ENDLOOP;
			/* done */
			*method = 1;
			return PAM_SUCCESS;
		}
	}

	/* second method - full scan of the group database - fails in ubuntu 8.04 */
	setgrent();
	while (1) {
		retval = getgrent_r(&gr_buf, buf, BUFLEN, &gr);
		if (gr == NULL)
			break;
		group = gr->gr_name;
		gid = gr->gr_gid;
		for (i = 0; gr->gr_mem[i] != NULL; i++) {
			if (strcmp(gr->gr_mem[i], user) == 0) {
				/* user belongs to this group */
				hash_put(pamh, user_groups, group, SET1);
				logit(pamh, LOG_DEBUG,
					"user \"%s\" belongs to \"%s\"", user, gr->gr_name);
				break;
			}
		}
		/* remember group id */
		hash_put(pamh, all_groups, group, (void *) gid);
		sprintf(gid_str, "%d", (int) gid);
		hash_put(pamh, group_gids, gid_str, mg_strdup(pamh, group));
		logit(pamh, LOG_DEBUG, "group \"%s\" id %d", group, (int) gid);
	}
	endgrent();
	memset(buf, '\0', BUFLEN);

	/* and the primary group for this user */
	sprintf(gid_str, "%d", user_gid);
	group = hash_get(pamh, group_gids, gid_str);
	if (group == NULL) {
		logit(pamh, LOG_INFO,
			"cannot get group %d name for user \"%s\"", user_gid, user);
	} else {
		hash_put(pamh, user_groups, group, SET1);
	}

	*method = 2;
	return PAM_SUCCESS;
}


#endif /* PGM_USER_C */

