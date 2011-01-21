/********************************************
 * vi: set ts=4 sw=4
 * Hallock
 * pam_gmirror module
 *
 * $Id$
 * Copyright (C) 2008-2011, vitki.net
 *
 */

#ifndef PGM_SESS_C
#define PGM_SESS_C

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <stdarg.h>
#include <syslog.h>
#include <string.h>

#include "pgm-logging.c"
#include "pgm-hashes.c"
#include "pgm-util.c"

static hash_t sessions;

static int
alloc_session_hashes(pam_handle_t *pamh)
{
	sessions = hash_alloc(pamh);
	return sessions == NULL ? PAM_BUF_ERR : PAM_SUCCESS;
}

static void
free_session_hashes(pam_handle_t *pamh)
{
	hash_free(pamh, sessions);
	sessions = NULL;
}

static int
load_sessions (pam_handle_t *pamh)
{
	const char *fname = MGROUPS_SESS;
	FILE *fgroup;
	char line[BUFLEN];
	char *name_p, *count_p, *s;
	int count;

	fgroup = fopen(fname, "r");
	if (fgroup == NULL) {
		logit(pamh, LOG_INFO, "%s not found", fname);
		return PAM_SUCCESS;
	}

	while (fgets(line, BUFLEN-1, fgroup) != NULL) {
		line[BUFLEN-1] = '\0';
		/* skip whitespace and check for comment */
		if (*line == '\0')
			continue;
		s = line + strlen(line) - 1;
		while ((isspace(*s) || *s == '\r' || *s == '\n') && s != line)
			s--;
		*(s + 1) = '\0';
		s = line;
		while (isspace(*s))
			s++;
		if (*s == '\0')
			continue;
		/* extract count */
		count_p = s;
		while (isdigit(*s))
			s++;
		if (s == count_p || !isspace(*s)) {
			logit(pamh, LOG_DEBUG, "syntax error in sessions: %s", line);
			continue;
		}
		*s++ = '\0';
		count = atoi(count_p);
		/* extract username */
		while (isspace(*s))
			s++;
		name_p = s;
		while (!isspace(*s) && *s != '\0')
			s++;
		if (s == name_p) {
			logit(pamh, LOG_DEBUG, "syntax error in sessions: %s", line);
			continue;
		}
		*s = '\0';

		/* add local group */
		hash_put(pamh, sessions, name_p, (void *)count);
	}
	fclose(fgroup);
	return PAM_SUCCESS;
}

static int
save_sessions (pam_handle_t *pamh)
{
	char temp_name[256];
	int htemp;
	char *user, *count_s;
	int count;
	int ret;
	char buf[BUFLEN], ermes[ERMESLEN];
	pid_t pid = getpid();

	pid = 0;
	sprintf(temp_name, TEMP_MGROUPS_SESS, (unsigned) pid);

	htemp = open(temp_name, O_WRONLY | O_CREAT | O_TRUNC, MGROUPS_SESS_MODE);
	if (htemp < 0) {
		logit(pamh, LOG_ERR, "cannot create temporary file %s: %s",
				temp_name, strerror_r(errno, ermes, ERMESLEN));
		return PAM_CRED_ERR;
	}

	HASH_LOOP(sessions, user, count_s) {
		count = (int) count_s;
		sprintf(buf, "%-10d %s\n", count, user);
		write(htemp, buf, strlen(buf));
	} HASH_ENDLOOP;

	close(htemp);
	logit(pamh, LOG_DEBUG, "wrote temporary file %s", temp_name);

	/* and rename the file atomically */
	ret = rename(temp_name, MGROUPS_SESS);
	if (ret < 0) {
		unlink(temp_name);
		logit(pamh, LOG_ERR, "cannot rename \"%s\" to \"%s\": %s",
				temp_name, MGROUPS_SESS, strerror_r(errno, ermes, ERMESLEN));
		return PAM_AUTH_ERR;
	}
	return PAM_SUCCESS;
}

static int
update_logon_count(pam_handle_t *pamh, const char *user, int logon, int *count_ptr)
{
	int ret, count;
	*count_ptr = 0;
	if ((ret = load_sessions(pamh)) != PAM_SUCCESS)
		return ret;
	count = (int) hash_get(pamh, sessions, user);
	if (logon) {
		count++;
	} else if (count <= 0) {
		logit(pamh, LOG_ERR, "logon count for \"%s\" is invalid: %d", user, count);
		count = 0;
	} else {
		count--;
	}
	*count_ptr = count;
	if (count == 0)
		hash_remove(pamh, sessions, user);
	else
		hash_put(pamh, sessions, user, (void *)count);
	if ((ret = save_sessions(pamh)) != PAM_SUCCESS)
		return ret;
	return PAM_SUCCESS;
}

#endif /* PGM_SESS_C */

