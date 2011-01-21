/********************************************
 * vi: set ts=4 sw=4
 * Hallock
 * pam_gmirror module
 *
 * $Id$
 * Copyright (C) 2008-2011, vitki.net
 *
 */

#ifndef PGM_ETCGROUP_C
#define PGM_ETCGROUP_C

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

enum { mod_none, mod_add, mod_remove };

typedef struct lgroup_st {
	struct lgroup_st *next;
	char *  name;
	char *  pass;
	int		gid;
	int		managed;
	int		modify;
	hash_t   members;
} lgroup_t;


static char *hidden_pass = "x";
static hash_t etc_groups;
static lgroup_t *free_lgroups;

static lgroup_t *
lgroup_alloc (pam_handle_t *pamh, const char *name)
{
	lgroup_t *lgroup;
	if (free_lgroups != NULL) {
		lgroup = free_lgroups;
		free_lgroups = lgroup->next;
	} else {
		lgroup = (lgroup_t *) mg_malloc(pamh, sizeof(lgroup_t));
	}
	if (lgroup != NULL) {
		lgroup->next = NULL;
		lgroup->name = mg_strdup(pamh, name);
		lgroup->pass = hidden_pass;
		lgroup->gid = 0;
		lgroup->managed = 0;
		lgroup->modify = 0;
		lgroup->members = hash_alloc(pamh);
	}
	return lgroup;
}

static void
lgroup_free (pam_handle_t *pamh, lgroup_t *lgroup)
{
	if (lgroup != NULL) {
		mg_free(pamh, lgroup->name, 0);
		lgroup->name = NULL;
		if (lgroup->pass != hidden_pass)
			mg_free(pamh, lgroup->pass, 0);
		lgroup->pass = NULL;
		lgroup->gid = 0;
		lgroup->managed = 0;
		lgroup->modify = 0;
		hash_free(pamh, lgroup->members);
		lgroup->members = NULL;
		lgroup->next = free_lgroups;
		free_lgroups = lgroup;
	}
}

static int
alloc_etcgroup_memory(pam_handle_t *pamh)
{
	free_lgroups = NULL;
	etc_groups = hash_alloc(pamh);
	return etc_groups == NULL ? PAM_BUF_ERR : PAM_SUCCESS;
}

static void
free_etcgroup_memory(pam_handle_t *pamh)
{
	char *name;
	lgroup_t *lgroup;
	HASH_LOOP(etc_groups, name, lgroup) {
		lgroup_free(pamh, lgroup);
	} HASH_ENDLOOP;
	hash_free(pamh, etc_groups);
	etc_groups = NULL;
	while (free_lgroups != NULL) {
		lgroup = free_lgroups;
		free_lgroups = lgroup->next;
		mg_free(pamh, lgroup, sizeof(lgroup_t));
	}
}

FUNC_UNUSED static int
group_is_managed (pam_handle_t *pamh, const char *group)
{
	lgroup_t *gptr = hash_get(pamh, etc_groups, group);
	return (gptr != NULL && gptr->managed);
}

static int
load_etc_groups (pam_handle_t *pamh)
{
	const char *fname = ETC_GROUP_FILE;
	FILE *fgroup;
	char line[BUFLEN];
	char *name_p, *gid_p, *member_p, *pass_p, *s;
	int gid;
	lgroup_t *lgroup;

	fgroup = fopen(fname, "r");
	if (fgroup == NULL) {
		logit(pamh, LOG_ERR, "cannot open %s, exiting.", fname);
		return PAM_CRED_ERR;
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
		if (*s == '#' || *s == '\0')
			continue;

		/* extract name */
		name_p = s;
		while (*s != ':' && *s != '\0')
			s++;
		if (s == name_p || *s != ':')
			continue;
		*s++ = '\0';

		/* extract pass */
		pass_p = s;
		while (*s != ':' && *s != '\0')
			s++;
		if (*s != ':')
			continue;
		*s++ = '\0';

		/* extract group id */
		gid_p = s;
		while (isdigit(*s))
			s++;
		if (s == gid_p || *s != ':')
			continue;
		*s++ = '\0';
		gid = atoi(gid_p);

		/* add local group */
		lgroup = hash_get(pamh, etc_groups, name_p);
		logit(pamh, LOG_DEBUG, "local group: name=\"%s\" gid=%d found=%p", name_p, gid, lgroup);
		if (lgroup == NULL) {
			lgroup = lgroup_alloc(pamh, name_p);
			hash_put(pamh, etc_groups, name_p, lgroup);
		}
		lgroup->gid = gid;
		if (strcmp(pass_p, hidden_pass) != 0)
			lgroup->pass = mg_strdup(pamh, pass_p);

		/* extract members */
		while (isspace(*s))
			s++;
		while (*s != '\0') {
			member_p = s;
			while (*s != ',' && *s != '\0')
				s++;
			if (*s != '\0')
				*s++ = '\0';
			hash_put(pamh, lgroup->members, member_p, SET1);
			logit(pamh, LOG_DEBUG, "    local group member: \"%s\"", member_p);
		}
	}
	fclose(fgroup);
	return PAM_SUCCESS;
}

static int
save_etc_groups (pam_handle_t *pamh)
{
	char temp_name[256];
	int htemp;
	char *group;
	lgroup_t *gptr;
	char *member;
	void *unused;
	int first;
	int ret;
	char buf[BUFLEN], ermes[ERMESLEN];
	char *s;
	pid_t pid = getpid();

	pid = 0;
	sprintf(temp_name, TEMP_ETC_GROUP_NAME, (unsigned) pid);

	htemp = open(temp_name, O_WRONLY | O_CREAT | O_TRUNC, ETC_GROUP_MODE);
	if (htemp < 0) {
		logit(pamh, LOG_ERR, "cannot create temporary file %s: %s",
				temp_name, strerror_r(errno, ermes, ERMESLEN));
		return PAM_CRED_ERR;
	}

	HASH_LOOP(etc_groups, group, gptr) {
		s = buf;
		s = mg_strcpy(s, group);
		mg_strcatc(s, ':');
		s = mg_strcpy(s, gptr->pass);
		mg_strcatc(s, ':');
		s += sprintf(s, "%d", gptr->gid);
		mg_strcatc(s, ':');
		first = 1;
		HASH_LOOP(gptr->members, member, unused) {
			if (!first) {
				first = 0;
				mg_strcatc(s, ',');
			}
			s = mg_strcpy(s, member);
		} HASH_ENDLOOP;
		mg_strcatc(s, '\n');
		write(htemp, buf, s - buf);
	} HASH_ENDLOOP;

	close(htemp);
	logit(pamh, LOG_DEBUG, "wrote temporary file %s", temp_name);

	/* and rename the file atomically */
	ret = rename(temp_name, ETC_GROUP_FILE);
	if (ret < 0) {
		unlink(temp_name);
		logit(pamh, LOG_ERR, "cannot rename \"%s\" to \"%s\": %s",
				temp_name, ETC_GROUP_FILE,
				strerror_r(errno, ermes, ERMESLEN));
		return PAM_CRED_ERR;
	}
	return PAM_SUCCESS;
}

#endif /* PGM_ETCGROUP_C */

