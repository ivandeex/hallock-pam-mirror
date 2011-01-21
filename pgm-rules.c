/********************************************
 * vi: set ts=4 sw=4
 * Hallock
 * pam_gmirror module
 *
 * $Id$
 * Copyright (C) 2008-2011, vitki.net
 *
 */

#ifndef PGM_RULES_C
#define PGM_RULES_C

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <semaphore.h>

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

static hash_t include, exclude, assoc, disable;

static int
alloc_rule_hashes(pam_handle_t *pamh)
{
	if ((include = hash_alloc(pamh)) == NULL)
		return PAM_BUF_ERR;
	if ((exclude = hash_alloc(pamh)) == NULL)
		return PAM_BUF_ERR;
	if ((assoc = hash_alloc(pamh)) == NULL)
		return PAM_BUF_ERR;
	if ((disable = hash_alloc(pamh)) == NULL)
		return PAM_BUF_ERR;
	return PAM_SUCCESS;
}

static void
free_hash_of_hashes(pam_handle_t *pamh, hash_t hash)
{
	char *name;
	hash_t h;
	HASH_LOOP(hash, name, h) {
		hash_free(pamh, h);
	} HASH_ENDLOOP;
	hash_free(pamh, hash);
}

static void
free_rule_hashes(pam_handle_t *pamh)
{
	free_hash_of_hashes(pamh, include);
	free_hash_of_hashes(pamh, exclude);
	free_hash_of_hashes(pamh, assoc);
	free_hash_of_hashes(pamh, disable);
	include = exclude = assoc = disable = NULL;
}

static int
rule_opcode (const char *op)
{
	if (strcmp(op, "+=") == 0)
		return op_include;
	if (strcmp(op, "-=") == 0)
		return op_exclude;
	if (strcmp(op, ":=") == 0)
		return op_assoc;
	if (strcmp(op, "::") == 0)
		return op_disable;
	if (strcmp(op, "==") == 0)
		return op_gid;
	return op_none;
}

/*
	pass 0:
		parse all directives, only apply '==' directives,
		only report syntax errors and errors in '==' directives,
		report debugging information
	pass 1:
		parse all directives, apply all but '==' directives
		do not report syntax errors and debugging information,
		report errors in all but '==' directives
*/
static int
apply_rule(pam_handle_t *pamh,
			const char *group, const char *skin, const char *op_str,
			hash_t members, int lineno, const char *fname, int pass)
{
	char *member;
	void *unused;
	char *s;
	int op;
	int gid;
	lgroup_t *gptr;
	hash_t set, op_set;

	op = rule_opcode(op_str);

	if (show_debug && pass == (op != op_gid)) {
		logit(pamh, LOG_DEBUG,
				"line %d: group=\"%s\" skin=\"%s\" op=\"%s\" member_num=%d",
				lineno, group, skin, op_str, hash_size(pamh, members));
		HASH_LOOP(members, member, unused) {
			logit(pamh, LOG_DEBUG, "line %d:     member \"%s\"", lineno, member);
		} HASH_ENDLOOP;
	}

	/* disable_for_skin */
	if (strcmp(group, "disable_for_skin") == 0
			|| op == op_disable || *skin != '\0') {
		if (pass == 0)
			return 0;
		logit(pamh, LOG_DEBUG, "skin directive: skin=\"%s\"", skin);

		if (strcmp(group, "disable_for_skin") != 0
				|| op != op_disable || *skin == '\0') {
			logit(pamh, LOG_ERR,
					"%s: line %d: error in disable_for_skin directive",
					fname, lineno);
			return -1;
		}

		set = hash_get(pamh, disable, skin);
		if (set == NULL) {
			set = hash_alloc(pamh);
			hash_put(pamh, disable, skin, set);
		}

		HASH_LOOP(members, member, unused) {
			if (group_is_managed(pamh, member)) {
				hash_put(pamh, set, member, SET1);
			} else {
				logit(pamh, LOG_ERR,
						"%s: line %d: disable_for_skin: local group \"%s\" not found",
						fname, lineno, member);
			}
		} HASH_ENDLOOP;

		return 0;
	}

	/* include/exclude directives */
	if (op == op_include || op == op_exclude) {
		if (pass == 0)
			return 0;
		logit(pamh, LOG_DEBUG, "%s directive: \"%s\" (members)",
				op == op_include ? "include" : "exclude", group);

		if (group_is_managed(pamh, group)) {
			logit(pamh, LOG_ERR,
					"%s: line %d: left-side group \"%s\" should not be local",
					fname, lineno, group);
			return -1;
		}

		op_set = op == op_include ? include : exclude;
		set = hash_get(pamh, op_set, group);
		if (set == NULL) {
			set = hash_alloc(pamh);
			hash_put(pamh, op_set, group, set);
		}

		HASH_LOOP(members, member, unused) {
			if (group_is_managed(pamh, member)) {
				logit(pamh, LOG_ERR,
						"%s: line %d: right-side group \"%s\" should not be local",
						fname, lineno, member);
			} else {
				hash_put(pamh, set, member, SET1);
			}
		} HASH_ENDLOOP;

		return 0;
	}

	/* association directive */
	if (op == op_assoc) {
		if (pass == 0)
			return 0;
		logit(pamh, LOG_DEBUG, "assign directive: \"%s\" (members)", group);

		if (group_is_managed(pamh, group)) {
			logit(pamh, LOG_ERR,
					"%s: line %d: left-side group \"%s\" should not be local",
					fname, lineno, group);
			return -1;
		}

		set = hash_get(pamh, assoc, group);
		if (set == NULL) {
			set = hash_alloc(pamh);
			hash_put(pamh, assoc, group, set);
		}

		HASH_LOOP(members, member, unused) {
			if (group_is_managed(pamh, member)) {
				hash_put(pamh, set, member, SET1);
			} else {
				logit(pamh, LOG_ERR,
						"%s: line %d: assign: local group \"%s\" not found",
						fname, lineno, member);
			}
		} HASH_ENDLOOP;

		return 0;
	}

	/* group id directive */
	if (op == op_gid) {
		if (pass == 1)
			return 0;
		if (hash_size(pamh, members) != 1) {
			logit(pamh, LOG_ERR, "%s: line %d: must be only one group id",
					fname, lineno);
			return -1;
		}

		HASH_LOOP(members, member, unused) {
			for (s = member; isdigit(*s); s++);
			if (*s != '\0') {
				logit(pamh, LOG_ERR,
					"%s: line %d: group id must be a number", fname, lineno);
				return -1;
			}
			gid = atoi(member);
		} HASH_ENDLOOP;

		logit(pamh, LOG_DEBUG, "group id directive: \"%s\" gid=%d", group, gid);
		gptr = hash_get(pamh, etc_groups, group);
		if (gptr == NULL) {
			logit(pamh, LOG_ERR, "%s: line %d: local group \"%s\" not found",
					fname, lineno, group);
			return -1;
		}
		if (gptr->gid != gid) {
			logit(pamh, LOG_ERR,
				"%s: line %d: local group \"%s\" id mismatch: %d != %d",
				fname, lineno, group, gptr->gid, gid);
			return -1;
		}

		gptr->managed = 1;
		return 0;
	}

	if (pass == 1) {
		logit(pamh, LOG_ERR, "%s: line %d: unknown rule \"%s\"", fname, lineno, op_str);
	}

	return -1;
}

static int
parse_rule_line(pam_handle_t *pamh, char *line, int pass, int lineno,
				hash_t members, const char *fname)
{
	char null[1];
	char *s, *group_p, *skin_p, *op_p, *member_p;
	int group_n, skin_n, op_n, member_n;

	/* parse line */
	*null = '\0';
	s = line;
	while (isspace(*s))
		s++;
	group_p = s;
	while (isalnum(*s) || *s == '-' || *s == '_')
		s++;
	group_n = s - group_p;
	while (isspace(*s))
		s++;
	skin_p = null;
	skin_n = 0;
	if (*s == '(') {
		skin_p = ++s;
		while (isalnum(*s) || *s == '-' || *s == '_')
			s++;
		if (*s == ')') {
			skin_n = s - skin_p;
			s++;
		} else {
			skin_p = null;
			while (!isspace(*s) && strchr(OPCHARS, *s) == NULL && *s != '\0')
				s++;
		}
	}
	while (isspace(*s))
		s++;
	op_p = s;
	while (strchr(OPCHARS, *s) != NULL)
		s++;
	op_n = s - op_p;
	while (isspace(*s))
		s++;
	while (*s != '\0') {
		member_p = s;
		while (isalnum(*s) || *s == '-' || *s == '_')
			s++;
		member_n = s - member_p;
		while (isspace(*s))
			s++;
		if (member_n == 0)
			break;
		hash_put_len(pamh, members, member_p, member_n, SET1);
	}
	if (group_n == 0 || op_n == 0 || *s != '\0') {
		if (pass == 0) {
			logit(pamh, LOG_ERR, "%s: illegal syntax in line %d: %s",
					fname, lineno, line);
			*(group_p + group_n) = '\0';
			*(skin_p + skin_n) = '\0';
			*(op_p + op_n) = '\0';
			logit(pamh, LOG_DEBUG,
				"error: group=\"%s\" skin=\"%s\" op=\"%s\" rest=\"%s\"",
				group_p, skin_p, op_p, s);
		}
		return -1;
	}
	*(group_p + group_n) = '\0';
	*(skin_p + skin_n) = '\0';
	*(op_p + op_n) = '\0';

	return apply_rule(pamh, group_p, skin_p, op_p, members, lineno, fname, pass);
}

static int
parse_rules_pass (pam_handle_t *pamh, FILE *frules, const char *fname, int pass)
{
	char *cont, *line, *s;
	char buf[BUFLEN];
	int lineno, lineadd;
	hash_t members;

	cont = NULL;
	line = buf;
	lineno = 1;
	lineadd = 0;
	while (1) {
		s = fgets(buf, BUFLEN-1, frules);
		if  (s == NULL)
			break;
		lineno += lineadd;
		lineadd = 0;
		buf[BUFLEN-1] = '\0';
		/* skip whitespace and check for comment */
		s = buf;
		while (isspace(*s))
			s++;
		if (*s == '#' || *s == '\0')
			continue;
		while (*s != '#' && *s != '\0')
			s++;
		if (*s == '#')
			*s = '\0';
		s = buf + strlen(buf)-1;
		while (s != buf && (*s == '\r' || *s == '\n')) {
			if (*s == '\n')
				lineadd++;
			s--;
		}
		if (s == buf)
			continue;
		if (*s == '\\') {
			/* to be continued */
			*s = '\0';
			if (cont == NULL) {
				cont = mg_strdup(pamh, buf);
			} else {
				cont = mg_realloc(pamh, cont, 0, strlen(cont) + strlen(buf) + 1);
				strcat(cont, buf);
			}
			continue;
		}
		*(s + 1) = '\0';
		/* merge current buffer and continuations */
		if (cont != NULL) {
			line = mg_malloc(pamh, strlen(cont) + strlen(buf) + 1);
			strcpy(line, cont);
			strcat(line, buf);
			cont = NULL;
		} else {
			line = buf;
		}
		members = hash_alloc(pamh);
		parse_rule_line(pamh, line, pass, lineno, members, fname);
		hash_free(pamh, members);
		if (line != buf)
			mg_free(pamh, line, 0);
	}

	return 0;
}

static int
parse_rules (pam_handle_t *pamh, int all_passes)
{
	char *group;
	lgroup_t *gptr;
	const char *fname = MIRRORGROUPS_CONF;
	FILE *frules;

	frules = fopen(fname, "r");
	if (frules == NULL) {
		logit(pamh, LOG_ERR, "cannot open %s, exiting.", fname);
		return -1;
	}

	parse_rules_pass(pamh, frules, fname, 0);
	if (all_passes) {
		rewind(frules);
		parse_rules_pass(pamh, frules, fname, 1);
	}
	fclose(frules);

	if (show_debug) {
		logit(pamh, LOG_DEBUG, "got local groups");
		HASH_LOOP(etc_groups, group, gptr) {
			if (gptr->managed) {
				logit(pamh, LOG_DEBUG, "    got managed local group \"%s\"", group);
			}
		} HASH_ENDLOOP;
	}

	return 0;
}

#endif /* PGM_RULES_C */

