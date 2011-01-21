/********************************************
 * vi: set ts=4 sw=4
 * Hallock
 * pam_gmirror module
 *
 * $Id$
 * Copyright (C) 2008-2011, vitki.net
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

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
#include "pgm-util.c"
#include "pgm-sess.c"
#include "pgm-nscd.c"

static int
alloc_hashes (pam_handle_t *pamh)
{
	if (   alloc_session_hashes(pamh) == PAM_SUCCESS
		&& alloc_rule_hashes(pamh) == PAM_SUCCESS
		&& alloc_etcgroup_memory(pamh) == PAM_SUCCESS
		&& alloc_user_hashes(pamh) == PAM_SUCCESS)
		return PAM_SUCCESS;
	else
		return PAM_BUF_ERR;
}

static void
free_hashes (pam_handle_t *pamh)
{
	free_session_hashes(pamh);
	free_rule_hashes(pamh);
	free_etcgroup_memory(pamh);
	free_user_hashes(pamh);
	free_hash_memory(pamh);
	mg_free_memory(pamh);
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
			logit(pamh, LOG_INFO, "remove \"%s\" from \"%s\"", user, group);
			hash_remove(pamh, gptr->members, user);
			gptr->modify = mod_remove;
			applied++;
		}
	} HASH_ENDLOOP;

	logit(pamh, LOG_DEBUG, "%d logoff changes will be applied", applied);
	return applied;
}

static int
handle_logoff(pam_handle_t *pamh, const char *user, int curr_uid)
{
	int ret, count, method;
	logit(pamh, LOG_DEBUG, "handle_logoff: user=%s curr_uid=%d", user, curr_uid);
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
	count = apply_logoff(pamh, user);
	if (count == 0)
		return PAM_SUCCESS;
	ret = save_etc_groups(pamh);
	update_nscd(pamh);
	return ret;
}

static void
su_sighandler(int sig)
{
#ifndef SA_RESETHAND
	/* emulate the behaviour of the SA_RESETHAND flag */
	if (sig == SIGILL || sig == SIGTRAP || sig == SIGBUS || sig = SIGSERV)
		signal(sig, SIG_DFL);
#endif
	if (sig > 0)
		_exit(sig);
}

static void
setup_signals(void)
{
	struct sigaction action;
	memset((void *) &action, 0, sizeof(action));
	action.sa_handler = su_sighandler;
#ifdef SA_RESETHAND
	action.sa_flags = SA_RESETHAND;
#endif
	sigaction(SIGILL, &action, NULL);
	sigaction(SIGTRAP, &action, NULL);
	sigaction(SIGBUS, &action, NULL);
	sigaction(SIGSEGV, &action, NULL);
	action.sa_handler = SIG_IGN;
	action.sa_flags = 0;
	sigaction(SIGTERM, &action, NULL);
	sigaction(SIGHUP, &action, NULL);
	sigaction(SIGINT, &action, NULL);
	sigaction(SIGQUIT, &action, NULL);
}

/*
	usage:
		/lib/security/pam_gmirror_helper logoff username non|info|debug
*/
int
main (int argc, char **argv)
{
	pam_handle_t *pamh = NULL;
	int retval;
	char *user, *option;
	sem_t *sem;
	int uid = (int) getuid();

	console = 0;
	user = argv[2];
	option = argv[3];

	/* catch or ignore as many signal as possible. */
	setup_signals();

	/*	discourage casual use */
	if (isatty(STDIN_FILENO)
		|| geteuid() != 0
		|| argc != 4
		|| strcmp(argv[1], "logoff") != 0
		|| *user == '\0'
		|| *option == '\0')
	{
		console = 1;
		logit(pamh, LOG_ERR, "inappropriate use of helper binary (uid=%d)", uid);
		sleep(10);		/* discourage/annoy the user */
		return PAM_SYSTEM_ERR;
	}

	show_debug = show_info = 0;
	if (strcmp(option, "debug") == 0)
		show_debug = 1;
	else if (strcmp(option, "info") == 0)
		show_info = 1;

	/* serialize access to internal structures */
	retval = PAM_SYSTEM_ERR;
	sem = mg_lock(pamh);
	if (sem != SEM_FAILED) {
		/* do the job */
		alloc_hashes(pamh);
		retval = handle_logoff(pamh, user, uid);
		free_hashes(pamh);
		mg_unlock(pamh, sem);
	}

	return retval;
}

