/********************************************
 * vi: set ts=4 sw=4
 * Hallock
 * pam_gmirror module
 *
 * $Id$
 * Copyright (C) 2008-2011, vitki.net
 *
 */

#ifndef PGM_NSCD
#define PGM_NSCD

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

static int
run_program (pam_handle_t *pamh, const char *prog, char * const argv[], const char *stdin)
{
	pid_t pid;
	int st, retval, fd, fds[2];
	char ermes[ERMESLEN];
	struct rlimit rlim;

	if (access(prog, X_OK) < 0) {
		logit(pamh, LOG_INFO, "program \"%s\" is not executable", prog);
		return PAM_IGNORE;
	}

    if (pipe(fds) != 0) {
		logit(pamh, LOG_ERR, "cannot create pipe: %s",
				strerror_r(errno, ermes, ERMESLEN));
		return PAM_SYSTEM_ERR;
    }

	pid = fork();
	if (pid < 0) {
		logit(pamh, LOG_ERR, "fork failed: %s",
				strerror_r(errno, ermes, ERMESLEN));
		return PAM_SYSTEM_ERR;
	}

	if (pid == 0) {
		/* only give him stdin */
		close(0);
		close(1);
		close(fds[1]);
		dup2(fds[0], STDIN_FILENO);
		if (getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
			for (fd = 2; fd < (int)rlim.rlim_max; fd++) {
				if (fds[0] != fd)
					close(fd);
			}
		}

		/*	set ruid to 0 so helper won't fail from setuid binary (su, sudo...) */
		if (geteuid() == 0)
			setuid(0);

		execv(prog, argv);
		logit(pamh, LOG_ERR, "\"%s\" invocation failed: %s",
				prog, strerror_r(errno, ermes, ERMESLEN));
		exit(PAM_SYSTEM_ERR);
	}

	/* write something to stdin */
	if (stdin != NULL) {
		write(fds[1], stdin, strlen(stdin));
	}
	close(fds[0]);		/* close here to avoid possible SIGPIPE above */
	close(fds[1]);

	/* wait for results */
	st = -1;
	pid = waitpid(pid, &st, 0);
	if (pid == -1) {
		logit(pamh, LOG_ERR, "waiting for \"%s\" failed: %s",
				prog, strerror_r(errno, ermes, ERMESLEN));
		return PAM_SYSTEM_ERR;
	}
	if (WIFEXITED(st) == 0) {
		logit(pamh, LOG_ERR, "\"%s\" aborted", prog);
		return PAM_SYSTEM_ERR;
	}

	retval = WEXITSTATUS(st);
	logit(pamh, LOG_DEBUG, "\"%s\" returns %d", prog, retval);
	return retval;
}

static int
update_nscd (pam_handle_t *pamh)
{
	char prog[32];
	char *argv[4];
	int retval;
	const char *pidfname = NSCD_PID_FILE;
	unsigned long ulpid;
	FILE *pidfile;

	pidfile = fopen(pidfname, "r");
	if (pidfile == NULL) {
		logit(pamh, LOG_DEBUG, "nscd pid file %s not found", pidfname);
		return PAM_IGNORE;
	}
	ulpid = 0;
	fscanf(pidfile, " %lu", &ulpid);
	fclose(pidfile);
	if (ulpid == 0) {
		logit(pamh, LOG_INFO, "nscd pid file %s is invalid", pidfname);
		return PAM_IGNORE;
	}
	if (kill((pid_t) ulpid, 0) < 0) {
		logit(pamh, LOG_INFO, "nscd pid %lu is stale in file %s", ulpid, pidfname);
		return PAM_IGNORE;
	}

#ifdef PROC_PID_EXE
	sprintf(prog, PROC_PID_EXE, ulpid);
#else
	strcpy(prog, NSCD_EXE);
#endif

	argv[0] = prog;
	argv[1] = "-i";
	argv[2] = "group";
	argv[3] = NULL;
	retval = run_program(pamh, prog, argv, NULL);

	logit(pamh, retval == 0 ? LOG_DEBUG : LOG_INFO,
			"nscd (pid=%lu) returns %d", ulpid, retval);

	return retval;
}

#endif /* PGM_NSCD */

