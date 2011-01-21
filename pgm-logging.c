/********************************************
 * vi: set ts=4 sw=4
 * Hallock
 * pam_gmirror module
 *
 * $Id$
 * Copyright (C) 2008-2011, vitki.net
 *
 */

#ifndef PGM_LOGGING_C
#define PGM_LOGGING_C

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <stdarg.h>
#include <syslog.h>
#include <string.h>

static int show_debug = 0;
static int show_info = 0;
static int console = 0;

static int
logit (pam_handle_t *pamh, int prio, const char *fmt, ...)
{
	char *prefix;
	char buf[BUFLEN];

	if (prio == LOG_DEBUG && !show_debug)
		return -1;
	else if (prio == LOG_INFO && !show_debug && !show_info)
		return -1;

	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFLEN, fmt, ap);
	va_end(ap);
	buf[BUFLEN-1] = '\0';

	if (console) {
		switch (prio) {
			case LOG_DEBUG:		prefix = "debug";	break;
			case LOG_ERR:		prefix = "err";		break;
			default:			prefix = "info";	break;
		}
		fprintf(stdout, "%s: %s\n", prefix, buf);
	} else if (pamh == NULL) {
		openlog("gmirror-helper", LOG_PID, LOG_AUTHPRIV);
		syslog(prio, "%s", buf);
		closelog();
	} else {
		pam_syslog(pamh, prio, "%s", buf);
	}

	return 0;
}

#endif /* PGM_LOGGING_C */

