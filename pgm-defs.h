/********************************************
 * vi: set ts=4 sw=4
 * Hallock
 * pam_gmirror module
 *
 * $Id$
 * Copyright (C) 2008-2011, vitki.net
 *
 */

#ifndef PGM_DEFS_H
#define PGM_DEFS_H

#define ETC_GROUP_FILE		"/etc/group"
#define TEMP_ETC_GROUP_NAME	"/etc/.group.gmirror.%u"
#define ETC_GROUP_MODE		0644
#define MIRRORGROUPS_CONF   "/etc/security/gmirror.conf"
#define MGROUPS_SESS		"/var/run/gmirror-sessions"
#define TEMP_MGROUPS_SESS	"/var/run/.gmirror-sessions.%u"
#define MGROUPS_SESS_MODE	0644
#define LOGOFF_HELPER		"/lib/security/pam_gmirror_helper"
#define SEMAPHORE_NAME		"pam_gmirror"
#define SEMAPHORE_MODE		0644
#define NSCD_PID_FILE		"/var/run/nscd/nscd.pid"
/*#define PROC_PID_EXE		"/proc/%lu/exe"*/
#define NSCD_EXE			"/usr/sbin/nscd"
#define BUFLEN				1024
#define ERMESLEN			128
#define ALWAYS_RUN_HELPER   0
#define UNUSED
#define FUNC_UNUSED __attribute__((unused))

enum rule_ops {
	op_none,	/* ?? */
	op_include,	/* += */
	op_exclude,	/* -= */
	op_assoc,	/* := */
	op_disable,	/* :: */
	op_gid		/* == */
};

enum pam_logon_entry {
	entry_logoff = 0,
	entry_logon_sess = 1,
	entry_logon_auth = 2,
};

#define OPCHARS "+-=:"

#endif /* PGM_DEFS_H */

