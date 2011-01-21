/********************************************
 * vi: set ts=4 sw=4
 * Hallock
 * pam_gmirror module
 *
 * $Id$
 * Copyright (C) 2008-2011, vitki.net
 *
 */

#ifndef PGM_UTIL_C
#define PGM_UTIL_C

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <semaphore.h>

#include "pgm-defs.h"

#define mg_strcpy(s,d)		(strcpy((s),(d)),(s)+strlen(s))
#define mg_strcatc(s,c)		(*(s)++ = (c), *(s) = '\0')

static void *
mg_malloc (pam_handle_t *pamh, size_t size)
{
	void *p = malloc(size);
	if (p != NULL)
		memset(p, '\0', size);
	return p;
}

static void
mg_free (pam_handle_t *pamh, void *p, size_t size)
{
	char *s;
	if (p != NULL) {
		if (size > 0) {
			memset(p, '\0', size);
		} else {
			for (s = p; *s != '\0'; s++)
				*s = '\0';
		}
		free(p);
	}
}

FUNC_UNUSED static void *
mg_realloc (pam_handle_t *pamh, void *p, size_t oldsize, size_t newsize)
{
	void *newp;
	if (p == NULL)
		return NULL;
	if (oldsize <= 0)
		oldsize = strlen((char *) p) + 1;
	if (newsize <= oldsize)
		return p;
	newp = mg_malloc(pamh, newsize);
	if (newp == NULL) {
		mg_free(pamh, p, oldsize);
		return NULL;
	}
	memcpy(newp, p, oldsize);
	return newp;
}

static char *
mg_strdup (pam_handle_t *pamh, const char *s)
{
	char *p;
	if (s == NULL)
		return NULL;
	p = mg_malloc(pamh, strlen(s) + 1);
	if (p != NULL)
		strcpy(p, s);
	return p;
}

static void
mg_free_memory (pam_handle_t *pamh)
{
}

static sem_t *
mg_lock(pam_handle_t *pamh)
{
	char ermes[ERMESLEN];
	sem_t *sem;

	sem = sem_open(SEMAPHORE_NAME, O_CREAT, SEMAPHORE_MODE, 1);
	if (sem == SEM_FAILED) {
		logit(pamh, LOG_ERR, "cannot open semaphore %s: %s",
				SEMAPHORE_NAME, strerror_r(errno, ermes, ERMESLEN));
		return SEM_FAILED;
	}
	if (sem_wait(sem) < 0) {
		logit(pamh, LOG_ERR, "cannot wait on semaphore %s: %s",
				SEMAPHORE_NAME, strerror_r(errno, ermes, ERMESLEN));
		sem_close(sem);
		return SEM_FAILED;
	}
	return sem;
}

static int
mg_unlock(pam_handle_t *pamh, sem_t *sem)
{
	if (sem == SEM_FAILED)
		return PAM_AUTH_ERR;
	sem_post(sem);
	sem_close(sem);
	return PAM_SUCCESS;
}

#endif /* PGM_UTIL_C */

