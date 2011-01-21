/********************************************
 * vi: set ts=4 sw=4
 * Hallock
 * pam_gmirror module
 *
 * $Id$
 * Copyright (C) 2008-2011, vitki.net
 *
 */

#ifndef PGM_HASHES_C
#define PGM_HASHES_C

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <stdarg.h>
#include <syslog.h>
#include <string.h>

#include "pgm-logging.c"
#include "pgm-util.c"

#define SET1	((void *)1)

typedef struct slist_elem_st {
	struct slist_elem_st *next;
	char *str;
	void *ptr;
} elem_t;

typedef elem_t *hash_t;

#define HASH_LOOP(__set, __str, __ptr)				\
	do {											\
		elem_t *__cur, *__next;						\
		if (__set != NULL) {						\
			__cur = __set->next;					\
			while (__cur != NULL) {					\
				__next = __cur->next;				\
				__str = __cur->str;					\
				__ptr = __cur->ptr;					\
				do {								\


#define HASH_ENDLOOP								\
				} while (0);						\
				__cur = __next;						\
			}										\
		}											\
	} while(0)

#define hash_find(pamh,set,str) hash_find_len(pamh,set,str,-1)
#define hash_get(pamh,set,str) hash_get_len(pamh,set,str,-1)
#define hash_put(pamh,set,str,ptr) hash_put_len(pamh,set,str,-1,ptr)
#define hash_remove(pamh,set,str) hash_remove_len(pamh,set,str,-1)

static elem_t *free_hash_list = NULL;
/*static char **free_str_list = NULL;*/

static void
free_hash_memory(pam_handle_t *pamh)
{
	while (free_hash_list != NULL) {
		elem_t *cur = free_hash_list;
		free_hash_list = cur->next;
		mg_free(pamh, cur, sizeof(elem_t));
	}
}


static hash_t
hash_alloc (pam_handle_t *pamh)
{
	hash_t hash;
	if (free_hash_list != NULL) {
		hash = free_hash_list;
		free_hash_list = hash->next;
	} else {
		hash = (hash_t) mg_malloc (pamh, sizeof(elem_t));
	}
	if (hash != NULL) {
		hash->str = NULL;
		hash->ptr = NULL;
		hash->next = NULL;
	}
	return hash;
}

static void
hash_clear (pam_handle_t *pamh, hash_t set)
{
	elem_t *cur, *next;
	if (set != NULL) {
		cur = set->next;
		while (cur != NULL) {
			next = cur->next;
			mg_free(pamh, cur->str, 0);
			cur->str = NULL;
			cur->ptr = NULL;
			cur->next = free_hash_list;
			free_hash_list = cur;
			cur = next;
		}
		set->next = NULL;
	}
}

static void
hash_free (pam_handle_t *pamh, hash_t set)
{
	hash_clear(pamh, set);
	set->next = free_hash_list;
	free_hash_list = set;
}

static elem_t *
hash_find_len (pam_handle_t *pamh, hash_t set, const char *str, int len)
{
	elem_t *cur;
	if (set != NULL) {
		if (len < 0)
			len = strlen(str);
		cur = set->next;
		while (cur != NULL) {
			if (strncmp(cur->str, str, len) == 0 && cur->str[len] == '\0')
				return cur;
			cur = cur->next;
		}
	}
	return NULL;
}

static void *
hash_get_len (pam_handle_t *pamh, hash_t set, const char *str, int len)
{
	elem_t *found;
	found = hash_find_len(pamh, set, str, len);
	return found == NULL ? NULL : found->ptr == NULL ? SET1 : found->ptr;
}

static int
hash_put_len (pam_handle_t *pamh, hash_t set, const char *str, int len, void *ptr)
{
	elem_t *elem, *last;
	if (set == NULL)
		return -1;
	if (len < 0)
		len = strlen(str);
	if (len == 0)
		return -1;
	elem = hash_find_len(pamh, set, str, len);
	if (elem != NULL) {
		if (elem->ptr == ptr)
			return 1;
		elem->ptr = ptr;
		return 0;
	}
	if (free_hash_list != NULL) {
		elem = free_hash_list;
		free_hash_list = elem->next;
	} else {
		elem = (elem_t *) mg_malloc(pamh, sizeof(elem_t));
		if (elem == NULL)
			return -1;
	}
	elem->str = (char *) mg_malloc(pamh, len + 1);
	if (elem->str == NULL)
		return -1;
	memcpy(elem->str, str, len);
	elem->str[len] = '\0';
	elem->ptr = ptr;
	for (last = set; last->next != NULL; last = last->next);
	elem->next = NULL;
	last->next = elem;
	return 0;
}

static int
hash_remove_len (pam_handle_t *pamh, hash_t set, const char *str, int len)
{
	elem_t *cur, *prev;
	if (set == NULL)
		return -1;
	prev = set;
	cur = set->next;
	while (cur != NULL) {
		if (strncmp(cur->str, str, len) == 0 && cur->str[len] == '\0') {
			prev->next = cur->next;
			mg_free(pamh, cur->str, 0);
			cur->next = free_hash_list;
			free_hash_list = cur;
			return 0;
		}
		prev = cur;
		cur = cur->next;
	}
	return -1;
}

FUNC_UNUSED static int
hash_size (pam_handle_t *pamh, hash_t set)
{
	int size;
	elem_t *cur;
	if (set == NULL)
		return -1;
	size = 0;
	cur = set->next;
	while (cur != NULL) {
		cur = cur->next;
		size++;
	}
	return size;
}

FUNC_UNUSED static hash_t
hash_copy (pam_handle_t *pamh, hash_t source)
{
	char *str;
	void *ptr;
	hash_t dest = hash_alloc(pamh);
	if (dest != NULL) {
		HASH_LOOP(source, str, ptr) {
			hash_put(pamh, dest, str, ptr);
		} HASH_ENDLOOP;
	}
	return dest;
}

#endif /* PGM_HASHES_C */

