/* radare - LGPL - Copyright 2018 - pancake */

#include <r_util/r_alloc.h>

static RMalloc *_r_malloc = malloc;
static RCalloc *_r_calloc = calloc;
static RRealloc *_r_realloc = realloc;
static RFree *_r_free = free;

R_API void r_alloc_hooks(RMalloc m, RCalloc c, RRealloc r, RFree f) {
	r_return_if_fail (m && c && r && f);
	_r_malloc = m;
	_r_calloc = c;
	_r_realloc = r;
	_r_free = f;
}

R_API void r_alloc_init () {
	r_alloc_hooks (malloc, calloc, realloc, free);
}

R_API void *r_malloc(size_t sz) {
	return _r_malloc (sz);
}

R_API void *r_calloc(size_t count, size_t sz) {
	return _r_calloc (sz);
}

R_API void *r_realloc(void *p, size_t sz) {
	return _r_realloc (p, sz);
}

R_API void r_free(void *p) {
	return _r_free (p);
}
