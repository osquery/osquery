/* gen_tables.h -- Declarations used for lookup tables.
 * Copyright 2008 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *      Miloslav Trmač <mitr@redhat.com>
 */
#ifndef GEN_TABLES_H__
#define GEN_TABLES_H__

#include <stddef.h>
#include <stdint.h>

/* Assumes ASCII; verified in gen_tables.c. */
#define GT_ISUPPER(X) ((X) >= 'A' && (X) <= 'Z')
#define GT_ISLOWER(X) ((X) >= 'a' && (X) <= 'z')

inline static int s2i__(const char *strings, const unsigned *s_table,
			const int *i_table, size_t n, const char *s, int *value)
{
	ssize_t left, right;

	left = 0;
	right = n - 1;
	while (left <= right) {	/* invariant: left <= x <= right */
		size_t mid;
		int r;

		mid = (left + right) / 2;
		/* FIXME? avoid recomparing a common prefix */
		r = strcmp(s, strings + s_table[mid]);
		if (r == 0) {
			*value = i_table[mid];
			return 1;
		}
		if (r < 0)
			right = mid - 1;
		else
			left = mid + 1;
	}
	return 0;
}

inline static const char *i2s_direct__(const char *strings,
				       const unsigned *table, int min, int max,
				       int v)
{
	unsigned off;

	if (v < min || v > max)
		return NULL;
	off = table[v - min];
	if (off != -1u)
		return strings + off;
	return NULL;
}

inline static const char *i2s_bsearch__(const char *strings,
					const int *i_table,
					const unsigned *s_table, size_t n,
					int v)
{
	ssize_t left, right;

	left = 0;
	right = n - 1;
	while (left <= right) {	/* invariant: left <= x <= right */
		size_t mid;
		int mid_val;

		mid = (left + right) / 2;
		mid_val = i_table[mid];
		if (v == mid_val)
			return strings + s_table[mid];
		if (v < mid_val)
			right = mid - 1;
		else
			left = mid + 1;
	}
	return NULL;
}

struct transtab {
	int value;
	unsigned offset;
};

#endif
