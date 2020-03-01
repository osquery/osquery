/* ARM64 sub_n -- Subtract two limb vectors of the same length > 0 and store
 *                sum in a third limb vector.
 *
 *      Copyright (C) 2013 Jussi Kivilinna <jussi.kivilinna@iki.fi>
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "sysdep.h"
#include "asm-syntax.h"

/*******************
 *  mpi_limb_t
 *  _gcry_mpih_sub_n( mpi_ptr_t res_ptr,	x0
 *		   mpi_ptr_t s1_ptr,		x1
 *		   mpi_ptr_t s2_ptr,		x2
 *		   mpi_size_t size)		x3
 */

.text

.globl _gcry_mpih_sub_n
.type  _gcry_mpih_sub_n,%function
_gcry_mpih_sub_n:
	and	x5, x3, #3;
	subs	xzr, xzr, xzr; /* prepare carry flag for sub */

	cbz	x5, .Large_loop;

.Loop:
	ldr	x4, [x1], #8;
	sub	x3, x3, #1;
	ldr	x11, [x2], #8;
	and	x5, x3, #3;
	sbcs	x4, x4, x11;
	str	x4, [x0], #8;
	cbz	x3, .Lend;
	cbnz	x5, .Loop;

.Large_loop:
	ldp	x4, x6, [x1], #16;
	ldp	x5, x7, [x2], #16;
	ldp	x8, x10, [x1], #16;
	ldp	x9, x11, [x2], #16;
	sub	x3, x3, #4;
	sbcs	x4, x4, x5;
	sbcs	x6, x6, x7;
	sbcs	x8, x8, x9;
	sbcs	x10, x10, x11;
	stp	x4, x6, [x0], #16;
	stp	x8, x10, [x0], #16;
	cbnz	x3, .Large_loop;

.Lend:
	cset	x0, cc;
	ret;
.size _gcry_mpih_sub_n,.-_gcry_mpih_sub_n;
