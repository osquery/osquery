/* ARM64 mul_2 -- Multiply a limb vector with a limb and add the result to
 *                a second limb vector.
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
 * mpi_limb_t
 * _gcry_mpih_addmul_1( mpi_ptr_t res_ptr,	x0
 *		     mpi_ptr_t s1_ptr,		x1
 *		     mpi_size_t s1_size,	x2
 *		     mpi_limb_t s2_limb)	x3
 */

.text

.globl _gcry_mpih_addmul_1
.type  _gcry_mpih_addmul_1,%function
_gcry_mpih_addmul_1:
	and	x5, x2, #3;
	mov	x6, xzr;
	mov	x7, xzr;

	cbz	x5, .Large_loop;

.Loop:
	ldr	x5, [x1], #8;

	mul	x12, x5, x3;
	ldr	x4, [x0];
	umulh	x13, x5, x3;
	sub	x2, x2, #1;

	adds	x12, x12, x4;
	and	x5, x2, #3;
	adc	x13, x13, x7;
	adds	x12, x12, x6;
	str	x12, [x0], #8;
	adc	x6, x7, x13;

	cbz	x2, .Lend;
	cbnz	x5, .Loop;

.Large_loop:
	ldp	x5, x9, [x1], #16;
	sub	x2, x2, #4;
	ldp	x4, x8, [x0];

	mul	x12, x5, x3;
	umulh	x13, x5, x3;

	adds	x12, x12, x4;
	mul	x14, x9, x3;
	adc	x13, x13, x7;
	adds	x12, x12, x6;
	umulh	x15, x9, x3;
	str	x12, [x0], #8;
	adc	x6, x7, x13;

	adds	x14, x14, x8;
	ldp	x5, x9, [x1], #16;
	adc	x15, x15, x7;
	adds	x14, x14, x6;
	mul	x12, x5, x3;
	str	x14, [x0], #8;
	ldp	x4, x8, [x0];
	umulh	x13, x5, x3;
	adc	x6, x7, x15;

	adds	x12, x12, x4;
	mul	x14, x9, x3;
	adc	x13, x13, x7;
	adds	x12, x12, x6;
	umulh	x15, x9, x3;
	str	x12, [x0], #8;
	adc	x6, x7, x13;

	adds	x14, x14, x8;
	adc	x15, x15, x7;
	adds	x14, x14, x6;
	str	x14, [x0], #8;
	adc	x6, x7, x15;

	cbnz	x2, .Large_loop;

.Lend:
	mov	x0, x6;
	ret;
.size _gcry_mpih_addmul_1,.-_gcry_mpih_addmul_1;
