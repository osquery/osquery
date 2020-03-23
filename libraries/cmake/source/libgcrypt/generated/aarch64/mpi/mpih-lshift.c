/* mpi-lshift.c  - MPI helper functions
 * Copyright (C) 1994, 1996, 1998, 2001, 2002 Free Software Foundation, Inc.
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
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 *
 * Note: This code is heavily based on the GNU MP Library.
 *	 Actually it's the same code with only minor changes in the
 *	 way the data is stored; this is to support the abstraction
 *	 of an optional secure memory allocation which may be used
 *	 to avoid revealing of sensitive data due to paging etc.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include "mpi-internal.h"

/* Shift U (pointed to by UP and USIZE digits long) CNT bits to the left
 * and store the USIZE least significant digits of the result at WP.
 * Return the bits shifted out from the most significant digit.
 *
 * Argument constraints:
 * 1. 0 < CNT < BITS_PER_MP_LIMB
 * 2. If the result is to be written over the input, WP must be >= UP.
 */

mpi_limb_t
_gcry_mpih_lshift( mpi_ptr_t wp, mpi_ptr_t up, mpi_size_t usize,
					    unsigned int cnt)
{
  mpi_limb_t high_limb, low_limb;
  unsigned sh_1, sh_2;
  mpi_size_t i;
  mpi_limb_t retval;

  sh_1 = cnt;
  wp += 1;
  sh_2 = BITS_PER_MPI_LIMB - sh_1;
  i = usize - 1;
  low_limb = up[i];
  retval = low_limb >> sh_2;
  high_limb = low_limb;
  while ( --i >= 0 ) 
    {
      low_limb = up[i];
      wp[i] = (high_limb << sh_1) | (low_limb >> sh_2);
      high_limb = low_limb;
    }
  wp[i] = high_limb << sh_1;

  return retval;
}


