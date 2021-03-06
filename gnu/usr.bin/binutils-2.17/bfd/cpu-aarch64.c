/* BFD Support for AArch64

   Copyright 2005 Free Software Foundation, Inc.

   This file is part of BFD, the Binary File Descriptor library.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA 02110-1301,
   USA.  */

#include "bfd.h"
#include "sysdep.h"
#include "libbfd.h"

const bfd_arch_info_type bfd_aarch64_arch =
  {
    64,     		/* Bits in a word.  */
    64,  		/* Bits in an address.  */
    8,     		/* Bits in a byte.  */
    bfd_arch_aarch64,
    0,                	/* Only one machine.  */
    "aarch64",        	/* Arch name.  */
    "aarch64",        	/* Arch printable name.  */
    4,                	/* Section align power.  */
    TRUE,             	/* The one and only.  */
    bfd_default_compatible, 
    bfd_default_scan ,
    0,
  };
