#ifndef _UAPI_LINUX_TYPES_32_64_H
#define _UAPI_LINUX_TYPES_32_64_H

/*
 * linux/types_32_64.h
 *
 * Integer type declaration for pointers across 32-bit and 64-bit systems.
 *
 * Copyright (c) 2015-2017 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifdef __KERNEL__
# include <linux/types.h>
#else
# include <stdint.h>
#endif

#include <asm/byteorder.h>

#ifdef __BYTE_ORDER
# if (__BYTE_ORDER == __BIG_ENDIAN)
#  define LINUX_BYTE_ORDER_BIG_ENDIAN
# else
#  define LINUX_BYTE_ORDER_LITTLE_ENDIAN
# endif
#else
# ifdef __BIG_ENDIAN
#  define LINUX_BYTE_ORDER_BIG_ENDIAN
# else
#  define LINUX_BYTE_ORDER_LITTLE_ENDIAN
# endif
#endif

#ifdef __LP64__
# define LINUX_FIELD_u32_u64(field)			__u64 field
# define LINUX_FIELD_u32_u64_INIT_ONSTACK(field, v)	field = (intptr_t)v
#else
# ifdef LINUX_BYTE_ORDER_BIG_ENDIAN
#  define LINUX_FIELD_u32_u64(field)	__u32 field ## _padding, field
#  define LINUX_FIELD_u32_u64_INIT_ONSTACK(field, v)	\
	field ## _padding = 0, field = (intptr_t)v
# else
#  define LINUX_FIELD_u32_u64(field)	__u32 field, field ## _padding
#  define LINUX_FIELD_u32_u64_INIT_ONSTACK(field, v)	\
	field = (intptr_t)v, field ## _padding = 0
# endif
#endif

#endif /* _UAPI_LINUX_TYPES_32_64_H */
