#ifndef _XBT_H_
#define _XBT_H_
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <elfutils/libdw.h>
#include "list.h"

#ifndef ARRAY_LENGTH
#define ARRAY_LENGTH(a) (sizeof(a) / sizeof((a)[0]))
#endif

#define xbt_trace(fmt, args...) \
	fprintf(stderr, "@ %s:%d: "fmt"\n", __func__, __LINE__, ##args)

#define xbt_error(fmt, args...) \
	fprintf(stderr, "@ %s:%d: "fmt"\n", __func__, __LINE__, ##args)

#define xbt_assert(x) (assert(x))

#define XBT_NR_REGS 16

enum {
	XBT_OK,
	XBT_BAD_REG,
	XBT_BAD_FRAME, /* Bad frame reference. */
	XBT_BAD_MEM,
	XBT_UNKNOWN,
	XBT_UNSUPP,
	XBT_TODO,

	XBT_EVAL_BAD_OP,
	XBT_EVAL_DIV_ERR,
	XBT_EVAL_UNDERFLOW,
	XBT_EVAL_OVERFLOW,
};

static inline const char *xbt_strerror(int err)
{
	return "XBT error";
}

struct load_module;
struct syment;

struct xbt_context {
	/* Frame data. */
	struct list_head	xc_link;
	int			xc_level; /* #i in crash 'bt'. */
	const void	       *xc_frame_base; /* Copy of frame in our memory. */
	unsigned long		xc_frame_start;
	unsigned long		xc_frame_end;
	unsigned long		xc_frame_rip; /* saved rip */

	unsigned long		xc_reg[XBT_NR_REGS];
	unsigned long		xc_reg_mask;

	/* Function data. */
	struct syment	       *xc_syment;
	const char	       *xc_func_name;
	unsigned long		xc_func_offset;
	unsigned long		xc_text_section;
	unsigned long		xc_text_offset;

	/* Module data. */
	struct load_module     *xc_module;
	const char	       *xc_module_name;
	const char	       *xc_module_debuginfo_path;

	unsigned long		xc_is_exception:1,
				xc_is_irq:1;

	int (*xc_reg_ref)(struct xbt_context *,
			  unsigned long * /* dest */,
			  unsigned /* reg */);
	int (*xc_frame_ref)(struct xbt_context *,
			    unsigned long * /* dest */,
			    long /* offset */);
	int (*xc_mem_ref)(struct xbt_context *,
			  void */* dest */,
			  unsigned long /* address */,
			  size_t /* size */);
};

static inline struct xbt_context *xbt_next(struct xbt_context *xc)
{
	return list_entry(xc->xc_link.next, struct xbt_context, xc_link);
}

static inline int xc_reg_ref(struct xbt_context *xc,
			     unsigned long *v,
			     unsigned i)
{
	if (xc->xc_reg_ref != NULL)
		return xc->xc_reg_ref(xc, v, i);

	if (!(i < ARRAY_LENGTH(xc->xc_reg)))
		return -XBT_BAD_REG;

	if (!(xc->xc_reg_mask & (1UL << i)))
		return -XBT_UNKNOWN;

	*v = xc->xc_reg[i];

	return XBT_OK;
}

static inline int xc_frame_ref(struct xbt_context *xc,
			       unsigned long *v,
			       long offset)
{
	if (xc->xc_frame_ref != NULL)
		return xc->xc_frame_ref(xc, v, offset);

	if (!(offset < xc->xc_frame_end - xc->xc_frame_start)) {
		/* ... */
		return -XBT_BAD_FRAME;
	}

	*v = *(const unsigned long *)
		(((const char *)xc->xc_frame_base) + offset);

	return 0;
}

static inline int xc_mem_ref(struct xbt_context *xc,
			     void *buf, unsigned long addr,
			     size_t size)
{
	if (xc->xc_mem_ref != NULL)
		return xc->xc_mem_ref(xc, buf, addr, size);

	return -XBT_UNSUPP;
}

int xbt_dwarf_eval(struct xbt_context *xc,
		   Dwarf_Word *result, Dwarf_Word *mask, size_t size,
		   const Dwarf_Op *expr, size_t expr_len);

#endif
