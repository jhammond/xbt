#ifndef _XBT_H_
#define _XBT_H_
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <elfutils/libdw.h>
#include "list.h"

#define XBT_ARRAY_LENGTH(a) (sizeof(a) / sizeof((a)[0]))

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

struct xbt_frame {
	/* Stack and frame data. */
	struct list_head	xf_link;
	int			xf_level; /* #i in crash 'bt'. */
	const void	       *xf_stack_base; /* Copy of stack in our memory. */
	unsigned long		xf_stack_start;
	unsigned long		xf_stack_end;
	const void	       *xf_frame_base; /* Copy of frame in our memory. */
	unsigned long		xf_frame_start;
	unsigned long		xf_frame_end;
	unsigned long		xf_rip; /* saved rip */

	unsigned long		xf_reg[XBT_NR_REGS];
	unsigned long		xf_reg_mask;

	/* Function data. */
	struct syment	       *xf_syment;
	const char	       *xf_func_name;
	unsigned long		xf_func_offset;
	unsigned long		xf_text_section;
	unsigned long		xf_text_offset;

	/* Module data. */
	struct load_module     *xf_mod;
	const char	       *xf_mod_name;
	const char	       *xf_mod_debuginfo_path;

	unsigned long		xf_is_exception:1,
				xf_is_irq:1;

	int (*xf_reg_ref)(struct xbt_frame *,
			  unsigned long * /* dest */,
			  unsigned /* reg */);
	int (*xf_frame_ref)(struct xbt_frame *,
			    unsigned long * /* dest */,
			    long /* offset */);
	int (*xf_mem_ref)(struct xbt_frame *,
			  void */* dest */,
			  unsigned long /* address */,
			  size_t /* size */);
};

static inline struct xbt_frame *xf_next(struct xbt_frame *xf)
{
	return list_entry(xf->xf_link.next, struct xbt_frame, xf_link);
}

static inline int xf_reg_ref(struct xbt_frame *xf,
			     unsigned long *v,
			     unsigned i)
{
	if (xf->xf_reg_ref != NULL)
		return xf->xf_reg_ref(xf, v, i);

	if (!(i < XBT_ARRAY_LENGTH(xf->xf_reg)))
		return -XBT_BAD_REG;

	if (!(xf->xf_reg_mask & (1UL << i)))
		return -XBT_UNKNOWN;

	*v = xf->xf_reg[i];

	return XBT_OK;
}

static inline int xf_frame_ref(struct xbt_frame *xf,
			       unsigned long *v,
			       long offset)
{
	if (xf->xf_frame_ref != NULL)
		return xf->xf_frame_ref(xf, v, offset);

	if (!(offset < xf->xf_frame_end - xf->xf_frame_start)) {
		/* ... */
		return -XBT_BAD_FRAME;
	}

	*v = *(const unsigned long *)
		(((const char *)xf->xf_frame_base) + offset);

	return 0;
}

static inline int xf_mem_ref(struct xbt_frame *xf,
			     void *buf, unsigned long addr,
			     size_t size)
{
	if (xf->xf_mem_ref != NULL)
		return xf->xf_mem_ref(xf, buf, addr, size);

	return -XBT_UNSUPP;
}

int xbt_dwarf_eval(struct xbt_frame *xf,
		   Dwarf_Word *obj, Dwarf_Word *bit_mask, size_t obj_size,
		   const Dwarf_Op *expr, size_t expr_len);

#endif
