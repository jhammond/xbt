#ifndef _XBT_H_
#define _XBT_H_
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <elfutils/libdw.h>
#include "xbt_crash.h" /* __error() */
#include "list.h"

#define XBT_ARRAY_LENGTH(a) (sizeof(a) / sizeof((a)[0]))

#if 0
#define xbt_trace(fmt, args...) \
	fprintf(stderr, "# %s:%d: "fmt"\n", __func__, __LINE__, ##args)

#define xbt_error(fmt, args...) \
	fprintf(stderr, "# %s:%d: "fmt"\n", __func__, __LINE__, ##args)

#endif

#define xbt_assert(x) (assert(x))

#undef xbt_trace
#undef xbt_error

extern int xbt_debug;

#define xbt_trace(fmt, args...)						\
	do {								\
		if (xbt_debug)						\
			fprintf(stderr, "# %s:%d: "fmt"\n",		\
				__func__, __LINE__, ##args);		\
	} while (0)

#define xbt_error(fmt, args...)						\
	do {								\
		xbt_trace(fmt, ##args);					\
		__error(INFO, fmt"\n", ##args);				\
	} while (0)

#define xbt_print(fmt, args...)			\
	fprintf(fp, fmt, ##args)

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

enum {
	XBT_RAX = 0,
	XBT_RDX = 1,
	XBT_RCX = 2,
	XBT_RBX = 3,
	XBT_RSI = 4,
	XBT_RDI = 5,
	XBT_RBP = 6,
	XBT_RSP = 7,
	XBT_R8 = 8,
	XBT_R9 = 9,
	XBT_R10 = 10,
	XBT_R11 = 11,
	XBT_R12 = 12,
	XBT_R13 = 13,
	XBT_R14 = 14,
	XBT_R15 = 15,
	XBT_RA = 16,
	XBT_NR_REGS,
};

static inline const char *xbt_strerror(int err)
{
	return "XBT error";
}

struct load_module;
struct syment;

struct xbt_context {
	unsigned long		xc_task;
	char		       *xc_stack;
	unsigned long		xc_stack_start;
	unsigned long		xc_stack_end; /* start < end */

	/* Frame list starts with leaf frame, prev is child/callee,
	 * next is parent/caller. */

	struct list_head	xc_frame_list;

	int (*xc_mem_ref)(struct xbt_context * /* this */,
			  void * /* dest */,
			  unsigned long /* address */,
			  size_t /* size */);
};

struct xbt_frame {
	struct xbt_context     *xf_context;
	struct list_head	xf_context_link;

	/* Frame data. */
	int			xf_level; /* #i in crash 'bt'. */
	const void	       *xf_frame_base; /* Copy of frame in our memory. */
	unsigned long		xf_frame_start;
	unsigned long		xf_frame_end;
	unsigned long		xf_rip; /* saved rip */
	unsigned long		xf_reg[XBT_NR_REGS];
	unsigned long		xf_reg_mask;

	/* Stack data. */
	const void	       *xf_stack_base; /* Copy of stack in our memory. */
	unsigned long		xf_stack_start;
	unsigned long		xf_stack_end;

	/* Function data. */
	struct syment	       *xf_syment;
	const char	       *xf_func_name;
	unsigned long		xf_func_start;
	unsigned long		xf_func_offset;
	unsigned long		xf_text_section;
	unsigned long		xf_text_offset;

	/* Module data. */
	struct load_module     *xf_mod;
	const char	       *xf_mod_name;

	/* Debuginfo. */
	char		       *xf_debuginfo_path;

	bool			xf_is_exception:1,
				xf_is_irq:1;

	int (*xf_reg_ref)(struct xbt_frame * /* this */,
			  unsigned long * /* dest */,
			  unsigned /* reg */);
	int (*xf_frame_ref)(struct xbt_frame * /* this */,
			    unsigned long * /* dest */,
			    long /* offset */);
};

#define xbt_for_each_frame(xf, xc)					\
	list_for_each_entry((xf), &(xc)->xc_frame_list, xf_context_link)

#define xbt_list_entry(h)					\
	list_entry(h, struct xbt_frame, xf_context_link)

static inline struct xbt_frame *xf_child(struct xbt_frame *xf)
{
	if (xf->xf_context_link.prev == &xf->xf_context->xc_frame_list)
		return NULL;

	return list_entry(xf->xf_context_link.prev, struct xbt_frame,
			  xf_context_link);
}

static inline struct xbt_frame *xf_parent(struct xbt_frame *xf)
{
	if (xf->xf_context_link.next == &xf->xf_context->xc_frame_list)
		return NULL;

	return list_entry(xf->xf_context_link.next, struct xbt_frame,
			  xf_context_link);
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

static inline int xc_mem_ref(struct xbt_context *xc,
			     void *dest, unsigned long addr, size_t size)
{
	if (xc->xc_stack_start <= addr && addr + size < xc->xc_stack_end) {
		memcpy(dest, &xc->xc_stack[addr - xc->xc_stack_start], size);
		return 0;
	}

	if (xc->xc_mem_ref != NULL)
		return xc->xc_mem_ref(xc, dest, addr, size);

	return -XBT_UNSUPP;
}

static inline int xf_mem_ref(struct xbt_frame *xf,
			     void *dest, unsigned long addr, size_t size)
{
	return xc_mem_ref(xf->xf_context, dest, addr, size);
}

/* TODO Convert this to dest, addr, size. */
static inline int xf_frame_ref(struct xbt_frame *xf,
			       unsigned long *v, long offset)
{
	unsigned long addr = xf->xf_frame_end + offset;

	xbt_trace("offset %ld, addr %lx", offset, addr);

	if (xf->xf_frame_ref != NULL)
		return xf->xf_frame_ref(xf, v, offset);

	return xf_mem_ref(xf, v, addr, sizeof(*v));
}

void xbt_frame_print(FILE *file, struct xbt_frame *xf);

int xbt_dwarf_eval(struct xbt_frame *xf, const char *obj_name,
		   Dwarf_Word *obj, Dwarf_Word *bit_mask, size_t obj_size,
		   const Dwarf_Op *expr, size_t expr_len);

#endif
