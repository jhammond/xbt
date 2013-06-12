#ifndef _XBT_H_
#define _XBT_H_
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <elfutils/libdw.h>
#include "list.h"

#define XBT_ARRAY_LENGTH(a) (sizeof(a) / sizeof((a)[0]))

#if 0
#define xbt_trace(fmt, args...) \
	fprintf(stderr, "# %s:%d: "fmt"\n", __func__, __LINE__, ##args)

#define xbt_error(fmt, args...) \
	fprintf(stderr, "# %s:%d: "fmt"\n", __func__, __LINE__, ##args)

#endif

#define xbt_assert(x) (assert(x))

/* FIXME */
#ifndef CRASHDEBUG
#include <crash/defs.h>
#endif

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

enum {
	XBT_RBX = 3,
	XBT_R12 = 12,
	XBT_R13 = 13,
	XBT_R14 = 14,
	XBT_R15 = 15,
};

static inline const char *xbt_strerror(int err)
{
	return "XBT error";
}

struct load_module;
struct syment;

struct xbt_frame {
	/* Frame data. */
	struct list_head	xf_link;
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
	char		       *xf_mod_debuginfo_path;

	unsigned long		xf_is_exception:1,
				xf_is_irq:1,
				xf_has_child:1,
				xf_has_parent:1;

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

static inline struct xbt_frame *xf_child(struct xbt_frame *xf)
{
	if (!xf->xf_has_child)
		return NULL;

	return list_entry(xf->xf_link.prev, struct xbt_frame, xf_link);
}

static inline struct xbt_frame *xf_parent(struct xbt_frame *xf)
{
	if (!xf->xf_has_parent)
		return NULL;

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

/* TODO Convert this to dest, addr, size. */
static inline int xf_frame_ref(struct xbt_frame *xf,
			       unsigned long *v,
			       long offset)
{
	unsigned long addr = xf->xf_frame_end + offset;
	unsigned long stack_offset;

	xbt_trace("offset %ld, addr %lx", offset, addr);

	if (xf->xf_frame_ref != NULL)
		return xf->xf_frame_ref(xf, v, offset);

	if (!(xf->xf_stack_start <= addr && addr < xf->xf_stack_end)) {
		/* ... */
		return -XBT_BAD_FRAME;
	}

	stack_offset = addr - xf->xf_stack_start;

	*v = *(unsigned long *)
		(((char *)xf->xf_stack_base) + stack_offset);

	xbt_trace("*v %lx", *v);

	return 0;
}

static inline int xf_mem_ref(struct xbt_frame *xf,
			     void *dest, unsigned long addr,
			     size_t size)
{
	if (xf->xf_mem_ref != NULL)
		return xf->xf_mem_ref(xf, dest, addr, size);

	/* TODO Try converting to stack reference. */

	return -XBT_UNSUPP;
}

void xbt_frame_restore_regs(struct xbt_frame *xp);

void xbt_frame_print(FILE *file, struct xbt_frame *xf);

int xbt_dwarf_eval(struct xbt_frame *xf, const char *obj_name,
		   Dwarf_Word *obj, Dwarf_Word *bit_mask, size_t obj_size,
		   const Dwarf_Op *expr, size_t expr_len);

#endif
