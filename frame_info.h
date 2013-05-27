#ifndef _FRAME_INFO_H_
#define _FRAME_INFO_H_
#include "list.h"

struct load_module;
struct syment;

struct frame_info {
	struct list_head fi_link;
	int fi_level; /* #i in crash 'bt'. */
	/* #0 [ffff880100a9d780] schedule at ffffffff814eb4d2 */
	void *fi_base;
	ulong fi_start;
	ulong fi_end;
	ulong fi_text; /* saved rip */
	struct load_module *fi_mod; /* in syment? */
	struct syment *fi_syment;
	ulong fi_offset; /* offset into function */
	ulong fi_except:1;
};

static inline struct frame_info *fi_next(struct frame_info *fi)
{
	return list_entry(fi->fi_link.next, struct frame_info, fi_link);
}

#endif
