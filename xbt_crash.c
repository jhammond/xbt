/* xbt_crash.c -- xbt crash module component.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * Copyright (C) 2004-2013 David Anderson
 * Copyright (C) 2004-2013 Red Hat, Inc. All rights reserved.
 * Copyright (c) 2013 Intel Corporation.
 *
 * Portions of this file are adapted from
 * x86_64_low_budget_back_trace_cmd() and supporting functions from
 * crash-7.0.0/x86_64.c.
 *
 * Author: John L. Hammond <john.hammond@intel.com>
 */
#include <stdbool.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <getopt.h>
#include "xbt.h"
#include "list.h"

int xbt_debug;

/* BEGIN copy from crash-7.0.0/x86_64.c */

#define EFRAME_PRINT  (0x1)
#define EFRAME_VERIFY (0x2)
#define EFRAME_CS     (0x4)
#define EFRAME_SEARCH (0x8)

static const char *x86_64_exception_stacks[MAX_EXCEPTION_STACKS] = {
	"STACKFAULT",
	"DOUBLEFAULT",
	"NMI",
	"DEBUG",
	"MCE",
	"(unknown)",
	"(unknown)"
};

static bool x86_64_is_module_addr(ulong vaddr)
{
	return vaddr >= MODULES_VADDR && vaddr <= MODULES_END;
}

/* Check whether an RIP is in the FIXMAP vsyscall page. */
static bool is_vsyscall_addr(ulong rip)
{
	ulong page = page = machdep->machspec->vsyscall_page;

	return page != 0 && rip >= page && rip < page + PAGESIZE();
}

struct frame_size_cache {
	ulong textaddr;
	int frame_size;
	int exception;
};

static struct frame_size_cache *x86_64_frame_size_cache;
static int frame_size_cache_entries;

#define FRAME_SIZE_QUERY  (1)
#define FRAME_SIZE_ENTER  (2)
#define FRAME_SIZE_DUMP   (3)

#define FRAME_SIZE_CACHE_INCR (50)

static int x86_64_frame_size_cache_resize(void)
{
	struct frame_size_cache *new_fc, *fc;
	int i;

	new_fc = realloc(x86_64_frame_size_cache,
			 (frame_size_cache_entries + FRAME_SIZE_CACHE_INCR) * 
			 sizeof(struct frame_size_cache));
	if (new_fc == NULL) {
		error(INFO, "cannot realloc x86_64_frame_size_cache space!\n");
		return false;
	}

	fc = new_fc + frame_size_cache_entries;
	for (i = frame_size_cache_entries; 
	     i < (frame_size_cache_entries+FRAME_SIZE_CACHE_INCR); 
	     fc++, i++) {
		fc->textaddr = 0;
		fc->frame_size = 0;
		fc->exception = 0;
	}	

	x86_64_frame_size_cache = new_fc;
	frame_size_cache_entries += FRAME_SIZE_CACHE_INCR;

	return true;
}

static int
x86_64_frame_size_cache_func(int cmd, ulong textaddr, int *frame_size, int exception)
{
	int i, n;
	struct frame_size_cache *fc;
	char buf[BUFSIZE];

	if (!x86_64_frame_size_cache) {
		frame_size_cache_entries = FRAME_SIZE_CACHE_INCR;
		if ((x86_64_frame_size_cache = calloc(frame_size_cache_entries,
		    sizeof(struct frame_size_cache))) == NULL)
			error(FATAL, 
			    "cannot calloc x86_64_frame_size_cache space!\n");
	}

	switch (cmd) {
	case FRAME_SIZE_QUERY:
		fc = &x86_64_frame_size_cache[0];
		for (i = 0; i < frame_size_cache_entries; i++, fc++) {
			if (fc->textaddr == textaddr) {
				if (fc->exception != exception)
					return FALSE;
				*frame_size = fc->frame_size;
				return TRUE;
			}
		}
		return FALSE;

	case FRAME_SIZE_ENTER:
retry:
		fc = &x86_64_frame_size_cache[0];
		for (i = 0; i < frame_size_cache_entries; i++, fc++) {
			if ((fc->textaddr == 0) ||
			    (fc->textaddr == textaddr)) {
				if (*frame_size == -1) {
					fc->textaddr = 0;
					fc->frame_size = 0;
					fc->exception = 0;
					for (n = i+1; n < frame_size_cache_entries; 
					    i++, n++)
						x86_64_frame_size_cache[i] = 
							x86_64_frame_size_cache[n];
					return 0;
				}
				fc->textaddr = textaddr;
				fc->frame_size = *frame_size;
				fc->exception = exception;
				return fc->frame_size;
			}
		}

		if (x86_64_frame_size_cache_resize())
			goto retry;

		return *frame_size;

	case FRAME_SIZE_DUMP:
		fc = &x86_64_frame_size_cache[0];
		for (i = 0; i < frame_size_cache_entries; i++, fc++) {
			if (fc->textaddr == 0) {
				if (i < frame_size_cache_entries - 1) {
					fprintf(fp, "[%d-%d]: (unused)\n",
						i, frame_size_cache_entries-1);
				}
				break;
			}

			fprintf(fp, "[%3d]: %lx %3d %s (%s)\n", i,
				fc->textaddr, fc->frame_size,
				fc->exception ? "EX" : "CF",
				value_to_symstr(fc->textaddr, buf, 0));
		}
		break;
	}

	return TRUE;
}

static struct syment *x86_64_function_called_by(ulong rip)
{
	struct syment *sp;
	char buf[BUFSIZE], *p1;
	ulong value, offset;
	unsigned char byte;

	value = 0;
	sp = NULL;

	if (!readmem(rip, KVADDR, &byte, sizeof(byte), "call byte", QUIET|RETURN_ON_ERROR))
		return sp;

	if (byte != 0xe8)
		return sp;

	sprintf(buf, "x/i 0x%lx", rip);

	open_tmpfile2();
	if (gdb_pass_through(buf, pc->tmpfile2, GNU_RETURN_ON_ERROR)) {
		rewind(pc->tmpfile2);
		while (fgets(buf, BUFSIZE, pc->tmpfile2)) {
			if ((p1 = strstr(buf, "callq")) &&
			    whitespace(*(p1-1))) { 
				if (extract_hex(p1, &value, NULLCHAR, TRUE)) 
					break;
			}
		}
	}
	close_tmpfile2();

	if (value != 0)
		sp = value_search(value, &offset);

	/*
	 *  Functions that jmp to schedule() or schedule_timeout().
	 */
	if (sp != NULL) {
		if (STREQ(sp->name, "schedule_timeout_interruptible") ||
		    STREQ(sp->name, "schedule_timeout_uninterruptible"))
			sp = symbol_search("schedule_timeout");
		else if (STREQ(sp->name, "__cond_resched"))
			sp = symbol_search("schedule");
	}

	return sp;
}

/*
 *  The __schedule() frame_size should only have to be calculated
 *  one time, but always verify that the previously-determined 
 *  frame_size applies to this task, and if it doesn't, recalculate.
 *  Update the bt->instptr here, and return the new stack pointer.
 */
static ulong __schedule_frame_adjust(ulong rsp_in, struct bt_info *bt)
{
	int i, found;
	ulong rsp, *up;
	struct syment *sp;
	int frame_size;

	if (x86_64_frame_size_cache_func(FRAME_SIZE_QUERY, 
					machdep->machspec->thread_return,
					&frame_size, 0)) {
		rsp = rsp_in + frame_size;
		i = (rsp - bt->stackbase) / sizeof(ulong);
		up = (ulong *)(&bt->stackbuf[i * sizeof(ulong)]);

		if (is_kernel_text_offset(*up) &&
		    (sp = x86_64_function_called_by((*up) - 5)) &&
		    STREQ(sp->name, "__schedule")) {
			bt->instptr = *up;
			return rsp;
		}
	}

	rsp = rsp_in;

	for (found = FALSE, i = (rsp - bt->stackbase) / sizeof(ulong);
	     rsp < bt->stacktop; i++, rsp += sizeof(ulong)) {
		up = (ulong *)(&bt->stackbuf[i * sizeof(ulong)]);

		if (!is_kernel_text_offset(*up))
			continue;

		if ((sp = x86_64_function_called_by((*up) - 5)) &&
		    STREQ(sp->name, "__schedule")) {
			frame_size = (int)(rsp - rsp_in);
			bt->instptr = *up;
			x86_64_frame_size_cache_func(FRAME_SIZE_ENTER, 
						    machdep->machspec->thread_return,
						    &frame_size, 0);
			bt->instptr = *up;
			found = TRUE;
			break;
		}
	}

	if (CRASHDEBUG(1) && !found)
		error(INFO, "cannot determine __schedule() caller\n");

	return found ? rsp : rsp_in;
}

static void
x86_64_do_bt_reference_check(struct bt_info *bt, ulong text, char *name)
{
	ulong offset;
	struct syment *sp = NULL;

	if (name == NULL)
		sp = value_search(text, &offset); 
	else if (text == 0)
		sp = symbol_search(name);

        switch (bt->ref->cmdflags & (BT_REF_SYMBOL|BT_REF_HEXVAL)) {
        case BT_REF_SYMBOL:
                if (name) {
			if (STREQ(name, bt->ref->str))
                        	bt->ref->cmdflags |= BT_REF_FOUND;
		} else {
			if (sp && !offset && STREQ(sp->name, bt->ref->str))
                        	bt->ref->cmdflags |= BT_REF_FOUND;
		}
                break;

        case BT_REF_HEXVAL:
                if (text) {
			if (bt->ref->hexval == text) 
                        	bt->ref->cmdflags |= BT_REF_FOUND;
		} else if (sp && (bt->ref->hexval == sp->value))
                       	bt->ref->cmdflags |= BT_REF_FOUND;
		else if (!name && !text && (bt->ref->hexval == 0))
			bt->ref->cmdflags |= BT_REF_FOUND;
                break;
        }
}

/*
 *  Determine the function containing a .text.lock. reference.
 */
static ulong
text_lock_function(const char *name, struct bt_info *bt, ulong text)
{
	int instr = -1, arg = -1;
	char buf[BUFSIZE];
	char *arglist[MAXARGS];
	ulong func = 0;

        open_tmpfile2();

	if (STREQ(name, ".text.lock.spinlock"))
        	sprintf(buf, "x/4i 0x%lx", text);
	else
        	sprintf(buf, "x/1i 0x%lx", text);

	if (!gdb_pass_through(buf, pc->tmpfile2, GNU_RETURN_ON_ERROR)) {
		close_tmpfile2();
		bt->flags |= BT_FRAMESIZE_DISABLE;
		return 0;
	}

	rewind(pc->tmpfile2);
	while (fgets(buf, BUFSIZE, pc->tmpfile2)) {
		int c = parse_line(buf, arglist);

		if (instr == -1) {
			/*
                         *  Check whether <function+offset> are in the
                         *  output string.
                         */
			if (LASTCHAR(arglist[0]) == ':') {
				instr = 1;
				arg = 2;
			} else {
				instr = 2;
				arg = 3;
			}
		}

		if (c < arg + 1)
			break;

		if (STREQ(arglist[instr], "jmpq") ||
		    STREQ(arglist[instr], "jmp")) {
			char *p1 = arglist[arg];
			int rc = 0;

			func = htol(p1, RETURN_ON_ERROR, &rc);
			if (rc != 0)
				func = 0;
			break;
		}
	}
	close_tmpfile2();

	if (func != 0)
		bt->flags |= BT_FRAMESIZE_DISABLE;

	return func;
}

ulong x86_64_get_framepointer(struct bt_info *bt, ulong rsp)
{
	ulong sp = rsp - sizeof(rsp);
	ulong fp = 0;
	ulong ra;

	if (!INSTACK(sp, bt))
		return 0;

	if (!readmem(sp, KVADDR, &fp, sizeof(fp), "FP", RETURN_ON_ERROR|QUIET))
		return 0;

	if (!INSTACK(fp, bt))
		return 0;

	if (fp <= rsp + sizeof(rsp))
		return 0;

	if (!readmem(fp + sizeof(fp), KVADDR, &ra, sizeof(ra), "RA",
		     RETURN_ON_ERROR|QUIET)) 
		return 0;

	if (!is_kernel_text(ra))
		return 0;

	return fp;
}

static int
x86_64_get_frame_size(struct bt_info *bt, ulong textaddr, ulong rsp)
{
	int c, frame_size, instr, arg, max;
	struct syment *sp;
	long max_instructions;
	ulong offset;
	char buf[BUFSIZE];
	char buf2[BUFSIZE];
	char *arglist[MAXARGS];
	ulong locking_func, textaddr_save, current, framepointer;
	char *p1, *p2;
	int reterror;
	int arg_exists;
	int exception;

	sp = value_search(textaddr, &offset);
	if (sp == NULL) {
		if (!(bt->flags & BT_FRAMESIZE_DEBUG))
			bt->flags |= BT_FRAMESIZE_DISABLE;
		return 0;
	}

	exception = bt->eframe_ip == textaddr ? TRUE : FALSE;

	if (!(bt->flags & BT_FRAMESIZE_DEBUG) &&
	    x86_64_frame_size_cache_func(FRAME_SIZE_QUERY, textaddr, &frame_size,
					exception)) {
		if (frame_size == -1)
			bt->flags |= BT_FRAMESIZE_DISABLE;

		return frame_size;
	}

	/*
	 *  Bait and switch an incoming .text.lock address with the
	 *  containing function's address.
	 */
	if (STRNEQ(sp->name, ".text.lock.") &&
	    (locking_func = text_lock_function(sp->name, bt, textaddr))) {
        	if (!(sp = value_search(locking_func, &offset))) {
			bt->flags |= BT_FRAMESIZE_DISABLE;
			return 0;
		}
		textaddr_save = textaddr;
		textaddr = locking_func;
	} else {
		textaddr_save = 0;
	}

	/*
	 *  As of 2.6.29, "irq_entries_start" replaced the range of
	 *  IRQ entry points named IRQ0x00_interrupt through
	 *  IRQ0x##_interrupt.  Each IRQ entry point in the list of
	 *  non-symbolically-named entry stubs consists of a single
	 *  pushq and a jmp.
	 */
	if (STREQ(sp->name, "irq_entries_start")) {
#define PUSH_IMM8 0x6a
		if (readmem(textaddr, KVADDR, &instr,
		    sizeof(short), "irq_entries_start instruction", 
		    QUIET|RETURN_ON_ERROR) &&
		    ((instr & 0xff) == PUSH_IMM8))
			frame_size = 0;
		else 
			frame_size = 8;

		return x86_64_frame_size_cache_func(FRAME_SIZE_ENTER, textaddr, 
						   &frame_size, exception);
	}

	if ((machdep->flags & FRAMEPOINTER) &&
	    rsp && !exception && !textaddr_save) {
		framepointer = x86_64_get_framepointer(bt, rsp);
		if (CRASHDEBUG(3)) {
			if (framepointer)
				fprintf(fp,
					" rsp: %lx framepointer: %lx -> %ld\n", 
					rsp, framepointer, framepointer - rsp);
			else
				fprintf(fp,
					" rsp: %lx framepointer: (unknown)\n", rsp);
		}

		if (framepointer) {
			frame_size = framepointer - rsp;
			return (x86_64_frame_size_cache_func(FRAME_SIZE_ENTER, 
				textaddr, &frame_size, 0));
		}
	}

	frame_size = max = 0;
        max_instructions = textaddr - sp->value; 
	instr = arg = -1;

        open_tmpfile2();

        sprintf(buf, "x/%ldi 0x%lx",
                max_instructions, sp->value);

        if (!gdb_pass_through(buf, pc->tmpfile2, GNU_RETURN_ON_ERROR)) {
        	close_tmpfile2();
		bt->flags |= BT_FRAMESIZE_DISABLE;
                return 0;
	}

        rewind(pc->tmpfile2);
        while (fgets(buf, BUFSIZE, pc->tmpfile2)) {
		strcpy(buf2, buf);

		if (CRASHDEBUG(3))
			fprintf(fp, buf2);

		c = parse_line(buf, arglist);

		if (instr == -1) {
			/*
			 *  Check whether <function+offset> are in the
			 *  output string.
			 */
			if (LASTCHAR(arglist[0]) == ':') {
				instr = 1;
				arg = 2;
			} else { 
				instr = 2;
				arg = 3;
			}
		}

		if (c < instr + 1)
			continue;
		else if (c >= arg + 1)
			arg_exists = TRUE;
		else
			arg_exists = FALSE;

		reterror = 0;
		current = htol(strip_ending_char(arglist[0], ':'),
			RETURN_ON_ERROR, &reterror);
		if (reterror)
			continue;

		if (current > textaddr)
			break;
		else if ((current == textaddr) && !exception)
			break;

		if (STRNEQ(arglist[instr], "push")) {
			frame_size += 8;
			if (CRASHDEBUG(2) || (bt->flags & BT_FRAMESIZE_DEBUG))
				fprintf(fp, "%s\t[frame_size: %d]\n", 
					strip_linefeeds(buf2), frame_size);
			max = frame_size;
	 	} else if (STRNEQ(arglist[instr], "pop") || 
		    STRNEQ(arglist[instr], "leaveq")) {
			if (frame_size > 0)
				frame_size -= 8;
			if (CRASHDEBUG(2) || (bt->flags & BT_FRAMESIZE_DEBUG))
				fprintf(fp, "%s\t[frame_size: %d]\n", 
					strip_linefeeds(buf2), frame_size);
		} else if (arg_exists && STRNEQ(arglist[instr], "add") && 
			(p1 = strstr(arglist[arg], ",%rsp"))) {
			*p1 = NULLCHAR;
			p2 = arglist[arg];
			reterror = 0;
			offset =  htol(p2+1, RETURN_ON_ERROR, &reterror);
			if (reterror)
				continue;
			if (frame_size > 0)
				frame_size -= offset;
			if (CRASHDEBUG(2) || (bt->flags & BT_FRAMESIZE_DEBUG))
				fprintf(fp, "%s\t[frame_size: %d]\n", 
					strip_linefeeds(buf2), frame_size);
		} else if (arg_exists && STRNEQ(arglist[instr], "sub") && 
			(p1 = strstr(arglist[arg], ",%rsp"))) {
			*p1 = NULLCHAR;
			p2 = arglist[arg];
			reterror = 0;
			offset =  htol(p2+1, RETURN_ON_ERROR, &reterror);
			if (reterror)
				continue;
			frame_size += offset;
			max = frame_size;
			if (CRASHDEBUG(2) || (bt->flags & BT_FRAMESIZE_DEBUG))
				fprintf(fp, "%s\t[frame_size: %d]\n", 
					strip_linefeeds(buf2), frame_size);
		} else if (STRNEQ(arglist[instr], "retq")) {
			if (!exception) {
				frame_size = max;
				if (CRASHDEBUG(2) || (bt->flags & BT_FRAMESIZE_DEBUG))
					fprintf(fp, "%s\t[frame_size restored to: %d]\n", 
						strip_linefeeds(buf2), max);
			}
		} else if (STRNEQ(arglist[instr], "retq_NOT_CHECKED")) {
			bt->flags |= BT_FRAMESIZE_DISABLE;
			frame_size = -1;
			if (CRASHDEBUG(2) || (bt->flags & BT_FRAMESIZE_DEBUG))
				fprintf(fp, "%s\t[frame_size: DISABLED]\n", 
					strip_linefeeds(buf2));
			break;
		} 
        }
        close_tmpfile2();

	if (textaddr_save)
		textaddr = textaddr_save;

	return (x86_64_frame_size_cache_func(FRAME_SIZE_ENTER, textaddr, 
		&frame_size, exception));
}

#if 0
static void x86_64_frame_size_debug(struct bt_info *bt)
{
	int frame_size;
	int exception;

	exception = (bt->flags & BT_EFRAME_SEARCH);

	switch (bt->hp->esp) {
	case 1: /* "dump" */
		x86_64_frame_size_cache_func(FRAME_SIZE_DUMP, 0, NULL, 0);
		break;
	case 0:
		if (bt->hp->eip) {  /* clear one entry */
			frame_size = -1;
			x86_64_frame_size_cache_func(FRAME_SIZE_ENTER, bt->hp->eip, 
				&frame_size, exception);
		} else { /* clear all entries */
			BZERO(&x86_64_frame_size_cache[0], 
			    sizeof(struct frame_size_cache)*frame_size_cache_entries);
			fprintf(fp, "frame_size cache cleared\n");
		}
		break;
	case -1:
		if (!bt->hp->eip)
			error(INFO, "x86_64_frame_size_debug: ignoring command\n");
		else
			x86_64_get_frame_size(bt, bt->hp->eip, 0);
		break;
	case -3:
		machdep->flags |= FRAMEPOINTER;
		BZERO(&x86_64_frame_size_cache[0], 
			sizeof(struct frame_size_cache)*frame_size_cache_entries);
		fprintf(fp, 
			"frame_size cache cleared and FRAMEPOINTER turned ON\n");
		break;
	case -4:
		machdep->flags &= ~FRAMEPOINTER;
		BZERO(&x86_64_frame_size_cache[0], 
			sizeof(struct frame_size_cache)*frame_size_cache_entries);
		fprintf(fp,
			"frame_size cache cleared and FRAMEPOINTER turned OFF\n");
		break;
	default:
		if (bt->hp->esp > 1) {
			frame_size = bt->hp->esp;
			if (bt->hp->eip)
				x86_64_frame_size_cache_func(FRAME_SIZE_ENTER, bt->hp->eip, 
					&frame_size, exception);
		} else {
			error(INFO, "x86_64_frame_size_debug: ignoring command\n");
		}
		break;
	}
}
#endif /* 0 x86_64_frame_size_debug */

static bool is_direct_call_target(struct bt_info *bt)
{
	/*
	 *  Functions that won't be called indirectly.  Add more to
	 *  this as they are discovered.
	 */
	static const char *direct_call_targets[] = {
		"schedule",
		"schedule_timeout",
		NULL
	};
	int i;

	if (!bt->call_target || (bt->flags & BT_NO_CHECK_CALLER))
		return FALSE;

	if (strstr(bt->call_target, "schedule") && is_task_active(bt->task))
		return FALSE;

	for (i = 0; direct_call_targets[i]; i++)
		if (STREQ(direct_call_targets[i], bt->call_target))
			return true;

	return false;
}

/*
 * As of 2.6.29, the handy check for the "error_exit:" label
 * no longer applies; it became an entry point that was jmp'd to 
 * after the exception handler was called.  Therefore, if the 
 * return address is an offset from any of these functions, 
 * then the exception frame should be checked for:
 *
 * .macro errorentry sym do_sym
 * errorentry invalid_TSS do_invalid_TSS
 * errorentry segment_not_present do_segment_not_present
 * errorentry alignment_check do_alignment_check
 * errorentry xen_stack_segment do_stack_segment
 * errorentry general_protection do_general_protection
 * errorentry page_fault do_page_fault
 *
 * .macro zeroentry sym do_sym
 * zeroentry divide_error do_divide_error
 * zeroentry overflow do_overflow
 * zeroentry bounds do_bounds
 * zeroentry invalid_op do_invalid_op
 * zeroentry device_not_available do_device_not_available
 * zeroentry coprocessor_segment_overrun do_coprocessor_segment_overrun
 * zeroentry spurious_interrupt_bug do_spurious_interrupt_bug
 * zeroentry coprocessor_error do_coprocessor_error
 * zeroentry simd_coprocessor_error do_simd_coprocessor_error
 * zeroentry xen_hypervisor_callback xen_do_hypervisor_callback
 * zeroentry xen_debug do_debug
 * zeroentry xen_int3 do_int3
*/
static const char *exception_functions[] = {
	"invalid_TSS",
	"segment_not_present",
	"alignment_check",
	"xen_stack_segment",
	"general_protection",
	"page_fault",
	"divide_error",
	"overflow",
	"bounds",
	"invalid_op",
	"device_not_available",
	"coprocessor_segment_overrun",
	"spurious_interrupt_bug",
	"coprocessor_error",
	"simd_coprocessor_error",
	"xen_hypervisor_callback",
	"xen_debug",
	"xen_int3",
	NULL,
};

static bool x86_64_print_eframe_location(ulong eframe, int level, FILE *fp)
{
	return false;
}

/*
 *  Calculate and verify the IRQ exception frame location from the
 *  stack reference at the top of the IRQ stack, possibly adjusting
 *  the ms->irq_eframe_link value.
 */
static ulong x86_64_irq_eframe_link(ulong stkref, struct bt_info *bt, FILE *fp)
{
	ulong irq_eframe;

	irq_eframe = stkref - machdep->machspec->irq_eframe_link;

	if (x86_64_exception_frame(EFRAME_VERIFY, irq_eframe, 0, bt, fp))
		return irq_eframe;

	if (x86_64_exception_frame(EFRAME_VERIFY, irq_eframe + 8, 0, bt, fp)) {
		machdep->machspec->irq_eframe_link -= 8;
		return irq_eframe + 8;
	}

	return irq_eframe;
}

static ulong x86_64_in_exception_stack(struct bt_info *bt, int *estack_index)
{
	int c, i;
	ulong rsp;
	ulong estack;
	struct machine_specific *ms;

	rsp = bt->stkptr;
	ms = machdep->machspec;
	estack = 0;

        for (c = 0; !estack && (c < kt->cpus); c++) {
		for (i = 0; i < MAX_EXCEPTION_STACKS; i++) {
			if (ms->stkinfo.ebase[c][i] == 0)
				break;

			if ((rsp >= ms->stkinfo.ebase[c][i]) &&
			    (rsp < (ms->stkinfo.ebase[c][i] + ms->stkinfo.esize[i]))) {
				estack = ms->stkinfo.ebase[c][i];

				if (estack_index)
					*estack_index = i;

				if (CRASHDEBUG(1) && (c != bt->tc->processor)) 
					error(INFO, "task cpu: %d  exception stack cpu: %d\n",
					      bt->tc->processor, c);
				break;
			}
		}
        }

	return estack;
}

static ulong x86_64_in_irqstack(struct bt_info *bt) 
{
	int c;
	ulong rsp;
	ulong irqstack;
	struct machine_specific *ms;

        rsp = bt->stkptr;
        ms = machdep->machspec;
        irqstack = 0;

        for (c = 0; !irqstack && (c < kt->cpus); c++) {
                if (ms->stkinfo.ibase[c] == 0)
                 	break;
                if ((rsp >= ms->stkinfo.ibase[c]) &&
                    (rsp < (ms->stkinfo.ibase[c] + ms->stkinfo.isize))) {
                	irqstack = ms->stkinfo.ibase[c];
                        if (CRASHDEBUG(1) && (c != bt->tc->processor)) 
                                error(INFO, 
			          "task cpu: %d  IRQ stack cpu: %d\n",
                                	bt->tc->processor, c);
                        break;
                }
        }

        return irqstack;
}

/*
 *  Check that the verifiable registers contain reasonable data.
 */
#define RAZ_MASK 0xffffffffffc08028    /* return-as-zero bits */

static int x86_64_eframe_verify(struct bt_info *bt, long kvaddr, long cs, long ss,
				long rip, long rsp, long rflags)
{
	int estack;

	if ((rflags & RAZ_MASK) || !(rflags & 0x2))
		return FALSE;

	if ((cs == 0x10) && (ss == 0x18)) {
		if (is_kernel_text(rip) && IS_KVADDR(rsp))
			return TRUE;

		if (x86_64_is_module_addr(rip) &&
		    IS_KVADDR(rsp) &&
		    (rsp == (kvaddr + SIZE(pt_regs))))
			return TRUE;

		if (is_kernel_text(rip) && 
		    (bt->flags & BT_EXCEPTION_STACK) &&
		    in_user_stack(bt->tc->task, rsp))
                        return TRUE;

		if (is_kernel_text(rip) && !IS_KVADDR(rsp) &&
		    (bt->flags & BT_EFRAME_SEARCH) &&
		    x86_64_in_exception_stack(bt, NULL))
			return TRUE;

		if (is_kernel_text(rip) && 
		    x86_64_in_exception_stack(bt, &estack) &&
		    (estack <= 1))
			return TRUE;
		
		/*
		 * RSP may be 0 from MSR_IA32_SYSENTER_ESP.
		 */
		if (STREQ(closest_symbol(rip), "ia32_sysenter_target"))
			return TRUE;
        }

        if ((cs == 0x10) && kvaddr) {
                if (is_kernel_text(rip) && IS_KVADDR(rsp) &&
		    (rsp == (kvaddr + SIZE(pt_regs) + 8)))
                        return TRUE;
	}

        if ((cs == 0x10) && kvaddr) {
                if (is_kernel_text(rip) && IS_KVADDR(rsp) &&
		    (rsp == (kvaddr + SIZE(pt_regs))))
                        return TRUE;
	}

	if ((cs == 0x10) && kvaddr) {
                if (is_kernel_text(rip) && IS_KVADDR(rsp) &&
		    x86_64_in_exception_stack(bt, NULL))
			return TRUE;
	}

        if ((cs == 0x33) && (ss == 0x2b)) {
                if (IS_UVADDR(rip, bt->tc) && IS_UVADDR(rsp, bt->tc))
                        return TRUE;
                if (is_vsyscall_addr(rip) && IS_UVADDR(rsp, bt->tc))
                        return TRUE;
        }

        if (XEN() && ((cs == 0x33) || (cs == 0xe033)) && 
	    ((ss == 0x2b) || (ss == 0xe02b))) {
                if (IS_UVADDR(rip, bt->tc) && IS_UVADDR(rsp, bt->tc))
                        return TRUE;
        }

	if (XEN() && ((cs == 0x10000e030) || (cs == 0xe030)) && 
	    (ss == 0xe02b)) {
                if (is_kernel_text(rip) && IS_KVADDR(rsp))
                        return TRUE;
	}

	/* 
	 *  32-bit segments 
	 */
        if ((cs == 0x23) && (ss == 0x2b)) {
                if (IS_UVADDR(rip, bt->tc) && IS_UVADDR(rsp, bt->tc))
                        return TRUE;
        }

	return FALSE;
}

/*
 *  Print exception frame information for x86_64.
 *
 *    Pid: 0, comm: swapper Not tainted 2.6.5-1.360phro.rootsmp
 *    RIP: 0010:[<ffffffff8010f534>] <ffffffff8010f534>{default_idle+36}
 *    RSP: 0018:ffffffff8048bfd8  EFLAGS: 00000246
 *    RAX: 0000000000000000 RBX: ffffffff8010f510 RCX: 0000000000000018
 *    RDX: 0000010001e37280 RSI: ffffffff803ac0a0 RDI: 000001007f43c400
 *    RBP: 0000000000000000 R08: ffffffff8048a000 R09: 0000000000000000
 *    R10: ffffffff80482188 R11: 0000000000000001 R12: 0000000000000000
 *    R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
 *    FS:  0000002a96e14fc0(0000) GS:ffffffff80481d80(0000) GS:0000000055578aa0
 *    CS:  0010 DS: 0018 ES: 0018 CR0: 000000008005003b
 *    CR2: 0000002a9556b000 CR3: 0000000000101000 CR4: 00000000000006e0
 *
 */

long x86_64_exception_frame(ulong flags, ulong kvaddr, char *local,
			    struct bt_info *bt, FILE *fp)
{
        long rip, rsp, cs, ss, rflags, orig_rax, rbp; 
	long rax, rbx, rcx, rdx, rsi, rdi;
        long r8, r9, r10, r11, r12, r13, r14, r15;
	struct machine_specific *ms;
	struct syment *sp;
	ulong offset;
	char *pt_regs_buf;
	long verified;
	long err;

        ms = machdep->machspec;

	if (!(machdep->flags & PT_REGS_INIT) || (flags == EFRAME_INIT)) {
		err = 0;
		err |= ((ms->pto.r15 = MEMBER_OFFSET("pt_regs", "r15")) == 
			INVALID_OFFSET);
		err |= ((ms->pto.r14 = MEMBER_OFFSET("pt_regs", "r14")) == 
			INVALID_OFFSET);
		err |= ((ms->pto.r13 = MEMBER_OFFSET("pt_regs", "r13")) == 
			INVALID_OFFSET);
		err |= ((ms->pto.r12 = MEMBER_OFFSET("pt_regs", "r12")) == 
			INVALID_OFFSET);
		err |= ((ms->pto.r11 = MEMBER_OFFSET("pt_regs", "r11")) == 
			INVALID_OFFSET);
		err |= ((ms->pto.r10 = MEMBER_OFFSET("pt_regs", "r10")) == 
			INVALID_OFFSET);
		err |= ((ms->pto.r9 = MEMBER_OFFSET("pt_regs", "r9")) == 
			INVALID_OFFSET);
		err |= ((ms->pto.r8 = MEMBER_OFFSET("pt_regs", "r8")) == 
			INVALID_OFFSET);
		err |= ((ms->pto.cs = MEMBER_OFFSET("pt_regs", "cs")) == 
			INVALID_OFFSET);
		err |= ((ms->pto.ss = MEMBER_OFFSET("pt_regs", "ss")) == 
			INVALID_OFFSET);
		/*
		 *  x86/x86_64 merge changed traditional register names.
		 */
		if (((ms->pto.rbp = MEMBER_OFFSET("pt_regs", "rbp")) == 
		    INVALID_OFFSET) &&
		    ((ms->pto.rbp = MEMBER_OFFSET("pt_regs", "bp")) == 
		    INVALID_OFFSET))
			err++; 
		if (((ms->pto.rax = MEMBER_OFFSET("pt_regs", "rax")) == 
		    INVALID_OFFSET) &&
		    ((ms->pto.rax = MEMBER_OFFSET("pt_regs", "ax")) == 
		    INVALID_OFFSET))
			err++; 
		if (((ms->pto.rbx = MEMBER_OFFSET("pt_regs", "rbx")) == 
		    INVALID_OFFSET) &&
		    ((ms->pto.rbx = MEMBER_OFFSET("pt_regs", "bx")) == 
		    INVALID_OFFSET))
			err++; 
		if (((ms->pto.rcx = MEMBER_OFFSET("pt_regs", "rcx")) == 
		    INVALID_OFFSET) &&
		    ((ms->pto.rcx = MEMBER_OFFSET("pt_regs", "cx")) == 
		    INVALID_OFFSET))
			err++; 
		if (((ms->pto.rdx = MEMBER_OFFSET("pt_regs", "rdx")) == 
		    INVALID_OFFSET) &&
		    ((ms->pto.rdx = MEMBER_OFFSET("pt_regs", "dx")) == 
		    INVALID_OFFSET))
			err++; 
		if (((ms->pto.rsi = MEMBER_OFFSET("pt_regs", "rsi")) == 
		    INVALID_OFFSET) &&
		    ((ms->pto.rsi = MEMBER_OFFSET("pt_regs", "si")) == 
		    INVALID_OFFSET))
			err++; 
		if (((ms->pto.rdi = MEMBER_OFFSET("pt_regs", "rdi")) == 
		    INVALID_OFFSET) &&
		    ((ms->pto.rdi = MEMBER_OFFSET("pt_regs", "di")) == 
		    INVALID_OFFSET))
			err++; 
		if (((ms->pto.rip = MEMBER_OFFSET("pt_regs", "rip")) == 
		    INVALID_OFFSET) &&
		    ((ms->pto.rip = MEMBER_OFFSET("pt_regs", "ip")) == 
		    INVALID_OFFSET))
			err++; 
		if (((ms->pto.rsp = MEMBER_OFFSET("pt_regs", "rsp")) == 
		    INVALID_OFFSET) &&
		    ((ms->pto.rsp = MEMBER_OFFSET("pt_regs", "sp")) == 
		    INVALID_OFFSET))
			err++; 
		if (((ms->pto.eflags = MEMBER_OFFSET("pt_regs", "eflags")) == 
		    INVALID_OFFSET) &&
		    ((ms->pto.eflags = MEMBER_OFFSET("pt_regs", "flags")) == 
		    INVALID_OFFSET))
			err++; 
		if (((ms->pto.orig_rax = MEMBER_OFFSET("pt_regs", "orig_rax")) == 
		    INVALID_OFFSET) &&
		    ((ms->pto.orig_rax = MEMBER_OFFSET("pt_regs", "orig_ax")) == 
		    INVALID_OFFSET))
			err++; 

		if (err)
			error(WARNING, "pt_regs structure has changed\n");

		machdep->flags |= PT_REGS_INIT;

		if (flags == EFRAME_INIT)
			return err;
	}

	if (kvaddr) {
		pt_regs_buf = GETBUF(SIZE(pt_regs));
        	readmem(kvaddr, KVADDR, pt_regs_buf,
                	SIZE(pt_regs), "pt_regs", FAULT_ON_ERROR);
	} else
		pt_regs_buf = local;

	rip = ULONG(pt_regs_buf + ms->pto.rip);
	rsp = ULONG(pt_regs_buf + ms->pto.rsp);
	cs = ULONG(pt_regs_buf + ms->pto.cs);
	ss = ULONG(pt_regs_buf + ms->pto.ss);
	rflags = ULONG(pt_regs_buf + ms->pto.eflags);
	orig_rax = ULONG(pt_regs_buf + ms->pto.orig_rax);
	rbp = ULONG(pt_regs_buf + ms->pto.rbp);
	rax = ULONG(pt_regs_buf + ms->pto.rax);
	rbx = ULONG(pt_regs_buf + ms->pto.rbx);
	rcx = ULONG(pt_regs_buf + ms->pto.rcx);
	rdx = ULONG(pt_regs_buf + ms->pto.rdx);
	rsi = ULONG(pt_regs_buf + ms->pto.rsi);
	rdi = ULONG(pt_regs_buf + ms->pto.rdi);
	r8 = ULONG(pt_regs_buf + ms->pto.r8);
	r9 = ULONG(pt_regs_buf + ms->pto.r9);
	r10 = ULONG(pt_regs_buf + ms->pto.r10);
	r11 = ULONG(pt_regs_buf + ms->pto.r11);
	r12 = ULONG(pt_regs_buf + ms->pto.r12);
	r13 = ULONG(pt_regs_buf + ms->pto.r13);
	r14 = ULONG(pt_regs_buf + ms->pto.r14);
	r15 = ULONG(pt_regs_buf + ms->pto.r15);

        verified = x86_64_eframe_verify(bt, 
		kvaddr ? kvaddr : (local - bt->stackbuf) + bt->stackbase,
		cs, ss, rip, rsp, rflags);

	/*
	 *  If it's print-if-verified request, don't print bogus eframes.
	 */
        if (!verified && ((flags & (EFRAME_VERIFY|EFRAME_PRINT)) == 
	    (EFRAME_VERIFY|EFRAME_PRINT))) 
		flags &= ~EFRAME_PRINT;
 	else if (CRASHDEBUG(1) && verified && (flags != EFRAME_VERIFY)) 
		fprintf(fp, "< exception frame at: %lx >\n", kvaddr ?
			kvaddr : (local - bt->stackbuf) + bt->stackbase);

	if (flags & EFRAME_PRINT) {
		if (flags & EFRAME_SEARCH) {
			fprintf(fp, "\n  %s-MODE EXCEPTION FRAME AT: %lx\n",
				cs & 3 ? "USER" : "KERNEL", 
				kvaddr ?  kvaddr : 
				(local - bt->stackbuf) + bt->stackbase);
			if (!(cs & 3)) {
				fprintf(fp, "    [exception RIP: ");
				if ((sp = value_search(rip, &offset))) {
					fprintf(fp, "%s", sp->name);
					if (offset)
						fprintf(fp, 
						    (*gdb_output_radix == 16) ? 
						    "+0x%lx" : "+%ld", 
						    offset);
				} else 
					fprintf(fp, 
						"unknown or invalid address");
				fprintf(fp, "]\n");
			}
		} else if (!(cs & 3)) {
			fprintf(fp, "    [exception RIP: ");
			if ((sp = value_search(rip, &offset))) {
                		fprintf(fp, "%s", sp->name);
                		if (offset)
                        		fprintf(fp, (*gdb_output_radix == 16) ? 
						"+0x%lx" : "+%ld", offset);
				bt->eframe_ip = rip;
			} else
                		fprintf(fp, "unknown or invalid address");
			fprintf(fp, "]\n");
		}
		fprintf(fp, "    RIP: %016lx  RSP: %016lx  RFLAGS: %08lx\n", 
			rip, rsp, rflags);
		fprintf(fp, "    RAX: %016lx  RBX: %016lx  RCX: %016lx\n", 
			rax, rbx, rcx);
		fprintf(fp, "    RDX: %016lx  RSI: %016lx  RDI: %016lx\n", 
	 		rdx, rsi, rdi);
		fprintf(fp, "    RBP: %016lx   R8: %016lx   R9: %016lx\n", 
			rbp, r8, r9);
		fprintf(fp, "    R10: %016lx  R11: %016lx  R12: %016lx\n", 
			r10, r11, r12);
		fprintf(fp, "    R13: %016lx  R14: %016lx  R15: %016lx\n", 
			r13, r14, r15);
		fprintf(fp, "    ORIG_RAX: %016lx  CS: %04lx  SS: %04lx\n", 
			orig_rax, cs, ss);

		if (!verified && CRASHDEBUG((pc->flags & RUNTIME) ? 0 : 1))
			error(WARNING, "possibly bogus exception frame\n");
	}

        if ((flags & EFRAME_PRINT) && BT_REFERENCE_CHECK(bt)) {
                x86_64_do_bt_reference_check(bt, rip, NULL);
                x86_64_do_bt_reference_check(bt, rsp, NULL);
                x86_64_do_bt_reference_check(bt, cs, NULL);
                x86_64_do_bt_reference_check(bt, ss, NULL);
                x86_64_do_bt_reference_check(bt, rflags, NULL);
                x86_64_do_bt_reference_check(bt, orig_rax, NULL);
                x86_64_do_bt_reference_check(bt, rbp, NULL);
                x86_64_do_bt_reference_check(bt, rax, NULL);
                x86_64_do_bt_reference_check(bt, rbx, NULL);
                x86_64_do_bt_reference_check(bt, rcx, NULL);
                x86_64_do_bt_reference_check(bt, rdx, NULL);
                x86_64_do_bt_reference_check(bt, rsi, NULL);
                x86_64_do_bt_reference_check(bt, rdi, NULL);
                x86_64_do_bt_reference_check(bt, r8, NULL);
                x86_64_do_bt_reference_check(bt, r9, NULL);
                x86_64_do_bt_reference_check(bt, r10, NULL);
                x86_64_do_bt_reference_check(bt, r11, NULL);
                x86_64_do_bt_reference_check(bt, r12, NULL);
                x86_64_do_bt_reference_check(bt, r13, NULL);
                x86_64_do_bt_reference_check(bt, r14, NULL);
                x86_64_do_bt_reference_check(bt, r15, NULL);
        }

	/* Remember the rip and rsp for unwinding the process stack */
	if (kt->flags & DWARF_UNWIND){
		bt->instptr = rip;
		bt->stkptr = rsp;
		bt->bptr = rbp;
	}

	if (kvaddr)
		FREEBUF(pt_regs_buf);

	if (flags & EFRAME_CS)
		return cs;
	else if (flags & EFRAME_VERIFY)
		return verified;

	return 0;
}

/* Only called from print_stack_entry. */
static void
x86_64_display_full_frame(struct bt_info *bt, ulong rsp, FILE *fp)
{
	int i, u_idx;
	ulong *up;
	ulong words, addr;
	char buf[BUFSIZE];

	if (rsp < bt->frameptr)
		return;

	if (!INSTACK(rsp, bt) || !INSTACK(bt->frameptr, bt))
		return;

        words = (rsp - bt->frameptr) / sizeof(ulong) + 1;

	addr = bt->frameptr;
	u_idx = (bt->frameptr - bt->stackbase) / sizeof(ulong);
	for (i = 0; i < words; i++, u_idx++) {
		if (!(i & 1)) 
			fprintf(fp, "%s    %lx: ", i ? "\n" : "", addr);
		
		up = (ulong *)(&bt->stackbuf[u_idx * sizeof(ulong)]);
		fprintf(fp, "%s ", format_stack_entry(bt, buf, *up, 0));
		addr += sizeof(ulong);
	}
	fprintf(fp, "\n");
}

#define BACKTRACE_COMPLETE                   (1)
#define BACKTRACE_ENTRY_IGNORED              (2)
#define BACKTRACE_ENTRY_DISPLAYED            (3)
#define BACKTRACE_ENTRY_AND_EFRAME_DISPLAYED (4)

/* Was x86_64_print_stack_entry() */
static int xbt_frame_add(struct list_head *xf_list,
			 struct bt_info *bt, FILE *fp, int level, 
			 int stkindex, ulong text)
{
	ulong rsp, offset, locking_func;
	struct syment *sp, *spl;
	char *func_name;
	long eframe_check;
	struct load_module *lm;
	struct xbt_frame *xf;
	int i; 
	int rc;

	/* FIXME Review control flow. */

	xf = malloc(sizeof(*xf));
	if (xf == NULL) {
		goto out;
		rc = -ENOMEM;
	}
	memset(xf, 0, sizeof(*xf));
	INIT_LIST_HEAD(&xf->xf_link);
	xf->xf_level = level;
	xf->xf_rip = text;

	eframe_check = -1;
	if (!(bt->flags & BT_SAVE_EFRAME_IP))
		bt->eframe_ip = 0;

	offset = 0;
	sp = value_search(text, &offset);
	if (sp == NULL) {
		rc = BACKTRACE_ENTRY_IGNORED;
		goto out;
	}

	func_name = sp->name;

	xf->xf_syment = sp;
	xf->xf_func_offset = offset;

	if (bt->flags & BT_EXCEPTION_FRAME)
		xf->xf_is_exception = 1;

	if (offset == 0 &&
	    !(bt->flags & BT_EXCEPTION_FRAME) &&
	    !(bt->flags & BT_START)) { 
		if (STREQ(func_name, "child_rip")) {
			if (symbol_exists("kernel_thread"))
				func_name = "kernel_thread";
			else if (symbol_exists("arch_kernel_thread"))
				func_name = "arch_kernel_thread";
		} else if (!(bt->flags & BT_SCHEDULE)) {
			if (STREQ(func_name, "error_exit")) 
				eframe_check = 8;
			else {
				if (CRASHDEBUG(2))
					fprintf(fp, 
		              "< ignoring text symbol with no offset: %s() >\n",
						sp->name);
				rc = BACKTRACE_ENTRY_IGNORED;
				goto out;
			}
		}
	}

	if (THIS_KERNEL_VERSION >= LINUX(2, 6, 29) &&
	    (eframe_check == -1) &&
	    offset != 0 && 
	    !(bt->flags & (BT_EXCEPTION_FRAME|BT_START|BT_SCHEDULE))) { 
		for (i = 0; exception_functions[i] != 0; i++) {
			if (STREQ(func_name, exception_functions[i])) {
				eframe_check = 8;
				break;
			}
		}
	}

	if (bt->flags & BT_SCHEDULE)
		func_name = "schedule";

	if (STREQ(func_name, "child_rip")) {
		if (symbol_exists("kernel_thread"))
			func_name = "kernel_thread";
                else if (symbol_exists("arch_kernel_thread"))
			func_name = "arch_kernel_thread";
		rc = BACKTRACE_COMPLETE;
        } else if (STREQ(func_name, "cpu_idle") || 
		   STREQ(func_name, "system_call_fastpath"))
		rc = BACKTRACE_COMPLETE;
	else {
		rc = BACKTRACE_ENTRY_DISPLAYED;
	}

	if (bt->flags & BT_EXCEPTION_FRAME)
		rsp = bt->stkptr;
	else if (bt->flags & BT_START)
		rsp = bt->stkptr;
	else
		rsp = bt->stackbase + (stkindex * sizeof(ulong));

	xf->xf_frame_start = rsp;

	if (bt->frameptr != 0)
		x86_64_display_full_frame(bt, rsp, fp);

	bt->frameptr = rsp + sizeof(ulong);

	fprintf(fp, "%s#%d [%8lx] %s at %lx", level < 10 ? " " : "", level,
		rsp, func_name, text);

	if (STREQ(func_name, "tracesys")) {
		fprintf(fp, " (via system_call)");
	} else if (STRNEQ(func_name, ".text.lock.")) {
		if ((locking_func = text_lock_function(func_name, bt, text)) &&
		    (spl = value_search(locking_func, &offset)))
			fprintf(fp, " (via %s)", spl->name);
	}

	if (module_symbol(text, NULL, &lm, NULL, 0)) {
		fprintf(fp, " [%s]", lm->mod_name);
		xf->xf_mod = lm;
		xf->xf_mod_name = lm->mod_name;
		if (strlen(lm->mod_namelist) > 0)
			xf->xf_debuginfo_path = lm->mod_namelist;

		xf->xf_text_section = lm->mod_text_start;
	} else {
		if (pc->debuginfo_file != NULL)
			xf->xf_debuginfo_path = pc->debuginfo_file;
		else
			xf->xf_debuginfo_path = pc->namelist;

		xf->xf_text_section = symbol_value("_text");
	}
	xf->xf_text_offset = xf->xf_rip - xf->xf_text_section;

	if (bt->flags & BT_FRAMESIZE_DISABLE)
		fprintf(fp, " *");

	fprintf(fp, "\n");

	if (eframe_check >= 0) {
		if (x86_64_exception_frame(EFRAME_PRINT|EFRAME_VERIFY, 
					   bt->stackbase +
					   (stkindex * sizeof(long)) +
					   eframe_check,
					   NULL, bt, fp))
			rc = BACKTRACE_ENTRY_AND_EFRAME_DISPLAYED;
	}

	if (BT_REFERENCE_CHECK(bt))
		x86_64_do_bt_reference_check(bt, text, func_name);

	bt->call_target = func_name;

	if (is_direct_call_target(bt)) {
		bt->flags |= BT_CHECK_CALLER;
	} else {
		if (bt->flags & BT_CHECK_CALLER)
			bt->flags |= BT_NO_CHECK_CALLER;

		bt->flags &= ~(ulonglong)BT_CHECK_CALLER;
	}

	/* This or use original. (Now I wonder what I meant by that.) */
	/* FIXME More init. */
	/* FIXME REview control flow. */
	xf->xf_func_name = func_name;
	xf->xf_func_start = xf->xf_syment->value;
	xf->xf_func_offset = xf->xf_rip - xf->xf_func_start;
out:
	/* FIXME Cleanup. */

	if (xf != NULL)
		list_add_tail(&xf->xf_link, xf_list);

	return rc;
}

#define STACK_TRANSITION_ERRMSG_E_I_P \
"cannot transition from exception stack to IRQ stack to current process stack:\n"\
"    exception stack pointer: %lx\n"\
"          IRQ stack pointer: %lx\n"\
"      process stack pointer: %lx\n"\
"         current stack base: %lx\n" 

#define STACK_TRANSITION_ERRMSG_E_P \
"cannot transition from exception stack to current process stack:\n"\
"    exception stack pointer: %lx\n"\
"      process stack pointer: %lx\n"\
"         current stack base: %lx\n"

#define STACK_TRANSITION_ERRMSG_I_P \
"cannot transition from IRQ stack to current process stack:\n"\
"        IRQ stack pointer: %lx\n"\
"    process stack pointer: %lx\n"\
"       current stack base: %lx\n"

/* xbt_back_trace_to_xf_list() -- convetr crash bt_info to xbt frame
   list.  Was x86_64_low_budget_back_trace_cmd(). */
static void xbt_back_trace_to_list(const struct bt_info *bt_in,
				   struct list_head *xf_list,
				   FILE *fp)
{
	struct machine_specific *ms = machdep->machspec;
	struct bt_info bt_local, *bt;
	struct syment *sp, *spt;
	ulong rsp, offset, stacktop;
	ulong *up;
	long cs;
	ulong estack, irqstack;
	ulong irq_eframe;
	ulong last_process_stack_eframe;
	ulong user_mode_eframe;
	char *rip_symbol;
	int level = 0;
	bool done = false;
	int i, frame_size, estack_index;

	bt_local = *bt_in;
	bt = &bt_local;
	bt->call_target = NULL;

	irq_eframe = 0;
	last_process_stack_eframe = 0;
	rsp = bt->stkptr;

	/* If rsp is in user stack, the memory may not be included in vmcore, and
	 * we only output the register's value. So it's not necessary to check
	 * whether it can be accessible.
	 */
	if (!(bt->flags & BT_USER_SPACE) && (rsp == 0 || !accessible(rsp))) {
		error(INFO, "cannot determine starting stack pointer\n");
		if (KVMDUMP_DUMPFILE())
			kvmdump_display_regs(bt->tc->processor, fp);
		else if (ELF_NOTES_VALID() && DISKDUMP_DUMPFILE())
			diskdump_display_regs(bt->tc->processor, fp);
		else if (SADUMP_DUMPFILE())
			sadump_display_regs(bt->tc->processor, fp);
		return;
	}

	/* BT_USER_SPACE set by get_{kvmdump,..}_regs(). */
	/* BT_TEXT_SYMBOLS set by options -t, -T. */

	if (bt->flags & BT_TEXT_SYMBOLS) {
		if ((bt->flags & BT_USER_SPACE) &&
		    !(bt->flags & BT_TEXT_SYMBOLS_ALL))
			return;
		if (!(bt->flags & BT_TEXT_SYMBOLS_ALL))
                	fprintf(fp, "%sSTART: %s%s at %lx\n",
                	    space(VADDR_PRLEN > 8 ? 14 : 6),
                	    closest_symbol(bt->instptr), 
			    STREQ(closest_symbol(bt->instptr), "thread_return") ?
			    " (schedule)" : "",
			    bt->instptr);
	} else if (bt->flags & BT_USER_SPACE) {
		fprintf(fp, "    [exception RIP: user space]\n");
		if (KVMDUMP_DUMPFILE())
			kvmdump_display_regs(bt->tc->processor, fp);
		else if (ELF_NOTES_VALID() && DISKDUMP_DUMPFILE())
			diskdump_display_regs(bt->tc->processor, fp);
		else if (SADUMP_DUMPFILE())
			sadump_display_regs(bt->tc->processor, fp);
		return;
	} else if ((bt->flags & BT_KERNEL_SPACE) &&
		   (KVMDUMP_DUMPFILE() ||
		    (ELF_NOTES_VALID() && DISKDUMP_DUMPFILE()) ||
		    SADUMP_DUMPFILE())) {
		fprintf(fp, "    [exception RIP: ");

		if ((sp = value_search(bt->instptr, &offset))) {
			fprintf(fp, "%s", sp->name);
			if (offset)
				fprintf(fp, (*gdb_output_radix == 16) ?
					"+0x%lx" : "+%ld", offset);
		} else {
			fprintf(fp, "unknown or invalid address");
		}

		fprintf(fp, "]\n");

		if (KVMDUMP_DUMPFILE())
			kvmdump_display_regs(bt->tc->processor, fp);
		else if (ELF_NOTES_VALID() && DISKDUMP_DUMPFILE())
			diskdump_display_regs(bt->tc->processor, fp);
		else if (SADUMP_DUMPFILE())
			sadump_display_regs(bt->tc->processor, fp);
        } else if (bt->flags & BT_START) {
                xbt_frame_add(xf_list, bt, fp, level,
                        0, bt->instptr);
		bt->flags &= ~BT_START;
		level++;
	}

        if ((estack = x86_64_in_exception_stack(bt, &estack_index))) {
in_exception_stack:
		bt->flags |= BT_EXCEPTION_STACK;
		/*
	 	 *  The stack buffer will have been loaded with the process
		 *  stack, so switch to the indicated exception stack.
		 */
                bt->stackbase = estack;
                bt->stacktop = estack + ms->stkinfo.esize[estack_index];
                bt->stackbuf = ms->irqstack;

                if (!readmem(bt->stackbase, KVADDR, bt->stackbuf,
                    bt->stacktop - bt->stackbase,
		    bt->hp && (bt->hp->esp == bt->stkptr) ? 
	 	    "irqstack contents via hook" : "irqstack contents", 
		    RETURN_ON_ERROR))
                    	error(FATAL, "read of exception stack at %lx failed\n",
                        	bt->stackbase);

		/*
	 	 *  If irq_eframe is set, we've jumped back here from the
		 *  IRQ stack dump below.  Do basically the same thing as if
		 *  had come from the processor stack, but presume that we
		 *  must have been in kernel mode, i.e., took an exception
	 	 *  while operating on an IRQ stack.  (untested)
		 */
		if (irq_eframe) {
			bt->flags |= BT_EXCEPTION_FRAME;
			i = (irq_eframe - bt->stackbase) / sizeof(ulong);
			xbt_frame_add(xf_list, bt, fp, level, i, bt->instptr);
			bt->flags &= ~(ulonglong)BT_EXCEPTION_FRAME;
			cs = x86_64_exception_frame(EFRAME_PRINT|EFRAME_CS, 0,
						    bt->stackbuf +
						    (irq_eframe - bt->stackbase), 
						    bt, fp);
			rsp += SIZE(pt_regs);  /* guaranteed kernel mode */
			if (bt->eframe_ip &&
			    ((frame_size = x86_64_get_frame_size(bt, bt->eframe_ip, rsp)) >= 0))
				rsp += frame_size;
			level++;
			irq_eframe = 0;
		}

		stacktop = bt->stacktop - SIZE(pt_regs);

		bt->flags &= ~BT_FRAMESIZE_DISABLE;

		for (i = (rsp - bt->stackbase) / sizeof(ulong);
		     !done && (rsp < stacktop);
		     i++, rsp += sizeof(ulong)) {

			up = (ulong *)(&bt->stackbuf[i*sizeof(ulong)]);

			if (!is_kernel_text(*up))
		        	continue;

			switch (xbt_frame_add(xf_list, bt, fp, level, i, *up)) {
			case BACKTRACE_ENTRY_AND_EFRAME_DISPLAYED:
				rsp += SIZE(pt_regs);
				i += SIZE(pt_regs) / sizeof(ulong);
				if (!bt->eframe_ip) {
					level++;
					break;
				} /* else fall through */
	                case BACKTRACE_ENTRY_DISPLAYED:
	                        level++;
				if ((frame_size = x86_64_get_frame_size(bt, 
								      bt->eframe_ip ?  bt->eframe_ip : *up, rsp)) >= 0) {
					rsp += frame_size;
					i += frame_size / sizeof(ulong);
				}
	                        break;
	                case BACKTRACE_ENTRY_IGNORED:
	                        break;
	                case BACKTRACE_COMPLETE:
	                        done = TRUE;
	                        break;
	                }
		}

		cs = x86_64_exception_frame(EFRAME_PRINT | EFRAME_CS, 0, 
					    bt->stackbuf +
					    (bt->stacktop - bt->stackbase) -
					    SIZE(pt_regs), bt, fp);

		if (!BT_REFERENCE_CHECK(bt))
			fprintf(fp, "--- <%s exception stack> ---\n",
				x86_64_exception_stacks[estack_index]);

                /* 
		 *  stack = (unsigned long *) estack_end[-2]; 
		 */
		up = (ulong *)(&bt->stackbuf[bt->stacktop - bt->stackbase]);
		up -= 2;
		rsp = bt->stkptr = *up;
		up -= 3;
		bt->instptr = *up;  
		if (cs & 3)
			done = TRUE;   /* user-mode exception */
		else
			done = FALSE;  /* kernel-mode exception */

		bt->frameptr = 0;

		/*
		 *  Print the return values from the estack end.
		 */
		if (!done) {
			bt->flags |= BT_START|BT_SAVE_EFRAME_IP;
			xbt_frame_add(xf_list, bt, fp, level,
						 0, bt->instptr);
			bt->flags &= 
			    	~(BT_START|BT_SAVE_EFRAME_IP|BT_FRAMESIZE_DISABLE);

			/*
			 *  Protect against exception stack recursion.
			 */
			if (x86_64_in_exception_stack(bt, NULL) == estack) {
				fprintf(fp, "    [ %s exception stack recursion: "
					"prior stack location overwritten ]\n",
					x86_64_exception_stacks[estack_index]);
				return;
			}

			level++;
			if ((frame_size = x86_64_get_frame_size(bt, bt->instptr, rsp)) >= 0)
				rsp += frame_size;
		}
	}

	/*
	 *  IRQ stack entry always comes in via the process stack, regardless
	 *  whether it happened while running in user or kernel space.
	 */
	if (!done && (irqstack = x86_64_in_irqstack(bt))) {
		bt->flags |= BT_IRQSTACK;
		/*
		 *  Until coded otherwise, the stackbase will be pointing to
		 *  either the exception stack or, more likely, the process
		 *  stack base.  Switch it to the IRQ stack.
		 */
		bt->stackbase = irqstack;
		bt->stacktop = irqstack + ms->stkinfo.isize;
		bt->stackbuf = ms->irqstack;

		if (!readmem(bt->stackbase, KVADDR, 
			     bt->stackbuf, bt->stacktop - bt->stackbase,
			     bt->hp && (bt->hp->esp == bt_in->stkptr) ?
			     "irqstack contents via hook" : "irqstack contents", 
			     RETURN_ON_ERROR))
			error(FATAL, "read of IRQ stack at %lx failed\n",
			      bt->stackbase);

		stacktop = bt->stacktop - 64; /* from kernel code */

		bt->flags &= ~BT_FRAMESIZE_DISABLE;

		for (i = (rsp - bt->stackbase) / sizeof(ulong);
		     !done && (rsp < stacktop);
		     i++, rsp += sizeof(ulong)) {

			up = (ulong *)(&bt->stackbuf[i * sizeof(ulong)]);

			if (!is_kernel_text(*up))
				continue;

			switch (xbt_frame_add(xf_list, bt, fp, level, i, *up)) {
			case BACKTRACE_ENTRY_AND_EFRAME_DISPLAYED:
				rsp += SIZE(pt_regs);
				i += SIZE(pt_regs) / sizeof(ulong);
				if (!bt->eframe_ip) {
					level++;
					break;
				} /* else fall through */
			case BACKTRACE_ENTRY_DISPLAYED:
				level++;
				if ((frame_size = x86_64_get_frame_size(bt, 
								      bt->eframe_ip ? bt->eframe_ip : *up, rsp)) >= 0) {
					rsp += frame_size;
					i += frame_size/sizeof(ulong);
				}
				break;
			case BACKTRACE_ENTRY_IGNORED:
				break;
			case BACKTRACE_COMPLETE:
				done = TRUE;
				break;
			}
		}

		if (!BT_REFERENCE_CHECK(bt))
			fprintf(fp, "--- <IRQ stack> ---\n");

                /*
		 *  stack = (unsigned long *) (irqstack_end[-1]);
		 *  (where irqstack_end is 64 bytes below page end)
                 */
		up = (ulong *)(&bt->stackbuf[stacktop - bt->stackbase]);
		up -= 1;
		irq_eframe = rsp = bt->stkptr = x86_64_irq_eframe_link(*up, bt, fp);
		up -= 1;
		bt->instptr = *up;
		/*
		 *  No exception frame when coming from call_softirq.
		 */
		sp = value_search(bt->instptr, &offset);
		if (sp != NULL && STREQ(sp->name, "call_softirq"))
			irq_eframe = 0;
		bt->frameptr = 0;
		done = false;
        } else {
		irq_eframe = 0;
	}

	if (!done && (estack = x86_64_in_exception_stack(bt, &estack_index))) 
		goto in_exception_stack;

	if (!done && (bt->flags & (BT_EXCEPTION_STACK|BT_IRQSTACK))) {
		/*
		 *  Verify that the rsp pointer taken from either the
		 *  exception or IRQ stack points into the process stack.
		 */
		bt->stackbase = GET_STACKBASE(bt->tc->task);
		bt->stacktop = GET_STACKTOP(bt->tc->task);

		if (!INSTACK(rsp, bt)) {
			switch (bt->flags & (BT_EXCEPTION_STACK|BT_IRQSTACK)) {
			case (BT_EXCEPTION_STACK|BT_IRQSTACK):
				error(FATAL, STACK_TRANSITION_ERRMSG_E_I_P,
				      bt_in->stkptr, bt->stkptr, rsp,
				      bt->stackbase);

			case BT_EXCEPTION_STACK:
				if (in_user_stack(bt->tc->task, rsp)) {
					done = TRUE;
					break;
				}

				if (STREQ(closest_symbol(bt->instptr), 
					  "ia32_sysenter_target")) {
					/*
					 * RSP 0 from MSR_IA32_SYSENTER_ESP?
					 */
					if (rsp == 0)
						return; /* XXX */
					done = TRUE;
					break;
				}
				error(FATAL, STACK_TRANSITION_ERRMSG_E_P,
				      bt_in->stkptr, rsp, bt->stackbase);

			case BT_IRQSTACK:
				error(FATAL, STACK_TRANSITION_ERRMSG_I_P,
				      bt_in->stkptr, rsp, bt->stackbase);
			}
		}

		/*
	 	 *  Now fill the local stack buffer from the process stack.
	  	 */
		if (!readmem(bt->stackbase, KVADDR, bt->stackbuf,
			     bt->stacktop - bt->stackbase, 
			     "irqstack contents", RETURN_ON_ERROR))
			error(FATAL, "read of process stack at %lx failed\n",
			      bt->stackbase);
	}

	/*
	 *  For a normally blocked task, hand-create the first level(s).
	 *  associated with __schedule() and/or schedule().
	 */
	if (!done &&
	    !(bt->flags & (BT_TEXT_SYMBOLS|BT_EXCEPTION_STACK|BT_IRQSTACK)) &&
	    (rip_symbol = closest_symbol(bt->instptr)) &&
	    (STREQ(rip_symbol, "thread_return") || 
	     STREQ(rip_symbol, "schedule") || 
	     STREQ(rip_symbol, "__schedule"))) {
		if (STREQ(rip_symbol, "__schedule")) {
			i = (rsp - bt->stackbase) / sizeof(ulong);
			xbt_frame_add(xf_list, bt, fp, level, i, bt->instptr);
			level++;
			rsp = __schedule_frame_adjust(rsp, bt);
			if (STREQ(closest_symbol(bt->instptr), "schedule"))
				bt->flags |= BT_SCHEDULE;
		} else {
			bt->flags |= BT_SCHEDULE;
		}

		if (bt->flags & BT_SCHEDULE) {
			i = (rsp - bt->stackbase) / sizeof(ulong);
			xbt_frame_add(xf_list, bt, fp, level, i, bt->instptr);
			bt->flags &= ~(ulonglong)BT_SCHEDULE;
			rsp += sizeof(ulong);
			level++;
		}
	}

	/*
	 *  Dump the IRQ exception frame from the process stack.
	 *  If the CS register indicates a user exception frame,
	 *  then set done to TRUE to avoid the process stack walk-through.
	 *  Otherwise, bump up the rsp past the kernel-mode eframe.
	 */
        if (irq_eframe) {
                bt->flags |= BT_EXCEPTION_FRAME;
                i = (irq_eframe - bt->stackbase) / sizeof(ulong);
                xbt_frame_add(xf_list, bt, fp, level, i, bt->instptr);
                bt->flags &= ~(ulonglong)BT_EXCEPTION_FRAME;
                cs = x86_64_exception_frame(EFRAME_PRINT|EFRAME_CS, 0, 
			bt->stackbuf + (irq_eframe - bt->stackbase), bt, fp);
		if (cs & 3)
			done = TRUE;   /* IRQ from user-mode */
		else {
			if (x86_64_print_eframe_location(rsp, level, fp))
				level++;
			rsp += SIZE(pt_regs);
			irq_eframe = 0;
			if (bt->eframe_ip && ((frame_size = x86_64_get_frame_size(bt, 
			    bt->eframe_ip, rsp)) >= 0))
				rsp += frame_size;
		}
		level++;
	}

	/*  Walk the process stack.  */
	bt->flags &= ~BT_FRAMESIZE_DISABLE;

	for (i = (rsp - bt->stackbase) / sizeof(ulong);
	     !done && (rsp < bt->stacktop);
	     i++, rsp += sizeof(ulong)) {

		up = (ulong *)(&bt->stackbuf[i * sizeof(ulong)]);

		if (!is_kernel_text(*up))
			continue;

		if (bt->flags & BT_CHECK_CALLER) {
			/*
			 *  A non-zero offset value from the value_search() 
			 *  lets us know if it's a real text return address.
			 */
			if (!(spt = value_search(*up, &offset)))
				continue;

			if (!offset && !(bt->flags & BT_FRAMESIZE_DISABLE))
				continue;

			/*
		         *  sp gets the syment of the function that the text 
			 *  routine above called before leaving its return 
			 *  address on the stack -- if it can be determined.
			 */
			sp = x86_64_function_called_by((*up) - 5); 
			if (sp == NULL) {
				/* 
				 *  We were unable to get the called function.
				 *  If the text address had an offset, then
				 *  it must have made an indirect call, and
				 *  can't have called our target function.
				 */
				if (offset != 0)
					continue;
			} else if ((machdep->flags & SCHED_TEXT) &&
				   STREQ(bt->call_target, "schedule") &&
				   STREQ(sp->name, "__sched_text_start")) {
				;  /*  bait and switch */
			} else if (!STREQ(sp->name, bt->call_target)) {
				/*
				 *  We got function called by the text routine,
			 	 *  but it's not our target function.
				 */
				continue;
			}
		}

		switch (xbt_frame_add(xf_list, bt, fp, level, i, *up)) {
		case BACKTRACE_ENTRY_AND_EFRAME_DISPLAYED:
			last_process_stack_eframe = rsp + 8;
			if (x86_64_print_eframe_location(last_process_stack_eframe, level, fp))
				level++;
			rsp += SIZE(pt_regs);
			i += SIZE(pt_regs) / sizeof(ulong);
			if (!bt->eframe_ip) {
				level++;
				break;
			} /* else fall through */
		case BACKTRACE_ENTRY_DISPLAYED:
			level++;
			frame_size = x86_64_get_frame_size(bt,
							   bt->eframe_ip ?
							   bt->eframe_ip :
							   *up, rsp);
			if (frame_size >= 0) {
				rsp += frame_size;
				i += frame_size / sizeof(ulong);
			}
			break;
		case BACKTRACE_ENTRY_IGNORED:	
			break;
		case BACKTRACE_COMPLETE:
			done = TRUE;
			break;
		}
        }

        if (!irq_eframe &&
	    !is_kernel_thread(bt->tc->task) &&
            (GET_STACKBASE(bt->tc->task) == bt->stackbase)) {
		user_mode_eframe = bt->stacktop - SIZE(pt_regs);
		if (last_process_stack_eframe < user_mode_eframe)
                	x86_64_exception_frame(EFRAME_PRINT, 0, bt->stackbuf +
					       (bt->stacktop - bt->stackbase) -
					       SIZE(pt_regs),
					       bt, fp);
	}

}
/* END copy from crash-7.0.0/x86_64.c */

static int xbt_crash_mem_ref(struct xbt_frame *xf, void *dest,
			     unsigned long addr, size_t size)
{
	int rc;

	if (readmem(addr, KVADDR, dest, size, "xbt_crash_mem_ref",
		    QUIET|RETURN_ON_ERROR))
		rc = 0;
	else
		rc = -XBT_BAD_MEM;

	xbt_trace("addr %lx, size %zu, rc %d", addr, size, rc);

	return rc;
}

/* xbt_frame_restore_regs() -- semibackwards nonportable prolog
 * disassembler.  The 30 minute works for me version.
 *
 * Try to disassemble prolog of child, restoring as many callee save
 * registers (rbx, r12-r15) as we can, while being as conservative as
 * possible.
 *
 * TODO Ensure noreturn functions handed properly.
 *
 * TODO Try to restore parent's xf_reg from child's xf_reg when not
 * saved by prolog. Requires that child registers be restored first as
 * is the case now. */
static void xbt_frame_restore_regs(struct xbt_frame *xp)
{
	struct xbt_frame *xc;
	unsigned long start;
	unsigned char prolog[64];
	long rsp_off;
	int i;

	xc = xf_child(xp);
	if (xc == NULL)
		return;

	start = xc->xf_func_start;
	if (start == 0)
		return;

	if (!readmem(start, KVADDR, prolog, sizeof(prolog), "prolog",
		     QUIET|RETURN_ON_ERROR))
		return;

	i = 0;
	if (!(prolog[i++] == 0x55 && /* push %rbp */
	      prolog[i++] == 0x48 && /* mov %rsp,%rbp */
	      prolog[i++] == 0x89 &&
	      prolog[i++] == 0xe5))
		return;

	rsp_off = - 2 * sizeof(unsigned long);

	while (i + 8 < sizeof(prolog)) {
		long off = LONG_MIN;
		unsigned int ri;
		unsigned char o1, o2, o3;

		switch (prolog[i++]) {
		case 0x41: /* push %r12-%r15 */
			o1 = prolog[i++];
			if (!(0x54 <= o1 && o1 < 0x58))
				return;

			ri = (o1 - 0x54) + XBT_R12;
			break;

		case 0x48: 
			o1 = prolog[i++];
			o2 = prolog[i++];
			o3 = prolog[i++];

			if (o1 == 0x81 && o2 == 0xec) {
				/* FIXME sub o3..o6,%rsp */
				return;
			}

 			if (o1 == 0x83 && o2 == 0xec) {
				/* sub o3,%rsp */
				rsp_off -= (signed char)o3;
				continue;
			}

			if (o1 == 0x89 && o2 == 0x5d) {
				/* 48 89 5d e8 mov %rbx,-0x18(%rbp) */
				ri = XBT_RBX;
				off = (signed char)o3;
				break;
			}
			return;

		case 0x4c:			
			o1 = prolog[i++];
			o2 = prolog[i++];
			o3 = prolog[i++];

			/*
			 * 4c 89 65 e8 mov %r12,-0x18(%rbp)
			 * 4c 89 6d f0 mov %r13,-0x10(%rbp)
			 * 4c 89 75 f8 mov %r14,-0x8(%rbp)
			 * 4c 89 7d f8 mov %r15,-0x8(%rbp)
			 *
			 * 4c 89 64 24 08 mov %r12,0x8(%rsp)
			 * 4c 89 6c 24 10 mov %r13,0x10(%rsp)
			 * 4c 89 74 24 18 mov %r14,0x18(%rsp)
			 */

			if (o1 != 0x89)
				return;

			if ((o2 & 0xfe) == 0x64)
				ri = XBT_R12;
			else if ((o2 & 0xfe) == 0x6c)
				ri = XBT_R13;
			else if ((o2 & 0xfe) == 0x74)
				ri = XBT_R14;
			else if ((o2 & 0xfe) == 0x7c)
				ri = XBT_R15;
			else
				return;

			if (o2 & 0x01)
				off = (signed char)o3;
			else if (o3 == 0x24)
				off = rsp_off + (signed char)prolog[i++];
			else
				return;
			break;

		case 0x53:
			/* push %rbx */
			ri = XBT_RBX;
			break;
		default:
			return;
		}

		if (off == LONG_MIN) {
			off = rsp_off;
			rsp_off -= sizeof(unsigned long);
		} else {
			off -= 8;
		}

		if (xf_frame_ref(xc, &xp->xf_reg[ri], off) < 0)
			return;

		xp->xf_reg_mask |= (1UL << ri);
	}
}

/* xbt_func() -- crash command callback. */
static void xbt_func(void)
{
	struct task_context *tc = CURRENT_CONTEXT();
	struct bt_info bt_info = {
		.stackbuf = NULL,
		.tc = tc,
		.task = tc->task,
		.stackbase = GET_STACKBASE(tc->task),
		.stacktop = GET_STACKTOP(tc->task),
		.flags = BT_FULL,
	}, *bt = &bt_info;
	ulong rsp;
	char *rip_sym;
	LIST_HEAD(xf_list);

	/*
	 * TODO Add option to select a specific frame.
	 * TODO Add option to select a specific object/variable.
	 * TODO Make frame numbering/display agree with 'bt -f'.
	 */
	int c;
	while ((c = getopt(argcnt, args, "d")) != -1) {
		switch (c) {
		case 'd':
			/* FIXME Global. */
			xbt_debug = 1;
			break;
		default:
			xbt_error("Usage: xbt [OPTION]... [PID]\n"
				  "\n"
				  "  -d, --debug   enable trace\n");
			goto out;
		}
	}

	xbt_trace("stack start %#016lx, end %#016lx", bt->stackbase, bt->stacktop);

	fill_stackbuf(bt);
	machdep->get_stack_frame(bt, &bt->instptr, &bt->stkptr);
	xbt_trace("rip %#016lx, rsp %#016lx",  bt->instptr, bt->stkptr);

	rsp = bt->stkptr;
	if (rsp == 0 || !accessible(rsp)) {
		error(INFO, "cannot access memory at rsp %#016lx\n", rsp);
		goto out;
	}

	if (!INSTACK(rsp, bt)) {
		error(INFO, "rsp %#016lx not in stack\n", rsp);
		goto out;
	}

	rip_sym = closest_symbol(bt->instptr);
	xbt_trace("rip_sym %s", rip_sym);

	xbt_back_trace_to_list(bt, &xf_list, pc->nullfp);

	struct xbt_frame *xf;
	list_for_each_entry(xf, &xf_list, xf_link) {
		/* Prev is child. */
		if (xf->xf_link.prev != &xf_list)
			xf->xf_has_child = true;

		/*  Next is parent. */
		if (xf->xf_link.next != &xf_list) {
			xf->xf_has_parent = true;
			xf->xf_frame_end = xf_parent(xf)->xf_frame_start;
		} else {
			xf->xf_frame_end = xf->xf_frame_start;
		}

		xf->xf_frame_base = &bt->stackbuf[xf->xf_frame_end -
						  bt->stackbase -
						  sizeof(ulong)];

		xf->xf_stack_base = bt->stackbuf;
		xf->xf_stack_start = bt->stackbase;
		xf->xf_stack_end = bt->stacktop;
		xf->xf_mem_ref = &xbt_crash_mem_ref;
	}

	list_for_each_entry(xf, &xf_list, xf_link)
		xbt_frame_restore_regs(xf);

	list_for_each_entry(xf, &xf_list, xf_link) {
		xbt_print("#%d\n"
			  "\tmod %s, name %s, RIP %#016lx\n"
			  "\tframe start %#016lx, end %#016lx, *base %#016lx\n",
			  xf->xf_level,
			  xf->xf_mod_name != NULL ? xf->xf_mod_name : "NONE",
			  xf->xf_func_name != NULL ? xf->xf_func_name : "NONE",
			  xf->xf_rip,
			  xf->xf_frame_start, xf->xf_frame_end,
			  *(ulong *)xf->xf_frame_base);

#define XBT_PRINT_REG(r)					\
		if (xf->xf_reg_mask & (1UL << (r)))		\
			xbt_print("\t%s = %lx\n", #r, xf->xf_reg[r])

		XBT_PRINT_REG(XBT_RBX);
		XBT_PRINT_REG(XBT_R12);
		XBT_PRINT_REG(XBT_R13);
		XBT_PRINT_REG(XBT_R14);
		XBT_PRINT_REG(XBT_R15);

		xbt_frame_print(fp, xf);

		xbt_print("\n");
	}
out:
	/* FIXME Cleanup. */

	xbt_debug = 0;
}

static void xmod_func(void)
{
	struct load_module *lm;
	struct mod_section_data *md;
        int i, j;

	for (i = 0; i < argcnt; i++) {
		if (!is_module_name(args[i], NULL, &lm))
			continue;

		fprintf(fp, "%s %8s %#016lx\n",
			lm->mod_name, "text", lm->mod_text_start);
		fprintf(fp, "%s %8s %#016lx\n",
			lm->mod_name, "etext", lm->mod_etext_guess);
		fprintf(fp, "%s %8s %#016lx\n",
			lm->mod_name, "rodata", lm->mod_rodata_start);
		fprintf(fp, "%s %8s %#016lx\n",
			lm->mod_name, "data", lm->mod_data_start);
		fprintf(fp, "%s %8s %#016lx\n",
			lm->mod_name, "bss", lm->mod_bss_start);

		for (j = 0; j < lm->mod_sections; j++) {
			md = &lm->mod_section_data[j];
			fprintf(fp, "# name=%s, offset=%#016lx, size=%#016lx\n",
				md->name, md->offset, md->size);
		}
	}
}

/* 
 *  The optional help data is simply an array of strings in a defined format.
 *  For example, the "help echo" command will use the help_echo[] string
 *  array below to create a help page that looks like this:
 * 
 *    NAME
 *      echo - echoes back its arguments
 *
 *    SYNOPSIS
 *      echo arg ...
 *
 *    DESCRIPTION
 *      This command simply echoes back its arguments.
 *
 *    EXAMPLE
 *      Echo back all command arguments:
 *
 *        crash> echo hello, world
 *        hello, world
 *
 */
 
static char *xmod_help[] = {
	"xmod", /* command name */
	"XMOD XMOD XMOD!", /* short description */
	"arg ...", /* argument synopsis, or " " if none */
	" ...,",
	NULL,
};

static struct command_table_entry xbt_entry[] = {
	{
		.name = "xbt",
		.func = xbt_func,
		/* FIXME .help_data = xbt_help, */
	},
	{
		.name = "xmod",
		.func = xmod_func,
		.help_data = xmod_help,
	},
	{
		.name = NULL,
	},
};

void __attribute__((constructor))
xmod_init(void)
{ 
	register_extension(xbt_entry);
}

void __attribute__((destructor))
xmod_fini(void)
{
}
