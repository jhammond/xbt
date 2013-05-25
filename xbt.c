/* xmod.c - simple example of a crash extension
 *
 # gcc -Wall -D_GNU_SOURCE -I/usr/include/crash -shared -rdynamic -o xmod.so xmod.c -fPIC -DX86_64
*/
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <ftw.h>
#include "defs.h"

/* Temp. Returns malloced string. */
static char *module_debuginfo_path(struct load_module *lm)
{
	const char *mod_dir_path = getenv("MODULE_PATH");
	char mod_name[PATH_MAX]; /* foo.ko */
	char *info_path = NULL;

	int ftw_cb(const char *path, const struct stat *sb, int type)
	{
		if (type != FTW_F)
			return 0;

		if (strcmp(mod_name, basename(path)) == 0) {
			info_path = strdup(path);
			return 1;
		}

		return 0;
	}

	if (mod_dir_path == NULL)
		return NULL;

	snprintf(mod_name, sizeof(mod_name), "%s.ko", lm->mod_name);
	ftw(mod_dir_path, &ftw_cb, 4);

	return info_path;
}


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
	ulong page;

	if ((page = machdep->machspec->vsyscall_page))
		if ((rip >= page) && (rip < (page+PAGESIZE())))
			return true;

	return false;
}

struct framesize_cache {
        ulong textaddr;
        int framesize;
	int exception;
};

static struct framesize_cache *x86_64_framesize_cache = NULL;
static int framesize_cache_entries = 0;

#define FRAMESIZE_QUERY  (1)
#define FRAMESIZE_ENTER  (2)
#define FRAMESIZE_DUMP   (3)

#define FRAMESIZE_CACHE_INCR (50)

static int x86_64_framesize_cache_resize(void)
{
	int i;
	struct framesize_cache *new_fc, *fc;

	if ((new_fc = realloc(x86_64_framesize_cache, 
			      (framesize_cache_entries + FRAMESIZE_CACHE_INCR) * 
			      sizeof(struct framesize_cache))) == NULL) {
		error(INFO, "cannot realloc x86_64_framesize_cache space!\n");
		return FALSE;
	}

	fc = new_fc + framesize_cache_entries;
	for (i = framesize_cache_entries; 
	     i < (framesize_cache_entries+FRAMESIZE_CACHE_INCR); 
	     fc++, i++) {
		fc->textaddr = 0;
		fc->framesize = 0;
		fc->exception = 0;
	} 	

	x86_64_framesize_cache = new_fc;
	framesize_cache_entries += FRAMESIZE_CACHE_INCR;

	return TRUE;
}

static int
x86_64_framesize_cache_func(int cmd, ulong textaddr, int *framesize, int exception)
{
	int i, n;
	struct framesize_cache *fc;
	char buf[BUFSIZE];

	if (!x86_64_framesize_cache) {
		framesize_cache_entries = FRAMESIZE_CACHE_INCR;
		if ((x86_64_framesize_cache = calloc(framesize_cache_entries,
		    sizeof(struct framesize_cache))) == NULL)
			error(FATAL, 
			    "cannot calloc x86_64_framesize_cache space!\n");
	}

	switch (cmd) 
	{
	case FRAMESIZE_QUERY:
		fc = &x86_64_framesize_cache[0];
		for (i = 0; i < framesize_cache_entries; i++, fc++) {
			if (fc->textaddr == textaddr) {
				if (fc->exception != exception)
					return FALSE;
				*framesize = fc->framesize;
				return TRUE;
			}
		}
		return FALSE;

	case FRAMESIZE_ENTER:
retry:
		fc = &x86_64_framesize_cache[0];
		for (i = 0; i < framesize_cache_entries; i++, fc++) {
			if ((fc->textaddr == 0) ||
			    (fc->textaddr == textaddr)) {
				if (*framesize == -1) {
					fc->textaddr = 0;
					fc->framesize = 0;
					fc->exception = 0;
					for (n = i+1; n < framesize_cache_entries; 
					    i++, n++)
						x86_64_framesize_cache[i] = 
							x86_64_framesize_cache[n];
					return 0;
				}
				fc->textaddr = textaddr;
				fc->framesize = *framesize;
				fc->exception = exception;
				return fc->framesize;
			}
		}

		if (x86_64_framesize_cache_resize())
			goto retry;

		return *framesize;

	case FRAMESIZE_DUMP:
		fc = &x86_64_framesize_cache[0];
		for (i = 0; i < framesize_cache_entries; i++, fc++) {
			if (fc->textaddr == 0) {
				if (i < (framesize_cache_entries-1)) {
					fprintf(fp, "[%d-%d]: (unused)\n",
						i, framesize_cache_entries-1);
				}
				break;
			}

			fprintf(fp, "[%3d]: %lx %3d %s (%s)\n", i,
				fc->textaddr, fc->framesize,
				fc->exception ? "EX" : "CF",
				value_to_symstr(fc->textaddr, buf, 0));
		}
		break;
	}

	return TRUE;
}

static struct syment *
x86_64_function_called_by(ulong rip)
{
	struct syment *sp;
	char buf[BUFSIZE], *p1;
	ulong value, offset;
	unsigned char byte;

	value = 0;
	sp = NULL;

        if (!readmem(rip, KVADDR, &byte, sizeof(unsigned char), "call byte",
            QUIET|RETURN_ON_ERROR)) 
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

	if (value)
		sp = value_search(value, &offset);

	/*
	 *  Functions that jmp to schedule() or schedule_timeout().
	 */
	if (sp) {
	    	if ((STREQ(sp->name, "schedule_timeout_interruptible") ||
	             STREQ(sp->name, "schedule_timeout_uninterruptible")))
			sp = symbol_search("schedule_timeout");

		if (STREQ(sp->name, "__cond_resched"))
			sp = symbol_search("schedule");
	}

	return sp;
}




/*
 *  The __schedule() framesize should only have to be calculated
 *  one time, but always verify that the previously-determined 
 *  framesize applies to this task, and if it doesn't, recalculate.
 *  Update the bt->instptr here, and return the new stack pointer.
 */
static ulong 
__schedule_frame_adjust(ulong rsp_in, struct bt_info *bt)
{
	int i, found;
	ulong rsp, *up;
	struct syment *sp;
	int framesize;

	if (x86_64_framesize_cache_func(FRAMESIZE_QUERY, 
	    machdep->machspec->thread_return, &framesize, 0)) {
		rsp = rsp_in + framesize;
		i = (rsp - bt->stackbase)/sizeof(ulong);
		up = (ulong *)(&bt->stackbuf[i*sizeof(ulong)]);

		if (is_kernel_text_offset(*up) &&
		    (sp = x86_64_function_called_by((*up)-5)) &&
		    STREQ(sp->name, "__schedule")) {
			bt->instptr = *up;
			return (rsp);
		}
	}

	rsp = rsp_in;

	for (found = FALSE, i = (rsp - bt->stackbase)/sizeof(ulong);
	     rsp < bt->stacktop; i++, rsp += sizeof(ulong)) {
		up = (ulong *)(&bt->stackbuf[i*sizeof(ulong)]);

		if (!is_kernel_text_offset(*up))
			continue;

		if ((sp = x86_64_function_called_by((*up)-5)) &&
		    (STREQ(sp->name, "__schedule"))) {
			framesize = (int)(rsp - rsp_in);
			bt->instptr = *up;
			x86_64_framesize_cache_func(FRAMESIZE_ENTER, 
			    machdep->machspec->thread_return,
			    &framesize, 0);
			bt->instptr = *up;
			found = TRUE;
			break;
		}
	}

	if (CRASHDEBUG(1) && !found)
		error(INFO, "cannot determine __schedule() caller\n");

	return (found ? rsp : rsp_in);
}

static void
x86_64_do_bt_reference_check(struct bt_info *bt, ulong text, char *name)
{
	ulong offset;
	struct syment *sp = NULL;

	if (!name)
		sp = value_search(text, &offset); 
	else if (!text)
		sp = symbol_search(name);

        switch (bt->ref->cmdflags & (BT_REF_SYMBOL|BT_REF_HEXVAL))
        {
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
text_lock_function(char *name, struct bt_info *bt, ulong locktext)
{
	int c, reterror, instr, arg;
	char buf[BUFSIZE];
	char *arglist[MAXARGS];
	char *p1;
	ulong locking_func;
	
	instr = arg = -1;
	locking_func = 0;

        open_tmpfile2();

	if (STREQ(name, ".text.lock.spinlock"))
        	sprintf(buf, "x/4i 0x%lx", locktext);
	else
        	sprintf(buf, "x/1i 0x%lx", locktext);

        if (!gdb_pass_through(buf, pc->tmpfile2, GNU_RETURN_ON_ERROR)) {
                close_tmpfile2();
                bt->flags |= BT_FRAMESIZE_DISABLE;
                return 0;
        }

        rewind(pc->tmpfile2);
        while (fgets(buf, BUFSIZE, pc->tmpfile2)) {
                c = parse_line(buf, arglist);

                if (instr == -1) {
                        /*
                         *  Check whether <function+offset> are
                         *  in the output string.
                         */
                        if (LASTCHAR(arglist[0]) == ':') {
                                instr = 1;
                                arg = 2;
                        } else {
                                instr = 2;
                                arg = 3;
                        }
                }

                if (c < (arg+1))
                        break;

		if (STREQ(arglist[instr], "jmpq") || STREQ(arglist[instr], "jmp")) {
                        p1 = arglist[arg];
                        reterror = 0;
                        locking_func = htol(p1, RETURN_ON_ERROR, &reterror);
                        if (reterror)
				locking_func = 0;
			break;
                }
	}
	close_tmpfile2();

	if (!locking_func)
                bt->flags |= BT_FRAMESIZE_DISABLE;

	return locking_func;

}

ulong
x86_64_get_framepointer(struct bt_info *bt, ulong rsp)
{
	ulong stackptr, framepointer, retaddr;

	framepointer = 0;
	stackptr = rsp - sizeof(ulong);

	if (!INSTACK(stackptr, bt))
		return 0;

	if (!readmem(stackptr, KVADDR, &framepointer,
	    sizeof(ulong), "framepointer", RETURN_ON_ERROR|QUIET)) 
		return 0;

	if (!INSTACK(framepointer, bt)) 
		return 0;

	if (framepointer <= (rsp+sizeof(ulong)))
		return 0;

	if (!readmem(framepointer + sizeof(ulong), KVADDR, &retaddr,
	    sizeof(ulong), "return address", RETURN_ON_ERROR|QUIET)) 
		return 0;

	if (!is_kernel_text(retaddr))
		return 0;

	return framepointer;
}

#define BT_FRAMESIZE_IGNORE_MASK \
	(BT_OLD_BACK_TRACE|BT_TEXT_SYMBOLS|BT_TEXT_SYMBOLS_ALL|BT_FRAMESIZE_DISABLE)
 
static int
x86_64_get_framesize(struct bt_info *bt, ulong textaddr, ulong rsp)
{
	int c, framesize, instr, arg, max;
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

	if (!(bt->flags & BT_FRAMESIZE_DEBUG)) {
		if ((bt->flags & BT_FRAMESIZE_IGNORE_MASK) ||
		    (kt->flags & USE_OLD_BT))
			return 0;
	}

        if (!(sp = value_search(textaddr, &offset))) {
		if (!(bt->flags & BT_FRAMESIZE_DEBUG))
			bt->flags |= BT_FRAMESIZE_DISABLE;
                return 0;
	}

	exception = bt->eframe_ip == textaddr ? TRUE : FALSE;

	if (!(bt->flags & BT_FRAMESIZE_DEBUG) &&
	    x86_64_framesize_cache_func(FRAMESIZE_QUERY, textaddr, &framesize,
		exception)) {
		if (framesize == -1)
			bt->flags |= BT_FRAMESIZE_DISABLE;
		return framesize; 
	}

	/*
	 *  Bait and switch an incoming .text.lock address
	 *  with the containing function's address.
	 */
	if (STRNEQ(sp->name, ".text.lock.") &&
	    (locking_func = text_lock_function(sp->name, bt, textaddr))) {
        	if (!(sp = value_search(locking_func, &offset))) {
			bt->flags |= BT_FRAMESIZE_DISABLE;
			return 0;
		}
		textaddr_save = textaddr;
		textaddr = locking_func;
	} else
		textaddr_save = 0;

	/*
	 *  As of 2.6.29, "irq_entries_start" replaced the range of IRQ
	 *  entry points named IRQ0x00_interrupt through IRQ0x##_interrupt.
	 *  Each IRQ entry point in the list of non-symbolically-named 
	 *  entry stubs consists of a single pushq and a jmp.
	 */
	if (STREQ(sp->name, "irq_entries_start")) {
#define PUSH_IMM8 0x6a
		if (readmem(textaddr, KVADDR, &instr,
		    sizeof(short), "irq_entries_start instruction", 
		    QUIET|RETURN_ON_ERROR) &&
		    ((instr & 0xff) == PUSH_IMM8))
			framesize = 0;
		else 
			framesize = 8;
		return (x86_64_framesize_cache_func(FRAMESIZE_ENTER, textaddr, 
                	&framesize, exception));
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
			framesize = framepointer - rsp;
			return (x86_64_framesize_cache_func(FRAMESIZE_ENTER, 
				textaddr, &framesize, 0));
		}
	}

	framesize = max = 0;
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
			 *  Check whether <function+offset> are 
			 *  in the output string.
			 */
			if (LASTCHAR(arglist[0]) == ':') {
				instr = 1;
				arg = 2;
			} else { 
				instr = 2;
				arg = 3;
			}
		}

		if (c < (instr+1))
			continue;
		else if (c >= (arg+1))
			arg_exists = TRUE;
		else
			arg_exists = FALSE;

		reterror = 0;
		current =  htol(strip_ending_char(arglist[0], ':'), 
			RETURN_ON_ERROR, &reterror);
		if (reterror)
			continue;

		if (current > textaddr)
			break;
		else if ((current == textaddr) && !exception)
			break;

		if (STRNEQ(arglist[instr], "push")) {
			framesize += 8;
			if (CRASHDEBUG(2) || (bt->flags & BT_FRAMESIZE_DEBUG))
				fprintf(fp, "%s\t[framesize: %d]\n", 
					strip_linefeeds(buf2), framesize);
			max = framesize;
	 	} else if (STRNEQ(arglist[instr], "pop") || 
		    STRNEQ(arglist[instr], "leaveq")) {
			if (framesize > 0)
				framesize -= 8;
			if (CRASHDEBUG(2) || (bt->flags & BT_FRAMESIZE_DEBUG))
				fprintf(fp, "%s\t[framesize: %d]\n", 
					strip_linefeeds(buf2), framesize);
		} else if (arg_exists && STRNEQ(arglist[instr], "add") && 
			(p1 = strstr(arglist[arg], ",%rsp"))) {
			*p1 = NULLCHAR;
			p2 = arglist[arg];
			reterror = 0;
			offset =  htol(p2+1, RETURN_ON_ERROR, &reterror);
			if (reterror)
				continue;
			if (framesize > 0)
				framesize -= offset;
			if (CRASHDEBUG(2) || (bt->flags & BT_FRAMESIZE_DEBUG))
				fprintf(fp, "%s\t[framesize: %d]\n", 
					strip_linefeeds(buf2), framesize);
		} else if (arg_exists && STRNEQ(arglist[instr], "sub") && 
			(p1 = strstr(arglist[arg], ",%rsp"))) {
			*p1 = NULLCHAR;
			p2 = arglist[arg];
			reterror = 0;
			offset =  htol(p2+1, RETURN_ON_ERROR, &reterror);
			if (reterror)
				continue;
			framesize += offset;
			max = framesize;
			if (CRASHDEBUG(2) || (bt->flags & BT_FRAMESIZE_DEBUG))
				fprintf(fp, "%s\t[framesize: %d]\n", 
					strip_linefeeds(buf2), framesize);
		} else if (STRNEQ(arglist[instr], "retq")) {
			if (!exception) {
				framesize = max;
				if (CRASHDEBUG(2) || (bt->flags & BT_FRAMESIZE_DEBUG))
					fprintf(fp, "%s\t[framesize restored to: %d]\n", 
						strip_linefeeds(buf2), max);
			}
		} else if (STRNEQ(arglist[instr], "retq_NOT_CHECKED")) {
			bt->flags |= BT_FRAMESIZE_DISABLE;
			framesize = -1;
			if (CRASHDEBUG(2) || (bt->flags & BT_FRAMESIZE_DEBUG))
				fprintf(fp, "%s\t[framesize: DISABLED]\n", 
					strip_linefeeds(buf2));
			break;
		} 
        }
        close_tmpfile2();

	if (textaddr_save)
		textaddr = textaddr_save;

	return (x86_64_framesize_cache_func(FRAMESIZE_ENTER, textaddr, 
		&framesize, exception));
}

static void x86_64_framesize_debug(struct bt_info *bt)
{
	int framesize;
	int exception;

	exception = (bt->flags & BT_EFRAME_SEARCH);

	switch (bt->hp->esp) {
	case 1: /* "dump" */
		x86_64_framesize_cache_func(FRAMESIZE_DUMP, 0, NULL, 0);
		break;
	case 0:
		if (bt->hp->eip) {  /* clear one entry */
			framesize = -1;
			x86_64_framesize_cache_func(FRAMESIZE_ENTER, bt->hp->eip, 
				&framesize, exception);
		} else { /* clear all entries */
			BZERO(&x86_64_framesize_cache[0], 
			    sizeof(struct framesize_cache)*framesize_cache_entries);
			fprintf(fp, "framesize cache cleared\n");
		}
		break;
	case -1:
		if (!bt->hp->eip)
			error(INFO, "x86_64_framesize_debug: ignoring command\n");
		else
			x86_64_get_framesize(bt, bt->hp->eip, 0);
		break;
	case -3:
		machdep->flags |= FRAMEPOINTER;
		BZERO(&x86_64_framesize_cache[0], 
			sizeof(struct framesize_cache)*framesize_cache_entries);
		fprintf(fp, 
			"framesize cache cleared and FRAMEPOINTER turned ON\n");
		break;
	case -4:
		machdep->flags &= ~FRAMEPOINTER;
		BZERO(&x86_64_framesize_cache[0], 
			sizeof(struct framesize_cache)*framesize_cache_entries);
		fprintf(fp,
			"framesize cache cleared and FRAMEPOINTER turned OFF\n");
		break;
	default:
		if (bt->hp->esp > 1) {
			framesize = bt->hp->esp;
			if (bt->hp->eip)
				x86_64_framesize_cache_func(FRAMESIZE_ENTER, bt->hp->eip, 
					&framesize, exception);
		} else {
			error(INFO, "x86_64_framesize_debug: ignoring command\n");
		}
		break;
	}
}

static void
x86_64_display_full_frame(struct bt_info *bt, ulong rsp, FILE *ofp)
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
	u_idx = (bt->frameptr - bt->stackbase)/sizeof(ulong);
	for (i = 0; i < words; i++, u_idx++) {
		if (!(i & 1)) 
			fprintf(ofp, "%s    %lx: ", i ? "\n" : "", addr);
		
		up = (ulong *)(&bt->stackbuf[u_idx*sizeof(ulong)]);
		fprintf(ofp, "%s ", format_stack_entry(bt, buf, *up, 0));
		addr += sizeof(ulong);
	}
	fprintf(ofp, "\n");
}

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

#define BACKTRACE_COMPLETE                   (1)
#define BACKTRACE_ENTRY_IGNORED              (2)
#define BACKTRACE_ENTRY_DISPLAYED            (3)
#define BACKTRACE_ENTRY_AND_EFRAME_DISPLAYED (4)

static int
x86_64_print_stack_entry(struct bt_info *bt, FILE *ofp, int level, 
	int stkindex, ulong text)
{
	ulong rsp, offset, locking_func;
	struct syment *sp, *spl;
	char *name, *name_plus_offset;
	int i, result; 
	long eframe_check;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	struct load_module *lm;

	eframe_check = -1;
	if (!(bt->flags & BT_SAVE_EFRAME_IP))
		bt->eframe_ip = 0;
	offset = 0;
	sp = value_search(text, &offset);
	if (!sp)
		return BACKTRACE_ENTRY_IGNORED;

	name = sp->name;

	if (offset && (bt->flags & BT_SYMBOL_OFFSET))
		name_plus_offset = value_to_symstr(text, buf2, bt->radix);
	else
		name_plus_offset = NULL;

	if (bt->flags & BT_TEXT_SYMBOLS) {
		if (bt->flags & BT_EXCEPTION_FRAME)
			rsp = bt->stkptr;
		else
			rsp = bt->stackbase + (stkindex * sizeof(long));
                fprintf(ofp, "  [%s] %s at %lx",
                	mkstring(buf1, VADDR_PRLEN, RJUST|LONG_HEX, MKSTR(rsp)),
			name_plus_offset ? name_plus_offset : name, text);
		if (module_symbol(text, NULL, &lm, NULL, 0))
			fprintf(ofp, " [%s]", lm->mod_name);
		fprintf(ofp, "\n");
		if (BT_REFERENCE_CHECK(bt))
			x86_64_do_bt_reference_check(bt, text, name);
		return BACKTRACE_ENTRY_DISPLAYED;
	}

	if (!offset && !(bt->flags & BT_EXCEPTION_FRAME) &&
	    !(bt->flags & BT_START)) { 
		if (STREQ(name, "child_rip")) {
			if (symbol_exists("kernel_thread"))
				name = "kernel_thread";
			else if (symbol_exists("arch_kernel_thread"))
				name = "arch_kernel_thread";
		}
		else if (!(bt->flags & BT_SCHEDULE)) {
			if (STREQ(name, "error_exit")) 
				eframe_check = 8;
			else {
				if (CRASHDEBUG(2))
					fprintf(ofp, 
		              "< ignoring text symbol with no offset: %s() >\n",
						sp->name);
				return BACKTRACE_ENTRY_IGNORED;
			}
		}
	}

	if ((THIS_KERNEL_VERSION >= LINUX(2,6,29)) && 
	    (eframe_check == -1) && offset && 
	    !(bt->flags & (BT_EXCEPTION_FRAME|BT_START|BT_SCHEDULE))) { 
		for (i = 0; exception_functions[i]; i++) {
			if (STREQ(name, exception_functions[i])) {
				eframe_check = 8;
				break;
			}
		}
	}

	if (bt->flags & BT_SCHEDULE)
		name = "schedule";

        if (STREQ(name, "child_rip")) {
                if (symbol_exists("kernel_thread"))
                        name = "kernel_thread";
                else if (symbol_exists("arch_kernel_thread"))
                        name = "arch_kernel_thread";
		result = BACKTRACE_COMPLETE;
        } else if (STREQ(name, "cpu_idle") || 
	    STREQ(name, "system_call_fastpath"))
		result = BACKTRACE_COMPLETE;
	else
		result = BACKTRACE_ENTRY_DISPLAYED;

	if (bt->flags & BT_EXCEPTION_FRAME)
		rsp = bt->stkptr;
	else if (bt->flags & BT_START)
		rsp = bt->stkptr;
	else
		rsp = bt->stackbase + (stkindex * sizeof(long));

	if ((bt->flags & BT_FULL)) {
		if (bt->frameptr) 
			x86_64_display_full_frame(bt, rsp, ofp);
		bt->frameptr = rsp + sizeof(ulong);
	}

       	fprintf(ofp, "%s#%d [%8lx] %s at %lx", level < 10 ? " " : "", level,
		rsp, name_plus_offset ? name_plus_offset : name, text);

	if (STREQ(name, "tracesys"))
		fprintf(ofp, " (via system_call)");
	else if (STRNEQ(name, ".text.lock.")) {
		if ((locking_func = text_lock_function(name, bt, text)) &&
		    (spl = value_search(locking_func, &offset)))
			fprintf(ofp, " (via %s)", spl->name);
	}
	if (module_symbol(text, NULL, &lm, NULL, 0))
		fprintf(ofp, " [%s]", lm->mod_name);

	if (bt->flags & BT_FRAMESIZE_DISABLE)
		fprintf(ofp, " *");

	fprintf(ofp, "\n");

        if (bt->flags & BT_LINE_NUMBERS) {
                get_line_number(text, buf1, FALSE);
                if (strlen(buf1))
                        fprintf(ofp, "    %s\n", buf1);
	}

	if (eframe_check >= 0) {
		if (x86_64_exception_frame(EFRAME_PRINT|EFRAME_VERIFY, 
		    bt->stackbase + (stkindex*sizeof(long)) + eframe_check,
		    NULL, bt, ofp))
			result = BACKTRACE_ENTRY_AND_EFRAME_DISPLAYED;
	}

	if (BT_REFERENCE_CHECK(bt))
		x86_64_do_bt_reference_check(bt, text, name);

	bt->call_target = name;

	if (is_direct_call_target(bt)) {
		if (CRASHDEBUG(2))
			fprintf(ofp, "< enable BT_CHECK_CALLER for %s >\n", 
				bt->call_target);
		bt->flags |= BT_CHECK_CALLER;
	} else {
		if (CRASHDEBUG(2) && (bt->flags & BT_CHECK_CALLER))
			fprintf(ofp, "< disable BT_CHECK_CALLER for %s >\n", 
				bt->call_target);
		if (bt->flags & BT_CHECK_CALLER) {
			if (CRASHDEBUG(2))
			    	fprintf(ofp, "< set BT_NO_CHECK_CALLER >\n");
			bt->flags |= BT_NO_CHECK_CALLER;
		}
		bt->flags &= ~(ulonglong)BT_CHECK_CALLER;
	}

	return result;
}


static bool x86_64_print_eframe_location(ulong eframe, int level, FILE *ofp)
{
	return false;
}



/*
 *  Calculate and verify the IRQ exception frame location from the 
 *  stack reference at the top of the IRQ stack, possibly adjusting
 *  the ms->irq_eframe_link value.
 */
static ulong
x86_64_irq_eframe_link(ulong stkref, struct bt_info *bt, FILE *ofp)
{
	ulong irq_eframe;

	irq_eframe = stkref - machdep->machspec->irq_eframe_link;

	if (x86_64_exception_frame(EFRAME_VERIFY, irq_eframe, 0, bt, ofp))
		return irq_eframe;

	if (x86_64_exception_frame(EFRAME_VERIFY, irq_eframe+8, 0, bt, ofp)) {
		machdep->machspec->irq_eframe_link -= 8;
		return (irq_eframe + 8);
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
			    (rsp < (ms->stkinfo.ebase[c][i] + 
			    ms->stkinfo.esize[i]))) {
				estack = ms->stkinfo.ebase[c][i]; 

				if (estack_index)
					*estack_index = i;

				if (CRASHDEBUG(1) && (c != bt->tc->processor)) 
					error(INFO, 
      		                      "task cpu: %d  exception stack cpu: %d\n",
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

static int 
x86_64_eframe_verify(struct bt_info *bt, long kvaddr, long cs, long ss,
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
			    struct bt_info *bt, FILE *ofp)
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
		fprintf(ofp, "< exception frame at: %lx >\n", kvaddr ?
			kvaddr : (local - bt->stackbuf) + bt->stackbase);

	if (flags & EFRAME_PRINT) {
		if (flags & EFRAME_SEARCH) {
			fprintf(ofp, "\n  %s-MODE EXCEPTION FRAME AT: %lx\n",
				cs & 3 ? "USER" : "KERNEL", 
				kvaddr ?  kvaddr : 
				(local - bt->stackbuf) + bt->stackbase);
			if (!(cs & 3)) {
				fprintf(ofp, "    [exception RIP: ");
				if ((sp = value_search(rip, &offset))) {
					fprintf(ofp, "%s", sp->name);
					if (offset)
						fprintf(ofp, 
						    (*gdb_output_radix == 16) ? 
						    "+0x%lx" : "+%ld", 
						    offset);
				} else 
					fprintf(ofp, 
						"unknown or invalid address");
				fprintf(ofp, "]\n");
			}
		} else if (!(cs & 3)) {
			fprintf(ofp, "    [exception RIP: ");
			if ((sp = value_search(rip, &offset))) {
                		fprintf(ofp, "%s", sp->name);
                		if (offset)
                        		fprintf(ofp, (*gdb_output_radix == 16) ? 
						"+0x%lx" : "+%ld", offset);
				bt->eframe_ip = rip;
			} else
                		fprintf(ofp, "unknown or invalid address");
			fprintf(ofp, "]\n");
		}
		fprintf(ofp, "    RIP: %016lx  RSP: %016lx  RFLAGS: %08lx\n", 
			rip, rsp, rflags);
		fprintf(ofp, "    RAX: %016lx  RBX: %016lx  RCX: %016lx\n", 
			rax, rbx, rcx);
		fprintf(ofp, "    RDX: %016lx  RSI: %016lx  RDI: %016lx\n", 
	 		rdx, rsi, rdi);
		fprintf(ofp, "    RBP: %016lx   R8: %016lx   R9: %016lx\n", 
			rbp, r8, r9);
		fprintf(ofp, "    R10: %016lx  R11: %016lx  R12: %016lx\n", 
			r10, r11, r12);
		fprintf(ofp, "    R13: %016lx  R14: %016lx  R15: %016lx\n", 
			r13, r14, r15);
		fprintf(ofp, "    ORIG_RAX: %016lx  CS: %04lx  SS: %04lx\n", 
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

static void
x86_64_low_budget_back_trace_cmd(struct bt_info *bt_in)
{
	int i, level, done, framesize, estack_index;
	ulong rsp, offset, stacktop;
	ulong *up;
	long cs;
	struct syment *sp, *spt;
	FILE *ofp;
	ulong estack, irqstack;
	ulong irq_eframe;
	struct bt_info bt_local, *bt;
	struct machine_specific *ms;
	ulong last_process_stack_eframe;
	ulong user_mode_eframe;
	char *rip_symbol;

#define STACK_TRANSITION_ERRMSG_E_I_P \
"cannot transition from exception stack to IRQ stack to current process stack:\n    exception stack pointer: %lx\n          IRQ stack pointer: %lx\n      process stack pointer: %lx\n         current stack base: %lx\n" 
#define STACK_TRANSITION_ERRMSG_E_P \
"cannot transition from exception stack to current process stack:\n    exception stack pointer: %lx\n      process stack pointer: %lx\n         current stack base: %lx\n"
#define STACK_TRANSITION_ERRMSG_I_P \
"cannot transition from IRQ stack to current process stack:\n        IRQ stack pointer: %lx\n    process stack pointer: %lx\n       current stack base: %lx\n"

#if 0
        /*
         *  User may have made a run-time switch.
         */
	if (kt->flags & DWARF_UNWIND) {
		machdep->back_trace = x86_64_dwarf_back_trace_cmd;
		x86_64_dwarf_back_trace_cmd(bt_in);
		return;
	}
#endif

	bt = &bt_local;
	BCOPY(bt_in, bt, sizeof(struct bt_info));

	if (bt->flags & BT_FRAMESIZE_DEBUG) {
		x86_64_framesize_debug(bt);
		return;
	}

	level = 0;
	done = FALSE;
	irq_eframe = 0;
	last_process_stack_eframe = 0;
	bt->call_target = NULL;
	rsp = bt->stkptr;
	ms = machdep->machspec;

	if (BT_REFERENCE_CHECK(bt))
		ofp = pc->nullfp;
	else
		ofp = fp;

	/* If rsp is in user stack, the memory may not be included in vmcore, and
	 * we only output the register's value. So it's not necessary to check
	 * whether it can be accessible.
	 */
	if (!(bt->flags & BT_USER_SPACE) && (!rsp || !accessible(rsp))) {
		error(INFO, "cannot determine starting stack pointer\n");
		if (KVMDUMP_DUMPFILE())
			kvmdump_display_regs(bt->tc->processor, ofp);
		else if (ELF_NOTES_VALID() && DISKDUMP_DUMPFILE())
			diskdump_display_regs(bt->tc->processor, ofp);
		else if (SADUMP_DUMPFILE())
			sadump_display_regs(bt->tc->processor, ofp);
		return;
	}

        if (bt->flags & BT_TEXT_SYMBOLS) {
		if ((bt->flags & BT_USER_SPACE) &&
		    !(bt->flags & BT_TEXT_SYMBOLS_ALL))
			return;
		if (!(bt->flags & BT_TEXT_SYMBOLS_ALL))
                	fprintf(ofp, "%sSTART: %s%s at %lx\n",
                	    space(VADDR_PRLEN > 8 ? 14 : 6),
                	    closest_symbol(bt->instptr), 
			    STREQ(closest_symbol(bt->instptr), "thread_return") ?
			    " (schedule)" : "",
			    bt->instptr);
	} else if (bt->flags & BT_USER_SPACE) {
		fprintf(ofp, "    [exception RIP: user space]\n");
		if (KVMDUMP_DUMPFILE())
			kvmdump_display_regs(bt->tc->processor, ofp);
		else if (ELF_NOTES_VALID() && DISKDUMP_DUMPFILE())
			diskdump_display_regs(bt->tc->processor, ofp);
		else if (SADUMP_DUMPFILE())
			sadump_display_regs(bt->tc->processor, ofp);
		return;
	} else if ((bt->flags & BT_KERNEL_SPACE) &&
		   (KVMDUMP_DUMPFILE() ||
		    (ELF_NOTES_VALID() && DISKDUMP_DUMPFILE()) ||
		    SADUMP_DUMPFILE())) {
		fprintf(ofp, "    [exception RIP: ");
		if ((sp = value_search(bt->instptr, &offset))) {
			fprintf(ofp, "%s", sp->name);
			if (offset)
				fprintf(ofp, (*gdb_output_radix == 16) ?
					"+0x%lx" : "+%ld", offset);
		} else
			fprintf(ofp, "unknown or invalid address");
		fprintf(ofp, "]\n");
		if (KVMDUMP_DUMPFILE())
			kvmdump_display_regs(bt->tc->processor, ofp);
		else if (ELF_NOTES_VALID() && DISKDUMP_DUMPFILE())
			diskdump_display_regs(bt->tc->processor, ofp);
		else if (SADUMP_DUMPFILE())
			sadump_display_regs(bt->tc->processor, ofp);
        } else if (bt->flags & BT_START) {
                x86_64_print_stack_entry(bt, ofp, level,
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
                        i = (irq_eframe - bt->stackbase)/sizeof(ulong);
                        x86_64_print_stack_entry(bt, ofp, level, i, 
				bt->instptr);
                        bt->flags &= ~(ulonglong)BT_EXCEPTION_FRAME;
                        cs = x86_64_exception_frame(EFRAME_PRINT|EFRAME_CS, 0,
                        	bt->stackbuf + (irq_eframe - bt->stackbase), 
				bt, ofp);
                        rsp += SIZE(pt_regs);  /* guaranteed kernel mode */
			if (bt->eframe_ip && ((framesize = x86_64_get_framesize(bt, 
			    bt->eframe_ip, rsp)) >= 0))
				rsp += framesize;
                        level++;
                        irq_eframe = 0;
                }

		stacktop = bt->stacktop - SIZE(pt_regs);

		bt->flags &= ~BT_FRAMESIZE_DISABLE;

        	for (i = (rsp - bt->stackbase)/sizeof(ulong);
	     	    !done && (rsp < stacktop); i++, rsp += sizeof(ulong)) {

			up = (ulong *)(&bt->stackbuf[i*sizeof(ulong)]);

			if (!is_kernel_text(*up))
		        	continue;

	                switch (x86_64_print_stack_entry(bt, ofp, level, i,*up))
	                {
	                case BACKTRACE_ENTRY_AND_EFRAME_DISPLAYED:
				rsp += SIZE(pt_regs);
				i += SIZE(pt_regs)/sizeof(ulong);
				if (!bt->eframe_ip) {
					level++;
					break;
				} /* else fall through */
	                case BACKTRACE_ENTRY_DISPLAYED:
	                        level++;
				if ((framesize = x86_64_get_framesize(bt, 
				    bt->eframe_ip ?  bt->eframe_ip : *up, rsp)) >= 0) {
					rsp += framesize;
					i += framesize/sizeof(ulong);
				}
	                        break;
	                case BACKTRACE_ENTRY_IGNORED:
	                        break;
	                case BACKTRACE_COMPLETE:
	                        done = TRUE;
	                        break;
	                }
		}

                cs = x86_64_exception_frame(EFRAME_PRINT|EFRAME_CS, 0, 
			bt->stackbuf + (bt->stacktop - bt->stackbase) - 
			SIZE(pt_regs), bt, ofp);

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
			x86_64_print_stack_entry(bt, ofp, level,
				0, bt->instptr);
			bt->flags &= 
			    	~(BT_START|BT_SAVE_EFRAME_IP|BT_FRAMESIZE_DISABLE);

			/*
			 *  Protect against exception stack recursion.
			 */
			if (x86_64_in_exception_stack(bt, NULL) == estack) {
				fprintf(ofp, 
     				    "    [ %s exception stack recursion: "
				    "prior stack location overwritten ]\n",
					x86_64_exception_stacks[estack_index]);
				return;
			}

			level++;
			if ((framesize = x86_64_get_framesize(bt, bt->instptr, rsp)) >= 0)
				rsp += framesize;
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

                for (i = (rsp - bt->stackbase)/sizeof(ulong);
                    !done && (rsp < stacktop); i++, rsp += sizeof(ulong)) {

                        up = (ulong *)(&bt->stackbuf[i*sizeof(ulong)]);

                        if (!is_kernel_text(*up))
                                continue;

                        switch (x86_64_print_stack_entry(bt, ofp, level, i,*up))
                        {
			case BACKTRACE_ENTRY_AND_EFRAME_DISPLAYED:
				rsp += SIZE(pt_regs);
				i += SIZE(pt_regs)/sizeof(ulong);
				if (!bt->eframe_ip) {
					level++;
					break;
				} /* else fall through */
                        case BACKTRACE_ENTRY_DISPLAYED:
                                level++;
				if ((framesize = x86_64_get_framesize(bt, 
				    bt->eframe_ip ? bt->eframe_ip : *up, rsp)) >= 0) {
					rsp += framesize;
					i += framesize/sizeof(ulong);
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
                irq_eframe = rsp = bt->stkptr = x86_64_irq_eframe_link(*up, bt, ofp);
		up -= 1;
                bt->instptr = *up;
		/*
		 *  No exception frame when coming from call_softirq.
		 */
		if ((sp = value_search(bt->instptr, &offset)) && 
		    STREQ(sp->name, "call_softirq"))
			irq_eframe = 0;
                bt->frameptr = 0;
                done = FALSE;
        } else
		irq_eframe = 0;

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
			switch (bt->flags & (BT_EXCEPTION_STACK|BT_IRQSTACK))
			{
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
						return;
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
			i = (rsp - bt->stackbase)/sizeof(ulong);
			x86_64_print_stack_entry(bt, ofp, level, 
				i, bt->instptr);
			level++;
			rsp = __schedule_frame_adjust(rsp, bt);
			if (STREQ(closest_symbol(bt->instptr), "schedule"))
				bt->flags |= BT_SCHEDULE;
		} else
			bt->flags |= BT_SCHEDULE;

		if (bt->flags & BT_SCHEDULE) {
			i = (rsp - bt->stackbase)/sizeof(ulong);
			x86_64_print_stack_entry(bt, ofp, level, 
				i, bt->instptr);
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
                i = (irq_eframe - bt->stackbase)/sizeof(ulong);
                x86_64_print_stack_entry(bt, ofp, level, i, bt->instptr);
                bt->flags &= ~(ulonglong)BT_EXCEPTION_FRAME;
                cs = x86_64_exception_frame(EFRAME_PRINT|EFRAME_CS, 0, 
			bt->stackbuf + (irq_eframe - bt->stackbase), bt, ofp);
		if (cs & 3)
			done = TRUE;   /* IRQ from user-mode */
		else {
			if (x86_64_print_eframe_location(rsp, level, ofp))
				level++;
			rsp += SIZE(pt_regs);
			irq_eframe = 0;
			if (bt->eframe_ip && ((framesize = x86_64_get_framesize(bt, 
			    bt->eframe_ip, rsp)) >= 0))
				rsp += framesize;
		}
		level++;
        }

	/*
	 *  Walk the process stack.  
	 */

	bt->flags &= ~BT_FRAMESIZE_DISABLE;

        for (i = (rsp - bt->stackbase)/sizeof(ulong);
	     !done && (rsp < bt->stacktop); i++, rsp += sizeof(ulong)) {

		up = (ulong *)(&bt->stackbuf[i*sizeof(ulong)]);

		if (!is_kernel_text(*up))
			continue;

		if ((bt->flags & BT_CHECK_CALLER)) {
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
			sp = x86_64_function_called_by((*up)-5); 

			if (sp == NULL) {
				/* 
				 *  We were unable to get the called function.
				 *  If the text address had an offset, then
				 *  it must have made an indirect call, and
				 *  can't have called our target function.
				 */
				if (offset) {
					if (CRASHDEBUG(1))
						fprintf(ofp, 
                       "< ignoring %s() -- makes indirect call and NOT %s()>\n",
						    	spt->name, 
						    	bt->call_target);
					continue;
				}
			} else if ((machdep->flags & SCHED_TEXT) &&
				STREQ(bt->call_target, "schedule") &&
				STREQ(sp->name, "__sched_text_start")) {
				;  /*  bait and switch */
			} else if (!STREQ(sp->name, bt->call_target)) {
				/*
				 *  We got function called by the text routine,
			 	 *  but it's not our target function.
				 */
				if (CRASHDEBUG(2))
					fprintf(ofp, 
 		                "< ignoring %s() -- calls %s() and NOT %s()>\n",
						spt->name, sp->name, 
						bt->call_target);
				continue;
			}
		}

		switch (x86_64_print_stack_entry(bt, ofp, level, i,*up))
		{
		case BACKTRACE_ENTRY_AND_EFRAME_DISPLAYED:
			last_process_stack_eframe = rsp + 8;
			if (x86_64_print_eframe_location(last_process_stack_eframe, level, ofp))
				level++;
			rsp += SIZE(pt_regs);
			i += SIZE(pt_regs)/sizeof(ulong);
			if (!bt->eframe_ip) {
				level++;
				break;
			} /* else fall through */
		case BACKTRACE_ENTRY_DISPLAYED:
			level++;
			if ((framesize = x86_64_get_framesize(bt, 
			    bt->eframe_ip ? bt->eframe_ip : *up, rsp)) >= 0) {
				rsp += framesize;
				i += framesize/sizeof(ulong);
			}
			break;
		case BACKTRACE_ENTRY_IGNORED:	
			break;
		case BACKTRACE_COMPLETE:
			done = TRUE;
			break;
		}
        }

        if (!irq_eframe && !is_kernel_thread(bt->tc->task) &&
            (GET_STACKBASE(bt->tc->task) == bt->stackbase)) {
		user_mode_eframe = bt->stacktop - SIZE(pt_regs);
		if (last_process_stack_eframe < user_mode_eframe)
                	x86_64_exception_frame(EFRAME_PRINT, 0, bt->stackbuf +
                        	(bt->stacktop - bt->stackbase) - SIZE(pt_regs),
                        	bt, ofp);
	}

        if (bt->flags & BT_TEXT_SYMBOLS) {
        	if (BT_REFERENCE_FOUND(bt)) {
                	print_task_header(fp, task_to_context(bt->task), 0);
			BCOPY(bt_in, bt, sizeof(struct bt_info));
                	bt->ref = NULL;
                	machdep->back_trace(bt);
                	fprintf(fp, "\n");
        	}
	}
}

/* END copy */

void xbt_func(void)
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
	int level = 0;
	bool is_done = false;
	ulong rsp;
	char *rip_sym;

	// ACTIVE();
	// KDUMP_DUMPFILE();

	fprintf(fp, "# stack %#016lx %#016lx\n", bt->stackbase, bt->stacktop);

	// back_trace(bt);
	fill_stackbuf(bt);

	// get_kdump_regs(bt, &bt->instptr, &bt->stkptr); DNW
	machdep->get_stack_frame(bt, &bt->instptr, &bt->stkptr);
	fprintf(fp, "# rip %#016lx, rsp %#016lx\n",  bt->instptr, bt->stkptr);

	rsp = bt->stkptr;
	if (rsp == 0 || !accessible(rsp)) {
		error(INFO, "cannot access memory at rsp %#016lx\n", rsp);
		return;
	}

	if (!INSTACK(rsp, bt)) {
		error(INFO, "rsp %#016lx not in stack\n", rsp);
		return;
	}

	rip_sym = closest_symbol(bt->instptr);
	fprintf(fp, "# rip_sym %s\n", rip_sym);

	/* Assume not in estack. */
	/* Assume not in IRQ stack. */
	/* machdep->back_trace(bt); */
	x86_64_low_budget_back_trace_cmd(bt); // not exported.
}

void xmod_func(void)
{
	struct load_module *lm;
	struct mod_section_data *md;
        int i, j;

	for (i = 0; i < argcnt; i++) {
		if (!is_module_name(args[i], NULL, &lm))
			continue;

		fprintf(fp, "%s %8s %#016lx\n", lm->mod_name, "text", lm->mod_text_start);
		fprintf(fp, "%s %8s %#016lx\n", lm->mod_name, "etext", lm->mod_etext_guess);
		fprintf(fp, "%s %8s %#016lx\n", lm->mod_name, "rodata", lm->mod_rodata_start);
		fprintf(fp, "%s %8s %#016lx\n", lm->mod_name, "data", lm->mod_data_start);
		fprintf(fp, "%s %8s %#016lx\n", lm->mod_name, "bss", lm->mod_bss_start);

		for (j = 0; j < lm->mod_sections; j++) {
			md = &lm->mod_section_data[j];
			fprintf(fp, "# name=%s, offset=%#016lx, size=%#016lx\n",
				md->name, md->offset, md->size);
		}

		char *info_path = module_debuginfo_path(lm);
		if (info_path != NULL)
			fprintf(fp, "# %s\n", info_path);

		free(info_path);
	}



/*
  p ((struct module *) 0xffffffffa0db5440)->sect_attrs[0].attrs[0]
 p ((struct module *) 0xffffffffa0db5440)->sect_attrs[0].attrs[0]
7 = {
  mattr = {
    attr = {
      name = 0xffff88011400ab60 ".note.gnu.build-id",
      owner = 0x0,
      mode = 292
    },
    show = 0xffffffff810abed0 <module_sect_show>,
    store = 0,
    setup = 0,
    test = 0,
    free = 0
  },
  name = 0xffff88011400ab60 ".note.gnu.build-id",
  address = 18446744072113252104
*/

/*
crash> p *((struct module *) 0xffffffffa0db5440)->notes_attrs
$7 = {
dir = 0xffff8801991745c0, 
notes = 1, 
attrs = 0xffff8801021ab4d0
}
crash> p ((struct module *) 0xffffffffa0db5440)->notes_attrs->attrs
$8 = 0xffff8801021ab4d0
crash> p *((struct module *) 0xffffffffa0db5440)->notes_attrs->attrs
$9 = {
attr = {
name = 0xffff88011400ab60 ".note.gnu.build-id", 
owner = 0x0, 
mode = 292
}, 
size = 36, 
private = 0xffffffffa0da6708, 
read = 0xffffffff810ab820 <module_notes_read>, 
write = 0, 
mmap = 0
}
*/


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
 
char *xmod_help[] = {
	"xmod", /* command name */
	"XMOD XMOD XMOD!", /* short description */
	"arg ...", /* argument synopsis, or " " if none */
	" ...,",
	NULL,
};

static struct command_table_entry xmod_entry[] = {
	{
		.name = "xmod",
		.func = xmod_func,
		.help_data = xmod_help,
	},
	{
		.name = "xbt",
		.func = xbt_func,
		/* .help_data = xbt_help, */
	},
	{
		.name = NULL,
	},
};

void __attribute__((constructor))
xmod_init(void)
{ 
	register_extension(xmod_entry);
}

void __attribute__((destructor))
xmod_fini(void)
{
	/* Uludag GAZOZ! */
}
