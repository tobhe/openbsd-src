/*	$OpenBSD: sched_bsd.c,v 1.74 2023/02/04 19:33:03 cheloha Exp $	*/
/*	$NetBSD: kern_synch.c,v 1.37 1996/04/22 01:38:37 christos Exp $	*/

/*-
 * Copyright (c) 1982, 1986, 1990, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)kern_synch.c	8.6 (Berkeley) 1/21/94
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/resourcevar.h>
#include <uvm/uvm_extern.h>
#include <sys/sched.h>
#include <sys/timeout.h>
#include <sys/smr.h>
#include <sys/tracepoint.h>

#ifdef KTRACE
#include <sys/ktrace.h>
#endif


int	lbolt;			/* once a second sleep address */
int	rrticks_init;		/* # of hardclock ticks per roundrobin() */

#ifdef MULTIPROCESSOR
struct __mp_lock sched_lock;
#endif

/*
 * Force switch among equal priority processes every 100ms.
 */
void
roundrobin(struct cpu_info *ci)
{
	struct schedstate_percpu *spc = &ci->ci_schedstate;

	spc->spc_rrticks = rrticks_init;

	if (ci->ci_curproc != NULL) {
		if (spc->spc_schedflags & SPCF_SEENRR) {
			/*
			 * The process has already been through a roundrobin
			 * without switching and may be hogging the CPU.
			 * Indicate that the process should yield.
			 */
			atomic_setbits_int(&spc->spc_schedflags,
			    SPCF_SHOULDYIELD);
		} else {
			atomic_setbits_int(&spc->spc_schedflags,
			    SPCF_SEENRR);
		}
	}

	if (cpu_haswork(ci))
		need_resched(ci);
}

void
everysecond(void *arg)
{
	struct timeout *to = (struct timeout *)arg;

	uvm_meter();
	wakeup(&lbolt);
	timeout_add_sec(to, 1);
}

/*
 * General yield call.  Puts the current process back on its run queue and
 * performs a voluntary context switch.
 */
void
yield(void)
{
	struct proc *p = curproc;
	int s;

	SCHED_LOCK(s);
	setrunqueue(p->p_cpu, p, 0);
	p->p_ru.ru_nvcsw++;
	mi_switch();
	SCHED_UNLOCK(s);
}

/*
 * General preemption call.  Puts the current process back on its run queue
 * and performs an involuntary context switch.  If a process is supplied,
 * we switch to that process.  Otherwise, we use the normal process selection
 * criteria.
 */
void
preempt(void)
{
	struct proc *p = curproc;
	int s;

	SCHED_LOCK(s);
	setrunqueue(p->p_cpu, p, 0);
	p->p_ru.ru_nivcsw++;
	mi_switch();
	SCHED_UNLOCK(s);
}

void
mi_switch(void)
{
	struct schedstate_percpu *spc = &curcpu()->ci_schedstate;
	struct proc *p = curproc;
	struct proc *nextproc;
	struct process *pr = p->p_p;
	struct timespec ts;
#ifdef MULTIPROCESSOR
	int hold_count;
	int sched_count;
#endif

	assertwaitok();
	KASSERT(p->p_stat != SONPROC);

	SCHED_ASSERT_LOCKED();

#ifdef MULTIPROCESSOR
	/*
	 * Release the kernel_lock, as we are about to yield the CPU.
	 */
	sched_count = __mp_release_all_but_one(&sched_lock);
	if (_kernel_lock_held())
		hold_count = __mp_release_all(&kernel_lock);
	else
		hold_count = 0;
#endif

	/*
	 * Compute the amount of time during which the current
	 * process was running, and add that to its total so far.
	 */
	nanouptime(&ts);
	if (timespeccmp(&ts, &spc->spc_runtime, <)) {
#if 0
		printf("uptime is not monotonic! "
		    "ts=%lld.%09lu, runtime=%lld.%09lu\n",
		    (long long)tv.tv_sec, tv.tv_nsec,
		    (long long)spc->spc_runtime.tv_sec,
		    spc->spc_runtime.tv_nsec);
#endif
	} else {
		timespecsub(&ts, &spc->spc_runtime, &ts);
		timespecadd(&p->p_rtime, &ts, &p->p_rtime);
	}

	/* add the time counts for this thread to the process's total */
	tuagg_unlocked(pr, p);

	/*
	 * Process is about to yield the CPU; clear the appropriate
	 * scheduling flags.
	 */
	atomic_clearbits_int(&spc->spc_schedflags, SPCF_SWITCHCLEAR);

	nextproc = sched_chooseproc();

	if (p != nextproc) {
		uvmexp.swtch++;
		TRACEPOINT(sched, off__cpu, nextproc->p_tid + THREAD_PID_OFFSET,
		    nextproc->p_p->ps_pid);
		cpu_switchto(p, nextproc);
		TRACEPOINT(sched, on__cpu, NULL);
	} else {
		TRACEPOINT(sched, remain__cpu, NULL);
		p->p_stat = SONPROC;
	}

	clear_resched(curcpu());

	SCHED_ASSERT_LOCKED();

	/*
	 * To preserve lock ordering, we need to release the sched lock
	 * and grab it after we grab the big lock.
	 * In the future, when the sched lock isn't recursive, we'll
	 * just release it here.
	 */
#ifdef MULTIPROCESSOR
	__mp_unlock(&sched_lock);
#endif

	SCHED_ASSERT_UNLOCKED();

	smr_idle();

	/*
	 * We're running again; record our new start time.  We might
	 * be running on a new CPU now, so don't use the cache'd
	 * schedstate_percpu pointer.
	 */
	KASSERT(p->p_cpu == curcpu());

	nanouptime(&p->p_cpu->ci_schedstate.spc_runtime);

#ifdef MULTIPROCESSOR
	/*
	 * Reacquire the kernel_lock now.  We do this after we've
	 * released the scheduler lock to avoid deadlock, and before
	 * we reacquire the interlock and the scheduler lock.
	 */
	if (hold_count)
		__mp_acquire_count(&kernel_lock, hold_count);
	__mp_acquire_count(&sched_lock, sched_count + 1);
#endif
}

/*
 * Change process state to be runnable,
 * placing it on the run queue.
 */
void
setrunnable(struct proc *p)
{
	struct process *pr = p->p_p;

	SCHED_ASSERT_LOCKED();

	switch (p->p_stat) {
	case 0:
	case SRUN:
	case SONPROC:
	case SDEAD:
	case SIDL:
	default:
		panic("setrunnable");
	case SSTOP:
		/*
		 * If we're being traced (possibly because someone attached us
		 * while we were stopped), check for a signal from the debugger.
		 */
		if ((pr->ps_flags & PS_TRACED) != 0 && pr->ps_xsig != 0)
			atomic_setbits_int(&p->p_siglist, sigmask(pr->ps_xsig));
		unsleep(p);
		setrunqueue(NULL, p, 0);
		break;
	case SSLEEP:
		unsleep(p);		/* e.g. when sending signals */
		setrunqueue(NULL, p, 1);
		break;
	}
}

void (*cpu_setperf)(int);

#define PERFPOL_MANUAL 0
#define PERFPOL_AUTO 1
#define PERFPOL_HIGH 2
int perflevel = 100;
int perfpolicy = PERFPOL_AUTO;

#ifndef SMALL_KERNEL
/*
 * The code below handles CPU throttling.
 */
#include <sys/sysctl.h>

void setperf_auto(void *);
struct timeout setperf_to = TIMEOUT_INITIALIZER(setperf_auto, NULL);
extern int hw_power;

void
setperf_auto(void *v)
{
	static uint64_t *idleticks, *totalticks;
	static int downbeats;
	int i, j = 0;
	int speedup = 0;
	CPU_INFO_ITERATOR cii;
	struct cpu_info *ci;
	uint64_t idle, total, allidle = 0, alltotal = 0;

	if (perfpolicy != PERFPOL_AUTO)
		return;

	if (cpu_setperf == NULL)
		return;

	if (hw_power) {
		speedup = 1;
		goto faster;
	}

	if (!idleticks)
		if (!(idleticks = mallocarray(ncpusfound, sizeof(*idleticks),
		    M_DEVBUF, M_NOWAIT | M_ZERO)))
			return;
	if (!totalticks)
		if (!(totalticks = mallocarray(ncpusfound, sizeof(*totalticks),
		    M_DEVBUF, M_NOWAIT | M_ZERO))) {
			free(idleticks, M_DEVBUF,
			    sizeof(*idleticks) * ncpusfound);
			return;
		}
	CPU_INFO_FOREACH(cii, ci) {
		if (!cpu_is_online(ci))
			continue;
		total = 0;
		for (i = 0; i < CPUSTATES; i++) {
			total += ci->ci_schedstate.spc_cp_time[i];
		}
		total -= totalticks[j];
		idle = ci->ci_schedstate.spc_cp_time[CP_IDLE] - idleticks[j];
		if (idle < total / 3)
			speedup = 1;
		alltotal += total;
		allidle += idle;
		idleticks[j] += idle;
		totalticks[j] += total;
		j++;
	}
	if (allidle < alltotal / 2)
		speedup = 1;
	if (speedup && downbeats < 5)
		downbeats++;

	if (speedup && perflevel != 100) {
faster:
		perflevel = 100;
		cpu_setperf(perflevel);
	} else if (!speedup && perflevel != 0 && --downbeats <= 0) {
		perflevel = 0;
		cpu_setperf(perflevel);
	}

	timeout_add_msec(&setperf_to, 100);
}

int
sysctl_hwsetperf(void *oldp, size_t *oldlenp, void *newp, size_t newlen)
{
	int err;

	if (!cpu_setperf)
		return EOPNOTSUPP;

	if (perfpolicy != PERFPOL_MANUAL)
		return sysctl_rdint(oldp, oldlenp, newp, perflevel);

	err = sysctl_int_bounded(oldp, oldlenp, newp, newlen,
	    &perflevel, 0, 100);
	if (err)
		return err;

	if (newp != NULL)
		cpu_setperf(perflevel);

	return 0;
}

int
sysctl_hwperfpolicy(void *oldp, size_t *oldlenp, void *newp, size_t newlen)
{
	char policy[32];
	int err;

	if (!cpu_setperf)
		return EOPNOTSUPP;

	switch (perfpolicy) {
	case PERFPOL_MANUAL:
		strlcpy(policy, "manual", sizeof(policy));
		break;
	case PERFPOL_AUTO:
		strlcpy(policy, "auto", sizeof(policy));
		break;
	case PERFPOL_HIGH:
		strlcpy(policy, "high", sizeof(policy));
		break;
	default:
		strlcpy(policy, "unknown", sizeof(policy));
		break;
	}

	if (newp == NULL)
		return sysctl_rdstring(oldp, oldlenp, newp, policy);

	err = sysctl_string(oldp, oldlenp, newp, newlen, policy, sizeof(policy));
	if (err)
		return err;
	if (strcmp(policy, "manual") == 0)
		perfpolicy = PERFPOL_MANUAL;
	else if (strcmp(policy, "auto") == 0)
		perfpolicy = PERFPOL_AUTO;
	else if (strcmp(policy, "high") == 0)
		perfpolicy = PERFPOL_HIGH;
	else
		return EINVAL;

	if (perfpolicy == PERFPOL_AUTO) {
		timeout_add_msec(&setperf_to, 200);
	} else if (perfpolicy == PERFPOL_HIGH) {
		perflevel = 100;
		cpu_setperf(perflevel);
	}
	return 0;
}
#endif

void
scheduler_start(void)
{
	static struct timeout onesec_to;

	rrticks_init = hz / 10;

	timeout_set(&onesec_to, everysecond, &onesec_to);
	everysecond(&onesec_to);

#ifndef SMALL_KERNEL
	if (perfpolicy == PERFPOL_AUTO)
		timeout_add_msec(&setperf_to, 200);
#endif
}
