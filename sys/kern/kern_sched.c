/*	$OpenBSD: kern_sched.c,v 1.76 2022/12/05 23:18:37 deraadt Exp $	*/
/*
 * Copyright (c) 2007, 2008 Artur Grabowski <art@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/param.h>

#include <sys/sched.h>
#include <sys/proc.h>
#include <sys/kthread.h>
#include <sys/systm.h>
#include <sys/task.h>
#include <sys/smr.h>
#include <sys/tracepoint.h>

#include <uvm/uvm_extern.h>

void sched_kthreads_create(void *);

TAILQ_HEAD(prochead, proc)	sched_qs;
volatile unsigned int		sched_nrun;	/* procs on the run queues */

/*
 * To help choosing which cpu should run which process we keep track
 * of cpus which are currently idle and which cpus have processes
 * queued.
 */
struct cpuset sched_idle_cpus;
struct cpuset sched_queued_cpus;
struct cpuset sched_all_cpus;

/*
 * Some general scheduler counters.
 */
uint64_t sched_nmigrations;	/* Cpu migration counter */
uint64_t sched_nomigrations;	/* Cpu no migration counter */
uint64_t sched_noidle;		/* Times we didn't pick the idle task */
uint64_t sched_stolen;		/* Times we stole proc from other cpus */
uint64_t sched_choose;		/* Times we chose a cpu */
uint64_t sched_wasidle;		/* Times we came out of idle */

int sched_smt;

/*
 * A few notes about cpu_switchto that is implemented in MD code.
 *
 * cpu_switchto takes two arguments, the old proc and the proc
 * it should switch to. The new proc will never be NULL, so we always have
 * a saved state that we need to switch to. The old proc however can
 * be NULL if the process is exiting. NULL for the old proc simply
 * means "don't bother saving old state".
 *
 * cpu_switchto is supposed to atomically load the new state of the process
 * including the pcb, pmap and setting curproc, the p_cpu pointer in the
 * proc and p_stat to SONPROC. Atomically with respect to interrupts, other
 * cpus in the system must not depend on this state being consistent.
 * Therefore no locking is necessary in cpu_switchto other than blocking
 * interrupts during the context switch.
 */

int
cpu_haswork(struct cpu_info *ci)
{
	return (sched_nrun > 0);
}

/*
 * sched_init_cpu is called from main() for the boot cpu, then it's the
 * responsibility of the MD code to call it for all other cpus.
 */
void
sched_init_cpu(struct cpu_info *ci)
{
	struct schedstate_percpu *spc = &ci->ci_schedstate;

	spc->spc_idleproc = NULL;

	kthread_create_deferred(sched_kthreads_create, ci);

	LIST_INIT(&spc->spc_deadproc);
	SIMPLEQ_INIT(&spc->spc_deferred);

	/*
	 * Slight hack here until the cpuset code handles cpu_info
	 * structures.
	 */
	cpuset_init_cpu(ci);

#ifdef __HAVE_CPU_TOPOLOGY
	if (!sched_smt && ci->ci_smt_id > 0)
		return;
#endif
	cpuset_add(&sched_all_cpus, ci);
}

void
sched_kthreads_create(void *v)
{
	struct cpu_info *ci = v;
	struct schedstate_percpu *spc = &ci->ci_schedstate;
	static int num;

	if (fork1(&proc0, FORK_SHAREVM|FORK_SHAREFILES|FORK_NOZOMBIE|
	    FORK_SYSTEM|FORK_IDLE, sched_idle, ci, NULL,
	    &spc->spc_idleproc))
		panic("fork idle");

	/* Name it as specified. */
	snprintf(spc->spc_idleproc->p_p->ps_comm,
	    sizeof(spc->spc_idleproc->p_p->ps_comm),
	    "idle%d", num);

	num++;
}

void
sched_idle(void *v)
{
	struct schedstate_percpu *spc;
	struct proc *p = curproc;
	struct cpu_info *ci = v;
	int s;

	KERNEL_UNLOCK();

	spc = &ci->ci_schedstate;

	/*
	 * First time we enter here, we're not supposed to idle,
	 * just go away for a while.
	 */
	SCHED_LOCK(s);
	cpuset_add(&sched_idle_cpus, ci);
	p->p_stat = SSLEEP;
	p->p_cpu = ci;
	atomic_setbits_int(&p->p_flag, P_CPUPEG);
	mi_switch();
	cpuset_del(&sched_idle_cpus, ci);
	SCHED_UNLOCK(s);

	KASSERT(ci == curcpu());
	KASSERT(curproc == spc->spc_idleproc);

	while (1) {
		while (!cpu_is_idle(ci)) {
			struct proc *dead;

			SCHED_LOCK(s);
			p->p_stat = SSLEEP;
			mi_switch();
			SCHED_UNLOCK(s);

			while ((dead = LIST_FIRST(&spc->spc_deadproc))) {
				LIST_REMOVE(dead, p_hash);
				exit2(dead);
			}
		}

		splassert(IPL_NONE);

		smr_idle();

		cpuset_add(&sched_idle_cpus, ci);
		cpu_idle_enter();
		while (cpu_is_idle(ci)) {
#ifdef MULTIPROCESSOR
			if (spc->spc_schedflags & SPCF_SHOULDHALT &&
			    (spc->spc_schedflags & SPCF_HALTED) == 0) {
				cpuset_del(&sched_idle_cpus, ci);
				atomic_setbits_int(&spc->spc_schedflags,
				    cpu_haswork(ci) ? 0 : SPCF_HALTED);
				wakeup(spc);
			}
#endif
			cpu_idle_cycle();
		}
		cpu_idle_leave();
		cpuset_del(&sched_idle_cpus, ci);
	}
}

/*
 * To free our address space we have to jump through a few hoops.
 * The freeing is done by the reaper, but until we have one reaper
 * per cpu, we have no way of putting this proc on the deadproc list
 * and waking up the reaper without risking having our address space and
 * stack torn from under us before we manage to switch to another proc.
 * Therefore we have a per-cpu list of dead processes where we put this
 * proc and have idle clean up that list and move it to the reaper list.
 * All this will be unnecessary once we can bind the reaper this cpu
 * and not risk having it switch to another in case it sleeps.
 */
void
sched_exit(struct proc *p)
{
	struct schedstate_percpu *spc = &curcpu()->ci_schedstate;
	struct timespec ts;
	struct proc *idle;
	int s;

	nanouptime(&ts);
	timespecsub(&ts, &spc->spc_runtime, &ts);
	timespecadd(&p->p_rtime, &ts, &p->p_rtime);

	LIST_INSERT_HEAD(&spc->spc_deadproc, p, p_hash);

#ifdef MULTIPROCESSOR
	/* This process no longer needs to hold the kernel lock. */
	KERNEL_ASSERT_LOCKED();
	__mp_release_all(&kernel_lock);
#endif

	SCHED_LOCK(s);
	idle = spc->spc_idleproc;
	idle->p_stat = SRUN;
	cpu_switchto(NULL, idle);
	panic("cpu_switchto returned");
}

/*
 * Run queue management.
 */
void
sched_init_runqueues(void)
{
	TAILQ_INIT(&sched_qs);

}

void
sched_kick_cpu(struct cpu_info *ci, struct proc *p, uint8_t sleep)
{
	if (ci == NULL)
		ci = sched_choosecpu(p);

	KASSERT(ci != NULL);
	if (cpuset_isset(&sched_idle_cpus, ci))
		cpu_unidle(ci);

	if (sleep)
		need_resched(ci);
}

void
setrunqueue(struct cpu_info *ci, struct proc *p, uint8_t sleep)
{
#if DIAGNOSTIC
	struct proc *q;

	TAILQ_FOREACH(q, &sched_qs, p_runq) {
		if (p == q)
			panic("thread %d already on queue", p->p_tid);
	}
#endif
	KASSERT(p->p_stat != SRUN);

	SCHED_ASSERT_LOCKED();
	sched_nrun++;
	TRACEPOINT(sched, enqueue, p->p_tid + THREAD_PID_OFFSET,
	    p->p_p->ps_pid);

	if (sleep)
		TAILQ_INSERT_HEAD(&sched_qs, p, p_runq);
	else
		TAILQ_INSERT_TAIL(&sched_qs, p, p_runq);
	p->p_stat = SRUN;

#if 1
	sched_kick_cpu(ci, p, sleep);
#endif
}

void
remrunqueue(struct proc *p)
{
#if DIAGNOSTIC
	struct proc *q;

	TAILQ_FOREACH(q, &sched_qs, p_runq) {
		if (p == q)
			break;
	}
	if (q == NULL)
		panic("thread %d not on queue", p->p_tid);
#endif

	SCHED_ASSERT_LOCKED();
	sched_nrun--;
	TRACEPOINT(sched, dequeue, p->p_tid + THREAD_PID_OFFSET,
	    p->p_p->ps_pid);

	TAILQ_REMOVE(&sched_qs, p, p_runq);
}

struct proc *
sched_chooseproc(void)
{
	struct schedstate_percpu *spc = &curcpu()->ci_schedstate;
	struct proc *p = NULL;

	SCHED_ASSERT_LOCKED();

#ifdef MULTIPROCESSOR
	if (spc->spc_schedflags & SPCF_SHOULDHALT) {
		TAILQ_FOREACH(p, &sched_qs, p_runq) {
			if ((p->p_flag & P_CPUPEG) && (p->p_cpu == curcpu())) {
				goto again;
			}
		}
		p = spc->spc_idleproc;
		KASSERT(p);
		KASSERT(p->p_wchan == NULL);
		p->p_stat = SRUN;
		return (p);
	}
#endif

again:
	if (sched_nrun > 0) {
		TAILQ_FOREACH(p, &sched_qs, p_runq) {
			KASSERT(p->p_stat == SRUN);
			if ((p->p_flag & P_CPUPEG) && (p->p_cpu != curcpu())) {
				continue;
			}
			break;
		}
	}

	if (p != NULL) {
		remrunqueue(p);
		if (p->p_cpu != curcpu()) {
			sched_stolen++;
			p->p_cpu = curcpu();
		} else {
			sched_noidle++;
		}
		if (p->p_stat != SRUN)
			panic("thread %d not in SRUN: %d", p->p_tid, p->p_stat);
	} else {
		p = spc->spc_idleproc;
		if (p == NULL) {
                        int s;
			/*
			 * We get here if someone decides to switch during
			 * boot before forking kthreads, bleh.
			 * This is kind of like a stupid idle loop.
			 */
#ifdef MULTIPROCESSOR
			__mp_unlock(&sched_lock);
#endif
			spl0();
			delay(10);
			SCHED_LOCK(s);
			goto again;
                }
		KASSERT(p);
		p->p_stat = SRUN;
	}

	KASSERT(p->p_wchan == NULL);
	return (p);
}

struct cpu_info *
sched_choosecpu(struct proc *p)
{
#ifdef MULTIPROCESSOR
	struct cpu_info *choice;
	struct cpuset set;

	/*
	 * If pegged to a cpu, don't allow it to move.
	 */
	if (p->p_flag & P_CPUPEG)
		return (p->p_cpu);

	sched_choose++;

	/*
	 * Look at all cpus that are currently idle.
	 */
	cpuset_intersection(&set, &sched_idle_cpus, &sched_all_cpus);

	/*
	 * First, just check if our current cpu is in that set, if it is,
	 * this is simple.
	 * Also, our cpu might not be idle, but if it's the current cpu
	 * and it has nothing else queued and we're curproc, take it.
	 */
	if (cpuset_isset(&set, p->p_cpu) ||
	    (p->p_cpu == curcpu() && !cpu_haswork(curcpu()) &&
	    (p->p_cpu->ci_schedstate.spc_schedflags & SPCF_SHOULDHALT) == 0 &&
	    curproc == p)) {
		sched_wasidle++;
		return (p->p_cpu);
	}

	if (cpuset_first(&set) == NULL)
		cpuset_copy(&set, &sched_all_cpus);

	choice = cpuset_first(&set);

	if (p->p_cpu != choice)
		sched_nmigrations++;
	else
		sched_nomigrations++;

	return (choice);
#else
	return (curcpu());
#endif
}

/*
 * Peg a proc to a cpu.
 */
void
sched_peg_curproc(struct cpu_info *ci)
{
	struct proc *p = curproc;
	int s;

	SCHED_LOCK(s);
	p->p_cpu = ci;
	atomic_setbits_int(&p->p_flag, P_CPUPEG);
	setrunqueue(ci, p, 0);
	p->p_ru.ru_nvcsw++;
	mi_switch();
	SCHED_UNLOCK(s);
}

#ifdef MULTIPROCESSOR

void
sched_start_secondary_cpus(void)
{
	CPU_INFO_ITERATOR cii;
	struct cpu_info *ci;

	CPU_INFO_FOREACH(cii, ci) {
		struct schedstate_percpu *spc = &ci->ci_schedstate;

		if (CPU_IS_PRIMARY(ci) || !CPU_IS_RUNNING(ci))
			continue;
		atomic_clearbits_int(&spc->spc_schedflags,
		    SPCF_SHOULDHALT | SPCF_HALTED);
#ifdef __HAVE_CPU_TOPOLOGY
		if (!sched_smt && ci->ci_smt_id > 0)
			continue;
#endif
		cpuset_add(&sched_all_cpus, ci);
	}
}

void
sched_stop_secondary_cpus(void)
{
	CPU_INFO_ITERATOR cii;
	struct cpu_info *ci;

	/*
	 * Make sure we stop the secondary CPUs.
	 */
	CPU_INFO_FOREACH(cii, ci) {
		struct schedstate_percpu *spc = &ci->ci_schedstate;

		if (CPU_IS_PRIMARY(ci) || !CPU_IS_RUNNING(ci))
			continue;
		cpuset_del(&sched_all_cpus, ci);
		atomic_setbits_int(&spc->spc_schedflags, SPCF_SHOULDHALT);
	}
	CPU_INFO_FOREACH(cii, ci) {
		struct schedstate_percpu *spc = &ci->ci_schedstate;
		struct sleep_state sls;

		if (CPU_IS_PRIMARY(ci) || !CPU_IS_RUNNING(ci))
			continue;
		while ((spc->spc_schedflags & SPCF_HALTED) == 0) {
			sleep_setup(&sls, spc, PZERO, "schedstate", 0);
			sleep_finish(&sls,
			    (spc->spc_schedflags & SPCF_HALTED) == 0);
		}
	}
}

struct sched_barrier_state {
	struct cpu_info *ci;
	struct cond cond;
};

void
sched_barrier_task(void *arg)
{
	struct sched_barrier_state *sb = arg;
	struct cpu_info *ci = sb->ci;

	sched_peg_curproc(ci);
	cond_signal(&sb->cond);
	atomic_clearbits_int(&curproc->p_flag, P_CPUPEG);
}

void
sched_barrier(struct cpu_info *ci)
{
	struct sched_barrier_state sb;
	struct task task;
	CPU_INFO_ITERATOR cii;

	if (ci == NULL) {
		CPU_INFO_FOREACH(cii, ci) {
			if (CPU_IS_PRIMARY(ci))
				break;
		}
	}
	KASSERT(ci != NULL);

	if (ci == curcpu())
		return;

	sb.ci = ci;
	cond_init(&sb.cond);
	task_set(&task, sched_barrier_task, &sb);

	task_add(systqmp, &task);
	cond_wait(&sb.cond, "sbar");
}

#else

void
sched_barrier(struct cpu_info *ci)
{
}

#endif

/*
 * Functions to manipulate cpu sets.
 */
struct cpu_info *cpuset_infos[MAXCPUS];
static struct cpuset cpuset_all;

void
cpuset_init_cpu(struct cpu_info *ci)
{
	cpuset_add(&cpuset_all, ci);
	cpuset_infos[CPU_INFO_UNIT(ci)] = ci;
}

void
cpuset_clear(struct cpuset *cs)
{
	memset(cs, 0, sizeof(*cs));
}

void
cpuset_add(struct cpuset *cs, struct cpu_info *ci)
{
	unsigned int num = CPU_INFO_UNIT(ci);
	atomic_setbits_int(&cs->cs_set[num/32], (1U << (num % 32)));
}

void
cpuset_del(struct cpuset *cs, struct cpu_info *ci)
{
	unsigned int num = CPU_INFO_UNIT(ci);
	atomic_clearbits_int(&cs->cs_set[num/32], (1U << (num % 32)));
}

int
cpuset_isset(struct cpuset *cs, struct cpu_info *ci)
{
	unsigned int num = CPU_INFO_UNIT(ci);
	return (cs->cs_set[num/32] & (1U << (num % 32)));
}

void
cpuset_add_all(struct cpuset *cs)
{
	cpuset_copy(cs, &cpuset_all);
}

void
cpuset_copy(struct cpuset *to, struct cpuset *from)
{
	memcpy(to, from, sizeof(*to));
}

struct cpu_info *
cpuset_first(struct cpuset *cs)
{
	int i;

	for (i = 0; i < CPUSET_ASIZE(ncpus); i++)
		if (cs->cs_set[i])
			return (cpuset_infos[i * 32 + ffs(cs->cs_set[i]) - 1]);

	return (NULL);
}

void
cpuset_union(struct cpuset *to, struct cpuset *a, struct cpuset *b)
{
	int i;

	for (i = 0; i < CPUSET_ASIZE(ncpus); i++)
		to->cs_set[i] = a->cs_set[i] | b->cs_set[i];
}

void
cpuset_intersection(struct cpuset *to, struct cpuset *a, struct cpuset *b)
{
	int i;

	for (i = 0; i < CPUSET_ASIZE(ncpus); i++)
		to->cs_set[i] = a->cs_set[i] & b->cs_set[i];
}

void
cpuset_complement(struct cpuset *to, struct cpuset *a, struct cpuset *b)
{
	int i;

	for (i = 0; i < CPUSET_ASIZE(ncpus); i++)
		to->cs_set[i] = b->cs_set[i] & ~a->cs_set[i];
}

int
cpuset_cardinality(struct cpuset *cs)
{
	int cardinality, i, n;

	cardinality = 0;

	for (i = 0; i < CPUSET_ASIZE(ncpus); i++)
		for (n = cs->cs_set[i]; n != 0; n &= n - 1)
			cardinality++;

	return (cardinality);
}

int
sysctl_hwncpuonline(void)
{
	return cpuset_cardinality(&sched_all_cpus);
}

int
cpu_is_online(struct cpu_info *ci)
{
	return cpuset_isset(&sched_all_cpus, ci);
}

#ifdef __HAVE_CPU_TOPOLOGY

#include <sys/sysctl.h>

int
sysctl_hwsmt(void *oldp, size_t *oldlenp, void *newp, size_t newlen)
{
	CPU_INFO_ITERATOR cii;
	struct cpu_info *ci;
	int err, newsmt;

	newsmt = sched_smt;
	err = sysctl_int_bounded(oldp, oldlenp, newp, newlen, &newsmt, 0, 1);
	if (err)
		return err;
	if (newsmt == sched_smt)
		return 0;

	sched_smt = newsmt;
	CPU_INFO_FOREACH(cii, ci) {
		if (CPU_IS_PRIMARY(ci) || !CPU_IS_RUNNING(ci))
			continue;
		if (ci->ci_smt_id == 0)
			continue;
		if (sched_smt)
			cpuset_add(&sched_all_cpus, ci);
		else
			cpuset_del(&sched_all_cpus, ci);
	}

	return 0;
}

#endif
