#include <windows.h>
#include <errno.h>

#ifndef _SIGSET_T_
#define _SIGSET_T_
typedef size_t _sigset_t;
#define sigset_t _sigset_t
#endif /* _SIGSET_T_ */

#ifndef SIG_SETMASK
#define SIG_SETMASK (0)
#define SIG_BLOCK   (1)
#define SIG_UNBLOCK (2)
#endif /* SIG_SETMASK */

/* threads avoiding pthread.h */
//typedef CRITICAL_SECTION pthread_mutex_t;
#define pthread_mutex_t CRITICAL_SECTION
#define pthread_attr_t ssize_t

#define pthread_mutex_init(a,b) (InitializeCriticalSectionAndSpinCount((a), 0x80000400),0)
#define pthread_mutex_destroy(a) DeleteCriticalSection((a))
#define pthread_mutex_lock EnterCriticalSection
#define pthread_mutex_unlock LeaveCriticalSection
#define pthread_equal(t1, t2) ((t1) == (t2))

#define pthread_attr_init(x) (*(x) = 0)
#define pthread_attr_getstacksize(x, y) (*(y) = *(x))
#define pthread_attr_setstacksize(x, y) (*(x) = y)

#define pthread_t unsigned int

#if (!defined HAVE_PTHREAD_COND_T)
#define HAVE_PTHREAD_COND_T 1
typedef struct pthread_cond_t_ {
	CRITICAL_SECTION waiters_lock;
	LONG waiters;
	int was_broadcast;
	HANDLE sema;
	HANDLE continue_broadcast;
};

typedef struct pthread_cond_t_ pthread_cond_t;
#endif

/* Function prototypes */
#if (!defined __WIN32_PTHREAD_C)
#define EXT extern
#else
#define EXT
#endif

#ifdef REDIS_PTHREAD
EXT int pthread_create(pthread_t *thread, const void *unused, void *(*start_routine)(void*), void *arg);
EXT int pthread_detach(pthread_t thread);
#else
EXT int pthread_create(pthread_t *threadId, void* notUsed, void *(*__start_routine) (void *), void* userParm);
EXT void pthread_detach(pthread_t *threadId);
EXT int pthread_join(pthread_t thread, void **value_ptr);
EXT void pthread_exit(void *retval);
#endif
EXT pthread_t pthread_self(void);
EXT int pthread_mutex_trylock(pthread_mutex_t *mutex);

EXT int pthread_cond_init(pthread_cond_t *cond, const void *unused);
EXT int pthread_cond_destroy(pthread_cond_t *cond);
EXT int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex);
EXT int pthread_cond_signal(pthread_cond_t *cond);
EXT int pthread_sigmask(int how, const sigset_t *set, sigset_t *oldset);

/*
struct pthread_mutex_t_
{
  LONG lock_idx;		// Provides exclusive access to mutex state
				   // via the Interlocked* mechanism.
				   // 0: unlocked/free.
				   // 1: locked - no other waiters.
				   // -1: locked - with possible other waiters.
  int recursive_count;		// Number of unlocks a thread needs to perform
				   // before the lock is released (recursive
				   // mutexes only).
  int kind;			// Mutex type.
  pthread_t ownerThread;
  HANDLE event;			// Mutex release notification to waiting threads.
  ptw32_robust_node_t* robustNode; // Extra state for robust mutexes
};

enum ptw32_robust_state_t_
{
  PTW32_ROBUST_CONSISTENT,
  PTW32_ROBUST_INCONSISTENT,
  PTW32_ROBUST_NOTRECOVERABLE
};

typedef enum ptw32_robust_state_t_   ptw32_robust_state_t;

// Node used to manage per-thread lists of currently-held robust mutexes.
struct ptw32_robust_node_t_
{
  pthread_mutex_t mx;
  ptw32_robust_state_t stateInconsistent;
  ptw32_robust_node_t* prev;
  ptw32_robust_node_t* next;
};

typedef struct pthread_mutex_t_ * pthread_mutex_t;

struct pthread_mutexattr_t_
{
  int pshared;
  int kind;
  int robustness;
};

typedef struct pthread_mutexattr_t_ * pthread_mutexattr_t;
*/
#undef EXT
