#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <elf.h>

#include <sys/ptrace.h>
#include <sys/wait.h>

#if defined(__x86_64__)
#  include <sys/reg.h>
#elif defined(__aarch64__)
#  include <linux/uio.h>
#  include <asm/ptrace.h>
#elif defined(__arm__)
#  error "not supported arm32 yet."
#else
#  error "not supported architecture."
#endif


/*
 * removeVDSO() alters the auxiliary table of a newly created process in order
 * to disable VDSO.
 */
void removeVDSO(int pid) {
  size_t pos;
  int zeroCount;
  long val;

#if defined(__x86_64__)
  pos = (size_t)ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * RSP, NULL);
#elif defined(__aarch64__)
  struct user_pt_regs regs;
  struct iovec io;

  io.iov_base = &regs;
  io.iov_len = sizeof(regs);
  if (ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &io)==-1) {
    fprintf(stderr, "ptrace(PTRACE_GETREGSET,...) failed\n");
    exit(1);
  }
  pos = regs.sp;
#endif

  /* skip to auxiliary vector */
  zeroCount = 0;
  while (zeroCount < 2) {
    val = ptrace(PTRACE_PEEKDATA, pid, pos += 8, NULL);
    if (val == 0)
      zeroCount++;
  }

  /* search the auxiliary vector for AT_SYSINFO_EHDR... */
  val = ptrace(PTRACE_PEEKDATA, pid, pos += 8, NULL);
  while(1) {
    if (val == AT_NULL)
      break;
    if (val == AT_SYSINFO_EHDR) {
      /* ... and overwrite it */
      ptrace(PTRACE_POKEDATA, pid, pos, AT_IGNORE);
      break;
    }
    val = ptrace(PTRACE_PEEKDATA, pid, pos += 16, NULL);
  }
}

/*
 * traceProcess() waits for execve(2) to return, calls removeVDSO() and
 * detaches from the child afterwards.
 */
int traceProcess(int pid) {
  int status, exitStatus;

  waitpid(pid, &status, 0);
  ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC);
  ptrace(PTRACE_SYSCALL, pid, NULL, NULL);

  while(1) {
    waitpid(pid, &status, 0);
    if (WIFEXITED(status))
      break;

    if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXEC << 8))) {
      removeVDSO(pid);
      kill(pid, SIGSTOP);
      ptrace(PTRACE_DETACH, pid, NULL, NULL);
      printf("--- Process paused and detached. PID: %i ---\n", pid);
      /* wait for child to exit */
      while (waitpid(pid, &status, 0) > 0);
      break;
    }

    ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
  }
  exitStatus = WEXITSTATUS(status);
  return exitStatus;
}

int main(int argc, char *argv[]) {
  char *myfile, **myargv;
  int exitStatus;
  pid_t child;

  if (argc < 3) {
    printf("usage: novdso FILE ARGV...\n");
    printf("example: novdso /bin/ls ls -l -i -s -a\n");
    return 1;
  }

  myfile = argv[1];
  myargv = &argv[2];

  child = fork();
  if (child == 0) {
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    kill(getpid(), SIGSTOP);
    execvp(myfile, myargv);
  } else {
    exitStatus = traceProcess(child);
  }

  return exitStatus;
}
