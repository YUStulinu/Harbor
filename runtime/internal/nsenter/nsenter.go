// Package nsenter joins existing namespaces (linux.namespaces[].path) for the container's
// init process. setns(2) into a mount namespace needs a single-threaded process, and a Go
// program has several threads before main runs, so this is done in C, in a constructor that
// runs before the Go runtime starts. Import it for its side effect.
package nsenter

/*
#cgo CFLAGS: -Wall -Werror
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

// Reports an error to the runtime on fd 4 (the init's status pipe) and exits.
static void harbor_fail(const char *what, const char *path) {
	char buf[512];
	int n = snprintf(buf, sizeof buf, "{\"type\":\"error\",\"error\":\"joining %s namespace %s: %s\"}\n", what, path, strerror(errno));
	if (n > 0) {
		ssize_t w = write(4, buf, (size_t)n);
		(void)w;
	}
	_exit(1);
}

__attribute__((constructor)) static void harbor_nsenter(void) {
	const char *v = getenv("_HARBOR_SETNS");
	if (!v || !*v || !getenv("_HARBOR_INIT"))
		return;
	char *list = strdup(v);
	char *save = NULL;
	int join_pid = 0;
	for (char *item = strtok_r(list, ",", &save); item; item = strtok_r(NULL, ",", &save)) {
		char *eq = strchr(item, '=');
		if (!eq)
			continue;
		*eq = 0;
		const char *type = item, *path = eq + 1;
		int flag = 0;
		if (!strcmp(type, "network")) flag = CLONE_NEWNET;
		else if (!strcmp(type, "ipc")) flag = CLONE_NEWIPC;
		else if (!strcmp(type, "uts")) flag = CLONE_NEWUTS;
		else if (!strcmp(type, "mount")) flag = CLONE_NEWNS;
		else if (!strcmp(type, "cgroup")) flag = CLONE_NEWCGROUP;
		else if (!strcmp(type, "pid")) flag = CLONE_NEWPID;
#ifdef CLONE_NEWTIME
		else if (!strcmp(type, "time")) flag = CLONE_NEWTIME;
#endif
		else {
			errno = EINVAL;
			harbor_fail(type, path);
		}
		int fd = open(path, O_RDONLY | O_CLOEXEC);
		if (fd < 0)
			harbor_fail(type, path);
		if (setns(fd, flag) < 0)
			harbor_fail(type, path);
		close(fd);
		if (flag == CLONE_NEWPID)
			join_pid = 1;
	}
	free(list);
	if (!join_pid)
		return;
	// setns into a pid namespace applies to children only: fork, and the child becomes the
	// container's init. The parent tells the runtime the child's pid, then waits for it and
	// exits with its status (so a runtime waiting on us sees the container's exit).
	pid_t child = fork();
	if (child < 0)
		harbor_fail("pid", "(fork)");
	if (child == 0)
		return;
	char buf[64];
	int n = snprintf(buf, sizeof buf, "{\"type\":\"pid\",\"pid\":%d}\n", (int)child);
	ssize_t w = write(4, buf, (size_t)n);
	(void)w;
	close(3);
	close(4);
	int status = 0;
	while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
	}
	if (WIFSIGNALED(status))
		_exit(128 + WTERMSIG(status));
	_exit(WEXITSTATUS(status));
}
*/
import "C"
