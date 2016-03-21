#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#if 0
#define II(x, ...) fprintf(stderr, "[%s:%d] "x"\n", __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define II(x, ...)
#endif

off_t in_limited_set(const char *str, size_t size, off_t pos);

__attribute__((constructor)) static void detect_debugger() {
}

int main(int argc, char * argv[]) {
    if (argc < 2) {
        printf("usage: %s <input>\n", argv[0]);
        return 0;
    }
    FILE *fd = fopen("/tmp", "r");

    if (fileno(fd) > 4) {
        printf("Try Again!\n");
        exit(0);
        return 0;
    }

    fclose(fd);

    if (ptrace(PTRACE_TRACEME, 0, NULL, 0) == -1) {
        II("traced me!");
        printf("Try Again!\n");
        exit(0);
        return 0;
    }

    if (in_limited_set(argv[1], strlen(argv[1]), 0) == 0) {
        printf("Congratulatinos!\n");
    } else {
        printf("Try Again!\n");
    }
    return 0;
}
