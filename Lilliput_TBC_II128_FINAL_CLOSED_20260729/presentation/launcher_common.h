#ifndef LILLIPUT_LAUNCHER_COMMON_H
#define LILLIPUT_LAUNCHER_COMMON_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__GNUC__)
#define LILLIPUT_MAYBE_UNUSED __attribute__((unused))
#else
#define LILLIPUT_MAYBE_UNUSED
#endif

__declspec(dllimport) int __stdcall CreateDirectoryA(const char *, void *);

typedef struct demo_item {
    const char *title;
    const char *exe;
    const char *explanation;
} demo_item;

static void divider(void)
{
    puts("===============================================================================");
}

static void prepare_directories(void)
{
    (void)CreateDirectoryA("logs", (void *)0);
    (void)CreateDirectoryA("logs\\windows", (void *)0);
    (void)CreateDirectoryA("results", (void *)0);
}

static int run_item(const demo_item *item, unsigned int index, unsigned int total)
{
    char command[2048];
    int rc;

    divider();
    printf("[%u/%u] %s\n", index, total, item->title);
    printf("Purpose : %s\n", item->explanation);
    printf("Binary  : bin\\windows\\%s\n", item->exe);
    divider();

    (void)sprintf(command,
        "cmd.exe /V:ON /C \"bin\\windows\\%s > logs\\windows\\%s.log 2>&1 & "
        "set RC=!ERRORLEVEL! & type logs\\windows\\%s.log & exit /B !RC!\"",
        item->exe, item->exe, item->exe);
    rc = system(command);
    printf("\nSTATUS: %s (launcher code=%d)\n\n", (rc == 0) ? "PASS" : "FAIL", rc);
    return (rc == 0) ? 0 : 1;
}

static LILLIPUT_MAYBE_UNUSED int run_items(const demo_item *items, unsigned int count)
{
    unsigned int i;
    int failures = 0;
    for (i = 0U; i < count; ++i) {
        failures += run_item(&items[i], i + 1U, count);
    }
    return failures;
}

static LILLIPUT_MAYBE_UNUSED void final_summary(const char *label, unsigned int total, int failures)
{
    divider();
    printf("%s SUMMARY\n", label);
    printf("Total executions : %u\n", total);
    printf("Passed           : %u\n", total - (unsigned int)failures);
    printf("Failed           : %d\n", failures);
    printf("Logs             : logs\\windows\\\n");
    printf("Result datasets  : results\\\n");
    divider();
}

static void wait_for_enter(void)
{
    puts("Press ENTER to close this presentation window...");
    (void)getchar();
}
#endif
