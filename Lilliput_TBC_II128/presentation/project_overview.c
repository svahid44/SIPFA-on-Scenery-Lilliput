#include "launcher_common.h"
int main(void)
{
    prepare_directories();
    divider();
    puts("LILLIPUT-TBC-II-128 / SIPFA - PROJECT OVERVIEW");
    divider();
    puts("Target cipher      : Lilliput-TBC-II-128");
    puts("Block/key/tweak    : 128 / 128 / 128 bits");
    puts("Rounds             : 32");
    puts("Fault model        : one persistent S-box table-entry corruption");
    puts("Attack framework   : Statistical Ineffective Persistent Fault Analysis");
    puts("Implemented cases  : known/unknown fault x detection/infection models");
    puts("Final capability   : delta + RTK[31] + RTK[30] + 128-bit master key");
    puts("");
    puts("Windows binaries   : 12 test EXEs + 7 scenario EXEs + presentation launchers");
    puts("Test logs          : logs\\windows\\");
    puts("Generated datasets : results\\");
    puts("Documentation      : docs\\ and validation\\");
    divider();
    puts("Recommended live presentation order:");
    puts("  1. PROJECT_OVERVIEW.exe");
    puts("  2. RUN_ALL_TESTS.exe");
    puts("  3. RUN_ALL_SCENARIOS.exe or RUN_FULL_PRESENTATION.exe");
    puts("  4. Open results\\scenario4_full_key_summary.csv");
    divider();
    wait_for_enter();
    return 0;
}
