#include "launcher_common.h"
int main(void)
{
    static const demo_item tests[] = {
        {"Official cipher vector and round trip", "test_tbc.exe", "Reference implementation correctness."},
        {"Persistent fault model", "test_persistent_fault.exe", "Persistent S-box fault semantics."},
        {"Attack-round peeling", "test_attack_round.exe", "Last-round inverse mapping."},
        {"Attack API boundaries", "test_attack_api.exe", "Attacker/oracle data separation."},
        {"Formal article mapping", "test_phase2_article_mapping.exe", "Implementation-to-paper mapping."},
        {"RTK[31]/RTK[30] recovery", "test_phase3_scenario1_rtk30.exe", "Two-round tweakey recovery."},
        {"Master-key recovery", "test_master_key_recovery.exe", "Rank-128 unique key solution."},
        {"Scenario 4 full-key recovery", "test_phase5_scenario4_full_key.exe", "Unknown infection end-to-end recovery."},
        {"Scenario 1 regression", "test_scenario1_known_detection.exe", "Known/detection case."},
        {"Scenario 2 regression", "test_scenario2_unknown_detection.exe", "Unknown/detection case."},
        {"Scenario 3 regression", "test_scenario3_known_infection.exe", "Known/infection case."},
        {"Scenario 4 regression", "test_scenario4_unknown_infection.exe", "Unknown/infection case."}
    };
    static const demo_item scenarios[] = {
        {"Scenario 1 - known fault / detection", "scenario1_known_detection.exe", "Baseline known-fault detection attack."},
        {"Scenario 1 - RTK[30]", "scenario1_rtk30_known_detection.exe", "Second recovered round tweakey."},
        {"Scenario 1 - complete master key", "scenario1_full_key_known_detection.exe", "Complete 128-bit key recovery."},
        {"Scenario 2 - unknown fault / detection", "scenario2_unknown_detection.exe", "Unknown fault localization and ranking."},
        {"Scenario 3 - known fault / infection", "scenario3_known_infection.exe", "SEI-based known-fault infection attack."},
        {"Scenario 4 - unknown fault / infection", "scenario4_unknown_infection.exe", "Unknown fault under unlabeled outputs."},
        {"Scenario 4 - complete master key", "scenario4_full_key_unknown_infection.exe", "Final end-to-end recovery demonstration."}
    };
    const unsigned int nt = (unsigned int)(sizeof(tests) / sizeof(tests[0]));
    const unsigned int ns = (unsigned int)(sizeof(scenarios) / sizeof(scenarios[0]));
    int failures;

    prepare_directories();
    divider();
    puts("LILLIPUT-TBC-II-128 / SIPFA - FULL PRESENTATION");
    puts("Stage A: correctness and regression tests");
    puts("Stage B: executable attack scenarios and generated evidence");
    divider();
    failures = run_items(tests, nt);
    final_summary("TEST", nt, failures);
    if (failures == 0) {
        puts("All tests passed. Starting the scenario demonstrations.\n");
        failures += run_items(scenarios, ns);
    } else {
        puts("Scenario stage skipped because at least one prerequisite test failed.");
    }
    final_summary("FULL PRESENTATION", nt + ns, failures);
    if (failures == 0) {
        puts("FINAL RESULT: PASS - all tests and scenarios completed successfully.");
        puts("Primary evidence: results\\scenario4_full_key_summary.csv");
    } else {
        puts("FINAL RESULT: FAIL - inspect logs\\windows for the failing stage.");
    }
    divider();
    wait_for_enter();
    return (failures == 0) ? 0 : 1;
}
