#include "launcher_common.h"
int main(void)
{
    static const demo_item items[] = {
        {"Official cipher vector and round trip", "test_tbc.exe", "Validates Lilliput-TBC-II-128 encryption/decryption against the reference vector."},
        {"Persistent fault model", "test_persistent_fault.exe", "Checks single persistent S-box entry faults, reset behavior, and effective/ineffective events."},
        {"Attack-round peeling", "test_attack_round.exe", "Validates inverse-round peeling used by the SIPFA analysis."},
        {"Attack API boundaries", "test_attack_api.exe", "Checks separation between published attacker inputs and hidden oracle-side labels."},
        {"Formal article mapping", "test_phase2_article_mapping.exe", "Maps the implementation to the SIPFA paper notation and equations."},
        {"RTK[31]/RTK[30] recovery", "test_phase3_scenario1_rtk30.exe", "Validates iterative recovery of the last two round tweakeys."},
        {"Master-key recovery", "test_master_key_recovery.exe", "Checks the GF(2) rank-128 system and unique 128-bit master-key solution."},
        {"Scenario 4 full-key recovery", "test_phase5_scenario4_full_key.exe", "Tests unknown persistent fault, infection model, RTK recovery, and full master key."},
        {"Scenario 1 regression", "test_scenario1_known_detection.exe", "Known fault with detection-based countermeasure."},
        {"Scenario 2 regression", "test_scenario2_unknown_detection.exe", "Unknown fault with detection-based countermeasure."},
        {"Scenario 3 regression", "test_scenario3_known_infection.exe", "Known fault with infection-based countermeasure."},
        {"Scenario 4 regression", "test_scenario4_unknown_infection.exe", "Unknown fault with infection-based countermeasure."}
    };
    const unsigned int count = (unsigned int)(sizeof(items) / sizeof(items[0]));
    int failures;
    prepare_directories();
    divider();
    puts("LILLIPUT-TBC-II-128 / SIPFA - COMPLETE WINDOWS TEST SUITE");
    divider();
    failures = run_items(items, count);
    final_summary("TEST", count, failures);
    wait_for_enter();
    return (failures == 0) ? 0 : 1;
}
