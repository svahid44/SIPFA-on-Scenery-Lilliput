#include "launcher_common.h"
int main(void)
{
    static const demo_item items[] = {
        {"Scenario 1 - known fault / detection", "scenario1_known_detection.exe", "Generates ineffective samples and recovers the final-round target value."},
        {"Scenario 1 - RTK[30]", "scenario1_rtk30_known_detection.exe", "Peels the final round and recovers the preceding round tweakey."},
        {"Scenario 1 - complete master key", "scenario1_full_key_known_detection.exe", "Builds a rank-128 GF(2) system and recovers the 128-bit master key."},
        {"Scenario 2 - unknown fault / detection", "scenario2_unknown_detection.exe", "Locates the faulty lane and ranks candidates without fault-value knowledge."},
        {"Scenario 3 - known fault / infection", "scenario3_known_infection.exe", "Uses statistical imbalance under unlabeled infected outputs."},
        {"Scenario 4 - unknown fault / infection", "scenario4_unknown_infection.exe", "Recovers the unknown persistent-fault input and last-round information."},
        {"Scenario 4 - complete master key", "scenario4_full_key_unknown_infection.exe", "End-to-end recovery of delta, RTK[31], RTK[30], and the master key."}
    };
    const unsigned int count = (unsigned int)(sizeof(items) / sizeof(items[0]));
    int failures;
    prepare_directories();
    divider();
    puts("LILLIPUT-TBC-II-128 / SIPFA - COMPLETE WINDOWS SCENARIO DEMO");
    divider();
    failures = run_items(items, count);
    final_summary("SCENARIO", count, failures);
    wait_for_enter();
    return (failures == 0) ? 0 : 1;
}
