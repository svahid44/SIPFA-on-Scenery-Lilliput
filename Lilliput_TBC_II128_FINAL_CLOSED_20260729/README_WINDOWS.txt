Lilliput-TBC-II-128 SIPFA Final Package
========================================

This package contains:

1. Complete C source code
2. Linux executables
3. Windows 64-bit EXE executables
4. All result CSV files
5. All test and scenario logs
6. Documentation for all four SIPFA scenarios

Windows execution
-----------------

Run all tests:

    RUN_ALL_TESTS_WINDOWS.bat

Run all scenarios:

    RUN_ALL_SCENARIOS_WINDOWS.bat

Run individual scenarios:

    RUN_SCENARIO1_WINDOWS.bat
    RUN_SCENARIO2_WINDOWS.bat
    RUN_SCENARIO3_WINDOWS.bat
    RUN_SCENARIO4_WINDOWS.bat

Windows executables are located in:

    bin\windows\

Linux executables are located in:

    bin\linux\

Results are located in:

    results\

Scenarios
---------

Scenario 1:
Known persistent fault + detection-based countermeasure

Scenario 2:
Unknown persistent fault + detection-based countermeasure

Scenario 3:
Known persistent fault + infection-based countermeasure

Scenario 4:
Unknown persistent fault + infection-based countermeasure

Expected recovered values
-------------------------

Fault input:

    0x5a

Final-round tweakey:

    b3ed58adabab101d
