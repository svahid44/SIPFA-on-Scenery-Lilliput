CC ?= cc
CFLAGS ?= -std=c99 -O2 -Wall -Wextra -Wpedantic -Wshadow -Wconversion
CPPFLAGS += -Iinclude
LDFLAGS ?=
LDLIBS ?=

BUILD := build
RESULTS := results
COMMON_SOURCES := src/cipher.c src/round.c src/tweakey.c \
                  src/persistent_fault.c src/attack_common.c \
                  src/attack_round.c src/reference_validation.c src/reference_trace.c \
                  src/detection_dataset.c src/known_detection_iterative.c src/master_key_recovery.c \
                  src/unknown_detection_attack.c src/infection_dataset.c src/known_infection_attack.c \
                  src/unknown_infection_attack.c src/unknown_infection_full_recovery.c
HEADERS := $(wildcard include/*.h)

TEST_TBC := $(BUILD)/test_tbc
TEST_FAULT := $(BUILD)/test_persistent_fault
TEST_ATTACK_ROUND := $(BUILD)/test_attack_round
TEST_ATTACK_API := $(BUILD)/test_attack_api
TEST_PHASE2_MAPPING := $(BUILD)/test_phase2_article_mapping
TEST_PHASE3_RTK30 := $(BUILD)/test_phase3_scenario1_rtk30
TEST_MASTER_KEY := $(BUILD)/test_master_key_recovery
TEST_SCENARIO1 := $(BUILD)/test_scenario1_known_detection
TEST_SCENARIO2 := $(BUILD)/test_scenario2_unknown_detection
TEST_SCENARIO3 := $(BUILD)/test_scenario3_known_infection
TEST_SCENARIO4 := $(BUILD)/test_scenario4_unknown_infection
TEST_PHASE5_SCENARIO4_FULL_KEY := $(BUILD)/test_phase5_scenario4_full_key
SCENARIO1 := $(BUILD)/scenario1_known_detection
SCENARIO1_RTK30 := $(BUILD)/scenario1_rtk30_known_detection
SCENARIO1_FULL_KEY := $(BUILD)/scenario1_full_key_known_detection
SCENARIO2 := $(BUILD)/scenario2_unknown_detection
SCENARIO3 := $(BUILD)/scenario3_known_infection
SCENARIO4 := $(BUILD)/scenario4_unknown_infection
SCENARIO4_FULL_KEY := $(BUILD)/scenario4_full_key_unknown_infection

TESTS := $(TEST_TBC) $(TEST_FAULT) $(TEST_ATTACK_ROUND) $(TEST_ATTACK_API) \
         $(TEST_PHASE2_MAPPING) $(TEST_PHASE3_RTK30) $(TEST_MASTER_KEY) $(TEST_PHASE5_SCENARIO4_FULL_KEY) $(TEST_SCENARIO1) $(TEST_SCENARIO2) $(TEST_SCENARIO3) $(TEST_SCENARIO4)
SCENARIOS := $(SCENARIO1) $(SCENARIO1_RTK30) $(SCENARIO1_FULL_KEY) $(SCENARIO2) $(SCENARIO3) $(SCENARIO4) $(SCENARIO4_FULL_KEY)

.PHONY: all test test-reference test-fault test-attack-round test-attack-api \
        test-phase2-mapping test-phase3-rtk30 test-master-key test-phase4-master-key test-phase5-scenario4-full-key test-scenario1 test-scenario2 test-scenario3 test-scenario4 check-boundaries \
        scenario1 scenario1-rtk30 scenario1-full-key scenario2 scenario3 scenario4 scenario4-full-key scenarios \
        check-gcc check-clang check-sanitize clean

all: $(TESTS) $(SCENARIOS)

$(BUILD)/test_%: tests/test_%.c $(COMMON_SOURCES) $(HEADERS)
	@mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(COMMON_SOURCES) $< $(LDFLAGS) $(LDLIBS) -o $@

$(BUILD)/scenario%: tools/scenario%.c $(COMMON_SOURCES) $(HEADERS)
	@mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(COMMON_SOURCES) $< $(LDFLAGS) $(LDLIBS) -o $@

test-reference: $(TEST_TBC)
	./$(TEST_TBC)

test-fault: $(TEST_FAULT)
	./$(TEST_FAULT)

test-attack-round: $(TEST_ATTACK_ROUND)
	./$(TEST_ATTACK_ROUND)

test-attack-api: $(TEST_ATTACK_API)
	./$(TEST_ATTACK_API)

test-phase2-mapping: $(TEST_PHASE2_MAPPING)
	./$(TEST_PHASE2_MAPPING)

test-phase3-rtk30: $(TEST_PHASE3_RTK30)
	./$(TEST_PHASE3_RTK30)

test-master-key: $(TEST_MASTER_KEY)
	./$(TEST_MASTER_KEY)

test-phase4-master-key: test-master-key

test-phase5-scenario4-full-key: $(TEST_PHASE5_SCENARIO4_FULL_KEY)
	./$(TEST_PHASE5_SCENARIO4_FULL_KEY)

test-scenario1: $(TEST_SCENARIO1)
	./$(TEST_SCENARIO1)

test-scenario2: $(TEST_SCENARIO2)
	./$(TEST_SCENARIO2)

test-scenario3: $(TEST_SCENARIO3)
	./$(TEST_SCENARIO3)

test-scenario4: $(TEST_SCENARIO4)
	./$(TEST_SCENARIO4)

check-boundaries:
	./scripts/check_attack_boundaries.sh

test: test-reference test-fault test-attack-round test-attack-api \
      test-phase2-mapping test-phase3-rtk30 test-master-key test-phase5-scenario4-full-key test-scenario1 test-scenario2 test-scenario3 test-scenario4 check-boundaries

scenario1: $(SCENARIO1)
	@mkdir -p $(RESULTS)
	./$(SCENARIO1)

scenario1-rtk30: $(SCENARIO1_RTK30)
	@mkdir -p $(RESULTS)
	./$(SCENARIO1_RTK30)

scenario1-full-key: $(SCENARIO1_FULL_KEY)
	@mkdir -p $(RESULTS)
	./$(SCENARIO1_FULL_KEY)

scenario2: $(SCENARIO2)
	@mkdir -p $(RESULTS)
	./$(SCENARIO2)

scenario3: $(SCENARIO3)
	@mkdir -p $(RESULTS)
	./$(SCENARIO3)

scenario4: $(SCENARIO4)
	@mkdir -p $(RESULTS)
	./$(SCENARIO4)

scenario4-full-key: $(SCENARIO4_FULL_KEY)
	@mkdir -p $(RESULTS)
	./$(SCENARIO4_FULL_KEY)

scenarios: scenario1 scenario1-rtk30 scenario1-full-key scenario2 scenario3 scenario4 scenario4-full-key

check-gcc:
	$(MAKE) clean
	$(MAKE) CC=gcc CFLAGS='-std=c99 -O2 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Werror' all
	$(MAKE) CC=gcc CFLAGS='-std=c99 -O2 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Werror' test

check-clang:
	$(MAKE) clean
	$(MAKE) CC=clang CFLAGS='-std=c99 -O2 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Werror' all
	$(MAKE) CC=clang CFLAGS='-std=c99 -O2 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Werror' test

check-sanitize:
	$(MAKE) clean
	$(MAKE) CC=clang \
	  CFLAGS='-std=c99 -O1 -g -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Werror -fsanitize=address,undefined -fno-omit-frame-pointer' \
	  LDFLAGS='-fsanitize=address,undefined' all
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1 \
	$(MAKE) CC=clang \
	  CFLAGS='-std=c99 -O1 -g -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Werror -fsanitize=address,undefined -fno-omit-frame-pointer' \
	  LDFLAGS='-fsanitize=address,undefined' test

clean:
	rm -rf $(BUILD)


# BEGIN WSL WINDOWS EXE BUILD TARGETS
.PHONY: windows-exes windows-verify windows-clean windows-rebuild

windows-exes:
	./scripts/build_windows_from_wsl.sh

windows-verify:
	./scripts/verify_windows_exes.sh

windows-clean:
	./scripts/clean_windows_exes.sh

windows-rebuild: windows-clean windows-exes windows-verify
# END WSL WINDOWS EXE BUILD TARGETS
