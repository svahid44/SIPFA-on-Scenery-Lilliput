CC ?= cc
AR ?= ar
CFLAGS ?= -std=c99 -O2 -Wall -Wextra -Wpedantic -Wshadow -Wconversion
CPPFLAGS ?= -Iinclude
LDFLAGS ?=

BUILD := build
LIBOBJ := $(BUILD)/scenery.o $(BUILD)/persistent_fault.o $(BUILD)/detection_dataset.o $(BUILD)/known_detection_attack.o $(BUILD)/unknown_detection_attack.o $(BUILD)/infection_dataset.o $(BUILD)/known_infection_attack.o $(BUILD)/unknown_infection_attack.o
LIB := $(BUILD)/libscenery.a

TESTS := \
	$(BUILD)/test_vectors \
	$(BUILD)/test_trace_tv1 \
	$(BUILD)/test_key_schedule \
	$(BUILD)/test_cross_validation \
	$(BUILD)/test_structural \
	$(BUILD)/test_persistent_fault \
	$(BUILD)/test_detection_dataset \
	$(BUILD)/test_known_detection_attack \
	$(BUILD)/test_known_detection_full_attack \
	$(BUILD)/test_unknown_detection_attack \
	$(BUILD)/test_unknown_detection_partial_decryption \
	$(BUILD)/test_known_infection_attack \
	$(BUILD)/test_known_infection_full_attack \
	$(BUILD)/test_unknown_infection_attack \
	$(BUILD)/test_unknown_infection_partial_decryption \
	$(BUILD)/test_unknown_infection_structural_equivalence

EXAMPLES := \
	$(BUILD)/example \
	$(BUILD)/trace_example

TOOLS := $(BUILD)/scenario1_collect_detection $(BUILD)/scenario1_recover_word \
         $(BUILD)/scenario1_collect_all_detection $(BUILD)/scenario1_recover_full_key \
         $(BUILD)/scenario1_repeated_experiments \
         $(BUILD)/scenario2_collect_unknown_detection $(BUILD)/scenario2_identify_fault \
         $(BUILD)/scenario2_filter_active_key $(BUILD)/scenario2_verify_active_key \
         $(BUILD)/scenario2_repeated_experiments \
         $(BUILD)/scenario3_collect_known_infection $(BUILD)/scenario3_recover_word \
         $(BUILD)/scenario3_collect_all_infection $(BUILD)/scenario3_recover_full_key \
         $(BUILD)/scenario3_repeated_experiments \
         $(BUILD)/scenario4_collect_unknown_infection $(BUILD)/scenario4_identify_fault \
         $(BUILD)/scenario4_rank_active_key \
         $(BUILD)/scenario4_audit_structural_tie

.PHONY: all clean test examples scenario1-dataset scenario1-recover-word scenario1-step3 \
        scenario1-all-datasets scenario1-recover-full scenario1-step4 \
        scenario1-repeated scenario1-report scenario1-final \
        scenario2-dataset scenario2-identify scenario2-step1 \
        scenario2-dataset-step2 scenario2-filter scenario2-verify scenario2-step2 \
        scenario2-repeated scenario2-report scenario2-final \
        scenario3-dataset scenario3-recover-word scenario3-step1 \
        scenario3-all-datasets scenario3-recover-full scenario3-step2 \
        scenario3-repeated scenario3-report scenario3-final \
        scenario4-dataset scenario4-identify scenario4-step1 \
        scenario4-rank scenario4-step2 scenario4-audit-tie scenario4-step3

all: $(LIB) $(TESTS) $(EXAMPLES) $(TOOLS)

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/scenery.o: src/scenery.c include/scenery.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD)/persistent_fault.o: src/persistent_fault.c include/persistent_fault.h include/scenery.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD)/detection_dataset.o: src/detection_dataset.c include/detection_dataset.h include/persistent_fault.h include/scenery.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD)/known_detection_attack.o: src/known_detection_attack.c include/known_detection_attack.h include/scenery.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD)/unknown_detection_attack.o: src/unknown_detection_attack.c include/unknown_detection_attack.h include/known_detection_attack.h include/scenery.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD)/infection_dataset.o: src/infection_dataset.c include/infection_dataset.h include/persistent_fault.h include/scenery.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD)/known_infection_attack.o: src/known_infection_attack.c include/known_infection_attack.h include/known_detection_attack.h include/scenery.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD)/unknown_infection_attack.o: src/unknown_infection_attack.c include/unknown_infection_attack.h include/known_detection_attack.h include/scenery.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(LIB): $(LIBOBJ)
	$(AR) rcs $@ $^

$(BUILD)/test_vectors: tests/test_vectors.c $(LIB) include/scenery.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

$(BUILD)/test_trace_tv1: tests/test_trace_tv1.c $(LIB) include/scenery.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

$(BUILD)/test_key_schedule: tests/test_key_schedule.c $(LIB) include/scenery.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

$(BUILD)/test_cross_validation: tests/test_cross_validation.c $(LIB) include/scenery.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

$(BUILD)/test_structural: tests/test_structural.c $(LIB) include/scenery.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@


$(BUILD)/test_persistent_fault: tests/test_persistent_fault.c $(LIB) include/persistent_fault.h include/scenery.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

$(BUILD)/test_detection_dataset: tests/test_detection_dataset.c $(LIB) include/detection_dataset.h include/persistent_fault.h include/scenery.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

$(BUILD)/test_known_detection_attack: tests/test_known_detection_attack.c $(LIB) include/known_detection_attack.h include/detection_dataset.h include/persistent_fault.h include/scenery.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@


$(BUILD)/test_known_detection_full_attack: tests/test_known_detection_full_attack.c $(LIB) include/known_detection_attack.h include/detection_dataset.h include/persistent_fault.h include/scenery.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

$(BUILD)/test_unknown_detection_attack: tests/test_unknown_detection_attack.c $(LIB) include/unknown_detection_attack.h include/known_detection_attack.h include/detection_dataset.h include/persistent_fault.h include/scenery.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

$(BUILD)/test_unknown_detection_partial_decryption: tests/test_unknown_detection_partial_decryption.c $(LIB) include/unknown_detection_attack.h include/known_detection_attack.h include/detection_dataset.h include/persistent_fault.h include/scenery.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

$(BUILD)/test_known_infection_attack: tests/test_known_infection_attack.c $(LIB) include/infection_dataset.h include/known_infection_attack.h include/known_detection_attack.h include/persistent_fault.h include/scenery.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

$(BUILD)/test_known_infection_full_attack: tests/test_known_infection_full_attack.c $(LIB) include/infection_dataset.h include/known_infection_attack.h include/known_detection_attack.h include/persistent_fault.h include/scenery.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

$(BUILD)/test_unknown_infection_attack: tests/test_unknown_infection_attack.c $(LIB) include/unknown_infection_attack.h include/infection_dataset.h include/known_detection_attack.h include/persistent_fault.h include/scenery.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

$(BUILD)/test_unknown_infection_partial_decryption: tests/test_unknown_infection_partial_decryption.c $(LIB) include/unknown_infection_attack.h include/unknown_detection_attack.h include/infection_dataset.h include/known_detection_attack.h include/persistent_fault.h include/scenery.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

$(BUILD)/test_unknown_infection_structural_equivalence: tests/test_unknown_infection_structural_equivalence.c $(LIB) include/unknown_infection_attack.h include/unknown_detection_attack.h include/infection_dataset.h include/known_detection_attack.h include/persistent_fault.h include/scenery.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

$(BUILD)/scenario1_collect_detection: tools/scenario1_collect_detection.c $(LIB) include/detection_dataset.h include/persistent_fault.h include/scenery.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

$(BUILD)/scenario1_recover_word: tools/scenario1_recover_word.c $(LIB) include/known_detection_attack.h include/scenery.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@


$(BUILD)/scenario1_collect_all_detection: tools/scenario1_collect_all_detection.c $(LIB) include/detection_dataset.h include/persistent_fault.h include/scenery.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

$(BUILD)/scenario1_recover_full_key: tools/scenario1_recover_full_key.c $(LIB) include/known_detection_attack.h include/scenery.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@


$(BUILD)/scenario1_repeated_experiments: tools/scenario1_repeated_experiments.c $(LIB) include/known_detection_attack.h include/detection_dataset.h include/persistent_fault.h include/scenery.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

$(BUILD)/scenario2_collect_unknown_detection: tools/scenario2_collect_unknown_detection.c $(LIB) include/detection_dataset.h include/known_detection_attack.h include/persistent_fault.h include/scenery.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

$(BUILD)/scenario2_identify_fault: tools/scenario2_identify_fault.c $(LIB) include/unknown_detection_attack.h include/scenery.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

$(BUILD)/scenario2_filter_active_key: tools/scenario2_filter_active_key.c $(LIB) include/unknown_detection_attack.h include/known_detection_attack.h include/scenery.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

$(BUILD)/scenario2_verify_active_key: tools/scenario2_verify_active_key.c $(LIB) include/unknown_detection_attack.h include/scenery.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

$(BUILD)/scenario2_repeated_experiments: tools/scenario2_repeated_experiments.c $(LIB) include/unknown_detection_attack.h include/known_detection_attack.h include/detection_dataset.h include/persistent_fault.h include/scenery.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

$(BUILD)/scenario3_collect_known_infection: tools/scenario3_collect_known_infection.c $(LIB) include/infection_dataset.h include/detection_dataset.h include/persistent_fault.h include/scenery.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

$(BUILD)/scenario3_recover_word: tools/scenario3_recover_word.c $(LIB) include/known_infection_attack.h include/known_detection_attack.h include/scenery.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

$(BUILD)/scenario3_collect_all_infection: tools/scenario3_collect_all_infection.c $(LIB) include/infection_dataset.h include/detection_dataset.h include/persistent_fault.h include/scenery.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

$(BUILD)/scenario3_recover_full_key: tools/scenario3_recover_full_key.c $(LIB) include/known_infection_attack.h include/known_detection_attack.h include/scenery.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

$(BUILD)/scenario3_repeated_experiments: tools/scenario3_repeated_experiments.c $(LIB) include/detection_dataset.h include/known_infection_attack.h include/persistent_fault.h include/scenery.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

$(BUILD)/scenario4_collect_unknown_infection: tools/scenario4_collect_unknown_infection.c $(LIB) include/infection_dataset.h include/detection_dataset.h include/persistent_fault.h include/scenery.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

$(BUILD)/scenario4_identify_fault: tools/scenario4_identify_fault.c $(LIB) include/unknown_infection_attack.h include/known_detection_attack.h include/scenery.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

$(BUILD)/scenario4_rank_active_key: tools/scenario4_rank_active_key.c $(LIB) include/unknown_infection_attack.h include/unknown_detection_attack.h include/known_detection_attack.h include/scenery.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

$(BUILD)/scenario4_audit_structural_tie: tools/scenario4_audit_structural_tie.c $(LIB) include/unknown_infection_attack.h include/unknown_detection_attack.h include/known_detection_attack.h include/scenery.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

$(BUILD)/example: examples/example.c $(LIB) include/scenery.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

$(BUILD)/trace_example: examples/trace_example.c $(LIB) include/scenery.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

test: $(TESTS)
	./$(BUILD)/test_vectors
	./$(BUILD)/test_trace_tv1
	./$(BUILD)/test_key_schedule
	./$(BUILD)/test_cross_validation
	./$(BUILD)/test_structural
	./$(BUILD)/test_persistent_fault
	./$(BUILD)/test_detection_dataset
	./$(BUILD)/test_known_detection_attack
	./$(BUILD)/test_known_detection_full_attack
	./$(BUILD)/test_unknown_detection_attack
	./$(BUILD)/test_unknown_detection_partial_decryption
	./$(BUILD)/test_known_infection_attack
	./$(BUILD)/test_known_infection_full_attack
	./$(BUILD)/test_unknown_infection_attack
	./$(BUILD)/test_unknown_infection_partial_decryption
	./$(BUILD)/test_unknown_infection_structural_equivalence

examples: $(EXAMPLES)
	./$(BUILD)/example

scenario1-dataset: $(BUILD)/scenario1_collect_detection
	mkdir -p results
	./$(BUILD)/scenario1_collect_detection

scenario1-recover-word: $(BUILD)/scenario1_recover_word
	mkdir -p results
	./$(BUILD)/scenario1_recover_word

scenario1-step3: scenario1-dataset scenario1-recover-word

clean:
	rm -rf $(BUILD)

scenario1-all-datasets: $(BUILD)/scenario1_collect_all_detection
	mkdir -p results
	./$(BUILD)/scenario1_collect_all_detection

scenario1-recover-full: $(BUILD)/scenario1_recover_full_key
	mkdir -p results
	./$(BUILD)/scenario1_recover_full_key

scenario1-step4: scenario1-all-datasets scenario1-recover-full

scenario1-repeated: $(BUILD)/scenario1_repeated_experiments
	mkdir -p results
	./$(BUILD)/scenario1_repeated_experiments 100

scenario1-report: scenario1-repeated
	python3 scripts/scenario1_analysis.py

scenario1-final: scenario1-step4 scenario1-report

scenario2-dataset: $(BUILD)/scenario2_collect_unknown_detection
	mkdir -p results
	./$(BUILD)/scenario2_collect_unknown_detection

scenario2-identify: $(BUILD)/scenario2_identify_fault
	mkdir -p results
	./$(BUILD)/scenario2_identify_fault

scenario2-step1: scenario2-dataset scenario2-identify

scenario2-dataset-step2: $(BUILD)/scenario2_collect_unknown_detection
	mkdir -p results
	./$(BUILD)/scenario2_collect_unknown_detection 512 20000 0x243F6A8885A308D3 5 0xB

scenario2-filter: $(BUILD)/scenario2_filter_active_key
	mkdir -p results
	./$(BUILD)/scenario2_filter_active_key

scenario2-verify: $(BUILD)/scenario2_verify_active_key
	mkdir -p results
	./$(BUILD)/scenario2_verify_active_key

scenario2-step2: scenario2-dataset-step2 scenario2-identify scenario2-filter scenario2-verify

scenario2-repeated: $(BUILD)/scenario2_repeated_experiments
	mkdir -p results
	./$(BUILD)/scenario2_repeated_experiments 100

scenario2-report:
	python3 scripts/scenario2_analysis.py

scenario2-final: scenario2-step2 scenario2-report

scenario3-dataset: $(BUILD)/scenario3_collect_known_infection
	mkdir -p results
	./$(BUILD)/scenario3_collect_known_infection

scenario3-recover-word: $(BUILD)/scenario3_recover_word
	mkdir -p results
	./$(BUILD)/scenario3_recover_word

scenario3-step1: scenario3-dataset scenario3-recover-word


scenario3-all-datasets: $(BUILD)/scenario3_collect_all_infection
	mkdir -p results
	./$(BUILD)/scenario3_collect_all_infection

scenario3-recover-full: $(BUILD)/scenario3_recover_full_key
	mkdir -p results
	./$(BUILD)/scenario3_recover_full_key

scenario3-step2: scenario3-all-datasets scenario3-recover-full

scenario3-repeated: $(BUILD)/scenario3_repeated_experiments
	mkdir -p results
	bash scripts/run_scenario3_repeated_chunked.sh 100 0x5343454E45525933

scenario3-report:
	python3 scripts/scenario3_analysis.py

scenario3-final: scenario3-step2 scenario3-repeated scenario3-report

scenario4-dataset: $(BUILD)/scenario4_collect_unknown_infection
	mkdir -p results
	./$(BUILD)/scenario4_collect_unknown_infection

scenario4-identify: $(BUILD)/scenario4_identify_fault
	mkdir -p results
	./$(BUILD)/scenario4_identify_fault

scenario4-step1: scenario4-dataset scenario4-identify

scenario4-rank: $(BUILD)/scenario4_rank_active_key
	mkdir -p results
	./$(BUILD)/scenario4_rank_active_key

scenario4-step2: scenario4-dataset scenario4-identify scenario4-rank

scenario4-audit-tie: $(BUILD)/scenario4_audit_structural_tie
	mkdir -p results
	./$(BUILD)/scenario4_audit_structural_tie

scenario4-step3: scenario4-step2 scenario4-audit-tie
