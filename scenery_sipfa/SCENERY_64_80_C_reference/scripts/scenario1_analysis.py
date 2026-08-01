#!/usr/bin/env python3
"""Generate Scenario-1 paper tables and figures from the reproducible CSV files."""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Iterable, Sequence

import matplotlib.pyplot as plt

Z95 = 1.959963984540054


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, fieldnames: Sequence[str], rows: Iterable[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def wilson(successes: int, total: int) -> tuple[float, float]:
    if total <= 0:
        return 0.0, 0.0
    p = successes / total
    z2 = Z95 * Z95
    denominator = 1.0 + z2 / total
    centre = (p + z2 / (2.0 * total)) / denominator
    margin = Z95 * math.sqrt((p * (1.0 - p) + z2 / (4.0 * total)) / total) / denominator
    return max(0.0, centre - margin), min(1.0, centre + margin)


def mean_std(values: Sequence[float]) -> tuple[float, float]:
    if not values:
        return 0.0, 0.0
    if len(values) == 1:
        return values[0], 0.0
    return statistics.mean(values), statistics.stdev(values)


def save_figure(fig: plt.Figure, base: Path) -> None:
    base.parent.mkdir(parents=True, exist_ok=True)
    for suffix in ("png", "pdf", "svg"):
        fig.savefig(base.with_suffix(f".{suffix}"), dpi=220, bbox_inches="tight")
    plt.close(fig)


def markdown_table(path: Path, headers: Sequence[str], rows: Sequence[Sequence[object]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        handle.write("| " + " | ".join(headers) + " |\n")
        handle.write("|" + "|".join(["---"] * len(headers)) + "|\n")
        for row in rows:
            handle.write("| " + " | ".join(str(value) for value in row) + " |\n")


def latex_escape(value: object) -> str:
    text = str(value)
    replacements = {
        "\\": r"\textbackslash{}",
        "&": r"\&",
        "%": r"\%",
        "$": r"\$",
        "#": r"\#",
        "_": r"\_",
        "{": r"\{",
        "}": r"\}",
    }
    return "".join(replacements.get(char, char) for char in text)


def latex_table(path: Path, headers: Sequence[str], rows: Sequence[Sequence[object]], caption: str, label: str) -> None:
    columns = "l" + "r" * (len(headers) - 1)
    with path.open("w", encoding="utf-8") as handle:
        handle.write("\\begin{table}[t]\n\\centering\n")
        handle.write(f"\\caption{{{latex_escape(caption)}}}\n")
        handle.write(f"\\label{{{label}}}\n")
        handle.write(f"\\begin{{tabular}}{{{columns}}}\n\\toprule\n")
        handle.write(" & ".join(latex_escape(h) for h in headers) + r" \\" + "\n")
        handle.write("\\midrule\n")
        for row in rows:
            handle.write(" & ".join(latex_escape(v) for v in row) + r" \\" + "\n")
        handle.write("\\bottomrule\n\\end{tabular}\n\\end{table}\n")


def aggregate_repeated(trials: list[dict[str, str]], words: list[dict[str, str]]) -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, object]]]:
    trial_groups: dict[int, list[dict[str, str]]] = defaultdict(list)
    word_groups: dict[tuple[int, int], list[dict[str, str]]] = defaultdict(list)
    all_word_groups: dict[int, list[dict[str, str]]] = defaultdict(list)

    for row in trials:
        trial_groups[int(row["samples_per_sbox"])].append(row)
    for row in words:
        samples = int(row["samples_per_sbox"])
        sbox = int(row["sbox"])
        word_groups[(samples, sbox)].append(row)
        all_word_groups[samples].append(row)

    success_rows: list[dict[str, object]] = []
    query_rows: list[dict[str, object]] = []
    per_sbox_rows: list[dict[str, object]] = []

    for samples in sorted(trial_groups):
        group = trial_groups[samples]
        total = len(group)
        successes = sum(int(row["full_key_success"]) for row in group)
        full_rate = successes / total
        low, high = wilson(successes, total)

        word_group = all_word_groups[samples]
        word_successes = sum(int(row["word_success"]) for row in word_group)
        word_total = len(word_group)
        word_rate = word_successes / word_total
        word_low, word_high = wilson(word_successes, word_total)

        correct_words = [float(row["correct_words"]) for row in group]
        unique_words = [float(row["unique_missing_words"]) for row in group]
        mean_correct, std_correct = mean_std(correct_words)
        mean_unique, std_unique = mean_std(unique_words)

        total_queries = [float(row["total_queries"]) for row in group]
        query_mean, query_std = mean_std(total_queries)
        query_ci = Z95 * query_std / math.sqrt(total) if total > 1 else 0.0
        empirical_rates = [float(row["aggregate_empirical_rate"]) for row in group]
        rate_mean, rate_std = mean_std(empirical_rates)
        errors = [float(row["absolute_rate_error"]) for row in group]
        error_mean, error_std = mean_std(errors)

        success_rows.append({
            "samples_per_sbox": samples,
            "trials": total,
            "full_key_successes": successes,
            "full_key_success_rate": f"{full_rate:.9f}",
            "full_key_ci95_low": f"{low:.9f}",
            "full_key_ci95_high": f"{high:.9f}",
            "word_successes": word_successes,
            "word_trials": word_total,
            "word_success_rate": f"{word_rate:.9f}",
            "word_ci95_low": f"{word_low:.9f}",
            "word_ci95_high": f"{word_high:.9f}",
            "mean_correct_words_of_8": f"{mean_correct:.6f}",
            "std_correct_words": f"{std_correct:.6f}",
            "mean_unique_missing_words_of_8": f"{mean_unique:.6f}",
            "std_unique_missing_words": f"{std_unique:.6f}",
        })

        query_rows.append({
            "samples_per_sbox": samples,
            "trials": total,
            "mean_total_queries": f"{query_mean:.6f}",
            "std_total_queries": f"{query_std:.6f}",
            "ci95_total_queries_low": f"{query_mean - query_ci:.6f}",
            "ci95_total_queries_high": f"{query_mean + query_ci:.6f}",
            "median_total_queries": f"{statistics.median(total_queries):.6f}",
            "min_total_queries": f"{min(total_queries):.0f}",
            "max_total_queries": f"{max(total_queries):.0f}",
            "mean_empirical_rate": f"{rate_mean:.12f}",
            "std_empirical_rate": f"{rate_std:.12f}",
            "mean_absolute_rate_error": f"{error_mean:.12f}",
            "std_absolute_rate_error": f"{error_std:.12f}",
        })

        for sbox in range(8):
            subgroup = word_groups[(samples, sbox)]
            successes_sbox = sum(int(row["word_success"]) for row in subgroup)
            unique_sbox = sum(int(row["unique_missing"]) for row in subgroup)
            n = len(subgroup)
            s_low, s_high = wilson(successes_sbox, n)
            queries = [float(row["query_count"]) for row in subgroup]
            q_mean, q_std = mean_std(queries)
            per_sbox_rows.append({
                "samples_per_sbox": samples,
                "sbox": sbox,
                "trials": n,
                "word_successes": successes_sbox,
                "word_success_rate": f"{successes_sbox / n:.9f}",
                "word_ci95_low": f"{s_low:.9f}",
                "word_ci95_high": f"{s_high:.9f}",
                "unique_missing_rate": f"{unique_sbox / n:.9f}",
                "mean_queries": f"{q_mean:.6f}",
                "std_queries": f"{q_std:.6f}",
            })

    return success_rows, query_rows, per_sbox_rows


def threshold_table(success_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for target in (0.50, 0.80, 0.90, 0.95, 0.99, 1.00):
        selected = None
        for row in success_rows:
            if float(row["full_key_success_rate"]) >= target:
                selected = row
                break
        rows.append({
            "target_success_rate": f"{target:.2f}",
            "minimum_samples_per_sbox": selected["samples_per_sbox"] if selected else "not reached",
            "observed_success_rate": selected["full_key_success_rate"] if selected else "",
            "trials": selected["trials"] if selected else "",
        })
    return rows


def figure_success_curve(success_rows: list[dict[str, object]], figures: Path) -> None:
    x = [int(r["samples_per_sbox"]) for r in success_rows]
    full = [float(r["full_key_success_rate"]) for r in success_rows]
    full_low = [float(r["full_key_ci95_low"]) for r in success_rows]
    full_high = [float(r["full_key_ci95_high"]) for r in success_rows]
    word = [float(r["word_success_rate"]) for r in success_rows]

    fig, ax = plt.subplots(figsize=(8.4, 5.2))
    ax.plot(x, full, marker="o", label="Complete SK28 recovery")
    ax.fill_between(x, full_low, full_high, alpha=0.2, label="95% Wilson interval")
    ax.plot(x, word, marker="s", linestyle="--", label="Per-word recovery")
    ax.set_xlabel("Ineffective ciphertexts per S-box")
    ax.set_ylabel("Success probability")
    ax.set_ylim(-0.03, 1.03)
    ax.grid(True, alpha=0.3)
    ax.legend()
    ax.set_title("Scenario 1 success probability versus data complexity")
    save_figure(fig, figures / "fig_s1_success_vs_samples")


def figure_failure_log(success_rows: list[dict[str, object]], figures: Path) -> None:
    x = [int(r["samples_per_sbox"]) for r in success_rows]
    failure = [max(1e-3, 1.0 - float(r["full_key_success_rate"])) for r in success_rows]
    fig, ax = plt.subplots(figsize=(8.4, 5.2))
    ax.plot(x, failure, marker="o")
    ax.set_yscale("log")
    ax.set_xlabel("Ineffective ciphertexts per S-box")
    ax.set_ylabel("Observed failure probability (log scale)")
    ax.grid(True, which="both", alpha=0.3)
    ax.set_title("Scenario 1 residual failure probability")
    save_figure(fig, figures / "fig_s1_failure_probability_log")


def figure_mean_words(success_rows: list[dict[str, object]], figures: Path) -> None:
    x = [int(r["samples_per_sbox"]) for r in success_rows]
    correct = [float(r["mean_correct_words_of_8"]) for r in success_rows]
    unique = [float(r["mean_unique_missing_words_of_8"]) for r in success_rows]
    fig, ax = plt.subplots(figsize=(8.4, 5.2))
    ax.plot(x, correct, marker="o", label="Correctly recovered words")
    ax.plot(x, unique, marker="s", linestyle="--", label="Unique missing-value words")
    ax.set_xlabel("Ineffective ciphertexts per S-box")
    ax.set_ylabel("Mean number of S-box words (out of 8)")
    ax.set_ylim(-0.2, 8.2)
    ax.grid(True, alpha=0.3)
    ax.legend()
    ax.set_title("Progress toward complete SK28 recovery")
    save_figure(fig, figures / "fig_s1_mean_recovered_words")


def figure_queries(query_rows: list[dict[str, object]], figures: Path) -> None:
    x = [int(r["samples_per_sbox"]) for r in query_rows]
    y = [float(r["mean_total_queries"]) for r in query_rows]
    low = [float(r["ci95_total_queries_low"]) for r in query_rows]
    high = [float(r["ci95_total_queries_high"]) for r in query_rows]
    yerr = [[v - l for v, l in zip(y, low)], [h - v for v, h in zip(y, high)]]
    fig, ax = plt.subplots(figsize=(8.4, 5.2))
    ax.errorbar(x, y, yerr=yerr, marker="o", capsize=3)
    ax.set_xlabel("Ineffective ciphertexts per S-box")
    ax.set_ylabel("Mean total oracle queries over 8 campaigns")
    ax.grid(True, alpha=0.3)
    ax.set_title("Scenario 1 oracle-query complexity")
    save_figure(fig, figures / "fig_s1_queries_vs_samples")


def figure_query_boxplot(trials: list[dict[str, str]], figures: Path) -> None:
    grouped: dict[int, list[float]] = defaultdict(list)
    for row in trials:
        grouped[int(row["samples_per_sbox"])].append(float(row["total_queries"]))
    selected = [48, 64, 80, 96, 112, 128, 160, 256]
    data = [grouped[value] for value in selected]
    fig, ax = plt.subplots(figsize=(9.2, 5.2))
    ax.boxplot(data, tick_labels=[str(v) for v in selected], showmeans=True)
    ax.set_xlabel("Ineffective ciphertexts per S-box")
    ax.set_ylabel("Total oracle queries over 8 campaigns")
    ax.grid(True, axis="y", alpha=0.3)
    ax.set_title("Distribution of Scenario 1 oracle-query cost")
    save_figure(fig, figures / "fig_s1_query_distribution")


def figure_rate_vs_theory(query_rows: list[dict[str, object]], theoretical: float, figures: Path) -> None:
    x = [int(r["samples_per_sbox"]) for r in query_rows]
    y = [float(r["mean_empirical_rate"]) for r in query_rows]
    fig, ax = plt.subplots(figsize=(8.4, 5.2))
    ax.plot(x, y, marker="o", label="Mean empirical rate")
    ax.axhline(theoretical, linestyle="--", label="Theoretical rate")
    ax.set_xlabel("Ineffective ciphertexts per S-box")
    ax.set_ylabel("Ineffective-event rate")
    ax.grid(True, alpha=0.3)
    ax.legend()
    ax.set_title("Empirical and theoretical ineffective-event rates")
    save_figure(fig, figures / "fig_s1_rate_convergence")


def figure_per_sbox_heatmap(per_sbox_rows: list[dict[str, object]], figures: Path) -> None:
    samples = sorted({int(r["samples_per_sbox"]) for r in per_sbox_rows})
    matrix = [[0.0 for _ in samples] for _ in range(8)]
    for row in per_sbox_rows:
        sbox = int(row["sbox"])
        column = samples.index(int(row["samples_per_sbox"]))
        matrix[sbox][column] = float(row["word_success_rate"])
    fig, ax = plt.subplots(figsize=(10.2, 4.8))
    image = ax.imshow(matrix, aspect="auto", origin="lower", vmin=0.0, vmax=1.0)
    ax.set_xticks(range(len(samples)), [str(v) for v in samples], rotation=45, ha="right")
    ax.set_yticks(range(8), [f"S-box {i}" for i in range(8)])
    ax.set_xlabel("Ineffective ciphertexts per S-box")
    ax.set_ylabel("Logical S-box")
    ax.set_title("Per-S-box word-recovery success rate")
    fig.colorbar(image, ax=ax, label="Success rate")
    save_figure(fig, figures / "fig_s1_per_sbox_success_heatmap")


def figure_fixed_rate(fixed: list[dict[str, str]], figures: Path) -> None:
    x = [int(r["target_sbox"]) for r in fixed]
    empirical = [float(r["empirical_rate"]) for r in fixed]
    theoretical = float(fixed[0]["theoretical_rate"])
    fig, ax = plt.subplots(figsize=(8.4, 5.2))
    ax.bar(x, empirical, label="Empirical rate")
    ax.axhline(theoretical, linestyle="--", label="Theoretical rate")
    ax.set_xticks(x)
    ax.set_xlabel("Logical S-box")
    ax.set_ylabel("Ineffective-event rate")
    ax.grid(True, axis="y", alpha=0.3)
    ax.legend()
    ax.set_title("Fixed 4096-sample campaigns: empirical rate by S-box")
    save_figure(fig, figures / "fig_s1_fixed_rate_by_sbox")


def figure_fixed_queries(fixed: list[dict[str, str]], figures: Path) -> None:
    x = [int(r["target_sbox"]) for r in fixed]
    total = [int(r["total_queries"]) for r in fixed]
    effective = [int(r["effective_count"]) for r in fixed]
    fig, ax = plt.subplots(figsize=(8.4, 5.2))
    ax.bar(x, total, label="Total queries")
    ax.plot(x, effective, marker="o", linestyle="--", label="Blocked effective events")
    ax.set_xticks(x)
    ax.set_xlabel("Logical S-box")
    ax.set_ylabel("Count")
    ax.grid(True, axis="y", alpha=0.3)
    ax.legend()
    ax.set_title("Query and blocked-event counts for the final eight campaigns")
    save_figure(fig, figures / "fig_s1_fixed_queries_by_sbox")


def figure_fixed_error(fixed: list[dict[str, str]], figures: Path) -> None:
    x = [int(r["target_sbox"]) for r in fixed]
    errors = [float(r["absolute_error"]) for r in fixed]
    fig, ax = plt.subplots(figsize=(8.4, 5.2))
    ax.bar(x, errors)
    ax.set_xticks(x)
    ax.set_xlabel("Logical S-box")
    ax.set_ylabel("Absolute rate error")
    ax.grid(True, axis="y", alpha=0.3)
    ax.set_title("Absolute deviation from the theoretical ineffective rate")
    save_figure(fig, figures / "fig_s1_fixed_rate_error_by_sbox")


def figure_histogram_heatmap(histograms: list[dict[str, str]], figures: Path) -> None:
    matrix = [[0.0 for _ in range(16)] for _ in range(8)]
    missing: list[tuple[int, int]] = []
    for row in histograms:
        sbox = int(row["target_sbox"])
        value = int(row["value"])
        matrix[sbox][value] = float(row["count"])
        if int(row["is_missing"]):
            missing.append((value, sbox))
    fig, ax = plt.subplots(figsize=(10.0, 5.0))
    image = ax.imshow(matrix, aspect="auto", origin="lower")
    if missing:
        ax.scatter([x for x, _ in missing], [y for _, y in missing], marker="x", s=90, label="Unique missing value")
    ax.set_xticks(range(16), [f"0x{i:X}" for i in range(16)])
    ax.set_yticks(range(8), [f"S-box {i}" for i in range(8)])
    ax.set_xlabel("Public last-round word value")
    ax.set_ylabel("Logical S-box")
    ax.set_title("Final 4096-sample histograms and unique missing values")
    fig.colorbar(image, ax=ax, label="Observed count")
    if missing:
        ax.legend(loc="upper right")
    save_figure(fig, figures / "fig_s1_histogram_heatmap")


def figure_recovery_words(recovery: list[dict[str, str]], figures: Path) -> None:
    rows = [r for r in recovery if r["target_sbox"] != "complete_sk28"]
    x = [int(r["target_sbox"]) for r in rows]
    recovered = [int(r["recovered_word"], 16) for r in rows]
    actual = [int(r["actual_word"], 16) for r in rows]
    fig, ax = plt.subplots(figsize=(8.4, 5.2))
    ax.plot(x, recovered, marker="o", label="Recovered word")
    ax.plot(x, actual, marker="x", linestyle="--", label="Actual word")
    ax.set_xticks(x)
    ax.set_yticks(range(16), [f"0x{i:X}" for i in range(16)])
    ax.set_xlabel("Logical S-box")
    ax.set_ylabel("Four-bit SK28 word")
    ax.grid(True, alpha=0.3)
    ax.legend()
    ax.set_title("Recovered and actual bitsliced SK28 words")
    save_figure(fig, figures / "fig_s1_recovered_words")


def figure_missing_values(recovery: list[dict[str, str]], figures: Path) -> None:
    rows = [r for r in recovery if r["target_sbox"] != "complete_sk28"]
    x = [int(r["target_sbox"]) for r in rows]
    missing = [int(r["missing_value"], 16) for r in rows]
    fig, ax = plt.subplots(figsize=(8.4, 5.2))
    ax.scatter(x, missing, s=80)
    ax.set_xticks(x)
    ax.set_yticks(range(16), [f"0x{i:X}" for i in range(16)])
    ax.set_xlabel("Logical S-box")
    ax.set_ylabel("Unique missing value")
    ax.grid(True, alpha=0.3)
    ax.set_title("Unique missing value identified in each campaign")
    save_figure(fig, figures / "fig_s1_missing_values")


def build_tables(root: Path, success_rows: list[dict[str, object]], query_rows: list[dict[str, object]], per_sbox_rows: list[dict[str, object]], fixed: list[dict[str, str]], histograms: list[dict[str, str]], recovery: list[dict[str, str]]) -> list[dict[str, str]]:
    tables = root / "paper_artifacts" / "tables"
    tables.mkdir(parents=True, exist_ok=True)

    write_csv(tables / "table_s1_success_curve.csv", list(success_rows[0].keys()), success_rows)
    write_csv(tables / "table_s1_query_complexity.csv", list(query_rows[0].keys()), query_rows)
    write_csv(tables / "table_s1_per_sbox_success.csv", list(per_sbox_rows[0].keys()), per_sbox_rows)
    write_csv(tables / "table_s1_fixed_campaigns.csv", list(fixed[0].keys()), fixed)
    write_csv(tables / "table_s1_histogram_counts.csv", list(histograms[0].keys()), histograms)
    write_csv(tables / "table_s1_final_recovery.csv", list(recovery[0].keys()), recovery)

    thresholds = threshold_table(success_rows)
    write_csv(tables / "table_s1_success_thresholds.csv", list(thresholds[0].keys()), thresholds)

    compact_success = [
        [
            r["samples_per_sbox"],
            f'{100 * float(r["full_key_success_rate"]):.1f}%',
            f'[{100 * float(r["full_key_ci95_low"]):.1f}%, {100 * float(r["full_key_ci95_high"]):.1f}%]',
            f'{100 * float(r["word_success_rate"]):.1f}%',
            r["mean_correct_words_of_8"],
        ]
        for r in success_rows
    ]
    headers = ["Samples/S-box", "Full SK28 success", "95% CI", "Word success", "Mean correct words"]
    markdown_table(tables / "table_s1_success_curve.md", headers, compact_success)
    latex_table(
        tables / "table_s1_success_curve.tex",
        headers,
        compact_success,
        "Scenario 1 recovery success versus ineffective ciphertexts per logical S-box.",
        "tab:s1-success-curve",
    )

    compact_recovery = [
        [r["target_sbox"], r["missing_value"], r["recovered_word"], r["actual_word"], r["word_verified"]]
        for r in recovery if r["target_sbox"] != "complete_sk28"
    ]
    recovery_headers = ["S-box", "Missing value", "Recovered word", "Actual word", "Result"]
    markdown_table(tables / "table_s1_final_recovery.md", recovery_headers, compact_recovery)
    latex_table(
        tables / "table_s1_final_recovery.tex",
        recovery_headers,
        compact_recovery,
        "Complete SK28 recovery from eight known persistent-fault campaigns.",
        "tab:s1-final-recovery",
    )

    compact_fixed = [
        [r["target_sbox"], r["total_queries"], r["effective_count"], f'{float(r["empirical_rate"]):.6f}', f'{float(r["absolute_error"]):.6f}']
        for r in fixed
    ]
    fixed_headers = ["S-box", "Total queries", "Blocked effective", "Empirical rate", "Absolute error"]
    markdown_table(tables / "table_s1_fixed_campaigns.md", fixed_headers, compact_fixed)
    latex_table(
        tables / "table_s1_fixed_campaigns.tex",
        fixed_headers,
        compact_fixed,
        "Data-collection statistics for the eight final 4096-sample campaigns.",
        "tab:s1-fixed-campaigns",
    )

    manifest = []
    for path in sorted(tables.iterdir()):
        if path.is_file():
            manifest.append({"artifact": path.name, "type": path.suffix.lstrip("."), "description": "Scenario 1 paper table"})
    write_csv(tables / "TABLE_MANIFEST.csv", ["artifact", "type", "description"], manifest)
    return manifest


def build_figure_manifest(figures: Path) -> list[dict[str, str]]:
    descriptions = {
        "fig_s1_success_vs_samples": "Complete-key and word-level success versus sample count, including 95% Wilson interval.",
        "fig_s1_failure_probability_log": "Residual full-key failure probability on a logarithmic scale.",
        "fig_s1_mean_recovered_words": "Mean number of uniquely identified and correctly recovered SK28 words.",
        "fig_s1_queries_vs_samples": "Mean oracle-query complexity with a 95% confidence interval.",
        "fig_s1_query_distribution": "Boxplots of total query counts at representative sample sizes.",
        "fig_s1_rate_convergence": "Convergence of the empirical ineffective rate to the theoretical model.",
        "fig_s1_per_sbox_success_heatmap": "Per-S-box word-recovery success across the sample grid.",
        "fig_s1_fixed_rate_by_sbox": "Empirical ineffective rate for each final 4096-sample campaign.",
        "fig_s1_fixed_queries_by_sbox": "Total queries and blocked effective events for each campaign.",
        "fig_s1_fixed_rate_error_by_sbox": "Absolute error from the theoretical ineffective rate by S-box.",
        "fig_s1_histogram_heatmap": "Eight 16-bin histograms with unique missing values marked.",
        "fig_s1_recovered_words": "Recovered versus actual four-bit SK28 words.",
        "fig_s1_missing_values": "Unique missing value identified for each S-box campaign.",
    }
    rows: list[dict[str, str]] = []
    for stem, description in descriptions.items():
        rows.append({
            "figure_id": stem,
            "png": f"{stem}.png",
            "pdf": f"{stem}.pdf",
            "svg": f"{stem}.svg",
            "description": description,
        })
    write_csv(figures / "FIGURE_MANIFEST.csv", ["figure_id", "png", "pdf", "svg", "description"], rows)
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    root = args.root.resolve()
    results = root / "results"
    figures = root / "paper_artifacts" / "figures"
    figures.mkdir(parents=True, exist_ok=True)

    trials = read_csv(results / "scenario1_repeated_trials.csv")
    words = read_csv(results / "scenario1_repeated_words.csv")
    fixed = read_csv(results / "scenario1_all_sboxes_detection_summary.csv")
    histograms = read_csv(results / "scenario1_all_sboxes_histograms.csv")
    recovery = read_csv(results / "scenario1_full_sk28_summary.csv")

    success_rows, query_rows, per_sbox_rows = aggregate_repeated(trials, words)
    write_csv(results / "scenario1_success_curve.csv", list(success_rows[0].keys()), success_rows)
    write_csv(results / "scenario1_query_complexity.csv", list(query_rows[0].keys()), query_rows)
    write_csv(results / "scenario1_per_sbox_success.csv", list(per_sbox_rows[0].keys()), per_sbox_rows)
    thresholds = threshold_table(success_rows)
    write_csv(results / "scenario1_success_thresholds.csv", list(thresholds[0].keys()), thresholds)

    theoretical = float(fixed[0]["theoretical_rate"])
    figure_success_curve(success_rows, figures)
    figure_failure_log(success_rows, figures)
    figure_mean_words(success_rows, figures)
    figure_queries(query_rows, figures)
    figure_query_boxplot(trials, figures)
    figure_rate_vs_theory(query_rows, theoretical, figures)
    figure_per_sbox_heatmap(per_sbox_rows, figures)
    figure_fixed_rate(fixed, figures)
    figure_fixed_queries(fixed, figures)
    figure_fixed_error(fixed, figures)
    figure_histogram_heatmap(histograms, figures)
    figure_recovery_words(recovery, figures)
    figure_missing_values(recovery, figures)

    table_manifest = build_tables(root, success_rows, query_rows, per_sbox_rows, fixed, histograms, recovery)
    figure_manifest = build_figure_manifest(figures)

    first_95 = next((r for r in success_rows if float(r["full_key_success_rate"]) >= 0.95), None)
    first_99 = next((r for r in success_rows if float(r["full_key_success_rate"]) >= 0.99), None)
    final_row = success_rows[-1]
    fixed_queries = [int(r["total_queries"]) for r in fixed]
    summary = {
        "repeated_trials": int(success_rows[0]["trials"]),
        "sample_grid": [int(r["samples_per_sbox"]) for r in success_rows],
        "minimum_samples_for_at_least_95_percent_success": int(first_95["samples_per_sbox"]) if first_95 else None,
        "observed_success_at_95_threshold": float(first_95["full_key_success_rate"]) if first_95 else None,
        "minimum_samples_for_at_least_99_percent_success": int(first_99["samples_per_sbox"]) if first_99 else None,
        "observed_success_at_99_threshold": float(first_99["full_key_success_rate"]) if first_99 else None,
        "maximum_grid_success_rate": float(final_row["full_key_success_rate"]),
        "theoretical_ineffective_rate": theoretical,
        "fixed_campaign_total_queries": sum(fixed_queries),
        "fixed_campaign_mean_queries": statistics.mean(fixed_queries),
        "fixed_campaign_min_queries": min(fixed_queries),
        "fixed_campaign_max_queries": max(fixed_queries),
        "recovered_sk28": recovery[-1]["recovered_word"],
        "actual_sk28": recovery[-1]["actual_word"],
        "figures": len(figure_manifest),
        "figure_files": len(figure_manifest) * 3,
        "table_files": len(table_manifest),
    }
    with (results / "scenario1_final_analysis_summary.json").open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)

    print(json.dumps(summary, indent=2))
    print("PASS: Scenario 1 tables and figures generated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
