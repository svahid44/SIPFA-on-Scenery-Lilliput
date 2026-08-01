#!/usr/bin/env python3
"""Generate Scenario-3 paper tables and figures from reproducible CSV files."""

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
        writer.writerows(rows)


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
        "\\": r"\textbackslash{}", "&": r"\&", "%": r"\%", "$": r"\$",
        "#": r"\#", "_": r"\_", "{": r"\{", "}": r"\}",
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


def aggregate_trials(trials: list[dict[str, str]]) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    groups: dict[int, list[dict[str, str]]] = defaultdict(list)
    for row in trials:
        groups[int(row["samples_per_sbox"])].append(row)

    success_rows: list[dict[str, object]] = []
    gap_rows: list[dict[str, object]] = []
    for samples in sorted(groups):
        group = groups[samples]
        n = len(group)
        successes = sum(int(row["full_key_success"]) for row in group)
        low, high = wilson(successes, n)
        correct_words = [float(row["correct_words"]) for row in group]
        unique_words = [float(row["unique_minimum_words"]) for row in group]
        full_word_successes = sum(int(row["correct_words"]) for row in group)
        word_total = n * 8
        wlow, whigh = wilson(full_word_successes, word_total)
        mean_correct, std_correct = mean_std(correct_words)
        mean_unique, std_unique = mean_std(unique_words)
        mean_gap = [float(row["mean_minimum_gap"]) for row in group]
        min_gap = [float(row["min_minimum_gap"]) for row in group]
        max_gap = [float(row["max_minimum_gap"]) for row in group]
        empirical = [float(row["aggregate_empirical_rate"]) for row in group]
        rate_errors = [float(row["absolute_rate_error"]) for row in group]
        mean_rate, std_rate = mean_std(empirical)
        mean_error, std_error = mean_std(rate_errors)
        mg, sg = mean_std(mean_gap)
        ming, smin = mean_std(min_gap)
        maxg, smax = mean_std(max_gap)

        success_rows.append({
            "samples_per_sbox": samples,
            "total_public_outputs": samples * 8,
            "trials": n,
            "full_key_successes": successes,
            "full_key_success_rate": f"{successes / n:.9f}",
            "full_key_ci95_low": f"{low:.9f}",
            "full_key_ci95_high": f"{high:.9f}",
            "word_successes": full_word_successes,
            "word_trials": word_total,
            "word_success_rate": f"{full_word_successes / word_total:.9f}",
            "word_ci95_low": f"{wlow:.9f}",
            "word_ci95_high": f"{whigh:.9f}",
            "mean_correct_words_of_8": f"{mean_correct:.6f}",
            "std_correct_words": f"{std_correct:.6f}",
            "mean_unique_minimum_words_of_8": f"{mean_unique:.6f}",
            "std_unique_minimum_words": f"{std_unique:.6f}",
            "mean_empirical_ineffective_rate": f"{mean_rate:.12f}",
            "std_empirical_ineffective_rate": f"{std_rate:.12f}",
            "mean_absolute_rate_error": f"{mean_error:.12f}",
            "std_absolute_rate_error": f"{std_error:.12f}",
        })
        gap_rows.append({
            "samples_per_sbox": samples,
            "trials": n,
            "mean_of_campaign_mean_gap": f"{mg:.6f}",
            "std_of_campaign_mean_gap": f"{sg:.6f}",
            "mean_of_trial_min_gap": f"{ming:.6f}",
            "std_of_trial_min_gap": f"{smin:.6f}",
            "mean_of_trial_max_gap": f"{maxg:.6f}",
            "std_of_trial_max_gap": f"{smax:.6f}",
        })
    return success_rows, gap_rows


def aggregate_words(words: list[dict[str, str]]) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    per_sbox: dict[tuple[int, int], list[dict[str, str]]] = defaultdict(list)
    for row in words:
        per_sbox[(int(row["samples_per_sbox"]), int(row["sbox"]))].append(row)
    sbox_rows: list[dict[str, object]] = []
    for (samples, sbox), group in sorted(per_sbox.items()):
        n = len(group)
        successes = sum(int(row["word_success"]) for row in group)
        unique = sum(int(row["unique_minimum"]) for row in group)
        gaps = [float(row["minimum_gap"]) for row in group]
        mean_gap, std_gap = mean_std(gaps)
        sbox_rows.append({
            "samples_per_sbox": samples,
            "sbox": sbox,
            "trials": n,
            "word_successes": successes,
            "word_success_rate": f"{successes / n:.9f}",
            "unique_minimum_rate": f"{unique / n:.9f}",
            "mean_minimum_gap": f"{mean_gap:.6f}",
            "std_minimum_gap": f"{std_gap:.6f}",
        })

    max_samples = max(int(row["samples_per_sbox"]) for row in words)
    per_delta: dict[int, list[dict[str, str]]] = defaultdict(list)
    for row in words:
        if int(row["samples_per_sbox"]) == max_samples and int(row["sbox"]) == 0:
            per_delta[int(row["known_delta"], 16)].append(row)
    # Full-key outcome is trial-level; get it from the eight word records at max N.
    delta_trials: dict[int, dict[int, list[dict[str, str]]]] = defaultdict(lambda: defaultdict(list))
    for row in words:
        if int(row["samples_per_sbox"]) == max_samples:
            delta_trials[int(row["known_delta"], 16)][int(row["trial"])].append(row)
    delta_rows: list[dict[str, object]] = []
    for delta in range(16):
        trial_groups = delta_trials.get(delta, {})
        n = len(trial_groups)
        if n == 0:
            delta_rows.append({"delta": f"0x{delta:X}", "trials": 0, "full_key_success_rate": "", "word_success_rate": "", "mean_minimum_gap": ""})
            continue
        full = sum(all(int(r["word_success"]) for r in rows) for rows in trial_groups.values())
        all_rows = [r for rows in trial_groups.values() for r in rows]
        word_success = sum(int(r["word_success"]) for r in all_rows)
        gaps = [float(r["minimum_gap"]) for r in all_rows]
        delta_rows.append({
            "delta": f"0x{delta:X}",
            "trials": n,
            "full_key_success_rate": f"{full / n:.9f}",
            "word_success_rate": f"{word_success / len(all_rows):.9f}",
            "mean_minimum_gap": f"{statistics.mean(gaps):.6f}",
        })
    return sbox_rows, delta_rows


def thresholds(success_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for metric, field in (("complete_SK28", "full_key_success_rate"), ("word_recovery", "word_success_rate")):
        for target in (0.50, 0.80, 0.90, 0.95, 0.99, 1.00):
            selected = next((row for row in success_rows if float(row[field]) >= target), None)
            rows.append({
                "metric": metric,
                "target_rate": f"{target:.2f}",
                "minimum_samples_per_sbox": selected["samples_per_sbox"] if selected else "not reached",
                "minimum_total_public_outputs": selected["total_public_outputs"] if selected else "not reached",
                "observed_rate": selected[field] if selected else "",
                "trials": selected["trials"] if selected else "",
            })
    return rows


def fig_success(rows: list[dict[str, object]], out: Path) -> None:
    x = [int(r["samples_per_sbox"]) for r in rows]
    full = [float(r["full_key_success_rate"]) for r in rows]
    word = [float(r["word_success_rate"]) for r in rows]
    low = [float(r["full_key_ci95_low"]) for r in rows]
    high = [float(r["full_key_ci95_high"]) for r in rows]
    fig, ax = plt.subplots(figsize=(8.8, 5.4))
    ax.plot(x, full, marker="o", label="Complete SK28")
    ax.plot(x, word, marker="s", label="Four-bit words")
    ax.fill_between(x, low, high, alpha=0.18, label="95% CI (complete SK28)")
    ax.set_xscale("log", base=2)
    ax.set_ylim(-0.03, 1.03)
    ax.set_xlabel("Published ciphertexts per logical S-box")
    ax.set_ylabel("Success probability")
    ax.grid(True, alpha=0.3)
    ax.legend()
    ax.set_title("Scenario 3 recovery success versus data complexity")
    save_figure(fig, out / "fig_s3_success_vs_samples")


def fig_failure(rows: list[dict[str, object]], out: Path) -> None:
    x = [int(r["samples_per_sbox"]) for r in rows]
    y = [max(0.005, 1.0 - float(r["full_key_success_rate"])) for r in rows]
    fig, ax = plt.subplots(figsize=(8.8, 5.4))
    ax.plot(x, y, marker="o")
    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    ax.set_xlabel("Published ciphertexts per logical S-box")
    ax.set_ylabel("Observed complete-key failure probability")
    ax.grid(True, alpha=0.3)
    ax.set_title("Residual failure probability of Algorithm 3")
    save_figure(fig, out / "fig_s3_failure_probability_log")


def fig_words(rows: list[dict[str, object]], out: Path) -> None:
    x = [int(r["samples_per_sbox"]) for r in rows]
    fig, ax = plt.subplots(figsize=(8.8, 5.4))
    ax.plot(x, [float(r["mean_correct_words_of_8"]) for r in rows], marker="o", label="Correct words")
    ax.plot(x, [float(r["mean_unique_minimum_words_of_8"]) for r in rows], marker="s", label="Unique minima")
    ax.set_xscale("log", base=2)
    ax.set_ylim(0, 8.2)
    ax.set_xlabel("Published ciphertexts per logical S-box")
    ax.set_ylabel("Mean count out of eight")
    ax.grid(True, alpha=0.3)
    ax.legend()
    ax.set_title("Mean recovered words and unique minimum-frequency bins")
    save_figure(fig, out / "fig_s3_mean_recovered_words")


def fig_gap(gaps: list[dict[str, object]], out: Path) -> None:
    x = [int(r["samples_per_sbox"]) for r in gaps]
    fig, ax = plt.subplots(figsize=(8.8, 5.4))
    ax.plot(x, [float(r["mean_of_campaign_mean_gap"]) for r in gaps], marker="o", label="Mean gap")
    ax.plot(x, [float(r["mean_of_trial_min_gap"]) for r in gaps], marker="s", label="Mean weakest-S-box gap")
    ax.plot(x, [float(r["mean_of_trial_max_gap"]) for r in gaps], marker="^", label="Mean strongest-S-box gap")
    ax.set_xscale("log", base=2)
    ax.set_xlabel("Published ciphertexts per logical S-box")
    ax.set_ylabel("Count gap: second minimum - minimum")
    ax.grid(True, alpha=0.3)
    ax.legend()
    ax.set_title("Growth of the minimum-frequency separation")
    save_figure(fig, out / "fig_s3_minimum_gap_vs_samples")


def fig_gap_box(words: list[dict[str, str]], out: Path) -> None:
    selected = [2048, 4096, 8192, 16384, 32768]
    data = [[int(r["minimum_gap"]) for r in words if int(r["samples_per_sbox"]) == n] for n in selected]
    fig, ax = plt.subplots(figsize=(8.8, 5.4))
    ax.boxplot(data, tick_labels=[str(n) for n in selected], showfliers=False)
    ax.set_xlabel("Published ciphertexts per logical S-box")
    ax.set_ylabel("Minimum-frequency gap")
    ax.grid(True, axis="y", alpha=0.3)
    ax.set_title("Distribution of the minimum-frequency gap")
    save_figure(fig, out / "fig_s3_minimum_gap_distribution")


def fig_rate(rows: list[dict[str, object]], theory: float, out: Path) -> None:
    x = [int(r["samples_per_sbox"]) for r in rows]
    y = [float(r["mean_empirical_ineffective_rate"]) for r in rows]
    fig, ax = plt.subplots(figsize=(8.8, 5.4))
    ax.plot(x, y, marker="o", label="Empirical mean")
    ax.axhline(theory, linestyle="--", label="Theoretical rate")
    ax.set_xscale("log", base=2)
    ax.set_xlabel("Published ciphertexts per logical S-box")
    ax.set_ylabel("Internal ineffective-event rate")
    ax.grid(True, alpha=0.3)
    ax.legend()
    ax.set_title("Convergence to the theoretical ineffective rate")
    save_figure(fig, out / "fig_s3_rate_convergence")


def fig_sbox_heatmap(rows: list[dict[str, object]], out: Path) -> None:
    samples = sorted({int(r["samples_per_sbox"]) for r in rows})
    matrix = [[0.0 for _ in samples] for _ in range(8)]
    for r in rows:
        matrix[int(r["sbox"])][samples.index(int(r["samples_per_sbox"]))] = float(r["word_success_rate"])
    fig, ax = plt.subplots(figsize=(11.2, 5.2))
    image = ax.imshow(matrix, aspect="auto", origin="lower", vmin=0.0, vmax=1.0)
    ax.set_xticks(range(len(samples)), [str(n) for n in samples], rotation=45, ha="right")
    ax.set_yticks(range(8), [f"S-box {i}" for i in range(8)])
    ax.set_xlabel("Published ciphertexts per logical S-box")
    ax.set_ylabel("Logical S-box")
    ax.set_title("Per-S-box word-recovery success")
    fig.colorbar(image, ax=ax, label="Success probability")
    save_figure(fig, out / "fig_s3_per_sbox_success_heatmap")


def fig_delta(rows: list[dict[str, object]], out: Path) -> None:
    valid = [r for r in rows if int(r["trials"]) > 0]
    x = [r["delta"] for r in valid]
    fig, ax = plt.subplots(figsize=(9.0, 5.2))
    ax.bar(x, [100 * float(r["full_key_success_rate"]) for r in valid])
    ax.set_ylim(0, 105)
    ax.set_xlabel("Known fault input delta")
    ax.set_ylabel("Complete SK28 success (%)")
    ax.grid(True, axis="y", alpha=0.3)
    ax.set_title("Final-grid success by fault input")
    save_figure(fig, out / "fig_s3_success_by_delta")


def fig_fixed_rate(fixed: list[dict[str, str]], theory: float, out: Path) -> None:
    rows = [r for r in fixed if r["target_sbox"] != "aggregate"]
    x = [int(r["target_sbox"]) for r in rows]
    fig, ax = plt.subplots(figsize=(8.4, 5.2))
    ax.bar(x, [float(r["empirical_ineffective_rate"]) for r in rows])
    ax.axhline(theory, linestyle="--", label="Theoretical rate")
    ax.set_xticks(x)
    ax.set_xlabel("Logical S-box")
    ax.set_ylabel("Internal ineffective-event rate")
    ax.grid(True, axis="y", alpha=0.3)
    ax.legend()
    ax.set_title("Ineffective rate in the final infection campaigns")
    save_figure(fig, out / "fig_s3_fixed_rate_by_sbox")


def fig_fixed_composition(fixed: list[dict[str, str]], out: Path) -> None:
    rows = [r for r in fixed if r["target_sbox"] != "aggregate"]
    x = [int(r["target_sbox"]) for r in rows]
    ineffect = [int(r["internal_ineffective_count"]) for r in rows]
    infected = [int(r["internal_infected_count"]) for r in rows]
    fig, ax = plt.subplots(figsize=(8.6, 5.2))
    ax.bar(x, infected, label="Random infected outputs")
    ax.bar(x, ineffect, bottom=infected, label="Ineffective correct outputs")
    ax.set_xticks(x)
    ax.set_xlabel("Logical S-box")
    ax.set_ylabel("Published outputs")
    ax.grid(True, axis="y", alpha=0.3)
    ax.legend()
    ax.set_title("Composition hidden behind the public infection oracle")
    save_figure(fig, out / "fig_s3_fixed_output_composition")


def fig_fixed_gap(recovery: list[dict[str, str]], out: Path) -> None:
    rows = [r for r in recovery if r["target_sbox"] != "complete_sk28"]
    x = [int(r["target_sbox"]) for r in rows]
    fig, ax = plt.subplots(figsize=(8.4, 5.2))
    ax.bar(x, [int(r["minimum_gap"]) for r in rows])
    ax.set_xticks(x)
    ax.set_xlabel("Logical S-box")
    ax.set_ylabel("Minimum-frequency gap")
    ax.grid(True, axis="y", alpha=0.3)
    ax.set_title("Minimum-frequency separation in the final campaigns")
    save_figure(fig, out / "fig_s3_fixed_minimum_gap")


def fig_hist_heatmap(hist: list[dict[str, str]], out: Path) -> None:
    matrix = [[0.0 for _ in range(16)] for _ in range(8)]
    minima: list[tuple[int, int]] = []
    for row in hist:
        sbox = int(row["target_sbox"])
        value = int(row["value"], 16)
        matrix[sbox][value] = float(row["count"])
        if int(row["is_minimum"]):
            minima.append((value, sbox))
    fig, ax = plt.subplots(figsize=(10.2, 5.2))
    image = ax.imshow(matrix, aspect="auto", origin="lower")
    ax.scatter([x for x, _ in minima], [y for _, y in minima], marker="x", s=90, label="Unique minimum")
    ax.set_xticks(range(16), [f"0x{i:X}" for i in range(16)])
    ax.set_yticks(range(8), [f"S-box {i}" for i in range(8)])
    ax.set_xlabel("Public last-round word value")
    ax.set_ylabel("Logical S-box")
    ax.set_title("Final infection histograms and minimum-frequency values")
    fig.colorbar(image, ax=ax, label="Observed count")
    ax.legend(loc="upper right")
    save_figure(fig, out / "fig_s3_histogram_heatmap")


def fig_recovery(recovery: list[dict[str, str]], out: Path) -> None:
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
    ax.set_title("Recovered and actual SK28 words")
    save_figure(fig, out / "fig_s3_recovered_words")


def build_contact_sheet(figures: Path, destination: Path) -> None:
    paths = sorted(p for p in figures.glob("fig_s3_*.png"))
    cols = 3
    rows = math.ceil(len(paths) / cols)
    fig, axes = plt.subplots(rows, cols, figsize=(15, 4.6 * rows))
    axes_list = list(axes.flat) if hasattr(axes, "flat") else [axes]
    for ax, path in zip(axes_list, paths):
        ax.imshow(plt.imread(path))
        ax.set_title(path.stem.replace("fig_s3_", "").replace("_", " ").title(), fontsize=10)
        ax.axis("off")
    for ax in axes_list[len(paths):]:
        ax.axis("off")
    fig.tight_layout()
    fig.savefig(destination, dpi=150, bbox_inches="tight")
    plt.close(fig)


def build_tables(root: Path, success: list[dict[str, object]], gaps: list[dict[str, object]], sboxes: list[dict[str, object]], deltas: list[dict[str, object]], fixed: list[dict[str, str]], hist: list[dict[str, str]], recovery: list[dict[str, str]], threshold_rows: list[dict[str, object]]) -> list[dict[str, str]]:
    tables = root / "paper_artifacts" / "scenario3" / "tables"
    tables.mkdir(parents=True, exist_ok=True)
    datasets = {
        "table_s3_success_curve": success,
        "table_s3_gap_statistics": gaps,
        "table_s3_per_sbox_success": sboxes,
        "table_s3_per_delta_success": deltas,
        "table_s3_fixed_campaigns": fixed,
        "table_s3_histogram_counts": hist,
        "table_s3_final_recovery": recovery,
        "table_s3_thresholds": threshold_rows,
    }
    for stem, rows in datasets.items():
        write_csv(tables / f"{stem}.csv", list(rows[0].keys()), rows)

    compact_success = [[r["samples_per_sbox"], r["total_public_outputs"], f'{100*float(r["full_key_success_rate"]):.1f}%', f'[{100*float(r["full_key_ci95_low"]):.1f}%, {100*float(r["full_key_ci95_high"]):.1f}%]', f'{100*float(r["word_success_rate"]):.1f}%', r["mean_correct_words_of_8"]] for r in success]
    headers = ["Samples/S-box", "Total public", "Full SK28", "95% CI", "Word success", "Mean correct words"]
    markdown_table(tables / "table_s3_success_curve.md", headers, compact_success)
    latex_table(tables / "table_s3_success_curve.tex", headers, compact_success, "Scenario 3 recovery success versus published ciphertexts per logical S-box.", "tab:s3-success-curve")

    compact_recovery = [[r["target_sbox"], r["minimum_value"], r["minimum_gap"], r["recovered_word"], r["actual_word"], r["word_verified"]] for r in recovery if r["target_sbox"] != "complete_sk28"]
    rh = ["S-box", "Minimum", "Gap", "Recovered", "Actual", "Result"]
    markdown_table(tables / "table_s3_final_recovery.md", rh, compact_recovery)
    latex_table(tables / "table_s3_final_recovery.tex", rh, compact_recovery, "Complete SK28 recovery from eight known-fault infection campaigns.", "tab:s3-final-recovery")

    compact_fixed = [[r["target_sbox"], r["published_count"], r["internal_ineffective_count"], r["internal_infected_count"], f'{float(r["empirical_ineffective_rate"]):.6f}'] for r in fixed if r["target_sbox"] != "aggregate"]
    fh = ["S-box", "Published", "Ineffective", "Infected", "Empirical rate"]
    markdown_table(tables / "table_s3_fixed_campaigns.md", fh, compact_fixed)
    latex_table(tables / "table_s3_fixed_campaigns.tex", fh, compact_fixed, "Internal simulation statistics for the eight final infection campaigns.", "tab:s3-fixed-campaigns")

    compact_gaps = [[r["samples_per_sbox"], r["mean_of_campaign_mean_gap"], r["mean_of_trial_min_gap"], r["mean_of_trial_max_gap"]] for r in gaps]
    gh = ["Samples/S-box", "Mean gap", "Weakest-S-box gap", "Strongest-S-box gap"]
    markdown_table(tables / "table_s3_gap_statistics.md", gh, compact_gaps)
    latex_table(tables / "table_s3_gap_statistics.tex", gh, compact_gaps, "Minimum-frequency separation versus data complexity.", "tab:s3-gap-statistics")

    manifest: list[dict[str, str]] = []
    for path in sorted(tables.iterdir()):
        if path.is_file():
            manifest.append({"artifact": path.name, "type": path.suffix.lstrip("."), "description": "Scenario 3 paper table"})
    write_csv(tables / "TABLE_MANIFEST.csv", ["artifact", "type", "description"], manifest)
    return manifest


def figure_manifest(figures: Path) -> list[dict[str, str]]:
    descriptions = {
        "fig_s3_success_vs_samples": "Complete-key and word-level success versus published sample count.",
        "fig_s3_failure_probability_log": "Residual complete-key failure probability on a logarithmic scale.",
        "fig_s3_mean_recovered_words": "Mean number of correctly recovered words and unique histogram minima.",
        "fig_s3_minimum_gap_vs_samples": "Growth of the separation between the smallest and second-smallest bins.",
        "fig_s3_minimum_gap_distribution": "Distribution of minimum-frequency gaps at representative sample sizes.",
        "fig_s3_rate_convergence": "Convergence of the internal ineffective rate to the theoretical model.",
        "fig_s3_per_sbox_success_heatmap": "Per-S-box word-recovery success over the sample grid.",
        "fig_s3_success_by_delta": "Complete-key success by known fault input at the maximum sample count.",
        "fig_s3_fixed_rate_by_sbox": "Internal ineffective rate for each final infection campaign.",
        "fig_s3_fixed_output_composition": "Hidden composition of correct ineffective and random infected outputs.",
        "fig_s3_fixed_minimum_gap": "Minimum-frequency gap for each final S-box campaign.",
        "fig_s3_histogram_heatmap": "Eight final 16-bin histograms with their unique minima marked.",
        "fig_s3_recovered_words": "Recovered versus actual four-bit SK28 words.",
    }
    rows = [{"figure_id": stem, "png": f"{stem}.png", "pdf": f"{stem}.pdf", "svg": f"{stem}.svg", "description": desc} for stem, desc in descriptions.items()]
    write_csv(figures / "FIGURE_MANIFEST.csv", ["figure_id", "png", "pdf", "svg", "description"], rows)
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    root = args.root.resolve()
    results = root / "results"
    artifact_root = root / "paper_artifacts" / "scenario3"
    figures = artifact_root / "figures"
    figures.mkdir(parents=True, exist_ok=True)

    trials = read_csv(results / "scenario3_repeated_trials.csv")
    words = read_csv(results / "scenario3_repeated_words.csv")
    fixed = read_csv(results / "scenario3_all_sboxes_infection_collection_summary.csv")
    hist = read_csv(results / "scenario3_all_sboxes_infection_histograms.csv")
    recovery = read_csv(results / "scenario3_full_sk28_recovery_summary.csv")

    success, gaps = aggregate_trials(trials)
    sboxes, deltas = aggregate_words(words)
    threshold_rows = thresholds(success)
    write_csv(results / "scenario3_success_curve.csv", list(success[0].keys()), success)
    write_csv(results / "scenario3_gap_statistics.csv", list(gaps[0].keys()), gaps)
    write_csv(results / "scenario3_per_sbox_success.csv", list(sboxes[0].keys()), sboxes)
    write_csv(results / "scenario3_per_delta_success.csv", list(deltas[0].keys()), deltas)
    write_csv(results / "scenario3_success_thresholds.csv", list(threshold_rows[0].keys()), threshold_rows)

    theory = float(trials[0]["theoretical_rate"])
    fig_success(success, figures)
    fig_failure(success, figures)
    fig_words(success, figures)
    fig_gap(gaps, figures)
    fig_gap_box(words, figures)
    fig_rate(success, theory, figures)
    fig_sbox_heatmap(sboxes, figures)
    fig_delta(deltas, figures)
    fig_fixed_rate(fixed, theory, figures)
    fig_fixed_composition(fixed, figures)
    fig_fixed_gap(recovery, figures)
    fig_hist_heatmap(hist, figures)
    fig_recovery(recovery, figures)

    tables = build_tables(root, success, gaps, sboxes, deltas, fixed, hist, recovery, threshold_rows)
    figures_manifest = figure_manifest(figures)
    build_contact_sheet(figures, artifact_root / "FIGURES_CONTACT_SHEET.png")

    first_95 = next((r for r in success if float(r["full_key_success_rate"]) >= 0.95), None)
    first_99 = next((r for r in success if float(r["full_key_success_rate"]) >= 0.99), None)
    final = success[-1]
    aggregate_fixed = next(r for r in fixed if r["target_sbox"] == "aggregate")
    summary = {
        "repeated_trials": int(success[0]["trials"]),
        "sample_grid": [int(r["samples_per_sbox"]) for r in success],
        "minimum_samples_for_at_least_95_percent_complete_key_success": int(first_95["samples_per_sbox"]) if first_95 else None,
        "observed_success_at_95_threshold": float(first_95["full_key_success_rate"]) if first_95 else None,
        "minimum_samples_for_at_least_99_percent_complete_key_success": int(first_99["samples_per_sbox"]) if first_99 else None,
        "observed_success_at_99_threshold": float(first_99["full_key_success_rate"]) if first_99 else None,
        "maximum_grid_success_rate": float(final["full_key_success_rate"]),
        "maximum_grid_word_success_rate": float(final["word_success_rate"]),
        "theoretical_ineffective_rate": theory,
        "fixed_campaign_published_outputs": int(aggregate_fixed["published_count"]),
        "fixed_campaign_internal_ineffective": int(aggregate_fixed["internal_ineffective_count"]),
        "fixed_campaign_infected": int(aggregate_fixed["internal_infected_count"]),
        "fixed_campaign_empirical_rate": float(aggregate_fixed["empirical_ineffective_rate"]),
        "recovered_sk28": recovery[-1]["recovered_word"],
        "actual_sk28": recovery[-1]["actual_word"],
        "figures": len(figures_manifest),
        "figure_files": len(figures_manifest) * 3,
        "table_files": len(tables),
    }
    with (results / "scenario3_final_analysis_summary.json").open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)

    artifact_root.mkdir(parents=True, exist_ok=True)
    with (artifact_root / "README_FA.md").open("w", encoding="utf-8") as handle:
        handle.write("# خروجی‌های مقاله‌ای سناریوی ۳\n\n")
        handle.write("این پوشه شامل نمودارهای PNG/PDF/SVG، جدول‌های CSV/Markdown/LaTeX و داشبورد Excel است.\n")

    print(json.dumps(summary, indent=2))
    print("PASS: Scenario 3 tables and figures generated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
