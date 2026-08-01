#!/usr/bin/env python3
"""Generate Scenario-2 paper tables and figures from reproducible CSV files."""

from __future__ import annotations

import csv
import json
import math
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Iterable, Sequence

import matplotlib.pyplot as plt

Z95 = 1.959963984540054
ROLES = ["A", "B", "C", "D", "E"]


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def read_parameter_csv(path: Path) -> dict[str, str]:
    rows = read_csv(path)
    return {row["parameter"]: row["value"] for row in rows}


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


def safe_int(text: str, default: int = 0) -> int:
    if text in {"", "NA", "AMBIGUOUS"}:
        return default
    return int(text, 0)


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


def aggregate_trials(trials: list[dict[str, str]]) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    groups: dict[int, list[dict[str, str]]] = defaultdict(list)
    for row in trials:
        groups[int(row["samples"])].append(row)

    success_rows: list[dict[str, object]] = []
    complexity_rows: list[dict[str, object]] = []

    for samples in sorted(groups):
        group = groups[samples]
        n = len(group)

        metrics = {}
        for field in (
            "localization_success",
            "actual_candidate_present",
            "delta_success",
            "target_outcome_success",
        ):
            successes = sum(int(row[field]) for row in group)
            low, high = wilson(successes, n)
            metrics[field] = (successes, successes / n, low, high)

        filter_rows = [row for row in group if int(row["filter_executed"]) == 1]
        filter_rate = len(filter_rows) / n
        bits_all = [float(row["recovered_active_bits"]) for row in group]
        bits_filter = [float(row["recovered_active_bits"]) for row in filter_rows]
        candidates = [float(row["surviving_candidates"]) for row in filter_rows]
        evaluations = [float(row["candidate_sample_evaluations"]) for row in filter_rows]
        filter_seconds = [float(row["estimated_filter_cpu_seconds"]) for row in filter_rows]
        queries = [float(row["total_queries"]) for row in group]
        empirical = [float(row["empirical_rate"]) for row in group]
        rate_errors = [abs(value - float(group[0]["theoretical_rate"])) for value in empirical]

        mean_bits_all, std_bits_all = mean_std(bits_all)
        mean_bits_filter, std_bits_filter = mean_std(bits_filter)
        mean_candidates, std_candidates = mean_std(candidates)
        mean_evaluations, std_evaluations = mean_std(evaluations)
        mean_seconds, std_seconds = mean_std(filter_seconds)
        mean_queries, std_queries = mean_std(queries)
        mean_rate, std_rate = mean_std(empirical)
        mean_error, std_error = mean_std(rate_errors)

        success_rows.append({
            "samples": samples,
            "trials": n,
            "localization_successes": metrics["localization_success"][0],
            "localization_success_rate": f"{metrics['localization_success'][1]:.9f}",
            "localization_ci95_low": f"{metrics['localization_success'][2]:.9f}",
            "localization_ci95_high": f"{metrics['localization_success'][3]:.9f}",
            "actual_candidate_retained": metrics["actual_candidate_present"][0],
            "actual_candidate_retention_rate": f"{metrics['actual_candidate_present'][1]:.9f}",
            "delta_successes": metrics["delta_success"][0],
            "delta_success_rate": f"{metrics['delta_success'][1]:.9f}",
            "delta_ci95_low": f"{metrics['delta_success'][2]:.9f}",
            "delta_ci95_high": f"{metrics['delta_success'][3]:.9f}",
            "target_outcome_successes": metrics["target_outcome_success"][0],
            "target_outcome_success_rate": f"{metrics['target_outcome_success'][1]:.9f}",
            "target_ci95_low": f"{metrics['target_outcome_success'][2]:.9f}",
            "target_ci95_high": f"{metrics['target_outcome_success'][3]:.9f}",
            "filter_execution_rate": f"{filter_rate:.9f}",
            "mean_recovered_bits_overall": f"{mean_bits_all:.6f}",
            "std_recovered_bits_overall": f"{std_bits_all:.6f}",
            "mean_recovered_bits_when_localized": f"{mean_bits_filter:.6f}",
            "std_recovered_bits_when_localized": f"{std_bits_filter:.6f}",
            "mean_surviving_candidates_when_localized": f"{mean_candidates:.6f}",
            "median_surviving_candidates_when_localized": f"{statistics.median(candidates) if candidates else 0:.6f}",
            "min_surviving_candidates_when_localized": f"{min(candidates) if candidates else 0:.0f}",
            "max_surviving_candidates_when_localized": f"{max(candidates) if candidates else 0:.0f}",
        })

        query_ci = Z95 * std_queries / math.sqrt(n) if n > 1 else 0.0
        complexity_rows.append({
            "samples": samples,
            "trials": n,
            "mean_total_queries": f"{mean_queries:.6f}",
            "std_total_queries": f"{std_queries:.6f}",
            "ci95_queries_low": f"{mean_queries - query_ci:.6f}",
            "ci95_queries_high": f"{mean_queries + query_ci:.6f}",
            "median_total_queries": f"{statistics.median(queries):.6f}",
            "min_total_queries": f"{min(queries):.0f}",
            "max_total_queries": f"{max(queries):.0f}",
            "mean_empirical_rate": f"{mean_rate:.12f}",
            "std_empirical_rate": f"{std_rate:.12f}",
            "mean_absolute_rate_error": f"{mean_error:.12f}",
            "std_absolute_rate_error": f"{std_error:.12f}",
            "localized_trials": len(filter_rows),
            "mean_candidate_sample_evaluations": f"{mean_evaluations:.6f}",
            "std_candidate_sample_evaluations": f"{std_evaluations:.6f}",
            "mean_estimated_filter_cpu_seconds": f"{mean_seconds:.6f}",
            "std_estimated_filter_cpu_seconds": f"{std_seconds:.6f}",
            "mean_surviving_candidates": f"{mean_candidates:.6f}",
            "std_surviving_candidates": f"{std_candidates:.6f}",
        })

    return success_rows, complexity_rows


def aggregate_by_category(trials: list[dict[str, str]], category: str, max_samples: int) -> list[dict[str, object]]:
    groups: dict[int, list[dict[str, str]]] = defaultdict(list)
    for row in trials:
        if int(row["samples"]) == max_samples:
            groups[safe_int(row[category])].append(row)

    rows: list[dict[str, object]] = []
    for value in sorted(groups):
        group = groups[value]
        n = len(group)
        loc = sum(int(row["localization_success"]) for row in group)
        delta = sum(int(row["delta_success"]) for row in group)
        target = sum(int(row["target_outcome_success"]) for row in group)
        retained = sum(int(row["actual_candidate_present"]) for row in group)
        bits = [float(row["recovered_active_bits"]) for row in group]
        candidates = [float(row["surviving_candidates"]) for row in group if int(row["filter_executed"]) == 1]
        mean_bits, std_bits = mean_std(bits)
        mean_candidates, std_candidates = mean_std(candidates)
        rows.append({
            category: value,
            "trials": n,
            "localization_success_rate": f"{loc / n:.9f}",
            "delta_success_rate": f"{delta / n:.9f}",
            "target_outcome_success_rate": f"{target / n:.9f}",
            "actual_candidate_retention_rate": f"{retained / n:.9f}",
            "mean_recovered_bits": f"{mean_bits:.6f}",
            "std_recovered_bits": f"{std_bits:.6f}",
            "mean_surviving_candidates": f"{mean_candidates:.6f}",
            "std_surviving_candidates": f"{std_candidates:.6f}",
        })
    return rows


def aggregate_roles(roles: list[dict[str, str]]) -> list[dict[str, object]]:
    groups: dict[tuple[int, int], list[dict[str, str]]] = defaultdict(list)
    for row in roles:
        groups[(int(row["samples"]), int(row["role"]))].append(row)

    rows: list[dict[str, object]] = []
    for (samples, role), group in sorted(groups.items()):
        executed = [row for row in group if int(row["filter_executed"]) == 1]
        known_bits = [float(row["known_bits"]) for row in executed]
        correct = sum(int(row["consensus_correct"]) for row in executed)
        mean_bits, std_bits = mean_std(known_bits)
        rows.append({
            "samples": samples,
            "role": ROLES[role],
            "trials": len(group),
            "localized_trials": len(executed),
            "mean_known_bits": f"{mean_bits:.6f}",
            "std_known_bits": f"{std_bits:.6f}",
            "consensus_correct_rate": f"{correct / len(executed) if executed else 0.0:.9f}",
        })
    return rows


def threshold_rows(success_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    metrics = [
        ("localization", "localization_success_rate"),
        ("unique_delta", "delta_success_rate"),
        ("18_of_20_plus_unique_delta", "target_outcome_success_rate"),
    ]
    for metric_name, field in metrics:
        for target in (0.50, 0.80, 0.90, 0.95, 0.99, 1.00):
            selected = next((row for row in success_rows if float(row[field]) >= target), None)
            rows.append({
                "metric": metric_name,
                "target_rate": f"{target:.2f}",
                "minimum_samples": selected["samples"] if selected else "not reached",
                "observed_rate": selected[field] if selected else "",
                "trials": selected["trials"] if selected else "",
            })
    return rows


def figure_success(success_rows: list[dict[str, object]], figures: Path) -> None:
    x = [int(row["samples"]) for row in success_rows]
    fig, ax = plt.subplots(figsize=(8.6, 5.3))
    for field, label, marker in (
        ("localization_success_rate", "Fault localization", "o"),
        ("actual_candidate_retention_rate", "True candidate retained", "s"),
        ("delta_success_rate", "Unique delta", "^"),
        ("target_outcome_success_rate", "18/20 bits + unique delta", "D"),
    ):
        ax.plot(x, [float(row[field]) for row in success_rows], marker=marker, label=label)
    ax.set_xlabel("Public ineffective ciphertexts")
    ax.set_ylabel("Success probability")
    ax.set_ylim(-0.03, 1.03)
    ax.grid(True, alpha=0.3)
    ax.legend()
    ax.set_title("Scenario 2 success probability versus data complexity")
    save_figure(fig, figures / "fig_s2_success_vs_samples")


def figure_candidates(success_rows: list[dict[str, object]], figures: Path) -> None:
    x = [int(row["samples"]) for row in success_rows]
    mean_values = [max(1.0, float(row["mean_surviving_candidates_when_localized"])) for row in success_rows]
    median_values = [max(1.0, float(row["median_surviving_candidates_when_localized"])) for row in success_rows]
    fig, ax = plt.subplots(figsize=(8.6, 5.3))
    ax.plot(x, mean_values, marker="o", label="Mean")
    ax.plot(x, median_values, marker="s", linestyle="--", label="Median")
    ax.set_yscale("log")
    ax.set_xlabel("Public ineffective ciphertexts")
    ax.set_ylabel("Surviving active-key candidates")
    ax.grid(True, alpha=0.3)
    ax.legend()
    ax.set_title("Algorithm-2 candidate reduction")
    save_figure(fig, figures / "fig_s2_candidate_count_vs_samples")


def figure_bits(success_rows: list[dict[str, object]], figures: Path) -> None:
    x = [int(row["samples"]) for row in success_rows]
    fig, ax = plt.subplots(figsize=(8.6, 5.3))
    ax.plot(x, [float(row["mean_recovered_bits_overall"]) for row in success_rows], marker="o", label="Overall")
    ax.plot(x, [float(row["mean_recovered_bits_when_localized"]) for row in success_rows], marker="s", linestyle="--", label="Conditioned on localization")
    ax.axhline(18.0, linestyle=":", label="Structural limit: 18 bits")
    ax.set_xlabel("Public ineffective ciphertexts")
    ax.set_ylabel("Mean recovered active-key bits (of 20)")
    ax.set_ylim(-0.5, 20.5)
    ax.grid(True, alpha=0.3)
    ax.legend()
    ax.set_title("Recovered active-key information")
    save_figure(fig, figures / "fig_s2_recovered_bits_vs_samples")


def figure_queries(complexity_rows: list[dict[str, object]], figures: Path) -> None:
    x = [int(row["samples"]) for row in complexity_rows]
    mean = [float(row["mean_total_queries"]) for row in complexity_rows]
    low = [float(row["ci95_queries_low"]) for row in complexity_rows]
    high = [float(row["ci95_queries_high"]) for row in complexity_rows]
    fig, ax = plt.subplots(figsize=(8.6, 5.3))
    ax.plot(x, mean, marker="o")
    ax.fill_between(x, low, high, alpha=0.2)
    ax.set_xlabel("Public ineffective ciphertexts")
    ax.set_ylabel("Mean oracle queries")
    ax.grid(True, alpha=0.3)
    ax.set_title("Detection-oracle data complexity")
    save_figure(fig, figures / "fig_s2_queries_vs_samples")


def figure_evaluations(complexity_rows: list[dict[str, object]], figures: Path) -> None:
    x = [int(row["samples"]) for row in complexity_rows]
    y = [float(row["mean_candidate_sample_evaluations"]) for row in complexity_rows]
    fig, ax = plt.subplots(figsize=(8.6, 5.3))
    ax.plot(x, y, marker="o")
    ax.set_xlabel("Public ineffective ciphertexts")
    ax.set_ylabel("Mean candidate-sample evaluations")
    ax.grid(True, alpha=0.3)
    ax.set_title("Partial-decryption computational complexity")
    save_figure(fig, figures / "fig_s2_candidate_evaluations")


def figure_runtime(complexity_rows: list[dict[str, object]], figures: Path) -> None:
    x = [int(row["samples"]) for row in complexity_rows]
    y = [float(row["mean_estimated_filter_cpu_seconds"]) for row in complexity_rows]
    fig, ax = plt.subplots(figsize=(8.6, 5.3))
    ax.plot(x, y, marker="o")
    ax.set_xlabel("Public ineffective ciphertexts")
    ax.set_ylabel("Mean CPU seconds")
    ax.grid(True, alpha=0.3)
    ax.set_title("Reference implementation filter runtime")
    save_figure(fig, figures / "fig_s2_filter_runtime")


def figure_rate(complexity_rows: list[dict[str, object]], theoretical: float, figures: Path) -> None:
    x = [int(row["samples"]) for row in complexity_rows]
    y = [float(row["mean_empirical_rate"]) for row in complexity_rows]
    fig, ax = plt.subplots(figsize=(8.6, 5.3))
    ax.plot(x, y, marker="o", label="Empirical mean")
    ax.axhline(theoretical, linestyle="--", label="Theoretical rate")
    ax.set_xlabel("Public ineffective ciphertexts")
    ax.set_ylabel("Ineffective-event rate")
    ax.grid(True, alpha=0.3)
    ax.legend()
    ax.set_title("Ineffective-rate convergence")
    save_figure(fig, figures / "fig_s2_rate_convergence")


def figure_category(rows: list[dict[str, object]], key: str, title: str, base: Path) -> None:
    labels = [str(row[key]) for row in rows]
    values = [100.0 * float(row["target_outcome_success_rate"]) for row in rows]
    fig, ax = plt.subplots(figsize=(8.6, 5.3))
    ax.bar(labels, values)
    ax.set_xlabel(key.replace("secret_", "Secret ").replace("_", " ").title())
    ax.set_ylabel("Target outcome success (%)")
    ax.set_ylim(0, 105)
    ax.grid(True, axis="y", alpha=0.3)
    ax.set_title(title)
    save_figure(fig, base)


def figure_role_heatmap(role_rows: list[dict[str, object]], figures: Path) -> None:
    samples = sorted({int(row["samples"]) for row in role_rows})
    matrix = []
    for role in ROLES:
        matrix.append([
            float(next(row["mean_known_bits"] for row in role_rows if row["role"] == role and int(row["samples"]) == sample))
            for sample in samples
        ])
    fig, ax = plt.subplots(figsize=(9.2, 4.5))
    image = ax.imshow(matrix, aspect="auto")
    ax.set_xticks(range(len(samples)), [str(sample) for sample in samples])
    ax.set_yticks(range(len(ROLES)), ROLES)
    ax.set_xlabel("Public ineffective ciphertexts")
    ax.set_ylabel("Active-key role")
    ax.set_title("Mean known bits per active word")
    fig.colorbar(image, ax=ax, label="Known bits (of 4)")
    for row_index, row in enumerate(matrix):
        for col_index, value in enumerate(row):
            ax.text(col_index, row_index, f"{value:.1f}", ha="center", va="center")
    save_figure(fig, figures / "fig_s2_role_known_bits_heatmap")


def figure_public_histogram(hist_rows: list[dict[str, str]], figures: Path) -> None:
    matrix = [[0.0] * 16 for _ in range(8)]
    for row in hist_rows:
        matrix[int(row["sbox"])][int(row["value"], 0)] = float(row["count"])
    fig, ax = plt.subplots(figsize=(9.2, 5.0))
    image = ax.imshow(matrix, aspect="auto")
    ax.set_xticks(range(16), [f"{value:X}" for value in range(16)])
    ax.set_yticks(range(8), [str(value) for value in range(8)])
    ax.set_xlabel("Public last-round word")
    ax.set_ylabel("Logical S-box")
    ax.set_title("Scenario 2 public histogram and unique missing cell")
    fig.colorbar(image, ax=ax, label="Count")
    save_figure(fig, figures / "fig_s2_public_histogram_heatmap")


def figure_fixed_candidates(candidate_rows: list[dict[str, str]], figures: Path) -> None:
    labels = [row["packed_active_words"] for row in candidate_rows]
    c_values = [int(row["word_C"], 0) for row in candidate_rows]
    fig, ax = plt.subplots(figsize=(8.6, 5.0))
    ax.bar(labels, c_values)
    ax.set_xlabel("Surviving active-key candidate")
    ax.set_ylabel("Ambiguous role-C word")
    ax.set_yticks(range(16))
    ax.grid(True, axis="y", alpha=0.3)
    ax.set_title("Four structural candidates differ only in role C")
    save_figure(fig, figures / "fig_s2_fixed_candidate_ambiguity")


def figure_outcome_composition(trials: list[dict[str, str]], figures: Path) -> None:
    selected_samples = [128, 192, 256, 384, 512]
    labels: list[str] = []
    loc_fail: list[float] = []
    loc_only: list[float] = []
    delta_only: list[float] = []
    target: list[float] = []
    for samples in selected_samples:
        group = [row for row in trials if int(row["samples"]) == samples]
        if not group:
            continue
        n = len(group)
        a = sum(1 for row in group if int(row["localization_success"]) == 0)
        b = sum(1 for row in group if int(row["localization_success"]) == 1 and int(row["delta_success"]) == 0)
        c = sum(1 for row in group if int(row["delta_success"]) == 1 and int(row["target_outcome_success"]) == 0)
        d = sum(1 for row in group if int(row["target_outcome_success"]) == 1)
        labels.append(str(samples))
        loc_fail.append(100.0 * a / n)
        loc_only.append(100.0 * b / n)
        delta_only.append(100.0 * c / n)
        target.append(100.0 * d / n)
    fig, ax = plt.subplots(figsize=(8.8, 5.3))
    ax.bar(labels, loc_fail, label="Localization failed")
    ax.bar(labels, loc_only, bottom=loc_fail, label="Localized, delta unresolved")
    bottom2 = [a + b for a, b in zip(loc_fail, loc_only)]
    ax.bar(labels, delta_only, bottom=bottom2, label="Delta recovered, >4 candidates")
    bottom3 = [a + b + c for a, b, c in zip(loc_fail, loc_only, delta_only)]
    ax.bar(labels, target, bottom=bottom3, label="18/20 bits + unique delta")
    ax.set_xlabel("Public ineffective ciphertexts")
    ax.set_ylabel("Trials (%)")
    ax.set_ylim(0, 100)
    ax.legend()
    ax.set_title("Scenario 2 outcome composition")
    save_figure(fig, figures / "fig_s2_outcome_composition")


def create_contact_sheet(figures_dir: Path, output: Path) -> None:
    try:
        from PIL import Image, ImageDraw
    except ImportError:
        return
    paths = sorted(figures_dir.glob("fig_s2_*.png"))
    if not paths:
        return
    thumbs = []
    for path in paths:
        image = Image.open(path).convert("RGB")
        image.thumbnail((520, 330))
        thumbs.append((path.stem, image.copy()))
    columns = 2
    rows = math.ceil(len(thumbs) / columns)
    sheet = Image.new("RGB", (1120, rows * 390 + 30), "white")
    draw = ImageDraw.Draw(sheet)
    for index, (name, image) in enumerate(thumbs):
        col = index % columns
        row = index // columns
        x = 25 + col * 550
        y = 20 + row * 390
        sheet.paste(image, (x, y + 30))
        draw.text((x, y), name, fill="black")
    output.parent.mkdir(parents=True, exist_ok=True)
    sheet.save(output)


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    results = root / "results"
    artifacts = root / "paper_artifacts" / "scenario2"
    figures = artifacts / "figures"
    tables = artifacts / "tables"
    figures.mkdir(parents=True, exist_ok=True)
    tables.mkdir(parents=True, exist_ok=True)

    trials = read_csv(results / "scenario2_repeated_trials.csv")
    roles = read_csv(results / "scenario2_repeated_roles.csv")
    candidates = read_csv(results / "scenario2_active_key_candidates.csv")
    consensus = read_csv(results / "scenario2_active_key_consensus.csv")
    public_hist = read_csv(results / "scenario2_unknown_detection_histograms.csv")
    fixed_summary = read_parameter_csv(results / "scenario2_partial_decryption_summary.csv")
    verification = read_parameter_csv(results / "scenario2_step2_verification.csv")

    success_rows, complexity_rows = aggregate_trials(trials)
    max_samples = max(int(row["samples"]) for row in trials)
    per_sbox_rows = aggregate_by_category(trials, "secret_sbox", max_samples)
    per_delta_rows = aggregate_by_category(trials, "secret_delta", max_samples)
    role_rows = aggregate_roles(roles)
    thresholds = threshold_rows(success_rows)

    write_csv(results / "scenario2_success_curve.csv", list(success_rows[0].keys()), success_rows)
    write_csv(results / "scenario2_complexity.csv", list(complexity_rows[0].keys()), complexity_rows)
    write_csv(results / "scenario2_per_sbox_performance.csv", list(per_sbox_rows[0].keys()), per_sbox_rows)
    write_csv(results / "scenario2_per_delta_performance.csv", list(per_delta_rows[0].keys()), per_delta_rows)
    write_csv(results / "scenario2_role_recovery.csv", list(role_rows[0].keys()), role_rows)
    write_csv(results / "scenario2_success_thresholds.csv", list(thresholds[0].keys()), thresholds)

    figure_success(success_rows, figures)
    figure_candidates(success_rows, figures)
    figure_bits(success_rows, figures)
    figure_queries(complexity_rows, figures)
    figure_evaluations(complexity_rows, figures)
    figure_runtime(complexity_rows, figures)
    figure_rate(complexity_rows, float(trials[0]["theoretical_rate"]), figures)
    figure_category(per_sbox_rows, "secret_sbox", "Final target outcome by fault location", figures / "fig_s2_success_by_sbox")
    figure_category(per_delta_rows, "secret_delta", "Final target outcome by persistent-fault input", figures / "fig_s2_success_by_delta")
    figure_role_heatmap(role_rows, figures)
    figure_public_histogram(public_hist, figures)
    figure_fixed_candidates(candidates, figures)
    figure_outcome_composition(trials, figures)
    create_contact_sheet(figures, artifacts / "FIGURES_CONTACT_SHEET.png")

    success_table_rows = [
        [
            row["samples"], row["trials"],
            f"{100*float(row['localization_success_rate']):.1f}%",
            f"{100*float(row['delta_success_rate']):.1f}%",
            f"{100*float(row['target_outcome_success_rate']):.1f}%",
            f"{float(row['mean_recovered_bits_when_localized']):.2f}",
            f"{float(row['median_surviving_candidates_when_localized']):.0f}",
        ]
        for row in success_rows
    ]
    headers = ["Samples", "Trials", "Localization", "Unique delta", "18/20 + delta", "Mean bits", "Median candidates"]
    markdown_table(tables / "table_s2_success_curve.md", headers, success_table_rows)
    latex_table(tables / "table_s2_success_curve.tex", headers, success_table_rows, "Scenario 2 success versus public ineffective ciphertexts.", "tab:s2-success")
    write_csv(tables / "table_s2_success_curve.csv", list(success_rows[0].keys()), success_rows)

    complexity_table_rows = [
        [
            row["samples"],
            f"{float(row['mean_total_queries']):.1f}",
            row["localized_trials"],
            f"{float(row['mean_candidate_sample_evaluations']):.0f}",
            f"{float(row['mean_estimated_filter_cpu_seconds']):.4f}",
            f"{float(row['mean_surviving_candidates']):.1f}",
        ]
        for row in complexity_rows
    ]
    headers = ["Samples", "Mean queries", "Localized trials", "Mean evaluations", "Mean CPU s", "Mean candidates"]
    markdown_table(tables / "table_s2_complexity.md", headers, complexity_table_rows)
    latex_table(tables / "table_s2_complexity.tex", headers, complexity_table_rows, "Scenario 2 data and computational complexity.", "tab:s2-complexity")
    write_csv(tables / "table_s2_complexity.csv", list(complexity_rows[0].keys()), complexity_rows)

    for name, rows, key in (
        ("per_sbox", per_sbox_rows, "secret_sbox"),
        ("per_delta", per_delta_rows, "secret_delta"),
    ):
        table_rows = [
            [
                row[key], row["trials"],
                f"{100*float(row['localization_success_rate']):.1f}%",
                f"{100*float(row['delta_success_rate']):.1f}%",
                f"{100*float(row['target_outcome_success_rate']):.1f}%",
                f"{float(row['mean_recovered_bits']):.2f}",
            ]
            for row in rows
        ]
        headers = [key, "Trials", "Localization", "Unique delta", "18/20 + delta", "Mean bits"]
        markdown_table(tables / f"table_s2_{name}.md", headers, table_rows)
        latex_table(tables / f"table_s2_{name}.tex", headers, table_rows, f"Scenario 2 performance by {key}.", f"tab:s2-{name}")
        write_csv(tables / f"table_s2_{name}.csv", list(rows[0].keys()), rows)

    fixed_candidate_rows = [
        [row["candidate_index"], row["packed_active_words"], row["word_A"], row["word_B"], row["word_C"], row["word_D"], row["word_E"], row["missing_values"]]
        for row in candidates
    ]
    headers = ["Index", "Packed", "A", "B", "C", "D", "E", "Missing"]
    markdown_table(tables / "table_s2_fixed_candidates.md", headers, fixed_candidate_rows)
    latex_table(tables / "table_s2_fixed_candidates.tex", headers, fixed_candidate_rows, "Four structurally equivalent active-key candidates.", "tab:s2-candidates")
    write_csv(tables / "table_s2_fixed_candidates.csv", list(candidates[0].keys()), candidates)

    fixed_consensus_rows = [[row["role"], row["source_sbox"], row["known_bit_mask"], row["known_bit_value"], row["known_bits"]] for row in consensus]
    headers = ["Role", "S-box", "Mask", "Value", "Known bits"]
    markdown_table(tables / "table_s2_fixed_consensus.md", headers, fixed_consensus_rows)
    latex_table(tables / "table_s2_fixed_consensus.tex", headers, fixed_consensus_rows, "Consensus across the four surviving candidates.", "tab:s2-consensus")
    write_csv(tables / "table_s2_fixed_consensus.csv", list(consensus[0].keys()), consensus)

    threshold_table_rows = [[row["metric"], row["target_rate"], row["minimum_samples"], row["observed_rate"], row["trials"]] for row in thresholds]
    headers = ["Metric", "Target", "Minimum samples", "Observed", "Trials"]
    markdown_table(tables / "table_s2_thresholds.md", headers, threshold_table_rows)
    latex_table(tables / "table_s2_thresholds.tex", headers, threshold_table_rows, "Observed Scenario 2 success thresholds.", "tab:s2-thresholds")
    write_csv(tables / "table_s2_thresholds.csv", list(thresholds[0].keys()), thresholds)

    structural_rows = [
        {"metric": "active_key_space", "value": "2^20"},
        {"metric": "tested_candidates", "value": fixed_summary["tested_candidates"]},
        {"metric": "surviving_candidates", "value": fixed_summary["surviving_candidates"]},
        {"metric": "recovered_active_bits", "value": f"{fixed_summary['recovered_active_bits']}/{fixed_summary['active_key_bits']}"},
        {"metric": "unique_delta", "value": fixed_summary["recovered_delta"]},
        {"metric": "actual_candidate_present", "value": verification["actual_candidate_present"]},
        {"metric": "honest_final_claim", "value": "18/20 active bits + unique delta; four structural candidates"},
    ]
    write_csv(tables / "table_s2_structural_summary.csv", ["metric", "value"], structural_rows)
    structural_table_rows = [[row["metric"], row["value"]] for row in structural_rows]
    markdown_table(tables / "table_s2_structural_summary.md", ["Metric", "Value"], structural_table_rows)
    latex_table(tables / "table_s2_structural_summary.tex", ["Metric", "Value"], structural_table_rows, "Honest final result of Scenario 2.", "tab:s2-structural")

    max_success = next(row for row in success_rows if int(row["samples"]) == max_samples)
    summary = {
        "repeated_trials": len({row["trial"] for row in trials}),
        "sample_grid": [int(row["samples"]) for row in success_rows],
        "maximum_samples": max_samples,
        "localization_success_at_max": float(max_success["localization_success_rate"]),
        "unique_delta_success_at_max": float(max_success["delta_success_rate"]),
        "target_18_of_20_plus_delta_success_at_max": float(max_success["target_outcome_success_rate"]),
        "actual_candidate_retention_at_max": float(max_success["actual_candidate_retention_rate"]),
        "mean_recovered_bits_at_max": float(max_success["mean_recovered_bits_when_localized"]),
        "median_surviving_candidates_at_max": float(max_success["median_surviving_candidates_when_localized"]),
        "theoretical_ineffective_rate": float(trials[0]["theoretical_rate"]),
        "fixed_surviving_candidates": int(fixed_summary["surviving_candidates"]),
        "fixed_recovered_active_bits": int(fixed_summary["recovered_active_bits"]),
        "fixed_active_key_bits": int(fixed_summary["active_key_bits"]),
        "fixed_recovered_delta": fixed_summary["recovered_delta"],
        "fixed_actual_candidate_present": verification["actual_candidate_present"],
        "honest_final_result": "18/20 active key bits + unique delta; four structural candidates",
        "figures": len(list(figures.glob("fig_s2_*.png"))),
        "figure_files": len(list(figures.glob("fig_s2_*.*"))),
        "table_files": len(list(tables.glob("table_s2_*.*"))),
    }
    with (results / "scenario2_final_analysis_summary.json").open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)
        handle.write("\n")

    figure_manifest = []
    for path in sorted(figures.glob("fig_s2_*.*")):
        figure_manifest.append({"file": path.name, "format": path.suffix.lstrip("."), "bytes": path.stat().st_size})
    write_csv(figures / "FIGURE_MANIFEST.csv", ["file", "format", "bytes"], figure_manifest)

    table_manifest = []
    for path in sorted(tables.glob("table_s2_*.*")):
        table_manifest.append({"file": path.name, "format": path.suffix.lstrip("."), "bytes": path.stat().st_size})
    write_csv(tables / "TABLE_MANIFEST.csv", ["file", "format", "bytes"], table_manifest)

    print(json.dumps(summary, indent=2))
    print("PASS: Scenario 2 tables and figures generated.")


if __name__ == "__main__":
    main()
