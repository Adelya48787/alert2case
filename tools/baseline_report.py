#!/usr/bin/env python3
"""docs/baseline/baseline_raw.csv → hesabat cədvəlləri və qrafik."""

import matplotlib
import matplotlib.pyplot as plt
import pandas as pd

matplotlib.use("Agg")

df = pd.read_csv("docs/baseline/baseline_raw.csv")
df = df[~df["note"].fillna("").str.contains("outlier")]
df["alert_type"] = df["alert_id"].str.split("-").str[0]


def p90(s: pd.Series) -> float:
    return s.quantile(0.9)


per_step = df.groupby("step")["duration_s"].agg(n="count", median="median", p90=p90, std="std").round(1)

per_alert = df.groupby(["alert_id", "analyst", "alert_type"])["duration_s"].sum().reset_index(name="total_s")
per_type = (
    per_alert.groupby("alert_type")["total_s"].agg(n="count", mean="mean", median="median", p90=p90).round(1)
)

share = (df.groupby("step")["duration_s"].sum() / df["duration_s"].sum() * 100).round(1).rename("share_%")

final = df[df["step"] == "S8"]
answers = pd.read_csv("docs/baseline/answers.csv")
merged = final.merge(answers, on="alert_id")
accuracy = round((merged["verdict"] == merged["expected_verdict"]).mean() * 100, 1)
disagree = final.groupby("alert_id")["verdict"].nunique() > 1

with open("docs/baseline/report_output.md", "w", encoding="utf-8") as f:
    f.write("## Addım üzrə (saniyə)\n" + per_step.to_markdown() + "\n\n")
    f.write("## Alert tipi üzrə manual MTTR (saniyə)\n" + per_type.to_markdown() + "\n\n")
    f.write("## Vaxt payı\n" + share.to_markdown() + "\n\n")
    f.write(f"Manual dəqiqlik: {accuracy}%\n\n")
    f.write(
        f"Verdict uyğunsuzluğu: {round(disagree.mean()*100, 1)}% alert " f"{list(disagree[disagree].index)}\n"
    )

ax = df.boxplot(column="duration_s", by="step", figsize=(8, 4))
ax.set_ylabel("saniyə")
ax.set_title("Manual triage: addım üzrə vaxt")
plt.suptitle("")
plt.tight_layout()
plt.savefig("docs/baseline/steps_boxplot.png", dpi=150)
print(open("docs/baseline/report_output.md", encoding="utf-8").read())
