"""AML / KYC: transaction-monitoring rules and sanctions name screening. Rules are deterministic on purpose:
regulators expect every alert to be explainable and reproducible."""
from __future__ import annotations

from difflib import SequenceMatcher

import pandas as pd

import config


def _norm(name: str) -> str:
    return " ".join("".join(ch for ch in name.lower() if ch.isalpha() or ch == " ").split())


def screen_name(name: str, sanctions: pd.DataFrame) -> list[dict]:
    hits = []
    n = _norm(name)
    for s in sanctions.itertuples():
        sim = SequenceMatcher(None, n, _norm(s.name)).ratio()
        if sim >= config.SANCTIONS_MATCH_THRESHOLD:
            hits.append({"matched_name": s.name, "list": s.list, "similarity": round(sim, 3)})
    return sorted(hits, key=lambda h: -h["similarity"])


def structuring(txns: pd.DataFrame) -> list[dict]:
    thr = config.CASH_REPORTING_THRESHOLD
    cash = txns[(txns.channel == "CASH_DEPOSIT") & (txns.amount < thr) &
                (txns.amount >= thr * (1 - config.STRUCTURING_BAND))].sort_values("ts")
    if len(cash) < config.STRUCTURING_MIN_COUNT:
        return []
    window = pd.Timedelta(days=config.STRUCTURING_WINDOW_DAYS)
    ts = cash.ts.reset_index(drop=True)
    for i in range(len(ts)):
        j = ts.searchsorted(ts[i] + window, side="right")
        if j - i >= config.STRUCTURING_MIN_COUNT:
            block = cash.iloc[i:j]
            return [{"rule": "STRUCTURING", "severity": "HIGH",
                     "detail": f"{len(block)} cash deposits between {thr * (1 - config.STRUCTURING_BAND):,.0f} "
                               f"and {thr:,.0f} within {config.STRUCTURING_WINDOW_DAYS} days "
                               f"(total {block.amount.sum():,.0f})",
                     "txn_ids": block.txn_id.tolist()}]
    return []


def rapid_movement(txns: pd.DataFrame) -> list[dict]:
    alerts = []
    credits = txns[(txns.direction == "CREDIT") & (txns.amount >= config.RAPID_MOVEMENT_MIN_AMOUNT)]
    debits = txns[txns.direction == "DEBIT"]
    for c in credits.itertuples():
        out = debits[(debits.ts > c.ts) & (debits.ts <= c.ts + pd.Timedelta(hours=config.RAPID_MOVEMENT_HOURS))]
        if out.amount.sum() >= config.RAPID_MOVEMENT_RATIO * c.amount:
            alerts.append({"rule": "RAPID_MOVEMENT", "severity": "HIGH",
                           "detail": f"{c.amount:,.0f} received from {c.counterparty}; {out.amount.sum():,.0f} "
                                     f"({out.amount.sum() / c.amount:.0%}) moved out within "
                                     f"{config.RAPID_MOVEMENT_HOURS}h to {sorted(set(out.country))}",
                           "txn_ids": [c.txn_id] + out.txn_id.tolist()})
    return alerts


def high_risk_geography(txns: pd.DataFrame) -> list[dict]:
    hr = txns[txns.country.isin(config.HIGH_RISK_COUNTRIES)]
    if hr.empty:
        return []
    return [{"rule": "HIGH_RISK_GEOGRAPHY", "severity": "MEDIUM",
             "detail": f"{len(hr)} transaction(s) totalling {hr.amount.sum():,.0f} with "
                       f"{sorted(set(hr.country))}", "txn_ids": hr.txn_id.tolist()}]


def assess_customer(customer: dict, txns: pd.DataFrame, sanctions: pd.DataFrame) -> dict:
    alerts = structuring(txns) + rapid_movement(txns) + high_risk_geography(txns)
    hits = screen_name(customer["name"], sanctions)
    if hits:
        alerts.insert(0, {"rule": "SANCTIONS_SCREENING", "severity": "CRITICAL",
                          "detail": f"name '{customer['name']}' resembles listed '{hits[0]['matched_name']}' "
                                    f"(similarity {hits[0]['similarity']})", "txn_ids": []})
    if customer.get("kyc_status") != "VERIFIED":
        alerts.append({"rule": "KYC_INCOMPLETE", "severity": "LOW",
                       "detail": f"KYC status is {customer.get('kyc_status')}", "txn_ids": []})
    weight = {"CRITICAL": 60, "HIGH": 50, "MEDIUM": 20, "LOW": 5}
    risk = min(100, sum(weight[a["severity"]] for a in alerts))
    return {"customer_id": customer["customer_id"], "risk_score": risk,
            "risk_band": "HIGH" if risk >= 50 else "MEDIUM" if risk >= 20 else "LOW",
            "alerts": alerts, "recommend_sar": risk >= 50}
