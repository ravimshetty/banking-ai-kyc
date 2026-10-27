"""Synthetic core-banking data with planted card misuse and AML patterns.

Outputs (CSV in data/): customers, accounts, transactions, sanctions.
Everything is fictional. Patterns are planted on purpose so the models and rules have something real to find.
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import config  # noqa: E402

FIRST = ["Aarav", "Vivaan", "Aditya", "Ishaan", "Rohan", "Kiran", "Priya", "Ananya", "Diya", "Meera",
         "Sneha", "Kavya", "Arjun", "Rahul", "Neha", "Pooja", "Suresh", "Lakshmi", "Farhan", "Zoya",
         "Rajesh", "Swathi", "Venkat", "Harini", "Imran", "Sana", "Deepak", "Divya", "Manoj", "Asha"]
LAST = ["Reddy", "Sharma", "Rao", "Iyer", "Naidu", "Gupta", "Khan", "Patel", "Menon", "Varma",
        "Goud", "Chowdary", "Joshi", "Pillai", "Das", "Singh", "Kulkarni", "Shetty", "Nair", "Bose"]
MCC = {  # merchant category -> base fraud risk weight
    "grocery": 0.2, "fuel": 0.3, "restaurants": 0.3, "utilities": 0.1, "travel": 0.8,
    "electronics": 1.0, "jewellery": 1.0, "gaming": 1.2, "crypto_exchange": 1.5, "pharmacy": 0.2,
}
CHANNELS = ["POS", "ONLINE", "UPI", "ATM", "TRANSFER"]
SANCTIONED = ["Viktor Draganov", "Hassan Al-Rami", "Lin Zhaoyang", "Petro Kovalenko", "Omar Bashiri"]


def _customers(rng, n=500):
    rows = []
    for i in range(n):
        income = float(np.round(rng.lognormal(mean=11.0, sigma=0.55), -2))  # monthly INR, median ~60k
        rows.append({
            "customer_id": f"C{i + 1:04d}",
            "name": f"{rng.choice(FIRST)} {rng.choice(LAST)}",
            "age": int(rng.integers(21, 70)),
            "monthly_income": income,
            "employment_years": int(rng.integers(0, 30)),
            "home_country": "IN",
            "kyc_status": rng.choice(["VERIFIED", "VERIFIED", "VERIFIED", "PENDING_REKYC"]),
            "segment": "PREMIUM" if income > 150_000 else "RETAIL",
        })
    df = pd.DataFrame(rows)
    # Plant one near-match to a sanctioned name so screening has something to catch.
    df.loc[17, "name"] = "Viktor Draganoff"
    return df


def _accounts(rng, customers):
    return pd.DataFrame({
        "account_id": [f"A{i + 1:05d}" for i in range(len(customers))],
        "customer_id": customers.customer_id,
        "balance": np.round(customers.monthly_income * rng.uniform(0.5, 6, len(customers)), 2),
        "card_id": [f"CARD{i + 1:05d}" for i in range(len(customers))],
        "card_status": "ACTIVE",
    })


def _transactions(rng, customers, days=90):
    start = pd.Timestamp("2026-07-01")
    rows = []
    tid = 0
    for c in customers.itertuples():
        typical = c.monthly_income / 40
        n = int(rng.integers(30, 110))
        for _ in range(n):
            tid += 1
            fraud = rng.random() < 0.015
            ts = start + pd.Timedelta(days=float(rng.uniform(0, days)))
            if fraud:
                # Each red flag is only *likely*, not guaranteed: real fraud often looks ordinary.
                hour = float(rng.choice([1, 2, 3, 4, 23])) if rng.random() < 0.55 else float(rng.normal(15, 4) % 24)
                ts = ts.normalize() + pd.Timedelta(hours=hour, minutes=float(rng.integers(0, 60)))
                mcc = rng.choice(["electronics", "jewellery", "gaming", "crypto_exchange", "travel"]) \
                    if rng.random() < 0.7 else rng.choice(["grocery", "restaurants", "fuel", "pharmacy"])
                amount = typical * (rng.uniform(3, 15) if rng.random() < 0.65 else rng.lognormal(0.3, 0.6))
                country = rng.choice(["AE", "SG", "NG", "RU"]) if rng.random() < 0.45 else "IN"
                channel = rng.choice(["ONLINE", "ONLINE", "POS", "ATM", "UPI"])
                new_device = rng.random() < 0.6
            else:
                night = rng.random() < 0.05
                hour = float(rng.choice([0, 1, 5, 23])) if night else float(rng.normal(14, 3.5) % 24)
                ts = ts.normalize() + pd.Timedelta(hours=hour, minutes=float(rng.integers(0, 60)))
                mcc = rng.choice(list(MCC), p=[0.25, 0.12, 0.15, 0.1, 0.05, 0.08, 0.04, 0.03, 0.01, 0.17])
                big = rng.random() < 0.03   # genuine big-ticket purchases (phones, flights, gold)
                amount = typical * (rng.uniform(4, 12) if big else rng.lognormal(0, 0.7))
                country = "IN" if rng.random() < 0.95 else rng.choice(["AE", "SG", "US", "GB"])
                channel = rng.choice(CHANNELS, p=[0.3, 0.25, 0.35, 0.05, 0.05])
                new_device = rng.random() < 0.05
            rows.append({
                "txn_id": f"T{tid:07d}", "customer_id": c.customer_id, "ts": ts,
                "amount": round(float(amount), 2), "direction": "DEBIT", "channel": channel,
                "merchant_category": mcc, "country": country, "new_device": bool(new_device),
                "counterparty": f"MERCHANT_{mcc.upper()}_{rng.integers(1, 40)}", "is_fraud": int(fraud),
            })
        # salary credits
        for m in range(3):
            tid += 1
            rows.append({
                "txn_id": f"T{tid:07d}", "customer_id": c.customer_id,
                "ts": start + pd.DateOffset(months=m) + pd.Timedelta(hours=10),
                "amount": c.monthly_income, "direction": "CREDIT", "channel": "TRANSFER",
                "merchant_category": "salary", "country": "IN", "new_device": False,
                "counterparty": "EMPLOYER", "is_fraud": 0,
            })
    df = pd.DataFrame(rows)
    return df, tid


def _plant_aml(rng, df, customers, tid):
    """Plant structuring, rapid in/out movement and high-risk-country transfers on a few customers."""
    extra = []
    thr = config.CASH_REPORTING_THRESHOLD
    structurers = customers.customer_id.iloc[[5, 42, 133]].tolist()
    movers = customers.customer_id.iloc[[8, 77]].tolist()
    hr_senders = customers.customer_id.iloc[[21]].tolist()
    base = pd.Timestamp("2026-08-10 11:00")
    for cid in structurers:
        for k in range(5):
            tid += 1
            extra.append({"txn_id": f"T{tid:07d}", "customer_id": cid, "ts": base + pd.Timedelta(days=k, hours=k),
                          "amount": round(float(thr * rng.uniform(0.91, 0.99)), 2), "direction": "CREDIT",
                          "channel": "CASH_DEPOSIT", "merchant_category": "cash", "country": "IN",
                          "new_device": False, "counterparty": "BRANCH_CASH", "is_fraud": 0})
    for cid in movers:
        t0 = base + pd.Timedelta(days=12)
        tid += 1
        extra.append({"txn_id": f"T{tid:07d}", "customer_id": cid, "ts": t0, "amount": 900_000.0,
                      "direction": "CREDIT", "channel": "TRANSFER", "merchant_category": "transfer_in",
                      "country": "IN", "new_device": False, "counterparty": "UNKNOWN_ENTITY_LLP", "is_fraud": 0})
        for j, amt in enumerate([400_000.0, 380_000.0]):
            tid += 1
            extra.append({"txn_id": f"T{tid:07d}", "customer_id": cid, "ts": t0 + pd.Timedelta(hours=3 + j * 5),
                          "amount": amt, "direction": "DEBIT", "channel": "TRANSFER",
                          "merchant_category": "transfer_out", "country": "AE", "new_device": False,
                          "counterparty": f"SHELL_TRADING_{j}", "is_fraud": 0})
    for cid in hr_senders:
        tid += 1
        extra.append({"txn_id": f"T{tid:07d}", "customer_id": cid, "ts": base + pd.Timedelta(days=20),
                      "amount": 150_000.0, "direction": "DEBIT", "channel": "TRANSFER",
                      "merchant_category": "transfer_out", "country": "IR", "new_device": False,
                      "counterparty": "TEHRAN_IMPEX", "is_fraud": 0})
    return pd.concat([df, pd.DataFrame(extra)], ignore_index=True)


def main():
    rng = np.random.default_rng(config.SEED)
    config.DATA_DIR.mkdir(exist_ok=True)
    customers = _customers(rng)
    accounts = _accounts(rng, customers)
    txns, tid = _transactions(rng, customers)
    txns = _plant_aml(rng, txns, customers, tid).sort_values("ts").reset_index(drop=True)
    sanctions = pd.DataFrame({"name": SANCTIONED, "list": "DEMO_SANCTIONS"})

    for name, df in [("customers", customers), ("accounts", accounts), ("transactions", txns),
                     ("sanctions", sanctions)]:
        df.to_csv(config.DATA_DIR / f"{name}.csv", index=False)
    print(f"customers={len(customers)} transactions={len(txns)} "
          f"pending_rekyc={(customers.kyc_status != 'VERIFIED').sum()} sanctions={len(sanctions)}")


if __name__ == "__main__":
    main()
