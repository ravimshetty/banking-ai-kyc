"""Optional LLM layer. The LLM only classifies intent and phrases answers from tool results;
every number and decision comes from deterministic tools. Without OPENAI_API_KEY it falls back to rules."""
from __future__ import annotations

import json
import re

import config

INTENTS = ["balance", "recent_transactions", "report_fraud", "dispute", "freeze_card", "kyc_status",
           "policy_question", "aml_review", "smalltalk"]

_KEYWORDS = [  # ordered: first match wins
    ("aml_review", r"\b(aml|money laundering|sanction|structuring|sar|kyc review|compliance check)\b"),
    ("kyc_status", r"\bkyc\b|\bre-?kyc\b|know your customer|\b(update|verify)\b.*\b(documents?|identity|address)\b"),
    ("report_fraud", r"\b(didn'?t make|not me|unauthori[sz]ed|fraud|scam|hacked|someone used)\b"),
    ("freeze_card", r"\b(freeze|block|lost|stolen)\b.*\bcard\b|\bcard\b.*\b(lost|stolen)\b"),
    ("dispute", r"\b(dispute|chargeback|refund)\b"),
    ("balance", r"\b(my|account|available|current) balance\b|^\s*balance\b|\bbalance (of|for) C\d{4}\b|"
                r"\b(show|check|get|see|what'?s|what is)( the)? balance\b|how much (money )?do i have"),
    ("recent_transactions", r"\b(transactions?|statement|spent|spending|last \d+)\b"),
    ("policy_question", r"\b(how|what|when|can i|policy|charge|fee|interest|minimum|limit|liability|document)\b"),
]


def keyword_intent(text: str) -> str:
    for intent, pat in _KEYWORDS:
        if re.search(pat, text, re.I):
            return intent
    return "smalltalk"


class LLM:
    def __init__(self):
        self.enabled = config.USE_LLM
        self.client = None
        if self.enabled:
            from openai import OpenAI  # imported lazily so offline mode needs no SDK
            self.client = OpenAI(api_key=config.OPENAI_API_KEY)

    def classify(self, text: str, allowed: list[str]) -> str:
        """Pick an intent. The LLM is only offered intents this user is permitted to run (RBAC), so a crafted
        message can't talk it into a staff-only action; the orchestrator still re-checks the result."""
        if not self.enabled:
            return keyword_intent(text)
        prompt = (f"Classify this banking request into exactly one intent from {allowed}. "
                  f"If none fits, use \"smalltalk\". "
                  f'Reply as JSON {{"intent": "..."}}.\nRequest: {text}')
        try:
            r = self.client.chat.completions.create(
                model=config.OPENAI_MODEL, temperature=0, response_format={"type": "json_object"},
                messages=[{"role": "user", "content": prompt}])
            intent = json.loads(r.choices[0].message.content).get("intent")
            return intent if intent in allowed else keyword_intent(text)   # reject anything not offered
        except Exception:
            return keyword_intent(text)   # never let the LLM be a single point of failure

    def compose(self, question: str, facts: dict, fallback: str) -> str:
        if not self.enabled:
            return fallback
        system = ("You are a bank's assistant. Answer ONLY from the FACTS JSON. Do not invent numbers, "
                  "policies or promises. Keep it under 120 words. If facts include policy sources, cite them "
                  "as (source: file#section). Never reveal internal risk scores to a customer role.")
        try:
            r = self.client.chat.completions.create(
                model=config.OPENAI_MODEL, temperature=0.2,
                messages=[{"role": "system", "content": system},
                          {"role": "user", "content": f"QUESTION: {question}\nFACTS: {json.dumps(facts, default=str)}"}])
            return r.choices[0].message.content.strip()
        except Exception:
            return fallback
