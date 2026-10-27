"""Input/output guardrails: PII masking, prompt-injection and scope checks. Access control lives in bank/rbac.py."""
from __future__ import annotations

import re

PII_PATTERNS = [
    (re.compile(r"\b(?:\d[ -]?){15}\d\b"), "[CARD]"),                 # 16-digit card numbers
    (re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b"), "[AADHAAR]"),          # 12-digit Aadhaar
    (re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"), "[PAN]"),                 # PAN
    (re.compile(r"\b(?:\+91[ -]?)?[6-9]\d{9}\b"), "[PHONE]"),          # Indian mobile
    (re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]+\b"), "[EMAIL]"),
    (re.compile(r"\b(?:otp|pin|cvv|password)\s*(?:is|:)?\s*\d{3,6}\b", re.I), "[SECRET]"),
]
INJECTION = re.compile(r"ignore (all |any )?(previous|prior|above) instructions|you are now|system prompt|"
                       r"developer mode|act as (an? )?(admin|staff)|reveal your", re.I)
OUT_OF_SCOPE = re.compile(r"\b(which|what) (stock|share|crypto|coin)s? (should|to) (i )?buy\b|"
                          r"\bguaranteed returns?\b|\binvestment advice\b", re.I)


def mask_pii(text: str) -> str:
    for pat, repl in PII_PATTERNS:
        text = pat.sub(repl, text)
    return text


def check_input(text: str) -> tuple[bool, str | None]:
    if INJECTION.search(text):
        return False, "I can only help with your own banking requests. I can't change how I operate."
    if OUT_OF_SCOPE.search(text):
        return False, ("I can't give investment advice. A registered advisor at the branch can help with "
                       "investment planning.")
    if re.search(r"\b(otp|cvv|pin)\b", text, re.I) and re.search(r"\d{3,6}", text):
        return False, "Please never share your OTP, CVV or PIN with anyone, including the bank or this assistant."
    return True, None

