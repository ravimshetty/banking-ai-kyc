"""Policy knowledge base: section-level chunking + TF-IDF retrieval (pure Python, no external services).

Same maths as scikit-learn's TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True) with smoothed IDF and
L2-normalised vectors, so search quality is unchanged without needing scikit-learn/scipy.
Drop-in point for your hybrid search / reranker stack: keep the `search()` signature."""
from __future__ import annotations

import math
import re
from collections import Counter

import config

_TOKEN = re.compile(r"(?u)\b\w\w+\b")
STOP_WORDS = frozenset("""a about above after again against all also am an and any are as at be because been before
being below between both but by can could did do does doing down during each few for from further had has have
having he her here hers herself him himself his how i if in into is it its itself just me more most my myself no
nor not now of off on once only or other our ours ourselves out over own same she should so some such than that
the their theirs them themselves then there these they this those through to too under until up very was we
were what when where which while who whom why will with would you your yours yourself yourselves""".split())


def _terms(text: str) -> list[str]:
    words = [w for w in _TOKEN.findall(text.lower()) if w not in STOP_WORDS]
    return words + [f"{a} {b}" for a, b in zip(words, words[1:])]      # unigrams + bigrams


class PolicyKB:
    def __init__(self, kb_dir=config.KB_DIR):
        self.chunks: list[dict] = []
        for path in sorted(kb_dir.glob("*.md")):
            text = path.read_text(encoding="utf-8")
            doc_title = text.splitlines()[0].lstrip("# ").strip()
            for sec in re.split(r"\n(?=## )", text)[1:]:
                head, _, body = sec.partition("\n")
                self.chunks.append({"source": path.name, "doc": doc_title,
                                    "section": head.lstrip("# ").strip(), "text": body.strip()})
        docs = [Counter(_terms(f"{c['doc']} {c['section']} {c['section']} {c['text']}")) for c in self.chunks]
        n = len(docs)
        df = Counter(t for d in docs for t in d)
        self.idf = {t: math.log((1 + n) / (1 + f)) + 1 for t, f in df.items()}
        self.vectors = [self._vector(d) for d in docs]

    def _vector(self, counts: Counter) -> dict[str, float]:
        v = {t: (1 + math.log(c)) * self.idf[t] for t, c in counts.items() if t in self.idf}
        norm = math.sqrt(sum(x * x for x in v.values())) or 1.0
        return {t: x / norm for t, x in v.items()}

    def search(self, query: str, k: int = 3, min_score: float = 0.05) -> list[dict]:
        q = self._vector(Counter(_terms(query)))
        sims = [sum(w * vec.get(t, 0.0) for t, w in q.items()) for vec in self.vectors]
        top = sorted(range(len(sims)), key=lambda i: -sims[i])[:k]
        return [{**self.chunks[i], "score": round(sims[i], 3)} for i in top if sims[i] >= min_score]
