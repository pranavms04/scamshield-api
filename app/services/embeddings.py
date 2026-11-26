"""Turn text into vectors. Two implementations behind one interface (Strategy pattern):
- HashingEmbedder: zero-download, deterministic, good for tests and CI
- SentenceTransformerEmbedder: real semantic embeddings (all-MiniLM-L6-v2, 384-dim), free and local
"""
from typing import Protocol

import numpy as np
from sklearn.feature_extraction.text import HashingVectorizer


class Embedder(Protocol):
    dim: int

    def embed(self, texts: list[str]) -> list[list[float]]: ...


class HashingEmbedder:
    def __init__(self, dim: int = 384):
        self.dim = dim
        self._vec = HashingVectorizer(n_features=dim, ngram_range=(1, 2), alternate_sign=False, norm="l2")

    def embed(self, texts: list[str]) -> list[list[float]]:
        return self._vec.transform(texts).toarray().astype(float).tolist()


class SentenceTransformerEmbedder:
    def __init__(self, model_name: str = "sentence-transformers/all-MiniLM-L6-v2"):
        from sentence_transformers import SentenceTransformer  # optional dependency

        self._model = SentenceTransformer(model_name)
        self.dim = self._model.get_sentence_embedding_dimension()

    def embed(self, texts: list[str]) -> list[list[float]]:
        return self._model.encode(texts, normalize_embeddings=True).tolist()


def build_embedder(kind: str, dim: int) -> Embedder:
    return SentenceTransformerEmbedder() if kind == "sentence-transformers" else HashingEmbedder(dim)


def cosine(a: list[float], b: list[float]) -> float:
    va, vb = np.asarray(a), np.asarray(b)
    denom = np.linalg.norm(va) * np.linalg.norm(vb)
    return float(va @ vb / denom) if denom else 0.0
