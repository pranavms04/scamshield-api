"""Train the scam classifier.  Run:  python -m ml.train
Prints cross-validated metrics so you can quote REAL numbers (not made-up ones) in your README."""
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_validate
from sklearn.pipeline import FeatureUnion, Pipeline

DATA = Path(__file__).parent / "data" / "seed_messages.csv"
OUT = Path(__file__).parent / "model.joblib"


def build_pipeline() -> Pipeline:
    features = FeatureUnion([
        ("words", TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True, lowercase=True)),
        ("chars", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True)),  # catches "bit.ly", "₹"
    ])
    return Pipeline([("features", features), ("clf", LogisticRegression(max_iter=1000, class_weight="balanced", C=4.0))])


def train_and_save(out: Path = OUT, data: Path = DATA, verbose: bool = False) -> None:
    df = pd.read_csv(data)
    pipe = build_pipeline()
    if verbose:
        scores = cross_validate(pipe, df.text, df.label, cv=5, scoring=["precision", "recall", "f1"])
        for m in ["precision", "recall", "f1"]:
            print(f"{m:>9}: {scores['test_' + m].mean():.3f} ± {scores['test_' + m].std():.3f}")
    pipe.fit(df.text, df.label)
    joblib.dump(pipe, out)
    if verbose:
        print(f"saved model to {out} (trained on {len(df)} rows)")


if __name__ == "__main__":
    train_and_save(verbose=True)
