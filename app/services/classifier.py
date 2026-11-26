"""TF-IDF + Logistic Regression scam classifier. Trained by ml/train.py; loaded once at startup."""
import logging
from pathlib import Path

import joblib
from sklearn.pipeline import Pipeline

log = logging.getLogger(__name__)
MODEL_PATH = Path(__file__).resolve().parents[2] / "ml" / "model.joblib"


class ScamClassifier:
    def __init__(self, pipeline: Pipeline):
        self.pipeline = pipeline

    def predict_proba(self, text: str) -> float:
        """Probability (0-1) that the text is a scam."""
        return float(self.pipeline.predict_proba([text])[0][1])

    @classmethod
    def load_or_train(cls, path: Path = MODEL_PATH) -> "ScamClassifier":
        if not path.exists():
            log.info("No trained model found — training on the seed dataset")
            from ml.train import train_and_save
            train_and_save(path)
        return cls(joblib.load(path))
