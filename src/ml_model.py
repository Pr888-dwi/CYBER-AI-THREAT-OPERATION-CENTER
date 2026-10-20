import os
import pickle
from pathlib import Path

import numpy as np


class SimpleThreatModel:
    def __init__(self, model_path: str | None = None):
        self.model_path = model_path or str(Path(__file__).resolve().parent / "models" / "threat_model.pkl")
        self._model = None
        self._train_if_missing()

    def _train_if_missing(self):
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        if os.path.exists(self.model_path):
            with open(self.model_path, "rb") as handle:
                self._model = pickle.load(handle)
            return

        X = np.array([
            [0.2, 0.1, 0.1, 0.0],
            [0.9, 0.8, 0.7, 1.0],
            [0.4, 0.3, 0.2, 0.5],
            [0.8, 0.7, 0.6, 0.9],
            [0.1, 0.2, 0.1, 0.2],
            [0.95, 0.9, 0.8, 1.0],
        ])
        y = np.array([0, 1, 0, 1, 0, 1])

        from sklearn.linear_model import LogisticRegression

        model = LogisticRegression(max_iter=1000)
        model.fit(X, y)
        with open(self.model_path, "wb") as handle:
            pickle.dump(model, handle)
        self._model = model

    def predict(self, features):
        arr = np.array([features], dtype=float)
        prob = self._model.predict_proba(arr)[0][1]
        label = 1 if prob >= 0.6 else 0
        return {"label": label, "score": float(prob)}
