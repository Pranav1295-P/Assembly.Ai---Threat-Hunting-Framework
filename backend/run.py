"""Bootstrapper: ensure the ML model exists, then start the Flask app.

Use this entry point in production-ish setups so first-time installs
auto-train the classifier."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import config
from app import create_app


def ensure_model() -> None:
    if Path(config.MODEL_PATH).exists():
        return
    print("[bootstrap] ML model not found — training now (~15 s) …")
    from ml_models import train_model
    train_model.main()


def main() -> None:
    ensure_model()
    app = create_app()
    print(f"[ready] Assembly.AI listening on "
          f"http://{config.FLASK_HOST}:{config.FLASK_PORT}")
    print(f"[ready] LLM provider: {config.llm_provider()}")
    app.run(host=config.FLASK_HOST,
            port=config.FLASK_PORT,
            debug=config.FLASK_DEBUG,
            use_reloader=False)


if __name__ == "__main__":
    main()
