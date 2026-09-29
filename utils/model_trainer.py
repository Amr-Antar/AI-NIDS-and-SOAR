import os
from pathlib import Path
import subprocess
import sys
import time


BASE_DIR = Path(__file__).resolve().parent.parent
TRAIN_SCRIPT = BASE_DIR / "train_models.py"


class RetrainError(RuntimeError):
    pass


def retrain_main(timeout: int = 3600):
    if not TRAIN_SCRIPT.exists():
        raise FileNotFoundError(f"Training script not found: {TRAIN_SCRIPT}")

    start_time = time.time()

    try:
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"
        result = subprocess.run(
            [sys.executable, str(TRAIN_SCRIPT)],
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        raise RetrainError(
            f"Training process exceeded timeout ({timeout} seconds)."
        ) from exc
    except Exception as exc:
        raise RetrainError(f"Failed to execute training process: {exc}") from exc

    duration = round(time.time() - start_time, 2)

    if result.returncode != 0:
        raise RetrainError(
            "Retraining script failed.\n"
            f"Exit Code: {result.returncode}\n\n"
            f"STDOUT:\n{result.stdout}\n\n"
            f"STDERR:\n{result.stderr}"
        )

    return {
        "status": "ok",
        "duration_seconds": duration,
        "message": "Retraining completed successfully.",
        "stdout": result.stdout.strip(),
    }


if __name__ == "__main__":
    try:
        response = retrain_main()
        print(response)
    except Exception as error:
        print(f"ERROR: {error}")
        sys.exit(1)