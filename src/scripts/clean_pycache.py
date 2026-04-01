

from pathlib import Path
import shutil


ROOT = Path("src")


for cache in ROOT.rglob("__pycache__"):
	shutil.rmtree(cache)
	print(cache)

