import os
import sys

# The app's modules use absolute imports like `from services.observability.retry
# import sync_retry`, which only resolve if the repo root is on sys.path. There
# are no __init__.py files (implicit namespace packages), so pytest's default
# rootdir insertion can be unreliable depending on invocation directory/CWD.
# Pin it explicitly here so `pytest` works from any directory.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
