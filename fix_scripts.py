import os
import glob

warning_suppression = """
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module='urllib3')
"""

for script in glob.glob("*.py"):
    with open(script, "r") as f:
        content = f.read()

    if "NotOpenSSLWarning" in content or "urllib3" in content or "requests" in content:
        if "warnings.filterwarnings" not in content:
            content = warning_suppression + content.lstrip()

    with open(script, "w") as f:
        f.write(content)

print("Warnings suppressed!")
