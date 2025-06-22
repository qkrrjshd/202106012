import os

with open("requirements.txt", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if line and not line.startswith("#"):
            print(f"🔧 Installing: {line}")
            os.system(f"pip install {line}")
