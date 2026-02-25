import os
import subprocess
import re
from pathlib import Path

# -------- CONFIG --------
ROOT_PATH = "/"      # Change as needed
TIMEOUT = 15         # Prevent hanging on malformed PDFs
# ------------------------

SUSPICIOUS_KEYWORDS = [
    "JavaScript",
    "JS",
    "OpenAction",
    "AA",
    "Launch",
    "EmbeddedFile",
    "EmbeddedFiles",
    "RichMedia",
    "XFA",
    "AcroForm",
    "URI",
    "URL"
]

def run_command(command):
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=TIMEOUT,
            text=True
        )
        return result.stdout
    except:
        return ""

def analyze_pdf(pdf_path):
    suspicious_hits = []

    info_output = run_command(["pdfinfo", pdf_path])
    js_output = run_command(["pdfinfo", "-js", pdf_path])
    struct_output = run_command(["pdfinfo", "-struct", pdf_path])

    combined_output = info_output + js_output + struct_output

    # Keyword detection
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword.lower() in combined_output.lower():
            suspicious_hits.append(keyword)

    # URL detection via regex
    urls = re.findall(r'https?://[^\s]+', combined_output)
    if urls:
        suspicious_hits.append(f"Detected URLs: {', '.join(set(urls))}")

    return suspicious_hits


def scan_drive(root_path):
    for root, dirs, files in os.walk(root_path):
        for file in files:
            if file.lower().endswith(".pdf"):
                full_path = os.path.join(root, file)

                flags = analyze_pdf(full_path)

                # 🔥 Only print if suspicious
                if flags:
                    print("=" * 80)
                    print(f"[!] Suspicious PDF Detected")
                    print(f"File Name : {file}")
                    print(f"Location  : {full_path}")
                    print("Indicators:")
                    for f in set(flags):
                        print(f"  - {f}")
                    print("=" * 80)


if __name__ == "__main__":
    scan_drive(ROOT_PATH)