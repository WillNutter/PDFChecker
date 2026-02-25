import os
import subprocess
import re
from pathlib import Path

# -------- CONFIG --------
ROOT_PATH = "/"  # Change to drive root (e.g. "/mnt/disk" or "C:\\")
TIMEOUT = 15     # seconds per pdf to prevent hang
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
    except subprocess.TimeoutExpired:
        return ""
    except Exception:
        return ""

def analyze_pdf(pdf_path):
    flagged = []

    # Basic metadata
    info_output = run_command(["pdfinfo", pdf_path])

    # JavaScript check
    js_output = run_command(["pdfinfo", "-js", pdf_path])

    # Structure check
    struct_output = run_command(["pdfinfo", "-struct", pdf_path])

    combined_output = info_output + js_output + struct_output

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword.lower() in combined_output.lower():
            flagged.append(keyword)

    # URL regex detection
    urls = re.findall(r'https?://[^\s]+', combined_output)
    if urls:
        flagged.append("Detected URLs")

    return flagged


def scan_drive(root_path):
    for root, dirs, files in os.walk(root_path):
        for file in files:
            if file.lower().endswith(".pdf"):
                full_path = os.path.join(root, file)

                print("=" * 80)
                print(f"[+] File Name : {file}")
                print(f"[+] Location  : {full_path}")

                flags = analyze_pdf(full_path)

                if flags:
                    print("[!] Suspicious Indicators Found:")
                    for f in set(flags):
                        print(f"    - {f}")
                else:
                    print("[✓] No suspicious indicators detected")

                print("=" * 80)


if __name__ == "__main__":
    scan_drive(ROOT_PATH)