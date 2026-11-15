"""Pre-upload safety check: refuses to continue if files that would be
committed contain credentials or personal data. Used by Upload_To_GitHub.bat.
Exit code 0 = clean, 1 = problems found."""
import os
import re
import subprocess
import sys

PATTERNS = [
    (r"ghp_[A-Za-z0-9]{30,}", "GitHub personal access token"),
    (r"github_pat_[A-Za-z0-9_]{40,}", "GitHub fine-grained token"),
    (r"gh[ousr]_[A-Za-z0-9]{30,}", "GitHub token"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key"),
    (r"AIza[0-9A-Za-z_\-]{35}", "Google API key"),
    (r"sk-[A-Za-z0-9_\-]{32,}", "API secret key"),
    (r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", "private key"),
    (r"https://[^/\s:@]+:[^/\s@]+@github\.com", "credentials inside a git URL"),
    (r"(?i)(password|passwd|secret|api_key|apikey|token)\s*[:=]\s*['\"][^'\"\s]{8,}['\"]", "hard-coded secret"),
]
FORBIDDEN_NAMES = re.compile(r"(^|/)(\.env|.*\.pem|.*\.key|id_rsa.*|credentials.*|profiles\.json|"
                             r"settings\.json|backup-.*\.json|original-.*\.json|.*\.log)$", re.I)
SELF = os.path.normpath("tools/check_secrets.py")


def files_to_commit() -> list:
    try:
        out = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard"],
                             capture_output=True, text=True, check=True).stdout
        return [l for l in out.splitlines() if l.strip()]
    except (OSError, subprocess.CalledProcessError):
        files = []
        for root, dirs, names in os.walk("."):
            dirs[:] = [d for d in dirs if d not in (".git", "__pycache__", "dist", "build")]
            files += [os.path.relpath(os.path.join(root, n)) for n in names]
        return files


def main() -> int:
    problems = []
    for f in files_to_commit():
        norm = f.replace("\\", "/")
        if FORBIDDEN_NAMES.search(norm):
            problems.append(f"{f}: file type must not be uploaded")
            continue
        if os.path.normpath(f) == SELF or not os.path.isfile(f) or os.path.getsize(f) > 2_000_000:
            continue
        try:
            text = open(f, encoding="utf-8", errors="ignore").read()
        except OSError:
            continue
        for pat, label in PATTERNS:
            if re.search(pat, text):
                problems.append(f"{f}: possible {label}")
        if re.search(r"\b([0-9A-F]{2}-){5}[0-9A-F]{2}\b", text) and not f.startswith("tests"):
            problems.append(f"{f}: contains a MAC address")
    if problems:
        print("UPLOAD BLOCKED - sensitive content found:")
        for p in problems:
            print("  -", p)
        return 1
    print("Secret scan: OK (no credentials or personal data found).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
