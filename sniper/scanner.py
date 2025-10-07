# sniper/scanner.py
import asyncio
import aiohttp
import zipfile
import os
import sys
import tempfile
import re
import textwrap
from pathlib import Path
from typing import List, Tuple

from colorama import Fore, init
from playwright.async_api import async_playwright

from .ai_deep_chat import get_final_response, banner

init(autoreset=True)

# ---------- Config ----------
ALLOWED_EXTENSIONS = (
    ".py", ".js", ".php", ".html", ".htm", ".txt", ".md", ".css", ".json",
    ".sh", ".yml", ".yaml", ".Dockerfile", ".rb", ".go", ".rs", ".java"
)
MAX_COMBINED_CHARS = 6000  # to avoid huge prompt sizes
MAX_FILES_COMBINED = 12
REPORT_FILE = "scan_report.txt"


# ---------- Utilities ----------
async def download_github_repo(github_url: str) -> Tuple[str, Path]:
    """
    Download a GitHub repo as ZIP (tries main then master), extract into tempdir.
    Returns (top_dir_path, extracted_root_path)
    """
    if github_url.endswith("/"):
        github_url = github_url[:-1]

    # produce codeload URL for main branch
    base = github_url.replace("github.com", "codeload.github.com")
    zip_main = base + "/zip/refs/heads/main"
    zip_master = base + "/zip/refs/heads/master"

    temp_dir = tempfile.mkdtemp(prefix="sniper_repo_")
    zip_path = os.path.join(temp_dir, "repo.zip")

    async with aiohttp.ClientSession() as session:
        for candidate in (zip_main, zip_master):
            print(Fore.YELLOW + f"⬇️  Trying to download: {candidate}")
            async with session.get(candidate) as resp:
                if resp.status == 200:
                    with open(zip_path, "wb") as f:
                        f.write(await resp.read())
                    print(Fore.GREEN + "✅ Download succeeded.")
                    break
                else:
                    print(Fore.YELLOW + f"⚠️ Attempt returned status {resp.status}")
        else:
            raise Exception("Failed to download repository from GitHub (checked 'main' and 'master').")

    # extract
    with zipfile.ZipFile(zip_path, "r") as z:
        z.extractall(temp_dir)

    # After extraction, the repository contents will be in a single subfolder whose name we can detect:
    entries = [p for p in os.listdir(temp_dir) if os.path.isdir(os.path.join(temp_dir, p))]
    if entries:
        extracted_root = Path(temp_dir) / entries[0]
    else:
        extracted_root = Path(temp_dir)

    print(Fore.GREEN + f"📦 Extracted to: {extracted_root}")
    return temp_dir, extracted_root


def collect_text_files(root: Path) -> List[Path]:
    """Walk tree and collect readable code/text files by extension."""
    files = []
    for sub in root.rglob("*"):
        if sub.is_file():
            if sub.name.lower() == "dockerfile" or sub.suffix.lower() in ALLOWED_EXTENSIONS:
                files.append(sub)
    files.sort()
    return files


# ---------- Local heuristic scanner ----------
HEURISTIC_PATTERNS = {
    "Data exfiltration / network POST": r"(requests\.post|fetch\(|axios\.post|urllib\.request|http\.post|fetch\(|socket\.send)",
    "Command execution / shell": r"(os\.system|subprocess\.Popen|subprocess\.call|eval\(|exec\(|system\(|popen\()",
    "Encoded / obfuscated payload": r"(base64\.b64decode|binascii\.a2b_base64|eval\(base64|from_base64|decode\('base64')",
    "Dangerous install/run pattern": r"(curl\s+.*\|\s*sh|wget\s+.*\|\s*sh|chmod\s+\+x\s+.*\&\&\s*\./)",
    "Suspicious permission change": r"(chmod\s+\d{3,4}|chown\s+)",
    "Hardcoded secret / token": r"(AKIA|BEGIN RSA PRIVATE KEY|PRIVATE KEY|api_key|secret|token\s*=)",
    "Downloads & exec binaries": r"(wget\s+http|curl\s+-fsSL|requests\.get\(.*content\))",
    "File deletion / cleanup": r"(rm\s+-rf|os\.remove|shutil\.rmtree)",
    "Cryptominer related": r"(xmrig|minerd|ethminer|cpuminer)",
    "Privilege escalation / sudo": r"\bsudo\b"
}


def local_heuristic_scan(content: str) -> List[str]:
    """Return list of matched heuristic descriptions."""
    findings = []
    for desc, patt in HEURISTIC_PATTERNS.items():
        if re.search(patt, content, re.IGNORECASE):
            findings.append(desc)
    return findings


# ---------- AI interaction ----------
async def ai_scan_with_deepai(prompt_text: str) -> str:
    """
    Open deepai.org/chat with Playwright, paste prompt_text, click send, wait for final response using helper.
    Returns the raw AI response (string).
    """
    # NOTE: The helper get_final_response expects the page to produce div.outputBox elements.
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.goto("https://deepai.org/chat", wait_until="domcontentloaded")
        await asyncio.sleep(1.5)

        # Fill prompt
        textarea = await page.wait_for_selector("#persistentChatbox", timeout=10000)
        await textarea.click()
        await textarea.fill(prompt_text)
        await asyncio.sleep(0.3)

        send_btn = await page.wait_for_selector("#chatSubmitButton", timeout=5000)
        await send_btn.click()

        print(Fore.CYAN + "⏳ Waiting for AI response...")
        response = await get_final_response(page, set())
        await browser.close()
        return response


def build_security_prompt(chunk_text: str) -> str:
    """Build the enhanced security prompt (strict output format)."""
    prompt = textwrap.dedent(
        f"""
        You are a cybersecurity code auditor. I will paste source code and file excerpts below.
        Your job: analyze and determine if the content is SAFE, SUSPICIOUS, or DANGEROUS for a user who would download and run it.

        Specifically identify:
         - Data exfiltration, network calls that send secrets, or telemetry that looks like exfiltration.
         - Remote execution / post-install scripts / auto-execute hooks.
         - Obfuscated code (base64 blobs, eval, long hex strings that are executed).
         - Hardcoded credentials, private keys, tokens.
         - Scripts that download binaries and execute them.
         - Persistence mechanisms (cron, systemd, autorun).
         - Any instruction requiring sudo/administrator privileges.

        RESPOND EXACTLY in this structure:

        1) Classification: <SAFE | SUSPICIOUS | DANGEROUS>
        2) Confidence (0-100): <integer percent>
        3) Summary (1-3 lines): <why>
        4) Key findings (bullet list, include file paths and short evidence excerpts, max 8 items)
        5) Immediate risk to a user: <one sentence>
        6) Recommended mitigations (3-6 concrete steps)

        Now analyze the content below (truncate if needed) and follow the above format strictly:

        {chunk_text}
        """
    )
    return prompt.strip()


# ---------- Report helpers ----------
def save_report(text: str, path: str = REPORT_FILE):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text or "No output")
    print(Fore.GREEN + f"📝 Saved report: {path}")


def append_report(text: str, path: str = REPORT_FILE):
    with open(path, "a", encoding="utf-8") as f:
        f.write(text or "")
    print(Fore.GREEN + f"📝 Appended to report: {path}")


# ---------- CLI flows ----------
async def flow_scan_all_in_one(files: List[Path], root: Path):
    """Combine top N files and send as one prompt to AI."""
    to_take = files[:MAX_FILES_COMBINED]
    combined = ""
    for p in to_take:
        try:
            body = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            body = ""
        rel = p.relative_to(root)
        combined += f"\n\n### FILE: {rel} ###\n{body[:2000]}"  # per-file truncate
        if len(combined) > MAX_COMBINED_CHARS:
            break

    prompt = build_security_prompt(combined)
    result = await ai_scan_with_deepai(prompt)
    save_report(result)


async def flow_scan_one_by_one(files: List[Path], root: Path):
    """Iterate files, run AI per file, and append results."""
    if not files:
        print(Fore.YELLOW + "No files found.")
        return

    # start fresh report
    save_report(f"SNIPER per-file AI scan\n\n")

    for idx, p in enumerate(files, start=1):
        print(Fore.YELLOW + f"[{idx}/{len(files)}] Scanning {p.name} ...")
        try:
            body = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            body = ""
        header = f"\n\n=== FILE: {p.relative_to(root)} ===\n"
        append_report(header)
        prompt = build_security_prompt(header + "\n\n" + body[:3000])
        try:
            res = await ai_scan_with_deepai(prompt)
            append_report(res + "\n")
        except Exception as e:
            append_report(f"AI scan failed for {p}: {e}\n")


def flow_scan_local_only(files: List[Path], root: Path):
    """Run local heuristics over all files and produce a summary report."""
    findings = []
    for p in files:
        try:
            body = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            body = ""
        hits = local_heuristic_scan(body)
        if hits:
            findings.append((p.relative_to(root), hits[:8]))
    if not findings:
        txt = "✅ Local heuristic scan: no suspicious patterns detected.\n"
        print(Fore.GREEN + txt)
        save_report(txt)
        return

    lines = ["⚠️ Local heuristic findings:\n"]
    for path, hits in findings:
        lines.append(f"- {path} -> {', '.join(hits)}\n")
    out = "".join(lines)
    print(Fore.RED + out)
    save_report(out)


# ---------- Interactive menu ----------
async def interactive_menu(github_url: str):
    banner()
    print(Fore.CYAN + f"Repository URL: {github_url}\n")
    temp_dir, root = await download_github_repo(github_url)
    files = collect_text_files(root)
    print(Fore.BLUE + f"Found {len(files)} readable files.\n")

    while True:
        print(Fore.YELLOW + "Choose scan mode:")
        print("[1] Scan all files in one (AI)")
        print("[2] Scan one by one (AI per file)")
        print("[3] Scan without AI (local heuristic only)")
        print("[4] Exit")

        choice = input(Fore.CYAN + "\n👉 Enter choice: ").strip()
        if choice == "1":
            await flow_scan_all_in_one(files, root)
        elif choice == "2":
            await flow_scan_one_by_one(files, root)
        elif choice == "3":
            flow_scan_local_only(files, root)
        elif choice == "4":
            print(Fore.MAGENTA + "👋 Exiting...")
            break
        else:
            print(Fore.RED + "Invalid choice. Try again.")


# ---------- Entrypoint ----------
def print_usage_and_exit():
    print("Usage: python -m sniper.scanner <github_repo_url>")
    sys.exit(1)


async def _main_async():
    if len(sys.argv) < 2:
        print_usage_and_exit()
    url = sys.argv[1]
    try:
        await interactive_menu(url)
    except Exception as e:
        print(Fore.RED + f"Fatal error: {e}")
        raise


def main():
    asyncio.run(_main_async())


if __name__ == "__main__":
    main()

