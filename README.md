
# 🧠 SNIPER | GitHub Files Scanner

```
███████╗███╗   ██╗██╗██████╗ ███████╗██████╗ 
██╔════╝████╗  ██║██║██╔══██╗██╔════╝██╔══██╗
███████╗██╔██╗ ██║██║██║  ██║█████╗  ██████╔╝
╚════██║██║╚██╗██║██║██║  ██║██╔══╝  ██╔══██╗
███████║██║ ╚████║██║██████╔╝███████╗██║  ██║
╚══════╝╚═╝  ╚═══╝╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝
        SNIPER | GitHub Files Security Scanner
           Author: <Gh. Ilyass> | 2025 Edition
```


## 📜 Overview

**SNIPER** is an intelligent reconnaissance & security scanner designed to analyze **GitHub repositories** before you download or execute them.

It detects **dangerous, malicious, or privacy-invasive** code using:

* **Heuristic pattern detection**
* **Static code inspection**
* **Optional AI analysis (DeepAI)**

The goal:

> Protect users from hidden scripts that steal data, execute malicious commands, or install backdoors in open-source tools.

---

## ⚔️ Key Features

| Type                            | Description                                                                               |                               |
| ------------------------------- | ----------------------------------------------------------------------------------------- | ----------------------------- |
| 🧠 **AI Mode**                  | Uses DeepAI to analyze repository code and classify it as SAFE, SUSPICIOUS, or DANGEROUS. |                               |
| ⚙️ **Heuristic Mode**           | Detects known malicious patterns — `eval()`, `os.system()`, `curl                         | bash`, encoded payloads, etc. |
| 🕵️ **Automatic Repo Analysis** | Downloads, extracts, and scans public GitHub repositories.                                |                               |
| 🧩 **Interactive CLI**          | Choose between AI scan, per-file analysis, or local offline scan.                         |                               |
| 📁 **Multi-Language Support**   | Supports `.py`, `.php`, `.js`, `.html`, `.sh`, `.yml`, `.json`, `.md`, and more.          |                               |
| 💾 **Report Generator**         | Saves all findings into `scan_report.txt` for offline review.                             |                               |

---

## 💻 Installation

### Requirements

* Python 3.9+
* Playwright
* Internet connection (for AI mode)

### Setup

```bash
git clone https://github.com/IlyassCODEX/SNIPER-Githubfiles.git
cd SNIPER-Github-Files-Scanner
pip install -r requirements.txt
python -m playwright install
```

---

## ⚙️ Usage

### Basic Command

```bash
python -m sniper.scanner https://github.com/owner/repo
```

### Interactive Menu

```
[1] Scan all in one (AI)
[2] Scan one by one (AI per file)
[3] Scan without AI (heuristic only)
[4] Exit
```

---

## 🧩 Example

```bash
python -m sniper.scanner https://github.com/IlyassCODEX/ARTEX
```

**Output Example:**

```
⬇️  Downloading repository from https://codeload.github.com/IlyassCODEX/ARTEX/zip/refs/heads/main
✅ Repository extracted.

📂 Found 37 files.

Choose scan mode:
[1] Scan all in one (AI)
[2] Scan one by one (AI per file)
[3] Scan without AI (heuristic only)
[4] Exit
👉 Your choice: 3

⚠️ Local heuristic findings:
- src/main.py -> Command Execution, Encoded Payload
- setup/install.sh -> Binary Download/Run

📝 Heuristic results saved to scan_report.txt
```

---

## 🧠 AI Analysis Example

If you choose AI mode, you’ll get professional-style output:

```
=== DeepAI Security Analysis ===

Classification: SUSPICIOUS
Confidence: 82%
Summary: The repository contains shell scripts and encoded Python payloads that execute network requests.
Key Findings:
 - setup/install.sh -> downloads and executes binaries
 - src/core.py -> uses eval() on user input
 - config/api.txt -> hardcoded API key
Immediate Risk: High — running this project may execute external scripts.
Mitigation: Remove untrusted shell code, sanitize user input, verify file hashes.
```

---

## 📂 Supported File Types

| Extension       | Language/Type |
| --------------- | ------------- |
| `.py`           | Python        |
| `.php`          | PHP           |
| `.js`           | JavaScript    |
| `.html`, `.htm` | Web files     |
| `.sh`           | Shell scripts |
| `.yml`, `.yaml` | Config files  |
| `.json`         | Data files    |
| `.md`, `.txt`   | Documentation |

---

## 🧬 Detection Heuristics

| Category             | Example Patterns                          |                |     |
| -------------------- | ----------------------------------------- | -------------- | --- |
| Command Execution    | `os.system`, `subprocess.Popen`, `exec()` |                |     |
| Encoded Payloads     | `base64.b64decode`, long hex strings      |                |     |
| Network Exfiltration | `requests.post`, `fetch()`                |                |     |
| Privilege Escalation | `sudo`, `chmod 777`                       |                |     |
| Binary Execution     | `curl ...                                 | sh`, `wget ... | sh` |

---

## 📁 Output

All results are saved in a single file:

```
scan_report.txt
```

Example snippet:

```
- setup.py -> Command Execution
- main.sh -> Binary Download/Run
Classification: DANGEROUS
Confidence: 94%
Immediate Risk: Could execute remote shell payloads.
```

---

## 🔐 Security Notice

* ⚠️ **SNIPER does not execute any code** — it only performs static analysis and AI-based reasoning.
* ❗ Always review suspicious code manually.
* 💻 Run unknown repositories inside **virtual machines or sandboxes**.
* 🧩 This tool assists in security awareness; it does not replace professional audits.

---

## 🧰 Troubleshooting

| Issue                            | Solution                                                      |
| -------------------------------- | ------------------------------------------------------------- |
| `playwright.errors.TimeoutError` | Run `python -m playwright install` again.                     |
| Empty AI output                  | DeepAI site may be slow — re-run or switch to heuristic mode. |
| “main branch not found”          | Repo uses another branch — specify it manually in URL.        |

---

---

## 🧩 Credits

* **Lead Developer:** `<Gh. Ilyass>`
* **Language:** Python 3
* **Frameworks:** Playwright, aiohttp, colorama
* **AI Integration:** DeepAI Chat

---

## 📜 License

```
MIT License
Copyright (c) 2025 <Gh. Ilyass>
```
