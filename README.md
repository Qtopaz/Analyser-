# Analyser - Automated HDD & Memory Forensics Script

**Analyser** is a Bash-based script for automating forensic analysis on HDD and memory image files. It leverages open-source tools such as `Volatility`, `Binwalk`, `Foremost`, `Bulk_Extractor`, and `Strings` to extract and analyze digital artifacts.

-----------------------------
Usage:
chmod +x analyser.sh
sudo ./analyser.sh
-----------------------------
## 🧰 Features

### 🧠 Memory Image Analysis:
- Detects Volatility profile automatically
- Runs a full Volatility module sweep: processes, DLLs, registry, kernel memory, networking, and more
- Performs carving and scanning with:
  - `Foremost` (file carving)
  - `Bulk_Extractor` (email, URLs, PCAPs, domains, etc.)
  - `Strings` (ASCII extraction)
- Organizes results into structured directories
- Generates analysis statistics per tool

### 💽 HDD Image Analysis:
- Performs binary extraction with:
  - `Binwalk` (file type detection)
  - `Foremost` (carving)
  - `Bulk_Extractor` and `Strings`
- Generates summary and statistics for all findings

---

## ⚙️ Requirements

Ensure the following tools are installed on your system:

- `volatility` (version 2.x)
- `binwalk`
- `foremost`
- `bulk_extractor`
- `strings`
- `awk`, `grep`, `cut`, `du`, `find`

You can install them via:

```bash
sudo apt update
sudo apt install volatility binwalk foremost bulk-extractor

