# Malware Analysis Python Tools Portfolio

This portfolio documents a set of Python scripts developed for basic malware analysis, including hashing, PE inspection, string extraction, YARA scanning, and an integrated analysis script.

---

## 1. Overview

The project contains five scripts designed to assist in static malware analysis:

1. **hash_calc.py** – Calculates MD5, SHA1, and SHA256 hashes.
2. **integrated_script.py** – Combines hashing, string extraction, PE import analysis, IOC detection, and a simple YARA scan.
3. **pe_info.py** – Extracts PE file metadata and imports.
4. **strings_extract.py** – Extracts printable ASCII strings from binary files.
5. **yara_test.py** – Tests files against a YARA rule.

This suite is intended for educational purposes, testing, and initial malware triage.

---

## 2. File Explanations

### 2.1 hash_calc.py

**Purpose:** Compute cryptographic hashes of a file.

**Key Features:**

* Supports MD5, SHA1, SHA256.
* Efficient reading of large files in chunks.

**Usage:**

```
python hash_calc.py <file_path>
```

*(Insert screenshot of terminal output showing hash values)*

**Sample Output:**

```
MD5:    <hash>
SHA1:   <hash>
SHA256: <hash>
```

---

### 2.2 integrated_script.py

**Purpose:** Unified malware analysis tool.

**Key Features:**

* Computes hashes.
* Extracts strings (first 100 for brevity).
* PE import analysis (using `pefile`).
* Detects IOCs (URLs and IPs) in the binary.
* Runs a simple YARA rule.

**Usage:**

```
python integrated_script.py <file_path>
```

*(Insert screenshot showing integrated analysis output with hashes, imports, strings, IOCs, and YARA matches)*

---

### 2.3 pe_info.py

**Purpose:** Extract detailed information from PE files.

**Key Features:**

* Entry point, image base, and section count.
* Imports and first few functions per DLL.

**Usage:**

```
python pe_info.py <pe_file_path>
```

*(Insert screenshot showing PE metadata and imports)*

---

### 2.4 strings_extract.py

**Purpose:** Extract printable ASCII strings from a binary.

**Key Features:**

* Minimum length configurable (default 4).
* Extracts strings efficiently.

**Usage:**

```
python strings_extract.py <file_path>
```

*(Insert screenshot showing first 200 extracted strings)*

---

### 2.5 yara_test.py

**Purpose:** Simple YARA rule tester.

**Key Features:**

* Detects presence of specified strings (e.g., "http").
* Easily extendable with additional rules.

**Usage:**

```
python yara_test.py <file_path>
```



---

## 3. Workflow Demonstration

1. **Hashing:** Quickly identify file fingerprints using `hash_calc.py`.
2. **PE Analysis:** Understand the file’s structure, entry point, and imports with `pe_info.py`.
3. **String Extraction:** Identify embedded strings or indicators of compromise using `strings_extract.py`.
4. **IOC & YARA Scanning:** Use `integrated_script.py` or `yara_test.py` to detect URLs, IPs, or known patterns.

*(Insert a series of screenshots showing a sample file being analyzed through all scripts.)*

---

## 4. Conclusion

This collection of scripts provides a basic but comprehensive static malware analysis toolkit. The integrated approach allows beginners to:

* Generate hashes.
* Explore PE structure.
* Extract and analyze strings.
* Detect basic IOCs.
* Perform YARA scanning.

It is ideal for educational purposes, initial malware triage, and understanding Python-based automation for malware analysis.

---


