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

Sample Text:  <img width="479" height="162" alt="image" src="https://github.com/user-attachments/assets/24f9e1c1-4cc4-4f69-863c-a69f65783203" />


<img width="2059" height="120" alt="image" src="https://github.com/user-attachments/assets/ee5d4cb8-4ce5-4457-a834-22114c4e1a28" />


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

<img width="1281" height="358" alt="image" src="https://github.com/user-attachments/assets/b06780f1-1d72-4099-8515-8a658105d2fc" />


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
Uses a .exe file instead of a .txt file 


<img width="1956" height="580" alt="image" src="https://github.com/user-attachments/assets/d69e6373-670c-450b-8757-a2c8d0d61d00" />

<img width="282" height="531" alt="image" src="https://github.com/user-attachments/assets/097cf620-40a4-4c2c-82fb-1d6ac96ae5c3" />

<img width="316" height="530" alt="image" src="https://github.com/user-attachments/assets/7e1ac4b8-6147-414e-a727-a7733de9a39f" />



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

<img width="348" height="100" alt="image" src="https://github.com/user-attachments/assets/f919795f-3ebc-4160-b276-07be5a431b0d" />


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
The script uses a very simple YARA rule: it only matches the exact string "http" and there wasnt any hence why it shows this:

<img width="151" height="35" alt="image" src="https://github.com/user-attachments/assets/b51c2b7f-d316-4b98-aa48-2297c69b147a" />

but once i added "http" to my sample.txt i got this : 

<img width="234" height="30" alt="image" src="https://github.com/user-attachments/assets/7969e943-728b-4995-8d3c-7df8d5b8f65e" />


---

## 3. Workflow Demonstration

1. **Hashing:** Quickly identify file fingerprints using `hash_calc.py`.
2. **PE Analysis:** Understand the file’s structure, entry point, and imports with `pe_info.py`.
3. **String Extraction:** Identify embedded strings or indicators of compromise using `strings_extract.py`.
4. **IOC & YARA Scanning:** Use `integrated_script.py` or `yara_test.py` to detect URLs, IPs, or known patterns.



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


