# NotPetya (ExPetr) — CAPE Sandbox Forensic Analysis

**A binary-informed case study of NotPetya's execution, privilege checks, cryptographic activity, network behavior, and unconfirmed boot-stage modification.**

[**Read the full technical report (PDF)**](./NotPetya_CAPE_Task4_Deep_Forensic_Analysis_EN.pdf)

> **Research focus:** The sample executed inside the sandbox, but the Windows guest restarted normally. This investigation asks **which stages can be demonstrated by the available evidence**, and why the expected destructive boot sequence was not observed.

## Case at a glance

| Field | Details |
| :--- | :--- |
| Malware family | NotPetya / ExPetr |
| Sample | `NotPetya.dll` — PE32 DLL, x86 |
| SHA-256 | `027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745` |
| Analysis environment | CAPE Sandbox, Task 4, Windows guest `cuckoo1` |
| Execution method | DLL package; `rundll32.exe` invoking export ordinal `#1` |
| Capture | 6 November 2026; 452 seconds recorded |
| Main report | [`NotPetya_CAPE_Task4_Deep_Forensic_Analysis_EN.pdf`](./NotPetya_CAPE_Task4_Deep_Forensic_Analysis_EN.pdf) |

## Executive summary

This study correlates **CAPE behavioral telemetry**, **static PE triage**, and a **Ghidra C-like decompilation** of the submitted DLL. The central finding is that NotPetya **did execute**: its primary process performed file operations, launched child processes, invoked Windows cryptographic APIs, and attempted network connections. However, the recovered telemetry **does not demonstrate a successful raw-disk write or installation of the malicious boot stage**.

A normal reboot is therefore consistent with the observed evidence, but the precise reason for the missing boot-stage transition remains **unresolved**.

### Key findings

- **Confirmed entry-point execution:** `rundll32.exe` (PID `4900`) invoked the DLL's ordinal-1 export.
- **Observed process chain:** `rundll32.exe` → `cmd.exe` → `schtasks.exe`, associated with an attempted scheduled reboot.
- **File operations:** the original temporary DLL was overwritten, and a **381,816-byte PE-like** artifact, `C:\ProgramData\dllhost.dat`, was written.
- **Cryptographic API activity:** **346 successful `CryptEncrypt` calls** were attributed to the primary process. This is **not** evidence that 346 separate files were encrypted.
- **Network activity:** the primary process made **191 `connect` calls**, none successful in the captured API results. Successful lateral movement was **not demonstrated**.
- **Privilege checks:** two `NtOpenProcessToken` requests returned `STATUS_ACCESS_DENIED`, while two others succeeded. The effective privilege state was **not captured conclusively**.
- **Boot-stage uncertainty:** raw-volume/disk code exists in the decompilation, but the available primary-process telemetry shows **no confirmed `PhysicalDrive0` write**.

## Inside the report

The **29-page English-language report** includes:

1. Evidence-backed executive determination and sample identification.
2. Collection methodology, data provenance, and completeness assessment.
3. Timestamped execution chronology and process-tree analysis.
4. File, process, API, and Windows Task Scheduler evidence.
5. Privilege-gated control flow and an investigation of the missing boot stage.
6. Cryptographic activity, resource extraction, and embedded components.
7. Network behavior, connection failures, and attribution caveats.
8. Ghidra function anchors and static-to-dynamic flow mapping.
9. CAPE signature triage, background-process filtering, and false-attribution risks.
10. Reproducibility notes, unanswered questions, and recommended forensic validation.

## Methodology and evidence standards

The analysis distinguishes four levels of confidence:

| Label | Meaning |
| :--- | :--- |
| **Observed** | Directly represented in attributable CAPE process, API, or file telemetry. |
| **Static** | Present in the executable/decompilation; execution during this task is not established. |
| **Inferred** | Consistent with the evidence, but missing a decisive runtime observation. |
| **Not demonstrated** | No supporting observation in the recovered material; **not** proof that an action was impossible. |

The core sources were a recovered CAPE `report.json` and analysis logs, the Ghidra-generated `NotPetya.dll.c`, and the original static triage dump. The report includes specific function anchors so findings can be cross-checked against the decompilation.

### Important limitations

The uploaded CAPE `.tar.gz` was **truncated**. The report and relevant logs were recovered, but not every referenced memory dump, EVTX file, packet capture, screenshot, or dropped binary was independently inspected. Automated CAPE findings were therefore not treated as proof of every behavior they label.

In particular, this case study **does not claim** confirmed MBR replacement, completed file encryption, successful lateral compromise, or a definitive root cause for the normal reboot.

## Report

**[NotPetya_CAPE_Task4_Deep_Forensic_Analysis_EN.pdf](./NotPetya_CAPE_Task4_Deep_Forensic_Analysis_EN.pdf)**

The PDF is the authoritative write-up for this repository. It documents the recorded behavior, the supporting evidence, the corresponding Ghidra references, and what remains unknown.

---

*Malware research and defensive reverse engineering. The sample was analyzed as evidence; no executable malware is required to read this report.*
