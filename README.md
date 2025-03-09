# Threat Report Analyzer
A lightweight tool to parse threat reports, map actions to MITRE ATT&CK, and evaluate detection rules.

## Tech Stack
- LLM: Google Gemini 1.5-pro (via Google API)
- Embeddings: sentence-transformers/all-MiniLM-L6-v2
- Framework: LangChain + Chroma

## Sample Output
```plaintext
=== Threat Report Analysis ===

Actions Extracted:
1. Executed a malicious script via PowerShell
2. Downloaded a file

MITRE ATT&CK Mappings:
- Executed a malicious script via PowerShell:
  Technique: T1059.001 (PowerShell)
  Confidence Score: 0.7307
- Downloaded a file:
  Technique: T1144 (Gatekeeper Bypass)
  Confidence Score: 0.9435

Detection Evaluation:
- Executed a malicious script via PowerShell:
  Yes. The attacker action explicitly mentions executing a malicious script via PowerShell. The rule specifically looks for PowerShell scripts using csc.exe, a common technique for compiling and executing malicious code.  While the action doesn't mention csc.exe specifically, it's plausible the malicious script utilizes it, thus triggering the rule. - Rule: 'Rule ID: 92006
  Rule Description: Powershell script compiling code using CSC.exe, possible malware drop.
  Alert description:: This alert triggers when an attempt to drop and execute malicious code through the powershell script compiling code using CSC,exe.' (Rule ID: Unknown, Score: 0.7615)
  Explanation: No explanation provided
- Downloaded a file:
  Yes.  While the rule description and alert description are a little awkwardly worded, they both indicate monitoring of file system changes. Downloading a file *adds* a file to the system, thus triggering the rule. - Rule: 'Rule ID: 554
  Rule Description: File added to the system.
  Alert description:: This event appears that someone has been added, deleted and modified the file system.' (Rule ID: Unknown, Score: 1.2713)
  Explanation: No explanation provided
