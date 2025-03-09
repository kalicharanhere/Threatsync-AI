# Threat Report Analyzer
A lightweight tool to parse threat reports, map actions to MITRE ATT&CK, and evaluate detection rules.

## Tech Stack
- LLM: Google Gemini 1.5-pro (via Google API)
- Embeddings: sentence-transformers/all-MiniLM-L6-v2
- Framework: LangChain + Chroma

## Sample Output
```plaintext
Actions Extracted:
1. Executed a malicious script via PowerShell
2. Downloaded a file

MITRE Mappings:
- Executed a malicious script via PowerShell: T1059.001 (PowerShell, Score: 0.73)
- Downloaded a file: T1144 (Gatekeeper Bypass, Score: 0.94)

Detection Results:
- Executed a malicious script via PowerShell:
  Detectable: Yes
  Rule: 'Powershell script compiling code using CSC.exe...' (ID: 92006, Score: 0.76)
  Why: Matches malicious PowerShell activity.
- Downloaded a file:
  Detectable: Yes
  Rule: 'File added to the system...' (ID: 554, Score: 1.27)
  Why: Triggers on file system changes.
