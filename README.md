# Intune macOS FileVault Key Audit (One-Off)

## Overview
This repo/folder contains a **one-off** PowerShell script that audits **macOS devices managed by Microsoft Intune** and reports whether each device has a **FileVault recovery key escrowed to Intune**.

**Important:** The script does **not** display or export any FileVault recovery key values. It only records whether a key is retrievable.

---

## What This Checks
For each Intune managed device with `operatingSystem = macOS`:
- **Corporate-owned devices:** attempts to retrieve the FileVault recovery key (without printing it)
  - If the API returns a non-empty value → considered **escrowed**
  - If the API returns 404/not found → considered **not escrowed** (or not available)
- **Personal/BYOD devices:** reported separately as **not accessible to admins** (expected behavior)

> This is an **escrow validation** check (key retrievability), not an encryption posture validation (FileVault enabled/disabled).

---

## Why Graph Beta
The Microsoft Graph endpoint used to retrieve FileVault recovery keys (`getFileVaultKey`) is currently exposed via **Microsoft Graph /beta**.
Beta endpoints can change more frequently than v1.0.

---

## Safety / Data Handling
- ✅ No recovery keys are printed to the screen
- ✅ No recovery keys are written to disk
- ✅ Output CSV includes device metadata and a boolean escrow result only

---

## Requirements

### PowerShell
- PowerShell 7+ recommended (Windows/macOS compatible)

### Modules (install once)
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
Install-Module Microsoft.Graph.Beta -Scope CurrentUser
