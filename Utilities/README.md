# Evo Utilities

This directory contains helper PowerShell utilities related to the **Evo Windows Agent**.

---

## 📄 Script: `EvoEnableWithDuo.ps1`

This script is intended for environments where **Evo** is used alongside **Duo Security**. It helps configure the Windows logon experience so Evo and Duo can coexist and operate as expected.

> ❗ **Note:** This script is designed for advanced administrators who understand their existing Duo/Evo deployment and Windows logon flows. Always test in a lab or pilot group before broad deployment.

### ✔️ Features

- Applies recommended Windows logon and credential provider settings for Evo + Duo coexistence
- Can be run interactively or silently (suitable for RMM/Intune/GPO deployment)
- Includes basic validation and logging support
- Designed to be **idempotent** where possible (safe to re-run if needed)

---

## 🔧 Parameters

> The exact parameter list and behavior may evolve over time. Run the script with `-Help` (if available) or inspect the script header for the most up‑to‑date details.

| Parameter        | Description                                                                                |
| ---------------- | ------------------------------------------------------------------------------------------ |
| `-Add   `        | Enables the Evo + Duo configuration on the local machine.                                  |
| `-Remove`        | Rolls back or disables the Evo + Duo configuration (when supported by the script version). |
| `-List`          | Shows the current Credential Providers whitelisted by Duo.                                 |

Only one of `-Add` or `-Remove` or `-List` should typically be used in a single invocation.

---

## 🚀 Example Usages

### Enable Evo + Duo configuration (recommended starting point)

```powershell
# From the repository root
cd .\utilities

# Enable Evo + Duo configuration with default options
.\EvoEnableWithDuo.ps1 -Add
```

### Remove / rollback configuration

```powershell
.\EvoEnableWithDuo.ps1 -Remove
```

> 💡 **Tip:** When deploying via RMM/Intune/GPO, use the `-Enable` (or `-Disable`) parameter and consider adding `-Verbose` for easier troubleshooting.

---

## ⚠️ Notes

- **Admin Rights Required**: Must be run from an elevated PowerShell session.
- Always test in a non‑production environment before wide rollout.
- Behavior may differ depending on the existing Duo configuration and Windows version; review results carefully.

---

## 📬 Support

Please contact [support@evosecurity.com](mailto:support@evosecurity.com) for assistance with Evo‑related questions.

For Duo‑specific issues, refer to Duo Security documentation or support.

---

## 📝 License

See the root `readme.md` for overall repository license information.
