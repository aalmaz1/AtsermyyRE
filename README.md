# AtsermyyRE
# Romance Scam APK Analysis — Pig Butchering (杀猪盘)

> **DISCLAIMER**
> This repository contains the results of **static analysis** of a suspicious Android application
> distributed via a romance scam. **The APK sample is NOT distributed here.** No malicious code,
> no hardcoded credentials, and no personal data are published.
> This material is provided for **educational and defensive purposes only**.
> If you received a similar APK — do not install it, do not run it, and report it.

---

## Executive Summary

An Android application (`com.FeiQQ.FeiQQ`) was received outside of any official app store
from a person met online, who then suggested installing it. The APK does not exist in
Google Play and has no legitimate publisher. Static analysis shows it is a **dating-themed
application with a hidden investment module** — a classic **pig butchering / romance scam**
pattern:

1. Trust is built through a dating interface (chat, video calls, gifts).
2. The victim is gradually pushed to "invest" USDT via the app.
3. Withdrawal is controlled by the operator's server and is effectively blocked.

The application also collects **full payment card data** and stores the user's
**password and AWS credentials in plaintext**.

---

## Sample Information

| Field | Value |
|---|---|
| Package name | `com.FeiQQ.FeiQQ` |
| SHA-256 | `2e9adbcfeb966e70029b4fead160c08b278276067466137973965fe97936a4c5` |
| VirusTotal | [link to report] |
| Detection at time of check | 0/67 — *absence of signatures, not a proof of safety* |
| Distribution | Sent directly via messenger (not Google Play) |

---

## Manifest Analysis

![Dangerous permissions](images/manifest_permissions.png)
*Dangerous permissions requested by the app.*

Key findings from `AndroidManifest.xml`:

- `MANAGE_EXTERNAL_STORAGE` — access to **all** files on the device, not just user-selected ones.
- `SYSTEM_ALERT_WINDOW` / `SYSTEM_OVERLAY_WINDOW` — draw overlays over other apps (clickjacking / phishing).
- `REQUEST_INSTALL_PACKAGES` — install additional APKs outside Google Play.
- `RECEIVE_BOOT_COMPLETED` — auto-start after reboot.
- `DISABLE_KEYGUARD` — dismiss the lock screen.
- `READ_PHONE_STATE`, `GET_TASKS`, `REAL_GET_TASKS` — device identifiers and running processes.
- `RECORD_AUDIO`, `CAMERA`, `ACCESS_FINE_LOCATION` — microphone, camera, precise location.

![Insecure application settings](images/manifest_application.png)
*Insecure settings: `allowBackup="true"`, `usesCleartextTraffic="true"`, `largeHeap="true"`.*

- `allowBackup="true"` — app data (including `SharedPreferences` with password and tokens) can be
  extracted via `adb backup`.
- `usesCleartextTraffic="true"` — HTTP without encryption is allowed.
- `exported="true"` on `MyWindowmanagerServiceRong` — the service is reachable from other apps.

---

## Hidden Investment Module

![Investment activities in manifest](images/manifest_investment_activities.png)
*Activities implementing the investment flow.*

The manifest contains a complete investment lifecycle that has nothing to do with dating:

- `ChuanTouAct` — investment (创投)
- `ChuanTouBuyAct`, `ChuanTouBuyQueRenAct` — purchase and confirmation
- `ChuanTiLingAct`, `ChuanTouTiLingAct`, `ChuanTiLingSuccessAct` — withdrawal flow
- `Usd_Activity` — USD/USDT operations
- `PayNew_Activity`, `PayStyle_Card_new_Activity`, `Pay_CountryActivity`,
  `RechargeActivity`, `JiaZhiActivity` — payment screens, including card payment

API endpoints (from `Constant.smali`) confirm the same flow:
