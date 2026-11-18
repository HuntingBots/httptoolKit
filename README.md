# ⚡ HTTP Toolkit Android Clone (Android 14+ Ready & 24/7 Workflow)

An enterprise-grade, 24/7 ready HTTP/HTTPS traffic interception suite for **Android 14+ (API 34/35/37)** based on the open-source HTTP Toolkit architecture and Frida SSL unpinning ecosystem.

---

## 🌟 Key Features

* 📱 **Android 14+ & 15+ Native Compatibility:** Built with modern Android SDK targets (`targetSdk 37`, Jetpack Compose, V2/V3/V4 APK signatures).
* 🔄 **24/7 Automated Build Workflow (CI/CD):** Automated GitHub Actions pipeline that compiles, aligns, signs, and publishes installable Release & Debug APKs directly to GitHub Releases.
* 🌐 **24/7 Continuous Proxy Server:** Standalone Docker Compose & Python server that runs 24/7 on any VPS, cloud host (Render, Railway, Fly.io, Oracle Cloud), or server with a live web traffic dashboard.
* 🛡️ **Android 14+ Conscrypt APEX Store Bypass:** Automated `tmpfs` + `nsenter` mount-namespace injection script and Magisk/KernelSU module to bypass Android 14's immutable APEX CA certificate lock.
* 🔓 **Universal Frida SSL Unpinning:** Universal bypass script for OkHttp3, TrustManagerImpl, NetworkSecurityConfig, WebViews, Flutter, and BoringSSL.
* 🎯 **Fine-Grained Filtering:** Select specific applications or destination ports (80, 443, custom) to intercept without capturing background noise.

---

## 📁 Repository Structure

```tree
httptoolKit/
├── .github/workflows/
│   └── build-apk.yml            # 24/7 GitHub Actions CI/CD Build & Release Pipeline
├── app/                         # Android Client Application Source (Kotlin + Java VPN)
│   ├── src/main/                # App code, VPN engine, UI screens, AndroidManifest
│   └── build.gradle.kts         # Target SDK 37 (Android 14+ ready)
├── server/                      # 24/7 Server Backend & Live Web Dashboard
│   ├── Dockerfile               # Production container image
│   ├── docker-compose.yml       # 1-command 24/7 deployment
│   ├── proxy_server.py          # Asynchronous HTTP/HTTPS proxy + Web UI (port 8081)
│   └── requirements.txt         # Python dependencies (cryptography)
├── scripts/
│   ├── android14-cert-inject.sh # Android 14+ APEX nsenter CA injection script
│   ├── generate-connect-qr.py   # Connect URL & QR Code generator
│   ├── frida/
│   │   ├── universal-unpin.js   # Frida universal SSL pinning bypass
│   │   └── frida-intercept.py   # Frida injector CLI
│   └── magisk-module/           # Magisk/KernelSU/APatch module for permanent CA trust
├── build.gradle.kts             # Root Gradle build file
└── settings.gradle.kts          # Gradle settings
```

---

## 🚀 Quick Start Guide

### Step 1: Build the APK with GitHub Actions (24/7 CI/CD)

Whenever you push commits or trigger manually:
1. Go to the **Actions** tab in this GitHub repository (`HuntingBots/httptoolKit`).
2. Select **Build Android APK (Android 14+ Ready)**.
3. Click **Run workflow** (select `build_type: all`).
4. Once finished:
   - Download the signed APK from the **Artifacts** section, or
   - Go to **Releases** on GitHub and download `httptoolkit-clone-release.apk` directly to your Android device!

---

### Step 2: Run the 24/7 Proxy Server

Deploy the server on your VPS, server, or cloud host so Android can intercept traffic 24/7 without needing a desktop computer open.

#### Option A: Docker (Recommended)
```bash
cd server
docker compose up -d --build
```
* **Proxy Port:** `8000` (Routes all Android traffic)
* **Web Inspection UI:** `http://<your-server-ip>:8081` (Live request stream)

#### Option B: Standalone Python
```bash
pip install -r server/requirements.txt
python3 server/proxy_server.py
```

---

### Step 3: Connect Your Android 14+ Device

1. Generate your device connection URL:
   ```bash
   python3 scripts/generate-connect-qr.py --ip <YOUR_SERVER_IP> --port 8000
   ```
2. Copy the generated `https://android.httptoolkit.tech/connect/?data=...` link to your phone's clipboard.
3. Open the **HTTP Toolkit** app on your phone.
4. Tap **Scan QR code** (the app automatically reads the connect URL from your clipboard).
5. The VPN establishes and traffic immediately starts streaming to your 24/7 Web Dashboard!

---

## 🔒 Android 14+ Certificate Installation (Rooted Devices)

Android 14 moved system certificates into an immutable APEX module (`/apex/com.android.conscrypt/cacerts`). Standard user certificates will not be trusted by most apps.

### Method 1: Automated Script (One-Time / ADB)
1. Push your server's CA certificate to the device:
   ```bash
   adb push server/certs/ca.crt /data/local/tmp/ca.crt
   adb push scripts/android14-cert-inject.sh /data/local/tmp/
   ```
2. Run the injector with root privileges:
   ```bash
   adb shell "su -c 'sh /data/local/tmp/android14-cert-inject.sh /data/local/tmp/ca.crt'"
   ```
*This mounts `tmpfs` and uses `nsenter` to inject the certificate into Zygote and all active application mount namespaces.*

### Method 2: Magisk / KernelSU Module (Permanent across Reboots)
1. Zip the `scripts/magisk-module/` folder:
   ```bash
   cd scripts/magisk-module
   zip -r ../../httptoolkit-ca-android14.zip .
   ```
2. Transfer `httptoolkit-ca-android14.zip` to your phone and flash it in **Magisk Manager** or **KernelSU**.
3. Reboot your device. All apps now trust your 24/7 proxy certificate!

---

## 🪝 Universal Frida SSL Pinning Bypass

For apps with hardcoded certificate hashes (OkHttp3 pinning, Flutter BoringSSL, React Native):

1. Start `frida-server` on your Android device:
   ```bash
   adb shell "su -c '/data/local/tmp/frida-server &'"
   ```
2. Inject the universal unpinning script into your target application:
   ```bash
   python3 scripts/frida/frida-intercept.py -p com.target.app --spawn
   ```

---

## ⚙️ GitHub Actions Signing Configuration (Optional)

The GitHub Actions workflow automatically generates a self-signed V2/V3/V4 release keystore if no custom secrets are configured.

To use your own production Android signing key, add these **GitHub Repository Secrets**:
* `ANDROID_SIGNING_JKS_BASE64`: Base64 encoded `.jks` or `.keystore` file
* `SIGNING_KEY_ALIAS`: Your key alias
* `SIGNING_KEY_STORE_PASSWORD`: Keystore password
* `SIGNING_KEY_PASSWORD`: Key password

---

## 🇮🇳 हिंदी सारांश (Hindi / Hinglish Overview)

* **Android 14+ Support:** Android 14 aur 15 ke APEX certificate store aur private namespaces ke liye full `nsenter` injector aur Magisk module ready hai.
* **24/7 Build Workflow:** `.github/workflows/build-apk.yml` push ya manual trigger par bina kisi error ke Release aur Debug APK build karke direct GitHub Releases me daal deta hai.
* **24/7 Proxy Server:** `server/docker-compose.yml` ko VPS ya Cloud par chala kar 24 ghante background me live traffic intercept kiya ja sakta hai (Web Dashboard: port 8081).
* **Frida Bypass:** `scripts/frida/universal-unpin.js` se kisi bhi app ka SSL pinning bypass karke pura HTTP/HTTPS data dekh sakte hain.
