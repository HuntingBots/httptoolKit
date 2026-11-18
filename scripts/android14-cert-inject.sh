#!/system/bin/sh
# ==============================================================================
# Android 14+ APEX System CA Certificate Injection Tool
# Supports: Android 14 (API 34), Android 15 (API 35), Magisk, KernelSU, APatch
# Bypasses: Conscrypt APEX immutable store & private mount namespaces
# ==============================================================================

set -e

CERT_INPUT="${1:-/data/local/tmp/ca.crt}"
TMP_STAGING="/data/local/tmp/htk-ca-staging"

echo "[*] Android 14+ System CA Injector initializing..."

# Check root privileges
if [ "$(id -u)" != "0" ]; then
    echo "[!] Error: Root access is required. Run via 'su' or 'adb root'."
    exit 1
fi

if [ ! -f "$CERT_INPUT" ]; then
    echo "[!] Error: Certificate file not found at $CERT_INPUT"
    echo "    Usage: $0 /path/to/certificate.crt"
    exit 1
fi

# Calculate Android CA Subject Hash (Old hash algorithm used by Android cacerts)
echo "[*] Processing certificate: $CERT_INPUT"
CERT_HASH=$(openssl x509 -inform PEM -subject_hash_old -in "$CERT_INPUT" | head -n 1)

if [ -z "$CERT_HASH" ]; then
    # Fallback to standard hash if subject_hash_old is not supported
    CERT_HASH=$(openssl x509 -inform PEM -hash -in "$CERT_INPUT" | head -n 1)
fi

CERT_TARGET_NAME="${CERT_HASH}.0"
echo "[+] Detected Certificate Hash: $CERT_TARGET_NAME"

# Clean up previous temporary staging
rm -rf "$TMP_STAGING"
mkdir -p "$TMP_STAGING"
chmod 700 "$TMP_STAGING"

# 1. Backup all existing certificates
echo "[*] Backing up existing trusted certificates..."
if [ -d "/apex/com.android.conscrypt/cacerts" ]; then
    cp -a /apex/com.android.conscrypt/cacerts/* "$TMP_STAGING/" 2>/dev/null || true
fi
if [ -d "/system/etc/security/cacerts" ]; then
    cp -a /system/etc/security/cacerts/* "$TMP_STAGING/" 2>/dev/null || true
fi

# Copy target certificate into staging
cp -f "$CERT_INPUT" "$TMP_STAGING/$CERT_TARGET_NAME"
chmod 644 "$TMP_STAGING"/*
chown root:root "$TMP_STAGING"/*

# 2. Mount tmpfs over /system/etc/security/cacerts
echo "[*] Overlaying in-memory tmpfs on /system/etc/security/cacerts..."
mount -t tmpfs tmpfs /system/etc/security/cacerts
cp -f "$TMP_STAGING"/* /system/etc/security/cacerts/

# Fix permissions and SELinux context
chown root:root /system/etc/security/cacerts/*
chmod 644 /system/etc/security/cacerts/*
chcon u:object_r:system_file:s0 /system/etc/security/cacerts
chcon u:object_r:system_file:s0 /system/etc/security/cacerts/*

echo "[+] System cacerts overlay ready."

# 3. Android 14+ APEX Namespace Injection
if [ -d "/apex/com.android.conscrypt/cacerts" ]; then
    echo "[*] Android 14+ Conscrypt APEX detected. Injecting into mount namespaces..."

    REBIND="mount --bind /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts"
    
    # Bind mount into global namespace
    $REBIND || true

    # Find Zygote processes
    ZYGOTE_PIDS=$(pidof zygote zygote64 || true)
    
    for Z_PID in $ZYGOTE_PIDS; do
        if [ -n "$Z_PID" ] && [ -d "/proc/$Z_PID/ns" ]; then
            echo "[*] Injecting into Zygote (PID: $Z_PID)..."
            nsenter --mount=/proc/$Z_PID/ns/mnt -- sh -c "$REBIND" || true
        fi
    done

    # Inject into currently running app processes
    echo "[*] Propagating to running app process namespaces..."
    APP_PIDS=$(ps -A -o PID,NAME | grep -v PID | awk '{print $1}')
    
    INJECTED_COUNT=0
    for PID in $APP_PIDS; do
        if [ -d "/proc/$PID/ns" ] && [ "$PID" != "$$" ]; then
            nsenter --mount=/proc/$PID/ns/mnt -- sh -c "$REBIND" 2>/dev/null &
            INJECTED_COUNT=$((INJECTED_COUNT + 1))
        fi
    done
    wait
    echo "[+] Successfully injected into $INJECTED_COUNT running process namespaces."
fi

# Clean up staging directory
rm -rf "$TMP_STAGING"

echo "[SUCCESS] CA Certificate $CERT_TARGET_NAME is now trusted system-wide across Android 14+!"
