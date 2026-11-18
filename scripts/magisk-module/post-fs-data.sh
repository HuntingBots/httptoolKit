#!/system/bin/sh
MODDIR=${0%/*}

mkdir -p "$MODDIR/system/etc/security/cacerts"
chmod 755 "$MODDIR/system/etc/security/cacerts"

# Mirror active system certificates into module directory
if [ -d "/apex/com.android.conscrypt/cacerts" ]; then
    cp -af /apex/com.android.conscrypt/cacerts/* "$MODDIR/system/etc/security/cacerts/" 2>/dev/null || true
fi
if [ -d "/system/etc/security/cacerts" ]; then
    cp -af /system/etc/security/cacerts/* "$MODDIR/system/etc/security/cacerts/" 2>/dev/null || true
fi

# Copy custom user-provided certificates if placed in /data/local/tmp/
if [ -f "/data/local/tmp/ca.crt" ]; then
    HASH=$(openssl x509 -inform PEM -subject_hash_old -in /data/local/tmp/ca.crt 2>/dev/null | head -n 1)
    if [ -n "$HASH" ]; then
        cp -f /data/local/tmp/ca.crt "$MODDIR/system/etc/security/cacerts/${HASH}.0"
    fi
fi

chown -R root:root "$MODDIR/system/etc/security/cacerts"
chmod 644 "$MODDIR/system/etc/security/cacerts"/* 2>/dev/null || true
chcon -R u:object_r:system_file:s0 "$MODDIR/system/etc/security/cacerts" 2>/dev/null || true
