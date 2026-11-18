#!/system/bin/sh
MODDIR=${0%/*}

# Wait until boot completes
until [ "$(getprop sys.boot_completed)" = "1" ]; do
    sleep 2
done

# Run Android 14+ APEX Injection
REBIND="mount --bind $MODDIR/system/etc/security/cacerts /apex/com.android.conscrypt/cacerts"
$REBIND 2>/dev/null || true

ZYGOTE_PIDS=$(pidof zygote zygote64 || true)
for Z_PID in $ZYGOTE_PIDS; do
    if [ -n "$Z_PID" ] && [ -d "/proc/$Z_PID/ns" ]; then
        nsenter --mount=/proc/$Z_PID/ns/mnt -- sh -c "$REBIND" 2>/dev/null || true
    fi
done

APP_PIDS=$(ps -A -o PID,NAME | grep -v PID | awk '{print $1}')
for PID in $APP_PIDS; do
    if [ -d "/proc/$PID/ns" ] && [ "$PID" != "$$" ]; then
        nsenter --mount=/proc/$PID/ns/mnt -- sh -c "$REBIND" 2>/dev/null &
    fi
done
wait
