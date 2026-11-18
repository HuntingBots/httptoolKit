/**
 * Universal Android SSL Pinning Bypass for Frida
 * Supports Android 7.0 - 15+ (Conscrypt, BoringSSL, OkHttp3, TrustManager, Flutter, React Native)
 * HTTP Toolkit & Frida Proxy Ready
 */

Java.perform(function () {
    console.log("[*] Injecting Universal SSL Pinning Bypass for Android 14+...");

    // 1. TrustManagerImpl (Android System Default)
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log('[+] Bypassed TrustManagerImpl.verifyChain for host: ' + host);
            return untrustedChain;
        };
    } catch (e) {
        console.log('[-] TrustManagerImpl not found: ' + e);
    }

    // 2. OkHttp3 CertificatePinner
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (str, list) {
            console.log('[+] Bypassed OkHttp3 CertificatePinner: ' + str);
            return;
        };
        CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function (str, certs) {
            console.log('[+] Bypassed OkHttp3 CertificatePinner (array): ' + str);
            return;
        };
    } catch (e) {
        console.log('[-] OkHttp3 CertificatePinner not found: ' + e);
    }

    // 3. NetworkSecurityConfig (Android 7+)
    try {
        var NetworkSecurityTrustManager = Java.use('android.security.net.config.NetworkSecurityTrustManager');
        NetworkSecurityTrustManager.checkPins.implementation = function (pins) {
            console.log('[+] Bypassed NetworkSecurityTrustManager.checkPins');
            return;
        };
    } catch (e) {
        console.log('[-] NetworkSecurityTrustManager not found: ' + e);
    }

    // 4. Custom X509TrustManager
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var TrustManager = Java.registerClass({
            name: 'tech.httptoolkit.TrustAllManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {},
                getAcceptedIssuers: function () { return []; }
            }
        });
        var TrustManagers = [TrustManager.$new()];
        var SSLContext_init = SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom'
        );
        SSLContext_init.implementation = function (keyManager, trustManager, secureRandom) {
            console.log('[+] Replaced SSLContext TrustManager with TrustAllManager');
            SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
        };
    } catch (e) {
        console.log('[-] Custom X509TrustManager override failed: ' + e);
    }

    // 5. WebView SSL Error Bypass
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function (view, handler, error) {
            console.log('[+] Bypassed WebViewClient.onReceivedSslError');
            handler.proceed();
        };
    } catch (e) {
        console.log('[-] WebViewClient not found: ' + e);
    }

    // 6. Native BoringSSL / OpenSSL Hook (e.g. Flutter / Native C++ networking)
    try {
        var m = Process.findModuleByName("libflutter.so") || Process.findModuleByName("libcrypto.so") || Process.findModuleByName("libssl.so");
        if (m) {
            console.log('[*] Found native library: ' + m.name + ', applying native hooks...');
            var ssl_verify_result_addr = Module.findExportByName(m.name, "ssl_verify_result");
            if (ssl_verify_result_addr) {
                Interceptor.replace(ssl_verify_result_addr, new NativeCallback(function () {
                    console.log('[+] Native ssl_verify_result bypassed');
                    return 0; // ssl_verify_ok
                }, 'int', []));
            }
        }
    } catch (e) {
        console.log('[-] Native SSL Hook note: ' + e);
    }

    console.log('[+] Universal SSL Pinning bypasses applied successfully!');
});
