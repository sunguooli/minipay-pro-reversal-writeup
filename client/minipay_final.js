'use strict';

Java.perform(function () {
    // TLS -> 系统默认信任（配合 Charles 解密）
    try {
        const SSLContext = Java.use('javax.net.ssl.SSLContext');
        const init = SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;',
            '[Ljavax.net.ssl.TrustManager;',
            'java.security.SecureRandom'
        );
        init.implementation = function (km, tm, sr) {
            console.log('[TLS] init -> 系统默认');
            return init.call(this, km, null, sr);
        };
        console.log('[+] TLS hook ok');
    } catch (e) { console.log('[-] TLS: ' + e); }

    // Java c() 只观察，不修改
    try {
        const P = Java.use('com.minipay.pro.runtime.p');
        const c = P.c.overload();
        c.implementation = function () {
            const real = c.call(this);
            console.log('[Java-c] real=0x' + (real >>> 0).toString(16) + '（原样放行）');
            return real;
        };
        console.log('[+] Java c() observe ok');
    } catch (e) { console.log('[-] c(): ' + e); }

    // NativeBridge.a() 黄金向量
    try {
        const NB = Java.use('com.minipay.pro.security.NativeBridge');
        NB.a.overloads.forEach(function (ol, idx) {
            ol.implementation = function () {
                const args = [];
                for (let i = 0; i < arguments.length; i++) args.push(String(arguments[i]));
                const ret = ol.apply(this, arguments);
                console.log('[a#' + idx + '] args=' + JSON.stringify(args));
                console.log('[a#' + idx + '] ret=' + ret);
                return ret;
            };
        });
        console.log('[+] NativeBridge.a observe ok');
    } catch (e) { console.log('[-] a(): ' + e); }
});

function installNative(base) {
    // 唯一的"攻击"：电表归零，抹掉 Frida 特征位 bit1
    Interceptor.attach(base.add(0x2BA4), {
        onLeave: function (retval) {
            console.log('[meter] raw=' + retval.toInt32() + ' -> 0');
            retval.replace(0);
        }
    });
    console.log('[+] native meter hook ok @ ' + base);
}

const timer = setInterval(function () {
    const m = Process.findModuleByName('libmpguard.so');
    if (m) {
        clearInterval(timer);
        installNative(m.base);
    }
}, 100);
