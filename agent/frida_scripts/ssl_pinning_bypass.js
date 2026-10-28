Java.perform(function () {
  var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
  var SSLContext = Java.use("javax.net.ssl.SSLContext");
  var TrustManager = Java.registerClass({
    name: "com.sentinel.TrustAll",
    implements: [X509TrustManager],
    methods: {
      checkClientTrusted: function () {},
      checkServerTrusted: function () {},
      getAcceptedIssuers: function () { return []; },
    },
  });
  SSLContext.init.overload("[javax.net.ssl.KeyManager[]", "[javax.net.ssl.TrustManager[]", "java.security.SecureRandom")
    .implementation = function (km, tm, sr) {
      console.log("[*] SSLContext.init -> trust all");
      this.init(km, [TrustManager.$new()], sr);
    };
  var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
  var VerifyAll = Java.registerClass({
    name: "com.sentinel.VerifyAll",
    implements: [HostnameVerifier],
    methods: { verify: function () { return true; } },
  });
  try {
    Java.use("javax.net.ssl.HttpsURLConnection").setHostnameVerifier.implementation = function (v) {
      this.setHostnameVerifier(VerifyAll.$new());
    };
  } catch (e) {}
  try {
    var pinner = Java.use("okhttp3.CertificatePinner");
    pinner.check.overload("java.lang.String", "java.util.List").implementation = function () {
      console.log("[*] OkHttp CertificatePinner.check bypassed: " + arguments[0]);
    };
  } catch (e) {}
  try {
    // OkHttp 4.x: the Kotlin compiler renamed check to check$okhttp.
    Java.use("okhttp3.CertificatePinner")["check$okhttp"].overload(
      "java.lang.String",
      "kotlin.jvm.functions.Function0",
      "java.util.Set",
    ).implementation = function (hostname) {
      console.log("[*] OkHttp check$okhttp bypassed: " + hostname);
    };
  } catch (e) {}
  try {
    // NetworkSecurityConfig: stop rejecting user-added CAs.
    var NSC = Java.use("android.security.net.config.NetworkSecurityTrustManager");
    NSC.checkServerTrusted.overload("[Ljava.security.cert.X509Certificate;", "java.lang.String", "java.net.Socket")
      .implementation = function () {};
  } catch (e) {}
  console.log("[*] SSL pinning bypass installed");
});
