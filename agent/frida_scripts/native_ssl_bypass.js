(function () {
  ["libssl.so", "libcrypto.so", "libconscrypt_jni.so"].forEach(function (lib) {
    var mod = Process.findModuleByName(lib);
    if (!mod) return;
    ["SSL_CTX_set_verify", "SSL_set_verify"].forEach(function (fn) {
      var addr = Module.findExportByName(lib, fn);
      if (addr) {
        Interceptor.replace(addr, new NativeCallback(function () {}, "void", ["pointer", "int", "pointer"]));
        console.log("[*] " + lib + "!" + fn + " -> no-op");
      }
    });
    var gv = Module.findExportByName(lib, "SSL_get_verify_result");
    if (gv) {
      Interceptor.replace(gv, new NativeCallback(function () { return 0; }, "long", ["pointer"]));
      console.log("[*] " + lib + "!SSL_get_verify_result -> X509_V_OK");
    }
  });
  console.log("[*] native ssl bypass installed");
})();
