(function () {
  var mod = Process.findModuleByName("libflutter.so");
  if (!mod) { console.log("[!] libflutter.so 未加载：确认这是 Flutter 应用，或用 spawn 模式重试"); return; }
  // BoringSSL ssl_x509.cc ssl_verify prologues (arm64), community-standard.
  var patterns = [
    "FF 03 01 D1 FD 7B 01 A9 3F C3 00 91 FA 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9",
    "F4 4F 04 A9 FD 7B 05 A9 FD C3 01 91 B5 00 00 34 C0 02 00 34"
  ];
  for (var i = 0; i < patterns.length; i++) {
    var matches;
    try {
      matches = Memory.scanSync(mod.base, mod.size, patterns[i]);
    } catch (e) { continue; }
    if (matches.length > 0) {
      matches.forEach(function (m) {
        Interceptor.attach(m.address, { onLeave: function (ret) { ret.replace(0); } });
        console.log("[*] ssl_verify patched @ " + m.address + " (pattern " + i + ")");
      });
      return;
    }
  }
  console.log("[!] 两个 pattern 都没命中：flutter 版本过新或引擎被改动，可改用 reFlutter 重打包方案");
})();
