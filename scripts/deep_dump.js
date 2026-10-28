Java.perform(function () {
  var dir = "/data/local/tmp/sentinel-unpack";
  try { Java.use("java.lang.Runtime").getRuntime().exec(["mkdir", "-p", dir]); } catch (e) {}
  var seen = {};
  var n = 0;
  function dump(addr, tag) {
    try {
      var m = new Uint8Array(Memory.readByteArray(addr, 8));
      if (m[0] !== 0x64 || m[1] !== 0x65 || m[2] !== 0x78 || m[3] !== 0x0a) return;
      var size = Memory.readU32(addr.add(32));
      if (size < 112 || size > 120 * 1024 * 1024) return;
      var k = addr.toString() + ":" + size;
      if (seen[k]) return;
      seen[k] = true;
      var f = new File(dir + "/" + tag + "_" + addr.toString(16) + "_" + size + ".dex", "wb");
      f.write(Memory.readByteArray(addr, size));
      f.close();
      n++;
      console.log("[deepdump] saved " + tag + " @" + addr.toString(16) + " size=" + size);
    } catch (e) {}
  }
  function scan(tag) {
    var rs = Process.enumerateRanges("r--").concat(
      Process.enumerateRanges("rw-"), Process.enumerateRanges("r-x"), Process.enumerateRanges("rwx"));
    var hits = 0;
    rs.forEach(function (r) {
      if (r.size < 4096 || r.size > 128 * 1024 * 1024) return;
      try {
        Memory.scan(r.base, r.size, "64 65 78 0a 30 33", {
          onMatch: function (a) { hits++; dump(a, tag); },
          onComplete: function () {},
        });
      } catch (e) {}
    });
    console.log("[deepdump] pass " + tag + " ranges=" + rs.length + " magicHits=" + hits + " saved=" + n);
  }
  // 多轮时机：壳的懒解密通常发生在首帧渲染与首个 Activity 创建之后
  [1200, 3500, 7000, 12000, 18000, 25000].forEach(function (t) { setTimeout(function () { scan("p" + t); }, t); });
  setTimeout(function () { console.log("[deepdump] finished total=" + n); }, 30000);
});
