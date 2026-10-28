(function () {
  var SAVE_DIR = "/data/local/tmp/sentinel-unpack";
  var dumped = {};
  var count = 0;
  function dumpDex(addr) {
    try {
      var magic = new Uint8Array(Memory.readByteArray(addr, 4));
      if (magic[0] !== 0x64 || magic[1] !== 0x65 || magic[2] !== 0x78 || magic[3] !== 0x0a) return;
      var fileSize = Memory.readU32(addr.add(32));
      if (fileSize < 112 || fileSize > 120 * 1024 * 1024) return;
      var key = addr.toString() + ":" + fileSize;
      if (dumped[key]) return;
      dumped[key] = true;
      var path = SAVE_DIR + "/classes_" + addr.toString(16) + "_" + fileSize + ".dex";
      var f = new File(path, "wb");
      f.write(Memory.readByteArray(addr, fileSize));
      f.close();
      count++;
      console.log("[dexdump] saved " + path);
    } catch (e) {}
  }
  function scan() {
    var ranges = Process.enumerateRanges("r--").concat(Process.enumerateRanges("rw-"));
    ranges.forEach(function (range) {
      if (range.size < 112 || range.size > 120 * 1024 * 1024) return;
      try {
        Memory.scan(range.base, range.size, "64 65 78 0a 30 33", {
          onMatch: function (addr) { dumpDex(addr); },
          onComplete: function () {},
        });
      } catch (e) {}
    });
  }
  Java.perform(function () {
    try {
      Java.use("java.lang.Runtime").getRuntime().exec(["mkdir", "-p", SAVE_DIR]);
    } catch (e) {}
    // One pass now (the class loader holds decrypted dex) and one later: late
    // plugins and multidex land between the passes.
    setTimeout(scan, 500);
    setTimeout(scan, 8000);
    setTimeout(function () { console.log("[dexdump] finished, " + count + " dex saved to " + SAVE_DIR); }, 9000);
  });
})();
