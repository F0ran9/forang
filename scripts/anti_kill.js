// anti_kill.js — 拦截 native 层早期自杀（爱加密类壳在 JNI_OnLoad 阶段 kill(getpid(),9)）。
// 组合拳：kill(getpid(),SIGKILL/SIGABRT) → 返回 0 假装成功；exit/_exit/abort → 挂起不退出。
// 注意：exit 类是 noreturn，用 Interceptor.replace 换成死循环前的安全停顿（长眠），
// 让壳以为已退出、进程实际保活，后续脚本（dex 扫描）得以运行。
(function () {
  var pid = Process.id;
  var SIGKILL = 9, SIGABRT = 6, SIGSEGV = 11;
  var blocked = 0;

  var killPtr = Module.findExportByName(null, "kill");
  if (killPtr) {
    Interceptor.attach(killPtr, {
      onEnter: function (args) {
        var target = args[0].toInt32();
        var sig = args[1].toInt32();
        if (target === pid && (sig === SIGKILL || sig === SIGABRT || sig === SIGSEGV)) {
          blocked++;
          console.log("[anti_kill] blocked kill(self, " + sig + ") #" + blocked);
          args[1] = ptr(0); // 信号改 0（探测信号），杀死不了任何人
        }
      },
    });
  }

  var exitPtr = Module.findExportByName(null, "exit");
  var exitGrp = Module.findExportByName(null, "exit_group");
  [exitPtr, exitGrp].forEach(function (p, i) {
    if (!p) return;
    try {
      Interceptor.replace(p, new NativeCallback(function (code) {
        console.log("[anti_kill] suppressed exit_group/exit(" + code + ") @" + p + " #" + (++blocked));
        // 不真正退出：长眠保活（壳线程停在这里，主流程其他线程继续）
        Thread.sleep(9999);
      }, "void", ["int"]));
    } catch (e) { console.log("[anti_kill] replace exit failed: " + e); }
  });

  ["_exit", "abort"].forEach(function (name) {
    var p = Module.findExportByName(null, name);
    if (!p) return;
    try {
      Interceptor.replace(p, new NativeCallback(function (a) {
        console.log("[anti_kill] suppressed " + name + "(" + a + ")");
        Thread.sleep(9999);
      }, "void", ["int"]));
    } catch (e) {}
  });

  console.log("[anti_kill] installed (pid=" + pid + ")");
})();
