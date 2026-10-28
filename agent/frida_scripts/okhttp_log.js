Java.perform(function () {
  var filter = sp("url", "");
  var Builder = Java.use("okhttp3.Request$Builder");
  Builder.build.overload().implementation = function () {
    var req = this.build();
    try {
      var url = req.url().toString();
      if (filter === "" || url.indexOf(filter) >= 0) {
        console.log("[okhttp] " + req.method() + " " + url);
        var body = req.body();
        if (body !== null) {
          var buf = Java.use("okio.Buffer").$new();
          body.writeTo(buf);
          console.log("[okhttp][body] " + buf.readUtf8());
        }
      }
    } catch (e) { console.log("[okhttp][err] " + e); }
    return req;
  };
  console.log("[*] okhttp request logger installed" + (filter ? " (url contains '" + filter + "')" : ""));
});
