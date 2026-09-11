const a = "\x48\x65\x6c\x6c\x6f";
const b = "\x57\x6f\x72\x6c\x64";
const c = "\x53\x65\x63\x72\x65\x74";
const d = "\x44\x61\x74\x61";

const payload = "VGhpcyBpcyBhIHRlc3Qgc3RyaW5nIHRvIHNpbXVsYXRlIGVuY29kZWQgY29udGVudCBpbiBhIEphdmFTY3JpcHQgc2FtcGxlLg==";

eval(atob(payload));

console.log(a + b + c + d);
