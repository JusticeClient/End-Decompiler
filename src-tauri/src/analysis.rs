
use crate::model::{AnalysisReport, Finding, Severity, Verdict};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::{HashMap, HashSet};

struct Rule {
    id: &'static str,
    category: &'static str,
    severity: Severity,
    re: Regex,
    why: &'static str,
}

fn rule(id: &'static str, cat: &'static str, sev: Severity, pat: &str, why: &'static str) -> Rule {
    Rule {
        id,
        category: cat,
        severity: sev,
        re: Regex::new(pat).expect("valid heuristic regex"),
        why,
    }
}

const C_PROC: &str = "Process Execution";
const C_NET: &str = "Networking / Exfiltration";
const C_FILE: &str = "Sensitive File Access";
const C_CRED: &str = "Credential Theft";
const C_REFL: &str = "Reflection / Obfuscation";
const C_SURV: &str = "Surveillance";
const C_NATIVE: &str = "Native / Persistence";
const C_SPREAD: &str = "Self-Propagation";
const C_EVASION: &str = "Anti-Analysis / Evasion";

static RULES: Lazy<Vec<Rule>> = Lazy::new(|| {
    use Severity::*;
    vec![
        rule(
            "discord-webhook", C_NET, Critical,
            r"(?i)https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/(?:v\d+/)?webhooks/\d+/[\w-]+",
            "Hardcoded Discord webhook URL — the classic exfiltration channel for token grabbers.",
        ),
        rule(
            "webhook-path", C_NET, High,
            r"(?i)/api/webhooks/",
            "References a webhook endpoint path — a frequent exfiltration sink.",
        ),
        rule(
            "discord-token-regex", C_NET, Critical,
            r"(?i)(?:[\w-]{24}\.[\w-]{6}\.[\w-]{25,}|[nm][\w-]{23}\.[x][\w-]{5}\.[\w-]{27})",
            "Embedded pattern matching a Discord auth token — a hallmark of token grabbers.",
        ),
        rule(
            "mfa-token-regex", C_NET, Critical,
            r"(?i)mfa\.[\w-]{20,}",
            "Pattern matching an MFA-protected Discord token (token grabber).",
        ),
        rule(
            "discord-api", C_NET, High,
            r"(?i)discord(?:app)?\.com/api/(?:v\d+/)?users/@me|cdn\.discordapp\.com/attachments",
            "Talks to the Discord API / CDN — validating stolen tokens or pulling a payload.",
        ),
        rule(
            "telegram-bot", C_NET, High,
            r"(?i)api\.telegram\.org/bot[\w:-]+",
            "Hardcoded Telegram bot API URL — another common exfiltration channel.",
        ),
        rule(
            "payload-host", C_NET, High,
            r"(?i)(?:pastebin\.com/raw|hastebin\.com|ghostbin|raw\.githubusercontent\.com|anonfiles\.com|transfer\.sh|0x0\.st|workupload|\bbytebin\b|mediafire\.com|file\.io|gofile\.io|catbox\.moe|litterbox\.catbox|tmpfiles\.org|uguu\.se|controlc\.com|termbin\.com|\bngrok\b|trycloudflare|dpaste|telegra\.ph)",
            "Pulls data from a paste/file-host — how multi-stage malware fetches its next payload.",
        ),
        rule(
            "networking", C_NET, Info,
            r"HttpURLConnection|java/net/URL\b|java\.net\.URL|openConnection|java/net/http|HttpClient|java/net/Socket|DatagramSocket",
            "Opens outbound network connections. Common in legit mods; context for any exfiltration.",
        ),
        rule(
            "process-exec", C_PROC, High,
            r"java/lang/ProcessBuilder|\bProcessBuilder\b|Ljava/lang/Process;|getRuntime\(\)\s*\.\s*exec|\.exec\s*\(",
            "Spawns external OS processes (Runtime.exec / ProcessBuilder) — rare and dangerous in a mod.",
        ),
        rule(
            "shell", C_PROC, High,
            r#"(?i)(?:"?cmd(?:\.exe)?"?\s*/c|powershell|pwsh|/bin/(?:ba)?sh|bash\s+-c|\bwscript\b|\bcscript\b|\bmshta\b|\bcertutil\b|\bbitsadmin\b|\bcurl\s|\bwget\s)"#,
            "Invokes a system shell or LOLBin (cmd/PowerShell/sh/certutil/bitsadmin) — runs attacker commands.",
        ),
        rule(
            "powershell-encoded", C_PROC, High,
            r"(?i)-encodedcommand\b|-enc\s+[A-Za-z0-9+/]{16}|FromBase64String|Invoke-Expression|\bIEX\s*\(",
            "Encoded/inline PowerShell — almost always used to run an obfuscated download-and-execute.",
        ),
        rule(
            "browser-storage", C_FILE, High,
            r"(?i)Local Storage|leveldb|Login Data|\\Cookies\b|Web Data|Cookies\.sqlite|Local State|key4\.db|logins\.json",
            "Reads browser/Discord local storage — stealing saved credentials, cookies, and tokens.",
        ),
        rule(
            "browser-dirs", C_FILE, Medium,
            r"(?i)\\Discord\b|discord\b.{0,30}leveldb|Google\\Chrome|\\Edge\\User Data|BraveSoftware\\|\\Opera Software|Mozilla\\Firefox|YandexBrowser",
            "Touches browser / Discord profile directories outside the game — typical credential theft.",
        ),
        rule(
            "appdata", C_FILE, Medium,
            r#"(?i)%APPDATA%|%LOCALAPPDATA%|getenv\(\s*"(?:LOCAL)?APPDATA|AppData\\Roaming|Roaming\\(?:Discord|Microsoft|\.minecraft)"#,
            "Reaches into AppData / Roaming directories — staging area for credential theft.",
        ),
        rule(
            "wallet-ssh", C_FILE, High,
            r"(?i)wallet\.dat|\bid_rsa\b|\.ssh[/\\]|seed\.txt|\bmetamask\b|nkbihfbeogaeaoehlefnkodbefgpgknn|\bExodus\\|Atomic\\|\bElectrum\\|Ethereum\\keystore|Ledger Live|\bTrezor\b|Coinbase Wallet|\bPhantom\\|Binance\\|Trust Wallet|\bGuarda\\|com\.liberty\.jaxx",
            "Targets SSH keys or crypto-wallet files (incl. MetaMask/Exodus/Ledger/Phantom) — data theft.",
        ),
        rule(
            "minecraft-creds", C_CRED, High,
            r"(?i)launcher_accounts\.json|launcher_profiles\.json|\.minecraft[/\\]+(?:launcher_accounts|launcher_profiles)",
            "Reads Minecraft launcher account files — used to hijack the player's account.",
        ),
        rule(
            "dpapi", C_CRED, High,
            r"(?i)CryptUnprotectData|\bDPAPI\b|Crypt32|os_crypt|encrypted_key",
            "Decrypts Windows DPAPI-protected secrets (browser cookies/passwords) — credential theft.",
        ),
        rule(
            "dynamic-load", C_REFL, High,
            r"defineClass|URLClassLoader|java/net/URLClassLoader|new\s+ClassLoader|\.loadClass\(",
            "Loads classes at runtime — lets malware run code that isn't visible in the jar.",
        ),
        rule(
            "reflection", C_REFL, Info,
            r"Class\.forName|getDeclaredMethod|getDeclaredField|setAccessible\s*\(\s*true|sun/misc/Unsafe|jdk/internal/misc/Unsafe",
            "Uses reflection / Unsafe, often to hide or dynamically dispatch sensitive calls.",
        ),
        rule(
            "crypto", C_REFL, Info,
            r"javax/crypto|javax\.crypto|Cipher\.getInstance|SecretKeySpec|IvParameterSpec|\bAES\b|\bRC4\b|\bXOR\b",
            "Encrypts/decrypts data — sometimes used to unpack a hidden payload at runtime.",
        ),
        rule(
            "base64-decode", C_REFL, Info,
            r"(?i)Base64|getDecoder|DatatypeConverter|decodeBase64|FromBase64",
            "Decodes Base64 data — benign alone, but a building block for hidden payloads.",
        ),
        rule(
            "robot-capture", C_SURV, High,
            r"java/awt/Robot|java\.awt\.Robot|new\s+Robot\(|createScreenCapture",
            "Uses java.awt.Robot to capture the screen or synthesize input — spyware behaviour.",
        ),
        rule(
            "clipboard", C_SURV, Medium,
            r"getSystemClipboard|java/awt/datatransfer/Clipboard|StringSelection",
            "Reads or writes the system clipboard — used to steal or hijack copied data.",
        ),
        rule(
            "keylog", C_SURV, High,
            r"(?i)nativeKeyPressed|GlobalScreen|jnativehook|GetAsyncKeyState|SetWindowsHookEx",
            "Hooks low-level keyboard input (native key hooks) — possible keylogger.",
        ),
        rule(
            "webcam", C_SURV, Medium,
            r"(?i)\bwebcam\b|com/github/sarxos|openimaj|org/bytedeco/javacv",
            "Accesses the webcam — surveillance behaviour with no place in a mod.",
        ),
        rule(
            "native-load", C_NATIVE, Medium,
            r"System\.load(?:Library)?\(|\bloadLibrary\b|\bJNA\b|com/sun/jna|\bJNI\b",
            "Loads a native library (.dll/.so) — can run code outside the JVM sandbox.",
        ),
        rule(
            "persistence", C_NATIVE, High,
            r#"(?i)CurrentVersion\\?\\Run|\bschtasks\b|reg(?:\.exe)?\s+add|shell:startup|\\Startup\\|\.lnk"#,
            "Edits autostart / Startup / Run keys — establishes persistence across reboots.",
        ),
        rule(
            "jar-infect", C_SPREAD, High,
            r"(?i)JarOutputStream|putNextEntry.{0,30}\.class|\bmods\b.{0,20}\.jar.{0,20}(?:write|inject)|injectInto.{0,10}jar",
            "Writes into other .jar files — self-propagation, the signature trait of fractureiser.",
        ),
        rule(
            "vm-detect", C_EVASION, Medium,
            r"(?i)VirtualBox|\bVBOX\b|VMwareVMX|vmware.*tools|\bqemu\b|sbiedll|Sandboxie|wine_get_unix|-agentlib:jdwp",
            "Checks for VMs / sandboxes — evasion to avoid analysis.",
        ),
        rule(
            "hidden-attrib", C_EVASION, Medium,
            r#"(?i)attrib\s+\+h|setHidden|FILE_ATTRIBUTE_HIDDEN|\+h\s+\+s"#,
            "Hides files from the user — stealth behaviour.",
        ),
        rule(
            "crypto-address", C_EVASION, Info,
            r"\b(?:bc1[a-z0-9]{25,}|0x[a-fA-F0-9]{40})\b",
            "Hardcoded crypto wallet address — clipboard-hijackers swap the victim's address for this one.",
        ),
        rule(
            "defender-tamper", C_EVASION, Critical,
            r"(?i)Set-MpPreference|Add-MpPreference|DisableRealtimeMonitoring|DisableAntiSpyware|DisableBehaviorMonitoring|-ExclusionPath|-ExclusionExtension|MpCmdRun",
            "Disables or excludes paths from Windows Defender — nothing legitimate does this.",
        ),
        rule(
            "cryptominer", C_NATIVE, Critical,
            r"(?i)stratum\+tcp|stratum\+ssl|\bxmrig\b|supportxmr|nanopool|cryptonight|\brandomx\b|minexmr|\bminerd\b|nicehash|ethermine|pool\.hashvault",
            "Cryptocurrency-miner pool/binary references — cryptojacking the victim's machine.",
        ),
        rule(
            "script-engine", C_REFL, High,
            r"(?i)javax/script|javax\.script|ScriptEngineManager|getEngineByName|\bNashorn\b|bsh/Interpreter|groovy/lang/GroovyShell|GroovyClassLoader|org/python/util|jruby|graal.*polyglot",
            "Runs a scripting engine (JS/Groovy/Python/BeanShell) — arbitrary code execution beyond classloading.",
        ),
        rule(
            "java-agent", C_REFL, High,
            r"(?i)java/lang/instrument|java\.lang\.instrument|\bInstrumentation\b|premain|agentmain|com/sun/tools/attach|VirtualMachine\.attach|loadAgent",
            "Uses the Java instrumentation/agent API — can rewrite or inject code into the running JVM.",
        ),
        rule(
            "unsafe-defineclass", C_REFL, High,
            r"(?i)MethodHandles.{0,40}defineClass|Lookup.{0,20}defineClass|Unsafe.{0,20}defineClass|defineAnonymousClass|defineHiddenClass",
            "Defines classes via Unsafe / MethodHandles — a stealthy way to load hidden code.",
        ),
        rule(
            "destructive", C_NATIVE, High,
            r#"(?i)\bdel\s+/[fqs]|\brd\s+/s|\brmdir\s+/s|rm\s+-rf|format\s+[a-z]:|deleteOnExit|FileUtils\.deleteDirectory|Files\.walk.{0,40}delete|cipher\s+/w"#,
            "Bulk file deletion / wipe commands — destructive or anti-forensic (self-delete) behaviour.",
        ),
        rule(
            "discord-inject", C_NATIVE, High,
            r"(?i)discord_desktop_core|betterdiscord|\bBdApi\b|discordPath|\\Discord\\app-|modules\\discord_|powercord|replugged",
            "Injects into the Discord desktop client (BetterDiscord/core module) — persistent token theft.",
        ),
        rule(
            "ms-auth-theft", C_CRED, High,
            r"(?i)login\.live\.com|login\.microsoftonline\.com|\bXSTS\b|RpsTicket|user\.auth\.xboxlive|sisu\.xboxlive|usercache\.json|servers\.dat|XboxLive",
            "Targets Microsoft / Xbox Live auth or Minecraft session files — full account takeover.",
        ),
        rule(
            "victim-profiling", C_NET, Medium,
            r"(?i)ip-api\.com|api\.ipify\.org|ipinfo\.io|checkip\.amazonaws|wtfismyip|ipwho\.is|api\.myip|getHardwareAddress",
            "Collects the victim's public IP / hardware (MAC) ID — profiling for an exfil report.",
        ),
        rule(
            "email-exfil", C_NET, High,
            r"(?i)javax/mail|javax\.mail|SMTPTransport|Transport\.send|com/sun/mail|smtp\.gmail|\bMimeMessage\b",
            "Sends email (SMTP/JavaMail) — an exfiltration channel with no place in a mod.",
        ),
        rule(
            "ftp-exfil", C_NET, Medium,
            r"(?i)ftp://|FTPClient|sun/net/ftp|commons/net/ftp|\bSFTP\b|JSch\b",
            "FTP/SFTP transfer — uncommon in mods; a possible exfiltration channel.",
        ),
        rule(
            "process-kill", C_PROC, Medium,
            r"(?i)taskkill\s+/|/IM\s+(?:discord|chrome|msedge|firefox|opera|brave)|Stop-Process|killall\s+(?:discord|chrome)",
            "Force-kills Discord/browser/AV processes — often to unlock files it wants to steal.",
        ),
        rule(
            "nitro-billing", C_CRED, High,
            r"(?i)/users/@me/billing|/billing/payment-sources|/store/skus|/promotions/outbound",
            "Hits Discord billing/Nitro endpoints — payment-method theft or Nitro abuse.",
        ),
        rule(
            "analysis-tools", C_EVASION, Medium,
            r"(?i)\bwireshark\b|\bprocmon\b|x64dbg|x32dbg|\bollydbg\b|\bfiddler\b|httpdebugger|processhacker|\bdnspy\b|\bde4dot\b|ida64|charles proxy",
            "Checks for reverse-engineering / network-analysis tools — evasion to avoid being studied.",
        ),
        rule(
            "antivm-mac", C_EVASION, Medium,
            r"(?i)00:05:69|00:0c:29|00:1c:14|00:50:56|08:00:27|0a:00:27|52:54:00|00:16:3e",
            "Compares MAC address against VM vendor prefixes (VMware/VirtualBox/QEMU/Xen) — sandbox evasion.",
        ),
        rule(
            "sandbox-names", C_EVASION, Medium,
            r"(?i)\bsandbox\b|cuckoo|\bvirustotal\b|\bany\.run\b|joesandbox|JOHN-?PC|DESKTOP-[A-Z0-9]{7}|\bmalware\b.*\buser\b|currentUser.{0,15}(?:sandbox|vmware|virus)",
            "Checks the username/hostname against known sandbox values — evasion to avoid detonation.",
        ),
        rule(
            "wmi-recon", C_EVASION, Medium,
            r"(?i)\bwmic\b|Get-WmiObject|Get-CimInstance|ManagementObjectSearcher|root\\cimv2|Win32_(?:Process|ComputerSystem|VideoController)|AntiVirusProduct|SecurityCenter2",
            "WMI system/AV queries — recon to fingerprint the machine and its defences.",
        ),
        rule(
            "pe-injection", C_PROC, High,
            r"(?i)CreateRemoteThread|VirtualAllocEx|WriteProcessMemory|NtCreateThreadEx|RtlCreateUserThread|SetThreadContext|ZwUnmapViewOfSection|NtQueueApcThread",
            "Process-injection APIs (CreateRemoteThread/VirtualAllocEx/WriteProcessMemory) — injects code into other processes.",
        ),
        rule(
            "pe-download-exec", C_NET, Info,
            r"(?i)URLDownloadToFile|URLDownloadToCacheFile|WinHttpOpen|InternetOpenUrl|HttpSendRequest|InternetReadFile|WSASocket|WinHttpConnect",
            "Download/network APIs — fetches remote content (capability; common in legit software too).",
        ),
        rule(
            "pe-shell-exec", C_PROC, Info,
            r"(?i)ShellExecute(?:Ex)?[AW]?|\bWinExec\b|CreateProcess(?:Internal)?[AW]?",
            "Process-creation APIs (CreateProcess/ShellExecute/WinExec) — spawns programs (capability).",
        ),
        rule(
            "pe-keylog-hook", C_SURV, Medium,
            r"(?i)SetWindowsHookExW|SetWindowsHookExA|GetAsyncKeyState|RegisterRawInputDevices|GetRawInputData",
            "Keyboard hooking/state APIs — possible keylogger (also used by games for input).",
        ),
        rule(
            "pe-screencap", C_SURV, Low,
            r"(?i)\bBitBlt\b|CreateCompatibleBitmap|PrintWindow",
            "Screen-capture GDI APIs — screenshot/spyware behaviour.",
        ),
        rule(
            "pe-antidebug", C_EVASION, Low,
            r"(?i)CheckRemoteDebuggerPresent|NtSetInformationThread.{0,20}HideFromDebugger|DbgUiRemoteBreakin|NtQueryInformationProcess.{0,20}DebugPort",
            "Anti-debugging APIs — evasion to resist analysis.",
        ),
        rule(
            "pe-priv", C_NATIVE, Info,
            r"(?i)AdjustTokenPrivileges|SeDebugPrivilege|ImpersonateLoggedOnUser",
            "Token/privilege APIs — privilege escalation or token manipulation (capability).",
        ),
        rule(
            "pe-dynamic-resolve", C_REFL, Info,
            r"(?i)GetProcAddress|LoadLibrary(?:Ex)?[AW]?|LdrLoadDll|LdrGetProcedureAddress",
            "Resolves APIs dynamically (GetProcAddress/LoadLibrary) — common in packers and to hide imports.",
        ),
        rule(
            "pe-crypto-api", C_REFL, Info,
            r"(?i)CryptEncrypt|CryptDecrypt|CryptAcquireContext|BCryptEncrypt|CryptGenKey|CryptHashData",
            "Windows crypto APIs — may encrypt C2 traffic or decrypt a payload.",
        ),
        rule(
            "pe-service-persist", C_NATIVE, Medium,
            r"(?i)CreateServiceA|CreateServiceW|ChangeServiceConfig",
            "Service-control APIs — may install a service to persist across reboots (also used by legit installers).",
        ),
    ]
});

static OBF_IDENT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(?:[lI]{4,}|[O0]{4,}|[lI1O0]{6,})\b").unwrap());
static BIG_BASE64: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#""?[A-Za-z0-9+/]{160,}={0,2}"?"#).unwrap());

static B64_TOKEN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[A-Za-z0-9+/_-]{24,}={0,2}").unwrap());
static IP_CAND: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b").unwrap());

fn is_public_ip(o: [u32; 4]) -> bool {
    let [a, b, c, _d] = o;
    if o.iter().any(|&x| x > 255) {
        return false;
    }
    if o[3] == 0 || a == 0 || a == 127 || a == 255 || a >= 224 {
        return false;
    }
    if a == 10 || (a == 192 && b == 168) || (a == 172 && (16..=31).contains(&b)) {
        return false;
    }
    if a == 169 && b == 254 {
        return false;
    }
    let _ = c;
    true
}

fn scan_line_ips(
    class: &str,
    line_no: u32,
    text: &str,
    findings: &mut Vec<Finding>,
    per_rule: &mut HashMap<&'static str, usize>,
) {
    for cap in IP_CAND.captures_iter(text) {
        let o = [1usize, 2, 3, 4].map(|i| cap[i].parse::<u32>().unwrap_or(999));
        if !is_public_ip(o) {
            continue;
        }
        let m = cap.get(0).unwrap();
        let after = &text[m.end()..];
        let before = &text[..m.start()];
        let has_port = after.starts_with(':')
            && after[1..].chars().next().map_or(false, |c| c.is_ascii_digit());
        let has_scheme = before.ends_with("//");
        let big_octet = o.iter().copied().max().unwrap_or(0) >= 100;
        if !(big_octet || has_port || has_scheme) {
            continue;
        }
        let count = per_rule.entry("raw-ip").or_insert(0);
        if *count >= MAX_PER_RULE_PER_CLASS {
            return;
        }
        *count += 1;
        findings.push(Finding {
            id: "raw-ip".into(),
            severity: Severity::Medium,
            category: C_NET.into(),
            class: class.into(),
            line: line_no,
            snippet: trunc(if line_no == 0 { &cap[0] } else { text.trim() }),
            why: "Hardcoded public IP address — mods use domain names; a bare IP is a C2 hint (e.g. fractureiser).".into(),
        });
    }
}
static DEC_WEBHOOK: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/(?:v\d+/)?webhooks/\d+/[\w-]+").unwrap()
});
static DEC_URL: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)https?://[\w.\-]{4,}").unwrap());
static DEC_IP: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b").unwrap());
static DEC_SHELL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)powershell|cmd\.exe|/bin/sh|FromBase64String|Invoke-Expression|certutil").unwrap());

const MAX_B64_PER_CLASS: usize = 60;
const MAX_B64_DEPTH: u8 = 2;

const MAX_PER_RULE_PER_CLASS: usize = 6;

pub fn analyze(
    sources: &HashMap<String, String>,
    symbols: &HashMap<String, String>,
    resources: &[(String, Vec<u8>)],
    class_names: &[String],
) -> AnalysisReport {
    let mut findings: Vec<Finding> = Vec::new();
    let mut scanned = 0usize;
    let mut done_outer = HashSet::new();

    for class in class_names {
        let outer = class.split('$').next().unwrap_or(class).to_string();
        if !done_outer.insert(outer.clone()) {
            continue;
        }
        scanned += 1;

        let mut local: Vec<Finding> = Vec::new();
        let mut b64_count = 0usize;
        if let Some(sym) = symbols.get(&outer) {
            scan_symbols(&outer, sym, &mut local);
            scan_base64(&outer, sym, &mut local, &mut b64_count, MAX_B64_DEPTH);
            scan_entropy(&outer, sym, &mut local);
        }
        if let Some(src) = sources.get(&outer) {
            scan_source(&outer, src, &mut local);
            scan_base64(&outer, src, &mut local, &mut b64_count, MAX_B64_DEPTH);
        }
        dedup_class(&mut local);
        findings.extend(local);
    }

    scan_resources(resources, &mut findings);
    finalize(findings, scanned)
}

pub fn scan_text(label: &str, blob: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    scan_symbols(label, blob, &mut findings);
    let mut b64 = 0usize;
    scan_base64(label, blob, &mut findings, &mut b64, MAX_B64_DEPTH);
    scan_entropy(label, blob, &mut findings);
    dedup_class(&mut findings);
    findings
}

pub fn finalize(mut findings: Vec<Finding>, scanned: usize) -> AnalysisReport {
    combo_dynamic_loading(&mut findings);
    combo_clipboard_hijack(&mut findings);
    combo_c2(&mut findings);
    combo_stealer(&mut findings);

    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(a.class.cmp(&b.class))
            .then(a.line.cmp(&b.line))
    });

    let verdict = verdict_for(&findings);
    let category_counts = count_by(&findings, |f| f.category.clone());
    let severity_counts = count_by(&findings, |f| f.severity.as_str().to_string());

    AnalysisReport {
        verdict,
        findings,
        category_counts,
        severity_counts,
        classes_scanned: scanned,
    }
}

fn scan_symbols(class: &str, blob: &str, findings: &mut Vec<Finding>) {
    let mut per_rule: HashMap<&'static str, usize> = HashMap::new();
    for entry in blob.lines() {
        scan_line(class, 0, entry, findings, &mut per_rule);
    }
}

fn scan_source(class: &str, src: &str, findings: &mut Vec<Finding>) {
    let mut per_rule: HashMap<&'static str, usize> = HashMap::new();
    let mut obf_hits = 0usize;
    for (i, line) in src.lines().enumerate() {
        let line_no = (i + 1) as u32;
        scan_line(class, line_no, line, findings, &mut per_rule);

        if OBF_IDENT.is_match(line) {
            obf_hits += 1;
        }
        if let Some(m) = BIG_BASE64.find(line) {
            let count = per_rule.entry("big-base64").or_insert(0);
            if *count < MAX_PER_RULE_PER_CLASS {
                *count += 1;
                findings.push(Finding {
                    id: "big-base64".into(),
                    severity: Severity::Medium,
                    category: C_REFL.into(),
                    class: class.into(),
                    line: line_no,
                    snippet: trunc(m.as_str()),
                    why: "Large Base64 blob embedded in source — often a hidden/encrypted payload.".into(),
                });
            }
        }
    }
    if obf_hits >= 4 {
        findings.push(Finding {
            id: "obfuscated-identifiers".into(),
            severity: Severity::Medium,
            category: C_REFL.into(),
            class: class.into(),
            line: 0,
            snippet: format!("{obf_hits} obfuscated identifiers"),
            why: "Heavily obfuscated identifiers (e.g. lllI, O0O0) — code is hiding its intent.".into(),
        });
    }
}

fn scan_line(
    class: &str,
    line_no: u32,
    text: &str,
    findings: &mut Vec<Finding>,
    per_rule: &mut HashMap<&'static str, usize>,
) {
    for r in RULES.iter() {
        if let Some(m) = r.re.find(text) {
            let count = per_rule.entry(r.id).or_insert(0);
            if *count >= MAX_PER_RULE_PER_CLASS {
                continue;
            }
            *count += 1;
            findings.push(Finding {
                id: r.id.into(),
                severity: r.severity,
                category: r.category.into(),
                class: class.into(),
                line: line_no,
                snippet: trunc(if line_no == 0 { m.as_str() } else { text.trim() }),
                why: r.why.into(),
            });
        }
    }
    scan_line_ips(class, line_no, text, findings, per_rule);
}

fn try_b64(tok: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
    use base64::Engine;
    for eng_decode in [
        |t: &str| STANDARD.decode(t),
        |t: &str| STANDARD_NO_PAD.decode(t),
        |t: &str| URL_SAFE_NO_PAD.decode(t),
    ] {
        if let Ok(d) = eng_decode(tok) {
            if d.len() >= 8 {
                return Some(d);
            }
        }
    }
    None
}

fn scan_base64(class: &str, text: &str, findings: &mut Vec<Finding>, count: &mut usize, depth: u8) {
    for m in B64_TOKEN.find_iter(text) {
        if *count >= MAX_B64_PER_CLASS {
            return;
        }
        let tok = m.as_str();
        if tok.len() < 28 || tok.len() > 2_000_000 {
            continue;
        }
        let Some(dec) = try_b64(tok) else {
            continue;
        };
        *count += 1;

        let mut emit = |id: &str, sev: Severity, why: &str, snippet: String| {
            findings.push(Finding {
                id: id.into(),
                severity: sev,
                category: C_REFL.into(),
                class: class.into(),
                line: 0,
                snippet,
                why: why.into(),
            });
        };

        if dec.len() >= 2 && &dec[..2] == b"MZ" {
            emit("b64-exe", Severity::Critical,
                "A Base64 string decodes to a Windows executable (MZ header) — an embedded payload.",
                format!("decodes to PE/EXE, {} bytes", dec.len()));
            continue;
        }
        if dec.len() >= 4 && dec[..4] == [0xCA, 0xFE, 0xBA, 0xBE] {
            emit("b64-class", Severity::Critical,
                "A Base64 string decodes to a Java class file (CAFEBABE) — a packed payload loaded at runtime.",
                format!("decodes to a .class, {} bytes", dec.len()));
            continue;
        }
        if dec.len() >= 4 && &dec[..4] == b"PK\x03\x04" {
            emit("b64-archive", Severity::High,
                "A Base64 string decodes to a ZIP/JAR archive — a bundled hidden payload.",
                format!("decodes to a zip/jar, {} bytes", dec.len()));
            continue;
        }

        let s = String::from_utf8_lossy(&dec);
        if let Some(w) = DEC_WEBHOOK.find(&s) {
            emit("b64-webhook", Severity::Critical,
                "A Base64 string decodes to a Discord webhook URL — a hidden exfiltration endpoint.",
                trunc(w.as_str()));
        } else if let Some(ip) = DEC_IP.find(&s) {
            emit("b64-ip", Severity::High,
                "A Base64 string decodes to an IP address — a hidden C2 endpoint.",
                trunc(ip.as_str()));
        } else if DEC_SHELL.is_match(&s) {
            emit("b64-shell", Severity::High,
                "A Base64 string decodes to shell/PowerShell content — a hidden command.",
                trunc(s.trim()));
        } else if let Some(u) = DEC_URL.find(&s) {
            emit("b64-url", Severity::Medium,
                "A Base64 string decodes to a URL — a hidden network endpoint worth checking.",
                trunc(u.as_str()));
        } else if depth > 0 && looks_base64ish(&s) {
            scan_base64(class, &s, findings, count, depth - 1);
        }
    }
}

fn looks_base64ish(s: &str) -> bool {
    s.len() >= 28
        && s.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=').count() * 100
            / s.len().max(1)
            >= 90
}

fn entropy(s: &str) -> f64 {
    entropy_bytes(s.as_bytes())
}

pub fn entropy_bytes(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut freq = [0usize; 256];
    for &b in bytes {
        freq[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let mut h = 0.0;
    for &c in freq.iter() {
        if c > 0 {
            let p = c as f64 / len;
            h -= p * p.log2();
        }
    }
    h
}

fn scan_entropy(class: &str, blob: &str, findings: &mut Vec<Finding>) {
    let mut hits = 0;
    for line in blob.lines() {
        if line.len() < 96 || hits >= 4 {
            continue;
        }
        if looks_base64ish(line) || line.contains('(') || line.contains(';') {
            continue;
        }
        if entropy(line) >= 6.2 {
            hits += 1;
            findings.push(Finding {
                id: "high-entropy-blob".into(),
                severity: Severity::Low,
                category: C_REFL.into(),
                class: class.into(),
                line: 0,
                snippet: format!("{} chars, entropy {:.1}", line.len(), entropy(line)),
                why: "Long high-entropy string constant — likely encrypted/packed data hidden from view.".into(),
            });
        }
    }
}

fn scan_resources(resources: &[(String, Vec<u8>)], findings: &mut Vec<Finding>) {
    for (path, head) in resources {
        if head.len() < 4 {
            continue;
        }
        let lower = path.to_ascii_lowercase();
        let (id, sev, what) = if &head[..2] == b"MZ" {
            ("res-exe", Severity::Critical, "a Windows executable (MZ)")
        } else if head[..4] == [0xCA, 0xFE, 0xBA, 0xBE] {
            ("res-class", Severity::Critical, "a Java class file (CAFEBABE)")
        } else if head[..4] == [0x7F, 0x45, 0x4C, 0x46] {
            ("res-elf", Severity::High, "a Linux ELF executable")
        } else if &head[..4] == b"PK\x03\x04"
            && !lower.ends_with(".jar")
            && !lower.ends_with(".zip")
        {
            ("res-archive", Severity::High, "a ZIP/JAR archive")
        } else {
            continue;
        };
        findings.push(Finding {
            id: id.into(),
            severity: sev,
            category: "Hidden Payload".into(),
            class: path.clone(),
            line: 0,
            snippet: format!("{path} is {what}"),
            why: "A bundled resource is actually an executable/class disguised by its name — a hidden payload stage.".into(),
        });
    }
}

fn dedup_class(local: &mut Vec<Finding>) {
    let lined: HashSet<String> = local
        .iter()
        .filter(|f| f.line > 0)
        .map(|f| f.id.clone())
        .collect();
    local.retain(|f| f.line > 0 || !lined.contains(&f.id));
    let mut seen = HashSet::new();
    local.retain(|f| seen.insert((f.id.clone(), f.line)));
}

fn combo_dynamic_loading(findings: &mut Vec<Finding>) {
    let mut by_class: HashMap<String, HashSet<&str>> = HashMap::new();
    for f in findings.iter() {
        let bucket = match f.id.as_str() {
            "dynamic-load" | "reflection" | "unsafe-defineclass" | "java-agent" => "load",
            "base64-decode" | "big-base64" | "crypto" | "b64-class" | "b64-exe"
            | "b64-archive" | "high-entropy-blob" => "unpack",
            _ => "other",
        };
        by_class.entry(f.class.clone()).or_default().insert(bucket);
    }
    let mut extra = Vec::new();
    for (class, caps) in by_class {
        if !class.is_empty() && caps.contains("load") && caps.contains("unpack") {
            extra.push(Finding {
                id: "dynamic-code-loading".into(),
                severity: Severity::Critical,
                category: C_REFL.into(),
                class,
                line: 0,
                snippet: "decode/decrypt + runtime classloading".into(),
                why: "Decrypts/decodes data and loads it as code at runtime — a packed payload hidden from static view.".into(),
            });
        }
    }
    findings.extend(extra);
}

fn combo_clipboard_hijack(findings: &mut Vec<Finding>) {
    let mut by_class: HashMap<String, HashSet<&str>> = HashMap::new();
    for f in findings.iter() {
        by_class.entry(f.class.clone()).or_default().insert(f.id.as_str());
    }
    let mut extra = Vec::new();
    for (class, ids) in by_class {
        if !class.is_empty() && ids.contains("clipboard") && ids.contains("crypto-address") {
            extra.push(Finding {
                id: "clipboard-hijack".into(),
                severity: Severity::Critical,
                category: C_EVASION.into(),
                class,
                line: 0,
                snippet: "clipboard write + hardcoded wallet address".into(),
                why: "Replaces clipboard contents with an attacker wallet address — crypto clipboard hijacking.".into(),
            });
        }
    }
    findings.extend(extra);
}

fn combo_c2(findings: &mut Vec<Finding>) {
    let mut by_class: HashMap<String, HashSet<&str>> = HashMap::new();
    for f in findings.iter() {
        by_class.entry(f.class.clone()).or_default().insert(f.id.as_str());
    }
    let host_ids = ["raw-ip", "payload-host", "discord-webhook", "discord-api", "telegram-bot", "webhook-path"];
    let action_ids = [
        "process-exec", "shell", "powershell-encoded", "dynamic-load", "pe-injection",
    ];
    let mut extra = Vec::new();
    for (class, ids) in by_class {
        if class.is_empty() {
            continue;
        }
        let has_host = host_ids.iter().any(|h| ids.contains(h));
        let has_action = action_ids.iter().any(|a| ids.contains(a));
        if has_host && has_action {
            extra.push(Finding {
                id: "rat-c2".into(),
                severity: Severity::Critical,
                category: C_NET.into(),
                class,
                line: 0,
                snippet: "hardcoded external host + code execution".into(),
                why: "Reaches a hardcoded external host and runs/loads code — remote-access trojan (RAT) / downloader behaviour.".into(),
            });
        } else if has_host && ids.contains("networking") {
            extra.push(Finding {
                id: "c2-channel".into(),
                severity: Severity::High,
                category: C_NET.into(),
                class,
                line: 0,
                snippet: "hardcoded host + outbound connection".into(),
                why: "Opens an outbound connection to a hardcoded host — likely command-and-control.".into(),
            });
        }
    }
    findings.extend(extra);
}

fn combo_stealer(findings: &mut Vec<Finding>) {
    let harvest = [
        "browser-storage", "browser-dirs", "minecraft-creds", "ms-auth-theft",
        "wallet-ssh", "dpapi",
    ];
    let exfil = [
        "discord-webhook", "webhook-path", "payload-host", "email-exfil",
        "ftp-exfil", "telegram-bot", "discord-api", "b64-webhook",
    ];
    let ids: HashSet<&str> = findings.iter().map(|f| f.id.as_str()).collect();
    let has_harvest = harvest.iter().any(|h| ids.contains(h));
    let has_exfil = exfil.iter().any(|e| ids.contains(e));
    if has_harvest && has_exfil {
        let class = findings
            .iter()
            .find(|f| harvest.contains(&f.id.as_str()))
            .map(|f| f.class.clone())
            .unwrap_or_default();
        findings.push(Finding {
            id: "infostealer".into(),
            severity: Severity::Critical,
            category: C_CRED.into(),
            class,
            line: 0,
            snippet: "credential harvesting + exfiltration channel".into(),
            why: "Harvests credentials/wallets AND has an exfiltration channel — the classic infostealer/grabber pattern.".into(),
        });
    }
}

fn verdict_for(findings: &[Finding]) -> Verdict {
    let score: u32 = findings.iter().map(|f| f.severity.weight()).sum();
    let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let high = findings.iter().filter(|f| f.severity == Severity::High).count();

    let (level, label) = if critical >= 2 || (critical >= 1 && score >= 40) {
        ("malicious", "Malicious")
    } else if critical >= 1 || high >= 2 || score >= 25 {
        ("likely_malicious", "Likely Malicious")
    } else if high >= 1 || score >= 5 {
        ("suspicious", "Suspicious")
    } else if score > 0 {
        ("suspicious", "Low Concern")
    } else {
        ("clean", "Clean")
    };

    let top = top_categories(findings, 3);
    let reasoning = if findings.iter().all(|f| f.severity <= Severity::Info) {
        if findings.is_empty() {
            "No suspicious patterns were detected. The jar appears clean, but always confirm against a trusted source.".to_string()
        } else {
            format!("Only low-signal/contextual indicators ({} total). Nothing characteristic of malware.", findings.len())
        }
    } else {
        let cats = top.iter().map(|(c, n)| format!("{c} ({n})")).collect::<Vec<_>>().join(", ");
        format!(
            "{} finding(s); {} critical, {} high. Strongest signals: {}.",
            findings.len(), critical, high, cats
        )
    };

    Verdict { level: level.into(), label: label.into(), score, reasoning }
}

fn top_categories(findings: &[Finding], n: usize) -> Vec<(String, usize)> {
    let mut counts = count_by(findings, |f| f.category.clone());
    counts.retain(|(_, _)| true);
    counts.sort_by(|a, b| b.1.cmp(&a.1));
    counts.truncate(n);
    counts
}

fn count_by<F: Fn(&Finding) -> String>(findings: &[Finding], key: F) -> Vec<(String, usize)> {
    let mut map: HashMap<String, usize> = HashMap::new();
    for f in findings {
        *map.entry(key(f)).or_insert(0) += 1;
    }
    let mut v: Vec<_> = map.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    v
}

fn trunc(s: &str) -> String {
    let s = s.trim();
    if s.chars().count() > 220 {
        let cut: String = s.chars().take(217).collect();
        format!("{cut}...")
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn b64(s: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(s)
    }

    fn run(symbols: HashMap<String, String>, names: &[&str]) -> AnalysisReport {
        let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
        analyze(&HashMap::new(), &symbols, &[], &names)
    }

    #[test]
    fn detects_base64_hidden_webhook() {
        let wh = "https://discord.com/api/webhooks/123456789012345678/abcdEFGHijklMNOPqrstUVWXyz1234567890";
        let mut symbols = HashMap::new();
        symbols.insert("com/x/Bad".to_string(), format!("harmless\n{}\nend", b64(wh)));
        let report = run(symbols, &["com/x/Bad"]);
        let ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
        assert!(ids.contains(&"b64-webhook"), "must decode a hidden webhook, got {ids:?}");
        assert_eq!(report.verdict.level, "likely_malicious");
    }

    #[test]
    fn detects_base64_hidden_ip() {
        let mut symbols = HashMap::new();
        symbols.insert("com/x/Stager".to_string(), b64("connect 185.220.101.42:4444 now"));
        let report = run(symbols, &["com/x/Stager"]);
        let ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
        assert!(ids.contains(&"b64-ip"), "must decode a hidden IP, got {ids:?}");
    }

    #[test]
    fn detects_nested_base64() {
        let wh = "https://discord.com/api/webhooks/123456789012345678/abcdEFGHijklMNOPqrstUVWXyz1234567890";
        let mut symbols = HashMap::new();
        symbols.insert("com/x/Nested".to_string(), b64(&b64(wh))); // base64-of-base64
        let report = run(symbols, &["com/x/Nested"]);
        let ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
        assert!(ids.contains(&"b64-webhook"), "must peel nested base64, got {ids:?}");
    }

    #[test]
    fn detects_resource_payload() {
        let res = vec![("assets/icon.png".to_string(), vec![0x4D, 0x5A, 0x90, 0x00])];
        let report = analyze(&HashMap::new(), &HashMap::new(), &res, &[]);
        let ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
        assert!(ids.contains(&"res-exe"), "must flag disguised exe, got {ids:?}");
        assert_eq!(report.verdict.level, "likely_malicious");
    }

    #[test]
    fn detects_infostealer_combo() {
        let mut symbols = HashMap::new();
        symbols.insert(
            "com/x/Grab".to_string(),
            "Local Storage\nleveldb\nhttps://discord.com/api/webhooks/1/abc".to_string(),
        );
        let report = run(symbols, &["com/x/Grab"]);
        let ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
        assert!(ids.contains(&"infostealer"), "must fire stealer combo, got {ids:?}");
    }

    #[test]
    fn clean_strings_stay_clean() {
        let mut symbols = HashMap::new();
        symbols.insert(
            "org/example/Widget".to_string(),
            "org/example/client/WidgetRenderer\njava/util/List\nrender".to_string(),
        );
        let report = run(symbols, &["org/example/Widget"]);
        assert_eq!(report.verdict.level, "clean", "got {:?}", report.findings);
    }
}
