//! Manual live-validation CLI for `apple-core`.
//!
//! **This is the only tool in the workspace that talks to Apple.** It exists so the plan's phase 5
//! (live validation, `native/LIVE-VALIDATION.md`) can be run step by step by
//! the owner. Every command that sends anything requires an explicit `--yes`; a shared 429 cooldown is
//! enforced; secrets are redacted.
//!
//! Nothing here is used by the app or any test. Run it by hand, one step at a time, and record what
//! comes back.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use apple_core::anisette::{provision_new_machine, CoreAdiAnisette, MachineFile, MachineIdentity, DS_ID};
use apple_core::cloudkit::client::{CloudKitAccount, CloudKitClient};
use apple_core::cloudkit::pcs::{self, PcsCurve, PcsKey};
use apple_core::cloudkit::records::CloudKitRecord;
use apple_core::cloudkit::CloudKitApi;
use apple_core::error::Error;
use apple_core::http::Http;
use apple_core::keychain::escrow::EscrowRecord;
use apple_core::keychain::session::KeychainSession;
use apple_core::login::account::AppleAccount;
use apple_core::login::device::{DeviceIdentity, LoginEndpoints};
use apple_core::login::{LoginResult, SecondFactorMethod};
use apple_core::reports::client::{AccountContext, ReportClient};
use apple_core::reports::keys::{AccessoryKeys, KeyPair};

const GSA_INIT: &str = "https://gsa.apple.com/grandslam/GsService2";
const LOOKUP_URL: &str = "https://gsa.apple.com/grandslam/GsService2/lookup";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = args.first().cloned() else {
        usage();
        std::process::exit(2);
    };
    let flags = Flags::parse(&args[1..]);
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("runtime");
    let result = runtime.block_on(run(&command, &flags));
    match result {
        Ok(()) => {}
        Err(Error::Throttled(message)) => {
            note_429(&flags);
            eprintln!("\nTHROTTLED: {message}");
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("error: {error}");
            std::process::exit(1);
        }
    }
}

async fn run(command: &str, flags: &Flags) -> Result<(), Error> {
    match command {
        "root-ca" => root_ca(flags).await,
        "machine-headers" => machine_headers(flags).await,
        "machine-probe" => machine_probe(flags).await,
        "provision" => provision(flags).await,
        "login" => login(flags).await,
        "reports" => reports(flags).await,
        "keychain-list" => keychain_list(flags).await,
        "keychain-recover" => keychain_recover(flags).await,
        "beacons" => beacons(flags).await,
        other => {
            eprintln!("unknown command {other:?}\n");
            usage();
            std::process::exit(2);
        }
    }
}

// ------------------------------------------------------------------------------------ state / safety

struct Flags {
    values: BTreeMap<String, Option<String>>,
}

impl Flags {
    fn parse(args: &[String]) -> Flags {
        const TAKES_VALUE: [&str; 14] = [
            "state-dir", "images", "machine", "session", "keys", "timeout", "username",
            "timezone", "locale", "2fa", "max-requests", "limit", "report-user-agent", "tag-key",
        ];
        let mut values = BTreeMap::new();
        let mut rest = args.iter();
        while let Some(arg) = rest.next() {
            if let Some(name) = arg.strip_prefix("--") {
                if let Some((name, value)) = name.split_once('=') {
                    values.insert(name.to_string(), Some(value.to_string()));
                } else if TAKES_VALUE.contains(&name) {
                    values.insert(name.to_string(), Some(rest.next().cloned().unwrap_or_default()));
                } else {
                    values.insert(name.to_string(), Some("true".into()));
                }
            }
        }
        Flags { values }
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.values.get(name).and_then(|v| v.as_deref())
    }

    fn has(&self, name: &str) -> bool {
        self.values.contains_key(name)
    }

    /// `--state-dir`, else `$FINDMY_STATE`, else `$XDG_STATE_HOME/findmy`, else `$HOME/.findmy`, else a cwd-relative
    /// fallback. This is the only place the state lives, so `findmy <command>` needs no environment.
    fn state_dir(&self) -> PathBuf {
        if let Some(dir) = self.get("state-dir") {
            return PathBuf::from(dir);
        }
        if let Ok(dir) = std::env::var("FINDMY_STATE") {
            if !dir.is_empty() {
                return PathBuf::from(dir);
            }
        }
        if let Ok(dir) = std::env::var("XDG_STATE_HOME") {
            if !dir.is_empty() {
                return PathBuf::from(dir).join("findmy");
            }
        }
        if let Ok(home) = std::env::var("HOME") {
            if !home.is_empty() {
                return PathBuf::from(home).join(".findmy");
            }
        }
        PathBuf::from(".findmy-state")
    }

    fn machine_path(&self) -> PathBuf {
        self.get("machine").map(PathBuf::from).unwrap_or_else(|| self.state_dir().join("machine.json"))
    }

    fn session_path(&self) -> PathBuf {
        self.get("session").map(PathBuf::from).unwrap_or_else(|| self.state_dir().join("session.json"))
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(self.get("timeout").and_then(|v| v.parse().ok()).unwrap_or(30))
    }

    fn require_yes(&self) {
        if !self.has("yes") {
            eprintln!(
                "This command talks to Apple. Re-run with --yes once you have read native/LIVE-VALIDATION.md \
                 and are ready for this step."
            );
            std::process::exit(2);
        }
    }

    fn guard_cooldown(&self) -> Result<(), Error> {
        let marker = self.state_dir().join("gsa-429");
        let Some(last) = std::fs::read_to_string(&marker).ok().and_then(|s| s.trim().parse::<i64>().ok()) else {
            return Ok(());
        };
        let now = unix_now();
        let left = last + 45 * 60 - now;
        if left > 0 && !self.has("ignore-cooldown") {
            return Err(Error::Throttled(format!(
                "a 429 was recorded {marker:?} at {}; {left} s of cooldown remain. Nothing was sent.",
                last
            )));
        }
        Ok(())
    }
}

fn note_429(flags: &Flags) {
    let marker = flags.state_dir().join("gsa-429");
    let _ = std::fs::create_dir_all(flags.state_dir());
    let _ = std::fs::write(marker, unix_now().to_string());
}

fn unix_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Find the CoreADI file without an environment: `--images`, `$FINDMY_COREADI`, the state dir, the current
/// directory, or (walking up) the repository's `app/prebuilt/assets/` layout.
fn load_image(flags: &Flags) -> Result<Vec<u8>, Error> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(path) = flags.get("images") {
        candidates.push(PathBuf::from(path));
    }
    if let Ok(path) = std::env::var("FINDMY_COREADI") {
        if !path.is_empty() {
            candidates.push(PathBuf::from(path));
        }
    }
    candidates.push(flags.state_dir().join("CoreADI"));
    let mut dir = std::env::current_dir().ok();
    while let Some(current) = dir {
        candidates.push(current.join("CoreADI"));
        candidates.push(current.join("app/prebuilt/assets/CoreADI-4.19-x86_64"));
        candidates.push(current.join("prebuilt/assets/CoreADI-4.19-x86_64"));
        dir = current.parent().map(Path::to_path_buf);
    }
    for path in &candidates {
        if path.is_file() {
            return std::fs::read(path).map_err(|e| Error::State(format!("cannot read {}: {e}", path.display())));
        }
    }
    Err(Error::State(format!(
        "no CoreADI file found; put it at {} or set FINDMY_COREADI (searched: {})",
        flags.state_dir().join("CoreADI").display(),
        candidates.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", ")
    )))
}

fn load_machine(flags: &Flags) -> Result<MachineFile, Error> {
    let path = flags.machine_path();
    let text = std::fs::read_to_string(&path).map_err(|e| Error::State(format!("cannot read {}: {e}", path.display())))?;
    MachineFile::parse(&text)
}

fn save_machine(flags: &Flags, machine: &MachineFile, anisette: &CoreAdiAnisette) -> Result<(), Error> {
    let updated = MachineFile {
        host_uuid: machine.host_uuid,
        identity: machine.identity.clone(),
        store_export: anisette.export_store()?,
    };
    write_private(&flags.machine_path(), updated.to_json().as_bytes())
}

fn build_anisette(flags: &Flags, machine: &MachineFile) -> Result<Arc<CoreAdiAnisette>, Error> {
    let image = load_image(flags)?;
    let http = Http::new(flags.timeout())?;
    let mut anisette = CoreAdiAnisette::new(&image, machine, http)?;
    if let (Some(tz), Some(locale)) = (flags.get("timezone"), flags.get("locale")) {
        anisette = anisette.with_host_locale(tz, locale);
    }
    Ok(Arc::new(anisette))
}

fn build_account(flags: &Flags) -> Result<(MachineFile, Arc<CoreAdiAnisette>, Arc<AppleAccount>), Error> {
    let machine = load_machine(flags)?;
    let anisette = build_anisette(flags, &machine)?;
    let http = Http::new(flags.timeout())?;
    let device = machine.login_config()?.device()?;
    let account = Arc::new(AppleAccount::new(device, anisette.clone(), LoginEndpoints::default(), http));
    Ok((machine, anisette, account))
}

fn restore_account(flags: &Flags) -> Result<(MachineFile, Arc<CoreAdiAnisette>, Arc<AppleAccount>), Error> {
    let machine = load_machine(flags)?;
    let anisette = build_anisette(flags, &machine)?;
    let http = Http::new(flags.timeout())?;
    let device = machine.login_config()?.device()?;
    let text = std::fs::read_to_string(flags.session_path())
        .map_err(|e| Error::State(format!("cannot read session {}: {e}", flags.session_path().display())))?;
    let saved = apple_core::login::SavedSession::from_json(&text)?;
    let account = Arc::new(AppleAccount::restore(saved, device, anisette.clone(), LoginEndpoints::default(), http)?);
    Ok((machine, anisette, account))
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| Error::State(format!("cannot create {}: {e}", parent.display())))?;
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| Error::State(format!("cannot write {}: {e}", path.display())))?;
        file.write_all(bytes).map_err(|e| Error::State(format!("cannot write {}: {e}", path.display())))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes).map_err(|e| Error::State(format!("cannot write {}: {e}", path.display())))?;
    }
    Ok(())
}

fn redact(value: &str) -> String {
    if value.len() <= 8 {
        return format!("<{} bytes>", value.len());
    }
    format!("<{} bytes, starts {}…>", value.len(), &value[..4])
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hexvec(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).filter_map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

// ------------------------------------------------------------------------------------ commands

/// Checks whether the bundled Apple 2006 root is trusted for `gsa.apple.com` (and only that root is
/// added on top of the bundled web roots). No machine, no account.
async fn root_ca(flags: &Flags) -> Result<(), Error> {
    if flags.has("dry-run") {
        println!("dry run: would GET {LOOKUP_URL} (1 request)");
        return Ok(());
    }
    flags.require_yes();
    flags.guard_cooldown()?;
    let http = Http::new(flags.timeout())?;
    let response = http.send(reqwest::Method::GET, LOOKUP_URL, &[], None, None).await?;
    println!("gsa.apple.com -> HTTP {} (TLS verified; Apple's 2006 root is bundled and hash-checked)", response.status);
    Ok(())
}

/// No network: prints one Anisette header set (redacted) and, with `--second`, a second one 31 s later,
/// proving the OTP changes with the real clock (the frozen-clock regression).
async fn machine_headers(flags: &Flags) -> Result<(), Error> {
    let machine = load_machine(flags)?;
    let anisette = build_anisette(flags, &machine)?;
    let first = anisette.provider_headers()?;
    print_headers(&first);
    if flags.has("second") {
        println!("waiting 31 s for the OTP window to roll…");
        tokio::time::sleep(Duration::from_secs(31)).await;
        let second = anisette.provider_headers()?;
        print_headers(&second);
        if first.get("X-Apple-I-MD") == second.get("X-Apple-I-MD") {
            eprintln!("FAIL: X-Apple-I-MD did not change; the clock is frozen (see EVIDENCE.md §8/§9).");
        } else {
            println!("OK: X-Apple-I-MD changed; the clock is real.");
        }
    }
    save_machine(flags, &machine, &anisette)?;
    Ok(())
}

fn print_headers(headers: &BTreeMap<String, String>) {
    for key in [
        "X-Apple-I-Client-Time",
        "X-Apple-I-TimeZone",
        "loc",
        "X-Apple-Locale",
        "X-Mme-Device-Id",
        "X-Apple-I-MD-RINFO",
        "X-Apple-I-SRL-NO",
    ] {
        if let Some(value) = headers.get(key) {
            println!("  {key}: {value}");
        }
    }
    for key in ["X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MD-LU"] {
        if let Some(value) = headers.get(key) {
            println!("  {key}: {}", redact(value));
        }
    }
}

/// Credential-free Grand Slam `init`: the cheapest live check of whether the machine is accepted, and
/// the one that shows a `hsc 434` lease lapse (Settles the clock/lease questions and the resync path).
async fn machine_probe(flags: &Flags) -> Result<(), Error> {
    if flags.has("dry-run") {
        println!("dry run: would POST {GSA_INIT} (1 credential-free init)");
        return Ok(());
    }
    flags.require_yes();
    flags.guard_cooldown()?;
    let machine = load_machine(flags)?;
    let anisette = build_anisette(flags, &machine)?;
    // The probe sends the raw `mac_anisette.headers()` set, not the login set (see `raw_headers`).
    let headers = anisette.raw_headers()?;
    let identity = DeviceIdentity::from_client_info(&machine.identity.client_info)?;
    let http = Http::new(flags.timeout())?;
    let status = apple_core::gsa::probe_init(&http, GSA_INIT, &identity, &headers).await?;
    let ec = status.get("ec").and_then(|v| v.as_i64());
    let hsc = status.get("hsc").and_then(|v| v.as_i64());
    let em = status.get("em").and_then(|v| v.as_str()).unwrap_or("");
    print!("machine-probe: ec={ec:?} hsc={hsc:?} em={em:?}");
    if let Some(at) = machine.identity.provisioned_at {
        print!("  age={:.0} s", unix_now() as f64 - at);
    }
    println!();
    println!("  machine: {}", classify_probe(ec, hsc));
    save_machine(flags, &machine, &anisette)?;
    Ok(())
}

/// Provision a fresh machine (one per device id). Writes `machine.json` (0600).
async fn provision(flags: &Flags) -> Result<(), Error> {
    let path = flags.machine_path();
    // Look for saved credentials first: a machine is provisioned once per device id, so an existing file is
    // the machine to use. Only generate and provision when there are none, or when --override is explicit.
    if path.exists() && !flags.has("override") {
        let machine = load_machine(flags)?;
        println!(
            "using the existing machine {} (serial {}, routing {:?}) from {}; pass --override to provision a new one",
            machine.identity.device_id,
            machine.identity.serial.as_deref().unwrap_or("?"),
            machine.identity.routing,
            path.display()
        );
        return Ok(());
    }
    if flags.has("dry-run") {
        if path.exists() {
            println!("dry run: --override set; would provision a new machine (URL bag + start + finish = 3 requests) and overwrite {}", path.display());
        } else {
            println!("dry run: no saved credentials at {}; would provision (URL bag + start + finish = 3 requests)", path.display());
        }
        return Ok(());
    }
    flags.require_yes();
    flags.guard_cooldown()?;
    let image = load_image(flags)?;
    let http = Http::new(flags.timeout())?;
    let client_info = apple_core::gsa::DEFAULT_CLIENT_INFO.to_string();
    let _ = DeviceIdentity::from_client_info(&client_info)?; // validate the release is known
    // Three independent random values, as `mac_anisette.py` generates them (`secrets.token_hex`):
    // the host UUID (the MID derives from it), the provisioning UDID, and the local user UUID.
    let mut host_uuid = [0u8; 16];
    rand_bytes(&mut host_uuid);
    let device_id = format!("00006000-{}", rand_hex(8));
    let local_user_uuid = rand_hex(16);
    // A Mac serial is 12 alphanumerics with no I or O; it must be the same one provisioning and login send.
    let serial = rand_serial();
    let machine = MachineFile {
        host_uuid,
        identity: MachineIdentity {
            device_id,
            local_user_uuid,
            client_info,
            serial: Some(serial),
            routing: None,
            provisioned_at: Some(unix_now() as f64),
        },
        store_export: Vec::new(),
    };
    let anisette = Arc::new({
        let a = CoreAdiAnisette::new(&image, &machine, http.clone())?;
        match (flags.get("timezone"), flags.get("locale")) {
            (Some(tz), Some(locale)) => a.with_host_locale(tz, locale),
            _ => a,
        }
    });
    println!("provisioning {} …", machine.identity.device_id);
    let routing = provision_new_machine(&anisette, DS_ID).await?;
    let mut machine = machine;
    machine.identity.routing = Some(routing);
    save_machine(flags, &machine, &anisette)?;
    println!("provisioned; routing={routing}; wrote {}", path.display());
    println!("note: this machine is bound to its device id; a second provisioning returns 433.");
    Ok(())
}

/// SRP login (plus 2FA). Writes `session.json` (0600).
async fn login(flags: &Flags) -> Result<(), Error> {
    if flags.has("dry-run") {
        println!("dry run: would log in (SRP init + complete + delegate = 3, +3 more with 2FA)");
        return Ok(());
    }
    flags.require_yes();
    flags.guard_cooldown()?;
    let (machine, anisette, account) = build_account(flags)?;
    // The Apple ID is not a secret: echo it. Only the password is read hidden.
    let username = flags.get("username").map(str::to_string).unwrap_or_else(|| prompt("Apple ID: "));
    let mut password = secret("Apple ID password: ").into_bytes();
    let result = account.login(&username, &mut password, true).await;
    match result {
        Ok(LoginResult::SignedIn) => println!("signed in."),
        Ok(LoginResult::SecondFactorRequired(methods)) => {
            // Apple does not push the trusted-device prompt on its own; ask for it. A failed push is
            // best-effort: still prompt for a code (the Python's auth_probe does the same).
            finish_second_factor(&account, methods, !flags.has("no-push")).await?;
        }
        Err(error) => {
            save_machine(flags, &machine, &anisette)?;
            return Err(error);
        }
    }
    let saved = account.snapshot().await?;
    write_private(&flags.session_path(), saved.to_json().as_bytes())?;
    save_machine(flags, &machine, &anisette)?;
    println!("session saved to {} (no password, no PET)", flags.session_path().display());
    Ok(())
}

async fn finish_second_factor(
    account: &AppleAccount,
    methods: Vec<SecondFactorMethod>,
    request_push: bool,
) -> Result<(), Error> {
    for (index, method) in methods.iter().enumerate() {
        match method {
            SecondFactorMethod::TrustedDevice => println!("  [{index}] trusted device (push)"),
            SecondFactorMethod::Sms { phone_number, .. } => println!("  [{index}] SMS {phone_number}"),
        }
    }
    let choice = prompt("choose a method index: ");
    let index: usize = choice.trim().parse().map_err(|_| Error::State("not a method index".into()))?;
    let method = methods.get(index).ok_or_else(|| Error::State("not a method index".into()))?;
    match method {
        SecondFactorMethod::TrustedDevice => {
            if request_push {
                match account.request_trusted_device_code().await {
                    Ok(()) => println!("asked Apple to push the code (it does not arrive on its own)"),
                    Err(error) => eprintln!("push request failed ({error}); enter a code anyway"),
                }
            } else {
                println!("--no-push: not asking Apple for the push; enter a code from a trusted device");
            }
            let code = prompt("code: ");
            expect_signed_in(account.submit_trusted_device_code(&code).await?)
        }
        SecondFactorMethod::Sms { phone_number_id, .. } => {
            account.request_sms_code(*phone_number_id).await?;
            let code = prompt("code: ");
            expect_signed_in(account.submit_sms_code(*phone_number_id, &code).await?)
        }
    }
}

fn expect_signed_in(result: LoginResult) -> Result<(), Error> {
    match result {
        LoginResult::SignedIn => Ok(()),
        LoginResult::SecondFactorRequired(_) => Err(Error::Authentication("Apple asked for a second factor again".into())),
    }
}

/// Fetch reports for the accessories in a keys file.
async fn reports(flags: &Flags) -> Result<(), Error> {
    let tag_key = flags.get("tag-key").map(str::to_string).or_else(|| std::env::var("FINDMY_KEY").ok().filter(|s| !s.trim().is_empty()));
    let keys_path = flags.get("keys").map(str::to_string);
    if flags.has("dry-run") {
        if let Some(path) = &keys_path {
            let max = flags.get("max-requests").and_then(|v| v.parse().ok()).unwrap_or(6);
            let limit = flags.get("limit").and_then(|v| v.parse().ok()).unwrap_or(3);
            println!("dry run: would restore the session and fetch up to {limit} accessory/ies from {path}, at most {max} fetch request(s) each");
        } else if tag_key.is_some() {
            println!("dry run: would restore the session and fetch the history of one tag key (1 request)");
        } else {
            println!("dry run: pass --keys FILE (FindMyAccessory JSON) or --tag-key/FINDMY_KEY (base64 private key)");
        }
        return Ok(());
    }
    flags.require_yes();
    flags.guard_cooldown()?;
    let (machine, anisette, account) = restore_account(flags)?;
    let mut client = ReportClient::new(account.as_ref() as &dyn AccountContext);
    if let Some(ua) = flags.get("report-user-agent") {
        client = client.with_user_agent(Some(ua.to_string()));
    }
    println!("report User-Agent: {}", flags.get("report-user-agent").unwrap_or(apple_core::reports::client::REPORT_USER_AGENT));

    if let Some(path) = &keys_path {
        let text = std::fs::read_to_string(path).map_err(|e| Error::State(format!("cannot read {path}: {e}")))?;
        let value: serde_json::Value = serde_json::from_str(&text).map_err(|_| Error::State("the keys file is not JSON".into()))?;
        let mut list = value.as_array().cloned().unwrap_or_else(|| vec![value]);
        // Safety: a stale alignment makes one accessory walk far more indices than the 7-day window; cap the
        // requests per accessory and how many accessories are fetched at all.
        let max_per_accessory: usize = flags.get("max-requests").and_then(|v| v.parse().ok()).unwrap_or(6);
        let limit: usize = flags.get("limit").and_then(|v| v.parse().ok()).unwrap_or(3);
        if limit > 0 && list.len() > limit {
            println!("(fetching the first {limit} of {} accessories; pass --limit 0 for all)", list.len());
            list.truncate(limit);
        }
        let client = client.with_max_requests(Some(max_per_accessory));
        for entry in &list {
            let accessory = AccessoryKeys::from_json(entry).map_err(|e| Error::State(e.to_string()))?;
            let result = client.fetch_location_history(&accessory, true).await?;
            print_result(accessory.name.as_deref().unwrap_or("?"), &result);
        }
    } else if let Some(b64) = &tag_key {
        let key = KeyPair::from_b64(b64.trim()).map_err(|_| Error::State("FINDMY_KEY/--tag-key is not a base64 P-224 private key".into()))?;
        for (key, result) in client.fetch_key_history(&[key]).await? {
            print_result(key.name().unwrap_or("tag"), &result);
        }
    } else {
        return Err(Error::State("pass --keys FILE (FindMyAccessory JSON) or --tag-key/FINDMY_KEY (base64 private key of your own tag)".into()));
    }
    save_machine(flags, &machine, &anisette)?;
    Ok(())
}

fn print_result(name: &str, result: &apple_core::reports::client::ReportFetchResult) {
    println!(
        "{name}: {} report(s) ({} requests, {} undecryptable, {} invalid, {} unknown)",
        result.reports.len(), result.requests, result.undecryptable, result.invalid, result.unknown_key
    );
    for report in &result.reports {
        println!(
            "  {}  {:.5}, {:.5}  +-{:.0} m",
            apple_core::reports::keys::isoformat(report.observed_at),
            report.latitude,
            report.longitude,
            report.horizontal_accuracy_meters.unwrap_or(0.0)
        );
    }
}

/// List the account's escrow records (no passcode).
async fn keychain_list(flags: &Flags) -> Result<(), Error> {
    if flags.has("dry-run") {
        println!("dry run: would open a keychain session (container + PET = 3) and list records (viable + escrow = 2)");
        return Ok(());
    }
    flags.require_yes();
    flags.guard_cooldown()?;
    let (machine, anisette, account) = restore_account(flags)?;
    provide_password_if_needed(flags, &account).await;
    let session = KeychainSession::open(account).await?;
    let options = session.recovery_options().await?;
    println!("{}", options.describe());
    for record in &options.recoverable {
        println!("  recoverable: {}", record.describe());
    }
    for record in &options.described_but_not_viable {
        println!("  not viable:  {}", record.describe());
    }
    println!("  distinct devices (by serial): {}", options.device_count());
    save_machine(flags, &machine, &anisette)?;
    Ok(())
}

/// Recover the keychain PCS keys with ONE passcode guess. Writes `pcs.json` (0600).
async fn keychain_recover(flags: &Flags) -> Result<(), Error> {
    if flags.has("dry-run") {
        println!("dry run: would open a keychain session, list records, then send ONE passcode guess (srp_init + recover)");
        return Ok(());
    }
    flags.require_yes();
    flags.guard_cooldown()?;
    let (machine, anisette, account) = restore_account(flags)?;
    provide_password_if_needed(flags, &account).await;
    let session = KeychainSession::open(account).await?;
    let options = session.recovery_options().await?;
    if options.recoverable.is_empty() {
        return Err(Error::Backend("no recoverable escrow record on this account".into()));
    }
    for (index, record) in options.recoverable.iter().enumerate() {
        println!("  [{index}] {}", record.describe());
    }
    let index: usize = prompt("record index to recover: ").trim().parse().map_err(|_| Error::State("not an index".into()))?;
    let record: EscrowRecord = options.recoverable.get(index).cloned().ok_or_else(|| Error::State("not an index".into()))?;
    println!("!! One passcode guess will be sent and NOT retried (Apple limits wrong guesses on the record).");
    let mut passcode = secret("screen-lock passcode of that device: ");
    let keys = session.recover_service_keys(&record, &passcode).await;
    passcode.zeroize();
    let keys = keys?;
    let json: Vec<serde_json::Value> = keys
        .iter()
        .map(|k| serde_json::json!({"curve": k.curve.name(), "d": hex(&k.scalar_bytes())}))
        .collect();
    write_private(&flags.state_dir().join("pcs.json"), serde_json::to_string(&json).unwrap().as_bytes())?;
    println!("recovered {} PCS key(s); wrote pcs.json (0600)", keys.len());
    save_machine(flags, &machine, &anisette)?;
    Ok(())
}

/// Fetch and decrypt the BeaconStore accessories, using the recovered PCS keys.
async fn beacons(flags: &Flags) -> Result<(), Error> {
    if flags.has("dry-run") {
        println!("dry run: would open the container, retrieve zones, and page the BeaconStore (3+ requests)");
        return Ok(());
    }
    flags.require_yes();
    flags.guard_cooldown()?;
    let (machine, anisette, account) = restore_account(flags)?;
    let pcs_path = flags.state_dir().join("pcs.json");
    let text = std::fs::read_to_string(&pcs_path).map_err(|e| Error::State(format!("cannot read {}: {e}", pcs_path.display())))?;
    let value: serde_json::Value = serde_json::from_str(&text).map_err(|_| Error::State("pcs.json is not JSON".into()))?;
    let mut pcs_keys = Vec::new();
    for entry in value.as_array().cloned().unwrap_or_default() {
        let curve_name = entry.get("curve").and_then(|v| v.as_str()).unwrap_or("");
        let curve = match curve_name {
            "secp256r1" => PcsCurve::P256,
            "secp384r1" => PcsCurve::P384,
            other => return Err(Error::State(format!("unknown curve {other}"))),
        };
        let scalar = hexvec(entry.get("d").and_then(|v| v.as_str()).unwrap_or(""));
        pcs_keys.push(PcsKey::from_scalar(curve, &scalar).ok_or_else(|| Error::State("bad scalar in pcs.json".into()))?);
    }

    let ck: Arc<dyn CloudKitAccount> = account;
    let client = CloudKitClient::new(ck);
    let zones = client.zone_retrieve().await?;
    let beacon = zones
        .iter()
        .find(|z| {
            z.target_zone
                .as_ref()
                .and_then(|t| t.zone_identifier.as_ref())
                .and_then(|i| i.value.as_ref())
                .and_then(|v| v.name.as_deref())
                == Some("BeaconStore")
        })
        .and_then(|z| z.target_zone.as_ref())
        .ok_or_else(|| Error::Backend("the BeaconStore zone is absent".into()))?;
    let zone_protection = beacon
        .protection_info
        .as_ref()
        .and_then(|p| p.protection_info.clone())
        .ok_or_else(|| Error::Backend("the BeaconStore zone carries no protection structure".into()))?;
    let zone_keys = pcs::unwrap_zone(&zone_protection, &pcs_keys)?;
    let defaults = beacon
        .record_protection_info
        .as_ref()
        .and_then(|p| p.protection_info.clone())
        .map(|info| pcs::unwrap_zone_record_defaults(&info, &zone_keys))
        .transpose()?
        .unwrap_or_default();

    let changes = client.iter_records("BeaconStore", None, 100).await?;
    let records = CloudKitRecord::from_changes(&changes, "BeaconStore");
    let now = time::OffsetDateTime::now_utc();
    let decrypted = apple_core::cloudkit::beacons::decrypt_records(&records, &zone_keys, &defaults, now);
    println!("{} record(s) fetched; {} decrypted; skipped {:?}", records.len(), decrypted.records.len(), decrypted.skipped);
    let accessories = apple_core::cloudkit::beacons::accessories_from_records(&decrypted.records);
    let mut tags = Vec::new();
    for accessory in &accessories {
        println!(
            "  {}  model {}  serial {}  master_key {}",
            accessory.name.as_deref().unwrap_or("?"),
            accessory.model.as_deref().unwrap_or("?"),
            accessory.serial_number.as_deref().unwrap_or("?"),
            redact(&hex(&accessory.master_key))
        );
        // Write the accessory shape `reports --keys` reads (`FindMyAccessory.to_json`), so the pieces chain.
        if let Ok(keys) = AccessoryKeys::new(
            accessory.master_key.clone(),
            accessory.skn.clone(),
            accessory.sks.clone(),
            accessory.paired_at,
            accessory.name.clone(),
            accessory.model.clone(),
            Some(accessory.identifier.clone()),
            accessory.group_identifier.clone(),
            accessory.serial_number.clone(),
            accessory.alignment_date,
            accessory.alignment_index.map(|i| i as i32),
        ) {
            tags.push(keys.to_json());
        }
    }
    if !tags.is_empty() {
        write_private(&flags.state_dir().join("tags.json"), serde_json::to_string(&tags).unwrap().as_bytes())?;
        println!("wrote {} accessory/ies to tags.json (0600) for `reports --keys`", tags.len());
    }
    save_machine(flags, &machine, &anisette)?;
    Ok(())
}

// ------------------------------------------------------------------------------------ misc

async fn provide_password_if_needed(flags: &Flags, account: &AppleAccount) {
    if !account.has_password().await {
        let mut password = secret("Apple ID password (only to renew the PET; not saved): ").into_bytes();
        account.provide_password(&mut password).await;
        password.zeroize();
    }
    let _ = flags;
}

fn secret(prompt_text: &str) -> String {
    rpassword::prompt_password(prompt_text).unwrap_or_default()
}

fn prompt(text: &str) -> String {
    use std::io::Write;
    print!("{text}");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    line.trim().to_string()
}

/// What a credential-free `init` verdict says about the **machine** (the account in a probe is synthetic).
///
/// Only a 434/`-22421` is a machine verdict (the lease lapsed). Every other `ec` is Apple's verdict on the
/// synthetic account, which means the machine's Anisette was accepted and processed. `-20209` is "account
/// locked", `-20970` "account information entered incorrectly", `-22406` "password wrong" — all account
/// verdicts, all a positive machine signal.
fn classify_probe(ec: Option<i64>, hsc: Option<i64>) -> &'static str {
    if ec == Some(-22421) || hsc == Some(434) {
        return "LEASE LAPSED (Apple wants a resync; the login answers this automatically)";
    }
    match ec {
        Some(0) => "accepted (no account verdict)",
        Some(-20970) => "accepted (Apple does not know the synthetic account, as expected)",
        Some(-20209) => "accepted (Apple calls the synthetic ACCOUNT locked; an account verdict, not a machine one)",
        Some(-22406) => "accepted (a password verdict; unexpected for a probe)",
        Some(other) => {
            let _ = other;
            "accepted if Apple's message is about the account; otherwise record the exact ec"
        }
        None => "accepted (no ec); record the full Status",
    }
}

fn rand_bytes(out: &mut [u8]) {
    use rand::RngCore;
    rand::thread_rng().fill_bytes(out);
}

/// `n` random bytes as uppercase hex (the Python `secrets.token_hex(n).upper()`).
fn rand_hex(n: usize) -> String {
    let mut bytes = vec![0u8; n];
    rand_bytes(&mut bytes);
    hex(&bytes).to_uppercase()
}

/// A Mac serial: `C02` + 9 alphanumerics with no I or O (`_SERIAL_ALPHABET`).
fn rand_serial() -> String {
    use rand::Rng;
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    let mut rng = rand::thread_rng();
    let mut out = String::from("C02");
    for _ in 0..9 {
        out.push(ALPHABET[rng.gen_range(0..ALPHABET.len())] as char);
    }
    out
}

fn usage() {
    eprintln!(
        "findmy <command> [--yes] [--state-dir DIR] [--images COREADI] [--machine FILE] [--session FILE] [--keys FILE] [--timeout SECS]\n\
         \n\
         Live validation (talks to Apple; read native/LIVE-VALIDATION.md first):\n\
           root-ca            TLS trust of Apple's 2006 root against gsa.apple.com\n\
           machine-probe      credential-free Grand Slam init: is the machine accepted? (lease/resync)\n\
           provision          use the saved machine, or provision a new one (--override) -> machine.json\n\
           login              SRP login (+2FA) -> session.json\n\
           reports            fetch reports for --keys FILE, or --tag-key/FINDMY_KEY [--limit N] [--max-requests N]\n\
           keychain-list      list escrow records (no passcode)\n\
           keychain-recover   recover the keychain PCS keys (ONE passcode guess) -> pcs.json\n\
           beacons            fetch + decrypt the BeaconStore accessories\n\
         Offline:\n\
           machine-headers    print one Anisette header set (redacted); --second checks the clock\n\
         \n\
         --yes is required for every command that sends anything."
    );
}

use zeroize::Zeroize;

#[cfg(test)]
mod tests {
    use super::classify_probe;

    #[test]
    fn probe_verdicts_are_classified_by_who_they_are_about() {
        // `-20209` is Apple's verdict on the (synthetic) account, so the machine was accepted.
        assert!(classify_probe(Some(-20209), Some(409)).contains("ACCOUNT locked"));
        assert!(classify_probe(Some(-20970), None).contains("does not know the synthetic account"));
        assert!(classify_probe(Some(0), None).contains("accepted"));
        // Only the resync code is a machine verdict.
        assert!(classify_probe(Some(-22421), Some(434)).contains("LEASE LAPSED"));
        assert!(classify_probe(None, Some(434)).contains("LEASE LAPSED"));
    }
}
