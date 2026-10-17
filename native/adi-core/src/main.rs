//! adi-cli: ask a CoreADI build for MID/OTP using a state directory in the Python tool's layout
//! (`identity.json` with `host_uuid`, `store/*.pb`). Prints hex, so it can be diffed against
//! `tools/machoadi/adi_run.py` byte for byte.
//!
//!     adi-cli --dylib CoreADI [--state DIR] [--frozen SECS [--step SECS]] [--repeat N] [--all]
//!
//! Each repeat is one session (reset, Initialize, IsMachineProvisioned, RequestOTP, GetIDMSRouting).
//! `--all` prints every session; the clock advances by `--step` per session.

use std::{env, fs, process::exit, time::Instant};

use adi_core::{CoreAdi, STORE_DIR};
use sha2::{Digest, Sha256};

const DS_ID: i64 = -2;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("adi-cli: {msg}");
    exit(1)
}

fn main() {
    let (mut dylib, mut state, mut frozen, mut repeat) = (None, None, None, 1usize);
    let (mut step, mut all) = (0u64, false);
    let mut args = env::args().skip(1);
    while let Some(a) = args.next() {
        let mut val = || args.next().unwrap_or_else(|| die(format!("{a} needs a value")));
        match a.as_str() {
            "--dylib" => dylib = Some(val()),
            "--state" => state = Some(val()),
            "--frozen" => frozen = Some(val().parse::<u64>().unwrap_or_else(|_| die("--frozen takes seconds"))),
            "--step" => step = val().parse().unwrap_or_else(|_| die("--step takes seconds")),
            "--all" => all = true,
            "--repeat" => repeat = val().parse().unwrap_or_else(|_| die("--repeat takes a number")),
            _ => die(format!("unknown argument {a}")),
        }
    }
    let dylib = dylib.unwrap_or_else(|| die("--dylib is required"));
    let image = fs::read(&dylib).unwrap_or_else(|e| die(format!("{dylib}: {e}")));

    let start = Instant::now();
    let mut adi = CoreAdi::new(&image).unwrap_or_else(|e| die(e));
    eprintln!("build: {}", adi.build());
    if let Some(s) = frozen {
        adi.set_frozen_time(Some(s));
    }
    if let Some(state) = state {
        let identity = fs::read_to_string(format!("{state}/identity.json")).unwrap_or_else(|e| die(e));
        let uuid = identity
            .split("\"host_uuid\"")
            .nth(1)
            .and_then(|r| r.split('"').nth(1))
            .and_then(unhex)
            .and_then(|v| <[u8; 16]>::try_from(v).ok())
            .unwrap_or_else(|| die("identity.json has no 16-byte host_uuid"));
        adi.set_host_uuid(uuid);
        for e in fs::read_dir(format!("{state}/store")).unwrap_or_else(|e| die(e)).flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name != "adi.pb" {
                adi.vm().files_mut().insert(format!("{STORE_DIR}/{name}"), fs::read(e.path()).unwrap());
            }
        }
    }
    let sha = |adi: &mut CoreAdi| -> String {
        let mut h = Sha256::new();
        for (k, v) in adi.vm().files() {
            h.update(k.as_bytes());
            h.update(v);
        }
        hex(&h.finalize())
    };
    let t0 = Instant::now();
    let mut total = std::time::Duration::ZERO;
    for i in 0..repeat {
        if let Some(s) = frozen {
            adi.set_frozen_time(Some(s + step * i as u64));
        }
        // One session, the same sequence as `mac_anisette.py headers`.
        let t = Instant::now();
        let init = adi.begin_session().unwrap_or_else(|e| die(e));
        let t_init = t.elapsed();
        let prov = adi.is_machine_provisioned(DS_ID).unwrap_or_else(|e| die(e));
        if prov.ret != 0 {
            die(format!("not provisioned (init {init:?}, ret {})", prov.ret));
        }
        let t_prov = t.elapsed();
        let otp = adi.request_otp(DS_ID).unwrap_or_else(|e| die(e));
        if !otp.reply.ok() {
            die(format!("RequestOTP failed: {:?}", otp.reply));
        }
        let (_, routing) = adi.get_routing(DS_ID).unwrap_or_else(|e| die(e));
        total += t.elapsed();
        eprintln!("session {i}: {:?} [init {:?}, prov {:?}] (heap {} KiB)", t.elapsed(), t_init, t_prov - t_init, adi.vm().heap_used() / 1024);
        if all || i + 1 == repeat {
            println!("t={} mid={} otp={} routing={routing} store={}", frozen.map_or(0, |s| s + step * i as u64), hex(&otp.mid), hex(&otp.otp), sha(&mut adi));
        }
    }
    eprintln!("{repeat} sessions in {:?} (sessions {:?}, load {:?})", t0.elapsed(), total, t0.duration_since(start));
}
