//! JNI entry points for `dev.osfindmy.adi.CoreAdi` (see `native/android/CoreAdi.kt`).
//! Errors become Java exceptions: `NotProvisionedException`, `AlreadyProvisionedException` or
//! `AdiException` (all in `dev.osfindmy.adi`); a panic becomes an `AdiException` too.

use std::panic::{catch_unwind, AssertUnwindSafe};

use jni::objects::{JByteArray, JClass, JObject, JObjectArray, JString};
use jni::sys::{jint, jlong};
use jni::JNIEnv;

use crate::capi::Handle;
use crate::{CoreAdi, Error};

const PKG: &str = "dev/osfindmy/adi/";

fn throw(env: &mut JNIEnv, e: &Error) {
    let class = match e {
        Error::NotProvisioned => "NotProvisionedException",
        Error::AlreadyProvisioned => "AlreadyProvisionedException",
        _ => "AdiException",
    };
    let _ = env.throw_new(format!("{PKG}{class}"), e.to_string());
}

/// Run `f`; on an error or a panic throw the matching Java exception and return `default`.
fn run<'l, T>(env: &mut JNIEnv<'l>, default: T, f: impl FnOnce(&mut JNIEnv<'l>) -> Result<T, Error>) -> T {
    match catch_unwind(AssertUnwindSafe(|| f(env))) {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            if !env.exception_check().unwrap_or(false) {
                throw(env, &e);
            }
            default
        }
        Err(_) => {
            let _ = env.throw_new(format!("{PKG}AdiException"), "internal panic");
            default
        }
    }
}

fn jerr<E: std::fmt::Display>(e: E) -> Error {
    Error::Emulation(e.to_string())
}

fn handle<'a>(h: jlong) -> Result<std::sync::MutexGuard<'a, CoreAdi>, Error> {
    if h == 0 {
        return Err(Error::Emulation("adi handle is closed".into()));
    }
    // SAFETY: `h` came from `nativeOpen` and is valid until `nativeClose`; the Kotlin class
    // serialises calls and never uses a handle after closing it.
    let h = unsafe { &*(h as *const Handle) };
    h.lock().map_err(|_| Error::Emulation("handle poisoned".into()))
}

fn bytes(env: &JNIEnv, a: &JByteArray) -> Result<Vec<u8>, Error> {
    env.convert_byte_array(a).map_err(jerr)
}

fn array_of<'l>(env: &mut JNIEnv<'l>, items: &[&[u8]]) -> Result<JObjectArray<'l>, Error> {
    let byte_array = env.find_class("[B").map_err(jerr)?;
    let out = env.new_object_array(items.len() as i32, byte_array, JObject::null()).map_err(jerr)?;
    for (i, b) in items.iter().enumerate() {
        let a = env.byte_array_from_slice(b).map_err(jerr)?;
        env.set_object_array_element(&out, i as i32, a).map_err(jerr)?;
    }
    Ok(out)
}

#[no_mangle]
pub extern "system" fn Java_dev_osfindmy_adi_CoreAdi_nativeOpen<'l>(mut env: JNIEnv<'l>, _: JClass<'l>, image: JByteArray<'l>) -> jlong {
    run(&mut env, 0, |env| {
        let adi = CoreAdi::new(&bytes(env, &image)?)?;
        Ok(Box::into_raw(Box::new(Handle::new(adi))) as jlong)
    })
}

#[no_mangle]
pub extern "system" fn Java_dev_osfindmy_adi_CoreAdi_nativeClose<'l>(_env: JNIEnv<'l>, _: JClass<'l>, h: jlong) {
    if h != 0 {
        // SAFETY: see `handle`; called once from `CoreAdi.close`.
        drop(unsafe { Box::from_raw(h as *mut Handle) });
    }
}

#[no_mangle]
pub extern "system" fn Java_dev_osfindmy_adi_CoreAdi_nativeBuild<'l>(mut env: JNIEnv<'l>, _: JClass<'l>, h: jlong) -> JString<'l> {
    let null = JString::from(JObject::null());
    run(&mut env, null, |env| {
        let name = handle(h)?.build();
        env.new_string(name).map_err(jerr)
    })
}

#[no_mangle]
pub extern "system" fn Java_dev_osfindmy_adi_CoreAdi_nativeSetHostUuid<'l>(mut env: JNIEnv<'l>, _: JClass<'l>, h: jlong, uuid: JByteArray<'l>) {
    run(&mut env, (), |env| {
        let u: [u8; 16] = bytes(env, &uuid)?.try_into().map_err(|_| Error::Emulation("host uuid needs 16 bytes".into()))?;
        handle(h)?.set_host_uuid(u);
        Ok(())
    })
}

#[no_mangle]
pub extern "system" fn Java_dev_osfindmy_adi_CoreAdi_nativeSetFrozenTime<'l>(mut env: JNIEnv<'l>, _: JClass<'l>, h: jlong, secs: jlong) {
    run(&mut env, (), |_| {
        handle(h)?.set_frozen_time(u64::try_from(secs).ok());
        Ok(())
    })
}

#[no_mangle]
pub extern "system" fn Java_dev_osfindmy_adi_CoreAdi_nativeStoreExport<'l>(mut env: JNIEnv<'l>, _: JClass<'l>, h: jlong) -> JByteArray<'l> {
    let null = JByteArray::from(JObject::null());
    run(&mut env, null, |env| {
        let mut v = Vec::new();
        for (name, data) in handle(h)?.store_files() {
            v.extend((name.len() as u16).to_be_bytes());
            v.extend(name.as_bytes());
            v.extend((data.len() as u32).to_be_bytes());
            v.extend(data);
        }
        env.byte_array_from_slice(&v).map_err(jerr)
    })
}

#[no_mangle]
pub extern "system" fn Java_dev_osfindmy_adi_CoreAdi_nativeStoreImport<'l>(mut env: JNIEnv<'l>, _: JClass<'l>, h: jlong, data: JByteArray<'l>) {
    run(&mut env, (), |env| {
        let raw = bytes(env, &data)?;
        let mut d = raw.as_slice();
        let mut g = handle(h)?;
        let bad = || Error::Emulation("malformed store export".into());
        while !d.is_empty() {
            let nl = u16::from_be_bytes(d.get(..2).ok_or_else(bad)?.try_into().unwrap()) as usize;
            let name = std::str::from_utf8(d.get(2..2 + nl).ok_or_else(bad)?).map_err(|_| bad())?;
            let dl = u32::from_be_bytes(d.get(2 + nl..6 + nl).ok_or_else(bad)?.try_into().unwrap()) as usize;
            g.store_put(name, d.get(6 + nl..6 + nl + dl).ok_or_else(bad)?);
            d = &d[6 + nl + dl..];
        }
        Ok(())
    })
}

/// `[mid, otp, routing as 8 big-endian bytes]`
#[no_mangle]
pub extern "system" fn Java_dev_osfindmy_adi_CoreAdi_nativeHeaders<'l>(mut env: JNIEnv<'l>, _: JClass<'l>, h: jlong, ds: jlong) -> JObjectArray<'l> {
    let null = JObjectArray::from(JObject::null());
    run(&mut env, null, |env| {
        let r = handle(h)?.headers(ds)?;
        array_of(env, &[&r.mid, &r.otp, &r.routing.to_be_bytes()])
    })
}

/// `[cpim, session as 4 big-endian bytes]`
#[no_mangle]
pub extern "system" fn Java_dev_osfindmy_adi_CoreAdi_nativeProvisioningBegin<'l>(
    mut env: JNIEnv<'l>,
    _: JClass<'l>,
    h: jlong,
    ds: jlong,
    spim: JByteArray<'l>,
) -> JObjectArray<'l> {
    let null = JObjectArray::from(JObject::null());
    run(&mut env, null, |env| {
        let (cpim, session) = handle(h)?.provisioning_begin(ds, &bytes(env, &spim)?)?;
        array_of(env, &[&cpim, &session.to_be_bytes()])
    })
}

#[no_mangle]
pub extern "system" fn Java_dev_osfindmy_adi_CoreAdi_nativeProvisioningFinish<'l>(
    mut env: JNIEnv<'l>,
    _: JClass<'l>,
    h: jlong,
    ds: jlong,
    session: jint,
    ptm: JByteArray<'l>,
    tk: JByteArray<'l>,
    routing: jlong,
) {
    run(&mut env, (), |env| {
        let (ptm, tk) = (bytes(env, &ptm)?, bytes(env, &tk)?);
        handle(h)?.provisioning_finish(ds, session as u32, &ptm, &tk, routing as u64)
    })
}

/// `[mid, srm]`
#[no_mangle]
pub extern "system" fn Java_dev_osfindmy_adi_CoreAdi_nativeSync<'l>(mut env: JNIEnv<'l>, _: JClass<'l>, h: jlong, ds: jlong, sim: JByteArray<'l>) -> JObjectArray<'l> {
    let null = JObjectArray::from(JObject::null());
    run(&mut env, null, |env| {
        let (mid, srm) = handle(h)?.sync(ds, &bytes(env, &sim)?)?;
        array_of(env, &[&mid, &srm])
    })
}

#[no_mangle]
pub extern "system" fn Java_dev_osfindmy_adi_CoreAdi_nativeUpdateRouting<'l>(mut env: JNIEnv<'l>, _: JClass<'l>, h: jlong, ds: jlong, routing: jlong) {
    run(&mut env, (), |_| handle(h)?.update_routing(ds, routing as u64))
}
