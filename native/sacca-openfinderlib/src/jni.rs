//! JNI entry points for `com.sacca.openfinder.lib.OpenFinderLib` (the thin Kotlin/Java wrapper over the C ABI).
//!
//! Every method returns or throws the same JSON the C ABI does; a failure to open becomes a Java
//! `FindMyException`. The handle owns the CoreADI machine and a tokio runtime, so calls run on the
//! caller's thread (Kotlin uses a background dispatcher).

use std::ffi::{c_char, CStr, CString};

use jni::objects::{JByteArray, JClass, JObject, JString};
use jni::sys::{jlong, jstring};
use jni::JNIEnv;

use crate::{openfinder_call, openfinder_open_machine, openfinder_string_free};

fn throw(env: &mut JNIEnv, message: &str) {
    let _ = env.throw_new("com/sacca/openfinder/lib/OpenFinderLibException", message);
}

fn jstring_or_empty<'l>(env: &mut JNIEnv<'l>, s: &str) -> JString<'l> {
    env.new_string(s).unwrap_or_else(|_| JString::from(JObject::null()))
}

/// Opens a session that owns the CoreADI machine (the machine file plus the CoreADI image).
#[no_mangle]
pub extern "system" fn Java_com_sacca_openfinder_lib_OpenFinderLib_nativeOpenMachine<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    machine_json: JString<'l>,
    image: JByteArray<'l>,
) -> jlong {
    let machine: String = match env.get_string(&machine_json) {
        Ok(s) => s.into(),
        Err(_) => {
            throw(&mut env, "machine file is not a string");
            return 0;
        }
    };
    let bytes = match env.convert_byte_array(&image) {
        Ok(b) => b,
        Err(_) => {
            throw(&mut env, "CoreADI image is not readable");
            return 0;
        }
    };
    let Ok(machine_c) = CString::new(machine) else {
        throw(&mut env, "machine file contains a NUL");
        return 0;
    };
    let handle = unsafe { openfinder_open_machine(machine_c.as_ptr(), bytes.as_ptr(), bytes.len()) };
    if handle.is_null() {
        throw(&mut env, "could not open the Find My session (bad machine file or CoreADI image)");
        return 0;
    }
    handle as jlong
}

/// Runs one command and returns its JSON response.
#[no_mangle]
pub extern "system" fn Java_com_sacca_openfinder_lib_OpenFinderLib_nativeCall<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    handle: jlong,
    request: JString<'l>,
) -> jstring {
    if handle == 0 {
        throw(&mut env, "the Find My session is closed");
        return std::ptr::null_mut();
    }
    let request: String = match env.get_string(&request) {
        Ok(s) => s.into(),
        Err(_) => {
            throw(&mut env, "request is not a string");
            return std::ptr::null_mut();
        }
    };
    let Ok(request_c) = CString::new(request) else {
        throw(&mut env, "request contains a NUL");
        return std::ptr::null_mut();
    };
    let response = unsafe { openfinder_call(handle as *mut _, request_c.as_ptr()) };
    if response.is_null() {
        throw(&mut env, "the Find My session returned no response");
        return std::ptr::null_mut();
    }
    let text = unsafe { CStr::from_ptr(response) }.to_string_lossy().into_owned();
    unsafe { openfinder_string_free(response) };
    jstring_or_empty(&mut env, &text).into_raw()
}

/// Closes a session.
#[no_mangle]
pub extern "system" fn Java_com_sacca_openfinder_lib_OpenFinderLib_nativeClose<'l>(_env: JNIEnv<'l>, _class: JClass<'l>, handle: jlong) {
    if handle != 0 {
        unsafe { crate::openfinder_close(handle as *mut _) };
    }
}

/// The library version.
#[no_mangle]
pub extern "system" fn Java_com_sacca_openfinder_lib_OpenFinderLib_nativeVersion<'l>(mut env: JNIEnv<'l>, _class: JClass<'l>) -> jstring {
    let version = unsafe { CStr::from_ptr(crate::openfinder_version()) }.to_string_lossy().into_owned();
    jstring_or_empty(&mut env, &version).into_raw()
}

// Keep the `c_char` import meaningful on all targets.
#[allow(dead_code)]
type _Unused = c_char;
