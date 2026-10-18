//! Fixture-driven tests for the keychain bottle cryptography
//! (`app/tools/oracle/keychain_vectors.py`). No network, nothing real.

use apple_core::crypto::aes_gcm_decrypt;
use apple_core::keychain::bottle::{
    derive_bottle_keys, find_bottle_keys, open_bottle, parse_peer_private_key, public_key_encodings,
};
use apple_proto::cuttlefish::Bottle;
use elliptic_curve::sec1::ToEncodedPoint;
use prost::Message;
use serde_json::Value;

fn fixture(name: &str) -> Value {
    let path = format!(
        "{}/../../app/android/app/src/test/resources/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

fn hexvec(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn bottle_vectors() {
    let d = fixture("keychain/bottle.json");

    // derive_bottle_keys
    let derive = &d["derive"];
    let entropy = hexvec(derive["entropy"].as_str().unwrap());
    let adsid = derive["adsid"].as_str().unwrap();
    let keys = derive_bottle_keys(&entropy, adsid).unwrap();
    assert_eq!(hex(&keys.symmetric), derive["symmetric"].as_str().unwrap());
    let forms: std::collections::HashMap<&str, String> =
        public_key_encodings(&keys.signing).into_iter().map(|(n, b)| (n, hex(&b))).collect();
    assert_eq!(forms["x962-uncompressed"], derive["signing"]["point"].as_str().unwrap());
    assert_eq!(forms["x962-compressed"], derive["signing"]["compressed"].as_str().unwrap());
    assert_eq!(forms["der-spki"], derive["signing"]["spki"].as_str().unwrap());
    let enc: std::collections::HashMap<&str, String> =
        public_key_encodings(&keys.encryption).into_iter().map(|(n, b)| (n, hex(&b))).collect();
    assert_eq!(enc["x962-uncompressed"], derive["encryption"]["point"].as_str().unwrap());
    assert_eq!(enc["der-spki"], derive["encryption"]["spki"].as_str().unwrap());

    // find_bottle_keys (the salt check)
    let m = &d["match"];
    let (found, salt) = find_bottle_keys(
        &hexvec(m["entropy"].as_str().unwrap()),
        &[m["adsid"].as_str().unwrap().to_string()],
        &hexvec(m["escrowed_signing"].as_str().unwrap()),
        &hexvec(m["escrowed_encryption"].as_str().unwrap()),
    )
    .unwrap();
    assert_eq!(salt, m["adsid"].as_str().unwrap());
    assert_eq!(hex(&found.symmetric), derive["symmetric"].as_str().unwrap());

    // open_bottle
    let o = &d["open"];
    let bottle = Bottle::decode(hexvec(o["bottle"].as_str().unwrap()).as_slice()).unwrap();
    let keys = derive_bottle_keys(&hexvec(o["entropy"].as_str().unwrap()), o["adsid"].as_str().unwrap()).unwrap();
    let opened = open_bottle(&bottle, &keys, true, None).unwrap();
    assert_eq!(hex(&opened.signing_key), o["signing_key"].as_str().unwrap());
    assert_eq!(hex(&opened.encryption_key), o["encryption_key"].as_str().unwrap());
    assert_eq!(opened.signing_key_type, o["signing_key_type"].as_u64().unwrap() as u32);
    assert_eq!(opened.encryption_key_type, o["encryption_key_type"].as_u64().unwrap() as u32);
    assert_eq!(opened.key_encoding, o["key_encoding"].as_str().unwrap());
    assert_eq!(opened.escrowed_key_verified, o["escrowed_key_verified"].as_bool().unwrap());
    assert!(!opened.sponsor_known);

    // parse_peer_private_key
    let pk = &d["peer_key"];
    let parsed = parse_peer_private_key(&hexvec(pk["material"].as_str().unwrap())).unwrap();
    assert_eq!(hex(parsed.public_key().to_encoded_point(false).as_bytes()), pk["point"].as_str().unwrap());
    assert_eq!(hex(&parsed.to_bytes()), pk["scalar"].as_str().unwrap());

    // GCM with a 32-byte IV and a 16-byte tag
    let g = &d["gcm32"];
    let plain = aes_gcm_decrypt(
        &hexvec(g["key"].as_str().unwrap()),
        &hexvec(g["iv"].as_str().unwrap()),
        &hexvec(g["aad"].as_str().unwrap()),
        &hexvec(g["ciphertext"].as_str().unwrap()),
        &hexvec(g["tag"].as_str().unwrap()),
    )
    .unwrap();
    assert_eq!(hex(&plain), g["plaintext"].as_str().unwrap());
}

// --------------------------------------------------------------------- escrow / recovery framing

mod recovery_path {
    use apple_core::keychain::escrow::{
        build_keyvault_message, escrow_host, join_recovery_options,
        parse_metadata, split_keyvault_message, EscrowListing, EscrowRecord, KeyVaultSection,
    };
    use apple_core::keychain::recovery::{
        build_recovery_proof, parse_challenge, unwrap_inner_blob, unwrap_outer_blob, RecoveryChallenge,
    };
    use serde_json::{json, Value};

    fn fixture(name: &str) -> Value {
        let path = format!(
            "{}/../../app/android/app/src/test/resources/fixtures/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
    }

    fn hexvec(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn keyvault_vectors() {
        let d = fixture("keychain/keyvault.json");
        for (name, case) in d["parsed"].as_object().unwrap() {
            let (header_length, section_count) = match name.as_str() {
                "basic" => (16, 4),
                "two_sections" => (12, 2),
                "footprint" => (16, 2),
                _ => unreachable!(),
            };
            let data = match name.as_str() {
                "basic" => hexvec(d["built"].as_str().unwrap()),
                "footprint" => hexvec(d["built_footprint"].as_str().unwrap()),
                _ => {
                    // Rebuild the two-section message from the parsed parts.
                    let header = hexvec(case["header"].as_str().unwrap());
                    let sections: Vec<KeyVaultSection> = case["sections"].as_array().unwrap().iter().map(|s| KeyVaultSection::new(hexvec(s.as_str().unwrap()))).collect();
                    build_keyvault_message(&header, &sections).unwrap()
                }
            };
            let (prefix, header, sections) = split_keyvault_message(&data, header_length, section_count).unwrap();
            assert_eq!(header, hexvec(case["header"].as_str().unwrap()), "{name} header");
            let got: Vec<String> = sections.iter().map(|s| hex(s)).collect();
            let want: Vec<String> = case["sections"].as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_string()).collect();
            assert_eq!(got, want, "{name} sections");
            assert_eq!(prefix.len(), 4);
            assert_eq!(u32::from_be_bytes(prefix.try_into().unwrap()) as i64, case["declared"].as_i64().unwrap(), "{name} declared");

            // Round-trip: rebuilding the basic message reproduces the fixture bytes exactly.
            if name == "basic" {
                let rebuilt = build_keyvault_message(&header, &sections.iter().map(|s| KeyVaultSection::new(s.clone())).collect::<Vec<_>>()).unwrap();
                assert_eq!(hex(&rebuilt), d["built"].as_str().unwrap());
            }
        }

        for (name, case) in d["errors"].as_object().unwrap() {
            let (header_length, section_count) = (16usize, 2usize);
            let data = hexvec(case["data"].as_str().unwrap());
            let result = split_keyvault_message(&data, header_length, section_count);
            if case["error"].is_string() {
                assert!(result.is_err(), "{name}");
            } else {
                assert!(result.is_ok(), "{name}");
            }
        }
    }

    #[test]
    fn recovery_srp_matches_pysrp() {
        use apple_core::login::srp::SrpClient;
        let d = fixture("keychain/recovery_srp.json");
        for case in d["cases"].as_array().unwrap() {
            let secret = hexvec(case["secret"].as_str().unwrap());
            let mut padded = vec![0u8; 256 - secret.len()];
            padded.extend_from_slice(&secret);
            let mut srp = SrpClient::new_standard("", &padded);
            assert_eq!(hex(&srp.public_a()), case["client_public"].as_str().unwrap(), "{} A", case["name"]);
            srp.set_username(case["identity"].as_str().unwrap());
            let proof = srp
                .process_challenge(
                    &hexvec(case["salt"].as_str().unwrap()),
                    &hexvec(case["server_public"].as_str().unwrap()),
                    case["password"].as_str().unwrap().as_bytes(),
                )
                .unwrap();
            assert_eq!(hex(&proof), case["proof"].as_str().unwrap(), "{} M1", case["name"]);
        }
    }

    #[test]
    fn recovery_vectors() {
        let d = fixture("keychain/recovery.json");

        for key in ["proof", "proof_club"] {
            let case = &d[key];
            let challenge = RecoveryChallenge {
                label: "com.apple.icdp.record.PEER-1".into(),
                transaction_id: "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0".into(),
                prefix: Vec::new(),
                header: hexvec(case["header"].as_str().unwrap()),
                exchange_token: hexvec(case["exchange_token"].as_str().unwrap()),
                salt: Vec::new(),
                server_public: Vec::new(),
                dsid: "1234567890".into(),
                club_type_id: case["club_type_id"].as_i64(),
            };
            let proof = hexvec(case["proof"].as_str().unwrap());
            let built = build_recovery_proof(&challenge, &proof).unwrap();
            assert_eq!(hex(&built), case["expected"].as_str().unwrap(), "{key}");
        }

        let cbc = &d["outer_cbc"];
        let inner = unwrap_outer_blob(
            &hexvec(cbc["blob"].as_str().unwrap()),
            &hexvec(cbc["session_key"].as_str().unwrap()),
            cbc["club_type_id"].as_i64(),
        )
        .unwrap();
        assert_eq!(hex(&inner), cbc["inner"].as_str().unwrap(), "outer cbc");

        let gcm = &d["outer_gcm"];
        let inner = unwrap_outer_blob(
            &hexvec(gcm["blob"].as_str().unwrap()),
            &hexvec(gcm["session_key"].as_str().unwrap()),
            gcm["club_type_id"].as_i64(),
        )
        .unwrap();
        assert_eq!(hex(&inner), gcm["inner"].as_str().unwrap(), "outer gcm");

        let inner_case = &d["inner"];
        let material = unwrap_inner_blob(&hexvec(inner_case["blob"].as_str().unwrap()), inner_case["passcode"].as_str().unwrap()).unwrap();
        assert_eq!(hex(&material), inner_case["material"].as_str().unwrap(), "inner");

        let challenge_case = &d["challenge"];
        let parsed = parse_challenge(
            &challenge_case["response"],
            challenge_case["label"].as_str().unwrap(),
            challenge_case["transaction_id"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(hex(&parsed.header), challenge_case["header"].as_str().unwrap());
        assert_eq!(hex(&parsed.exchange_token), challenge_case["exchange_token"].as_str().unwrap());
        assert_eq!(hex(&parsed.salt), challenge_case["salt"].as_str().unwrap());
        assert_eq!(hex(&parsed.server_public), challenge_case["server_public"].as_str().unwrap());
        assert_eq!(parsed.dsid, challenge_case["dsid"].as_str().unwrap());
    }

    fn record_json(r: &EscrowRecord) -> Value {
        json!({
            "label": r.label,
            "peer_id": r.peer_id(),
            "is_companion": r.is_companion(),
            "companion_of": r.companion_of(),
            "device_name": r.device_name,
            "device_model": r.device_model,
            "serial": r.serial,
            "build": r.build,
            "bottle_id": r.bottle_id,
            "escrowed_at": r.escrowed_at.map(|d| apple_core::reports::keys::isoformat(d)),
            "is_recovery_candidate": r.is_recovery_candidate(),
        })
    }

    #[test]
    fn escrow_vectors() {
        let d = fixture("keychain/escrow.json");
        let mut records = Vec::new();
        for (entry, want) in d["listed"].as_array().unwrap().iter().zip(d["records"].as_array().unwrap()) {
            let label = entry["label"].as_str().unwrap();
            let record = parse_metadata(label, entry["metadata"].as_str().unwrap().as_bytes()).unwrap();
            assert_eq!(&record_json(&record), want, "record {label}");
            records.push(record);
        }

        let listing = EscrowListing { records, unreadable: Vec::new(), status: Some(0), message: None };
        let viable: Vec<String> = d["options"]["recoverable"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["label"].as_str().unwrap().to_string())
            .collect();
        let options = join_recovery_options(&listing, &viable);

        let got_recoverable: Vec<Value> = options.recoverable.iter().map(record_json).collect();
        assert_eq!(Value::Array(got_recoverable), d["options"]["recoverable"]);
        let got_not_viable: Vec<Value> = options.described_but_not_viable.iter().map(record_json).collect();
        assert_eq!(Value::Array(got_not_viable), d["options"]["described_but_not_viable"]);
        assert_eq!(json!(options.viable_but_undescribed), d["options"]["viable_but_undescribed"]);
        assert_eq!(options.device_count(), d["options"]["device_count"].as_u64().unwrap() as usize);
        assert_eq!(options.viability_is_trustworthy(), d["options"]["viability_is_trustworthy"].as_bool().unwrap());

        assert_eq!(escrow_host("24"), "https://p24-escrowproxy.icloud.com:443");
    }
}

// --------------------------------------------------------------------- peers

mod peer_path {
    use apple_core::keychain::peers::{
        apply_changes, check_peer_identifiers, load_public_key, peer_identifier, PeerDirectory,
    };
    use apple_proto::cuttlefish::CuttlefishChanges;
    use prost::Message;
    use serde_json::{json, Value};

    fn fixture(name: &str) -> Value {
        let path = format!(
            "{}/../../app/android/app/src/test/resources/fixtures/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
    }

    fn hexvec(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn peer_vectors() {
        let d = fixture("keychain/peers.json");

        let id = &d["identifier"];
        assert_eq!(
            peer_identifier(&hexvec(id["permanent_info"].as_str().unwrap()), &hexvec(id["signature"].as_str().unwrap())),
            id["peer_id"].as_str().unwrap()
        );

        for case in d["public_keys"].as_array().unwrap() {
            let loaded = if let Some(k) = case["key"].as_object() {
                ["uncompressed", "compressed", "spki"]
                    .iter()
                    .find_map(|f| load_public_key(&hexvec(k[*f].as_str().unwrap())))
                    .map(|p| hex(p.uncompressed()))
            } else {
                load_public_key(&hexvec(case["garbage"].as_str().unwrap())).map(|p| hex(p.uncompressed()))
            };
            assert_eq!(loaded, case["loaded"].as_str().map(str::to_string));
        }

        let changes = CuttlefishChanges::decode(hexvec(d["changes"].as_str().unwrap()).as_slice()).unwrap();
        let mut peers = std::collections::BTreeMap::new();
        let added = apply_changes(&mut peers, &changes);
        assert_eq!(added, 1);
        let directory = PeerDirectory { peers, sync_token: changes.sync_token.clone() };
        assert_eq!(directory.sync_token.as_deref(), d["directory"]["sync_token"].as_str());

        for want in d["directory"]["peers"].as_array().unwrap() {
            let peer = directory.get(want["hash"].as_str().unwrap()).unwrap();
            assert_eq!(hex(&peer.signing_key), want["signing_key"].as_str().unwrap());
            assert_eq!(hex(&peer.permanent_info), want["permanent_info"].as_str().unwrap());
            assert_eq!(peer.stable_clock, want["stable_clock"].as_u64().unwrap());
            assert_eq!(peer.dynamic_clock, want["dynamic_clock"].as_u64().unwrap());
            assert_eq!(json!(peer.includeds), want["includeds"]);
            assert_eq!(json!(peer.excludeds), want["excludeds"]);
            assert_eq!(peer.hash_is_derivable(), want["hash_is_derivable"].as_bool().unwrap());
        }
        assert!(check_peer_identifiers(&directory).confirmed());
    }
}

// --------------------------------------------------------------------- shares

mod share_path {
    use apple_core::keychain::shares::{
        parse_key_material, sfies_decrypt, sfies_decrypt_archive, sfies_parts, share_signed_data,
        unwrap_class_key, SfiesParts, ShareRecord,
    };
    use serde_json::Value;

    fn fixture(name: &str) -> Value {
        let path = format!(
            "{}/../../app/android/app/src/test/resources/fixtures/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
    }

    fn hexvec(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn share_vectors() {
        let d = fixture("keychain/shares.json");

        let sfies = &d["sfies"];
        let private = p384::SecretKey::from_slice(&hexvec(sfies["receiver_private"].as_str().unwrap())).unwrap();
        let parts = SfiesParts {
            point: hexvec(sfies["point"].as_str().unwrap()),
            ciphertext: hexvec(sfies["ciphertext"].as_str().unwrap()),
            code: hexvec(sfies["code"].as_str().unwrap()),
        };
        let plaintext = sfies_decrypt(&private, &parts).unwrap();
        assert_eq!(hex(&plaintext), sfies["plaintext"].as_str().unwrap(), "sfies direct");

        let from_archive = sfies_parts(&hexvec(sfies["archive"].as_str().unwrap())).unwrap();
        assert_eq!(hex(&from_archive.point), sfies["point"].as_str().unwrap(), "archive point");
        assert_eq!(hex(&from_archive.ciphertext), sfies["ciphertext"].as_str().unwrap(), "archive ciphertext");
        assert_eq!(hex(&from_archive.code), sfies["code"].as_str().unwrap(), "archive code");
        let via_archive = sfies_decrypt_archive(&private, &hexvec(sfies["archive"].as_str().unwrap())).unwrap();
        assert_eq!(hex(&via_archive), sfies["plaintext"].as_str().unwrap(), "sfies archive");

        let class_key = &d["class_key"];
        let unwrapped = unwrap_class_key(
            &hexvec(class_key["wrapped"].as_str().unwrap()),
            &hexvec(class_key["top_level"].as_str().unwrap()),
        )
        .unwrap();
        assert_eq!(hex(&unwrapped), class_key["unwrapped"].as_str().unwrap());

        let signed = &d["share_signed_data"];
        let s = &signed["share"];
        let record = ShareRecord {
            sender: s["sender"].as_str().unwrap().to_string(),
            receiver: s["receiver"].as_str().unwrap().to_string(),
            receiver_public_encryption_key: {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD.decode(s["receiver_public_encryption_key"].as_str().unwrap()).unwrap()
            },
            wrapped_key: {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD.decode(s["wrapped_key"].as_str().unwrap()).unwrap()
            },
            signature: {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD.decode(s["signature"].as_str().unwrap()).unwrap()
            },
            curve: s["curve"].as_i64().unwrap(),
            epoch: s["epoch"].as_i64().unwrap(),
            poisoned: s["poisoned"].as_i64().unwrap(),
            version: s["version"].as_i64().unwrap(),
        };
        assert_eq!(hex(&share_signed_data(&record)), signed["signed_data"].as_str().unwrap());

        let material = &d["material"];
        let parsed = parse_key_material(&hexvec(material["serialized"].as_str().unwrap())).unwrap();
        assert_eq!(parsed.uuid.as_deref(), Some(material["uuid"].as_str().unwrap()));
        assert_eq!(hex(parsed.key.as_deref().unwrap()), material["key"].as_str().unwrap());
    }
}

// --------------------------------------------------------------------- items

mod item_path {
    use apple_core::cloudkit::records::CloudKitRecord;
    use apple_core::keychain::items::{additional_data, decrypt_item, payload_of};
    use apple_core::keychain::shares::ViewKeyring;
    use apple_proto::cloudkit::Record;
    use prost::Message;
    use serde_json::Value;

    fn fixture(name: &str) -> Value {
        let path = format!(
            "{}/../../app/android/app/src/test/resources/fixtures/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
    }

    fn hexvec(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn item_vectors() {
        let d = fixture("keychain/items.json");
        for case in d["cases"].as_array().unwrap() {
            let proto = Record::decode(hexvec(case["record"].as_str().unwrap()).as_slice()).unwrap();
            let record = CloudKitRecord::from_proto(&proto, "Manatee");
            let view_uuid = case["view_uuid"].as_str().unwrap();
            let view_key = hexvec(case["view_key"].as_str().unwrap());

            let additional = additional_data(&record, view_uuid).unwrap();
            assert_eq!(additional.len(), case["additional_count"].as_u64().unwrap() as usize, "additional count");

            let keyring = ViewKeyring {
                by_uuid: std::collections::BTreeMap::from([(view_uuid.to_string(), view_key)]),
                by_slot: std::collections::BTreeMap::new(),
            };
            let item = decrypt_item(&record, &keyring).unwrap();
            assert_eq!(hex(&payload_of(&item).unwrap()), case["v_data"].as_str().unwrap(), "v_Data");

            // `acct` is base64 in the plist, decoding to the raw account key.
            let acct = match item.get("acct") {
                Some(apple_core::plist::Value::String(s)) => s.clone(),
                other => panic!("unexpected acct {other:?}"),
            };
            use base64::Engine as _;
            let account = base64::engine::general_purpose::STANDARD.decode(acct).unwrap();
            assert_eq!(hex(&account), case["acct"].as_str().unwrap(), "acct");
        }
    }
}

// ------------------------------------------------------- session end-to-end (offline)

mod session_path {
    use std::sync::{Arc, Mutex};

    use apple_core::cloudkit::client::{CloudKitAccount, CloudKitClient};
    use apple_core::cloudkit::{CloudKitApi, CloudKitContainerInfo, RecordSyncPage};
    use apple_core::keychain::escrow::{
        build_keyvault_message, escrow_host, EscrowAccount, EscrowCommands, EscrowListing, EscrowRecord,
        EscrowProxy, KeyVaultSection,
    };
    use apple_core::keychain::session::{KeychainAccount, KeychainSession};
    use apple_core::login::srp::{group_n, minimal};
    use apple_core::login::BoxFuture;
    use apple_proto::cloudkit::{RecordChange, ZoneSummary};
    use num_bigint::BigUint;
    use serde_json::Value;
    use sha2::{Digest, Sha256};

    fn fixture(name: &str) -> Value {
        let path = format!(
            "{}/../../app/android/app/src/test/resources/fixtures/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
    }

    fn hexvec(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn h(parts: &[&[u8]]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for p in parts {
            hasher.update(p);
        }
        hasher.finalize().into()
    }

    fn pad(b: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; (256usize).saturating_sub(b.len())];
        out.extend_from_slice(b);
        out
    }

    fn little_big(n: &BigUint) -> Vec<u8> {
        minimal(n)
    }

    // ---- account

    struct FakeAccount {
        http: apple_core::http::Http,
        adsid: String,
    }

    impl CloudKitAccount for FakeAccount {
        fn dsid<'a>(&'a self) -> BoxFuture<'a, apple_core::Result<String>> {
            Box::pin(async move { Ok("1234567890".to_string()) })
        }
        fn device_uuid(&self) -> String {
            "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0".to_string()
        }
        fn client_info(&self) -> String {
            "<MacBookPro18,3> <Mac OS X;13.4.1;22F82>".to_string()
        }
        fn serial(&self) -> Option<String> {
            None
        }
        fn service_token<'a>(&'a self, _name: &'a str) -> BoxFuture<'a, Option<String>> {
            Box::pin(async move { None })
        }
        fn anisette_headers<'a>(&'a self) -> BoxFuture<'a, apple_core::Result<std::collections::BTreeMap<String, String>>> {
            Box::pin(async move { Ok(std::collections::BTreeMap::new()) })
        }
        fn http(&self) -> &apple_core::http::Http {
            &self.http
        }
        fn timeout(&self) -> std::time::Duration {
            std::time::Duration::from_secs(5)
        }
    }

    impl EscrowAccount for FakeAccount {
        fn client_info(&self, _bundle: &str) -> String {
            "<MacBookPro18,3> <Mac OS X;13.4.1;22F82>".to_string()
        }
        fn user_agent(&self, _product: &str) -> String {
            "synthetic".to_string()
        }
        fn timeout(&self) -> std::time::Duration {
            std::time::Duration::from_secs(5)
        }
        fn anisette_headers<'a>(&'a self) -> BoxFuture<'a, apple_core::Result<std::collections::BTreeMap<String, String>>> {
            Box::pin(async move { Ok(std::collections::BTreeMap::new()) })
        }
        fn http(&self) -> &apple_core::http::Http {
            &self.http
        }
    }

    impl KeychainAccount for FakeAccount {
        fn adsid<'a>(&'a self) -> BoxFuture<'a, String> {
            Box::pin(async move { self.adsid.clone() })
        }
        fn account_name<'a>(&'a self) -> BoxFuture<'a, String> {
            Box::pin(async move { "synthetic@example.invalid".to_string() })
        }
        fn request_pet<'a>(&'a self) -> BoxFuture<'a, apple_core::Result<String>> {
            Box::pin(async move { Ok("PET".to_string()) })
        }
    }

    // ---- CloudKit

    struct FakeCloudKit {
        viable: Vec<u8>,
        changes: Vec<u8>,
        shares: Vec<u8>,
    }

    impl CloudKitApi for FakeCloudKit {
        fn open_container<'a>(&'a self, _refresh: bool) -> BoxFuture<'a, apple_core::Result<CloudKitContainerInfo>> {
            Box::pin(async move {
                Ok(CloudKitContainerInfo {
                    user_id: "_synthetic".into(),
                    database_gateway_url: Some("http://127.0.0.1/ckdatabase".into()),
                    ..Default::default()
                })
            })
        }
        fn zone_retrieve<'a>(&'a self) -> BoxFuture<'a, apple_core::Result<Vec<ZoneSummary>>> {
            Box::pin(async move { Ok(Vec::new()) })
        }
        fn record_sync<'a>(&'a self, _zone: &'a str, _token: Option<Vec<u8>>, _max: Option<i32>) -> BoxFuture<'a, apple_core::Result<RecordSyncPage>> {
            Box::pin(async move { Ok(RecordSyncPage { status: Some(3), ..Default::default() }) })
        }
        fn function_invoke<'a>(&'a self, _service: &'a str, name: &'a str, _parameters: Vec<u8>) -> BoxFuture<'a, apple_core::Result<Vec<u8>>> {
            let bytes = match name {
                "fetchViableBottles" => self.viable.clone(),
                "fetchChanges" => self.changes.clone(),
                "fetchRecoverableTLKShares" => self.shares.clone(),
                _ => Vec::new(),
            };
            Box::pin(async move { Ok(bytes) })
        }
    }

    // ---- escrow (SRP server)

    struct FakeEscrow {
        record: EscrowRecord,
        passcode: String,
        entropy: Vec<u8>,
        salt: Vec<u8>,
        b: Vec<u8>,
        exchange_token: Vec<u8>,
        state: Mutex<Option<(BigUint, BigUint)>>, // (A, B)
    }

    impl FakeEscrow {
        fn server_public(&self, a: &BigUint) -> BigUint {
            let n = group_n();
            let g = BigUint::from(2u8);
            let k = BigUint::from_bytes_be(&h(&[&minimal(&n), &pad(&minimal(&g))]));
            let colon = h(&[b"1234567890:", self.passcode.as_bytes()]);
            let x = BigUint::from_bytes_be(&h(&[&self.salt, &colon]));
            let v = g.modpow(&x, &n);
            let b = BigUint::from_bytes_be(&self.b);
            let bb = (k * v + g.modpow(&b, &n)) % &n;
            *self.state.lock().unwrap() = Some((a.clone(), bb.clone()));
            bb
        }

        fn session_key(&self, m1: &[u8]) -> ([u8; 32], Vec<u8>) {
            let n = group_n();
            let g = BigUint::from(2u8);
            let (a, bb) = self.state.lock().unwrap().clone().unwrap();
            let u = BigUint::from_bytes_be(&h(&[&pad(&little_big(&a)), &pad(&little_big(&bb))]));
            let colon = h(&[b"1234567890:", self.passcode.as_bytes()]);
            let x = BigUint::from_bytes_be(&h(&[&self.salt, &colon]));
            let v = g.modpow(&x, &n);
            let s = (a.clone() * v.modpow(&u, &n)).modpow(&BigUint::from_bytes_be(&self.b), &n);
            let key = h(&[&little_big(&s)]);
            let m2 = h(&[&little_big(&a), m1, &key]);
            (key, m2.to_vec())
        }
    }

    impl EscrowCommands for FakeEscrow {
        fn list_records<'a>(&'a self) -> BoxFuture<'a, apple_core::Result<EscrowListing>> {
            let record = self.record.clone();
            Box::pin(async move { Ok(EscrowListing { records: vec![record], unreadable: Vec::new(), status: Some(0), message: None }) })
        }
        fn srp_init<'a>(&'a self, _label: &'a str, client_public: &'a [u8], _tx: &'a str) -> BoxFuture<'a, apple_core::Result<Value>> {
            let bb = self.server_public(&BigUint::from_bytes_be(client_public));
            let blob = build_keyvault_message(&[0u8; 24], &[
                KeyVaultSection::new(self.exchange_token.clone()),
                KeyVaultSection::new(self.salt.clone()),
                KeyVaultSection::new(little_big(&bb)),
            ])
            .unwrap();
            use base64::Engine as _;
            let response = serde_json::json!({
                "respBlob": base64::engine::general_purpose::STANDARD.encode(blob),
                "dsid": "1234567890",
                "clubTypeID": null,
            });
            Box::pin(async move { Ok(response) })
        }
        fn recover<'a>(&'a self, _label: &'a str, proof_blob: &'a [u8], _tx: &'a str, _dsid: Option<&'a str>) -> BoxFuture<'a, apple_core::Result<Value>> {
            let (_, _, sections) = apple_core::keychain::escrow::split_keyvault_message(proof_blob, 24, 2).unwrap();
            let m1 = sections[1].clone();
            let (key, m2) = self.session_key(&m1);

            // The material, sealed first under the passcode (inner), then under the SRP session key (outer).
            let material = apple_core::plist::to_xml(&apple_core::plist::dict([(
                "BottledPeerEntropy",
                apple_core::plist::Value::Data(self.entropy.clone()),
            )]));
            let inner_salt = vec![7u8; 20];
            let mut derived = [0u8; 16];
            pbkdf2::pbkdf2_hmac::<Sha256>(self.passcode.as_bytes(), &inner_salt, 1000, &mut derived);
            let inner_ct = aes_cbc_encrypt(&derived, &inner_salt[..16], &material);
            let mut inner_header = [0u8; 16];
            inner_header[8..12].copy_from_slice(&1000u32.to_be_bytes());
            let inner_blob = build_keyvault_message(&inner_header, &[
                KeyVaultSection::new(Vec::new()),
                KeyVaultSection::new(inner_salt),
                KeyVaultSection::new(Vec::new()),
                KeyVaultSection::new(inner_ct),
                KeyVaultSection::new(Vec::new()),
                KeyVaultSection::new(Vec::new()),
            ])
            .unwrap();

            let iv = vec![9u8; 16];
            let outer_ct = aes_cbc_encrypt(&key, &iv, &inner_blob);
            let mut outer_header = [0u8; 24];
            outer_header[4..8].copy_from_slice(&0u32.to_be_bytes());
            let outer_blob = build_keyvault_message(&outer_header, &[
                KeyVaultSection::new(m2),
                KeyVaultSection::new(iv),
                KeyVaultSection::new(outer_ct),
            ])
            .unwrap();
            use base64::Engine as _;
            let response = serde_json::json!({ "respBlob": base64::engine::general_purpose::STANDARD.encode(outer_blob) });
            Box::pin(async move { Ok(response) })
        }
    }

    fn aes_cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
        use cbc::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
        match key.len() {
            16 => cbc::Encryptor::<aes::Aes128>::new(key.into(), iv.into()).encrypt_padded_vec_mut::<Pkcs7>(data),
            32 => cbc::Encryptor::<aes::Aes256>::new(key.into(), iv.into()).encrypt_padded_vec_mut::<Pkcs7>(data),
            _ => panic!("bad key"),
        }
    }

    fn escrow_record(d: &Value) -> EscrowRecord {
        EscrowRecord {
            label: d["label"].as_str().unwrap().to_string(),
            device_name: Some(d["device_name"].as_str().unwrap().to_string()),
            device_model: None,
            device_model_class: None,
            serial: Some(d["serial"].as_str().unwrap().to_string()),
            build: None,
            escrowed_at: None,
            bottle_id: Some(d["bottle_id"].as_str().unwrap().to_string()),
            passcode_generation: None,
            metadata: std::collections::BTreeMap::new(),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn session_end_to_end() {
        let d = fixture("keychain/session.json");
        let passcode = d["passcode"].as_str().unwrap();
        let entropy = hexvec(d["entropy"].as_str().unwrap());

        let cloudkit = Arc::new(FakeCloudKit {
            viable: hexvec(d["viable_response"].as_str().unwrap()),
            changes: hexvec(d["changes_response"].as_str().unwrap()),
            shares: hexvec(d["shares_response"].as_str().unwrap()),
        });
        let escrow = Arc::new(FakeEscrow {
            record: escrow_record(&d),
            passcode: passcode.to_string(),
            entropy: entropy.clone(),
            salt: vec![3u8; 32],
            b: vec![5u8; 32],
            exchange_token: vec![1u8; 8],
            state: Mutex::new(None),
        });
        let account = Arc::new(FakeAccount {
            http: apple_core::http::Http::new(std::time::Duration::from_secs(5)).unwrap(),
            adsid: d["adsid"].as_str().unwrap().to_string(),
        });

        let session = KeychainSession::from_parts(account, cloudkit.clone(), cloudkit, escrow, "42".to_string());

        let options = session.recovery_options().await.unwrap();
        assert_eq!(options.recoverable.len(), 1, "one recoverable record");
        let record = options.recoverable[0].clone();

        let peer = session.recover(&record, passcode).await.unwrap();
        assert_eq!(peer.record.label, record.label);
        assert_eq!(peer.peer_id(), d["peer"].as_str().unwrap());

        let shares = session.key_shares(&peer).await.unwrap();
        assert_eq!(shares.len(), 1, "one share");
        assert_eq!(shares[0].error, None, "share should unwrap: {:?}", shares[0].error);
        assert_eq!(shares[0].view_keys.by_slot.get("tlk").map(|k| hex(k)), Some(d["expected_view_key"].as_str().unwrap().to_string()));
        assert_eq!(
            shares[0].view_keys.by_slot.get("classA").map(|k| hex(k)),
            Some(d["expected_class_key"].as_str().unwrap().to_string())
        );

        let _ = escrow_host("42");
        let _ = CloudKitClient::new;
        let _ = EscrowProxy::new;
        let _ = RecordChange::default();
    }
}
