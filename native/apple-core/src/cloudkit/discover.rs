//! Reads the owner's Find My accessories out of the BeaconStore zone with already recovered PCS keys
//! (the body of `findmy beacons`, moved here so the FFI and the CLI share it). Read-only.

use std::sync::Arc;

use crate::cloudkit::beacons::{self, DecryptedAccessory};
use crate::cloudkit::client::{CloudKitAccount, CloudKitClient};
use crate::cloudkit::pcs::{self, PcsKey};
use crate::cloudkit::records::CloudKitRecord;
use crate::cloudkit::CloudKitApi;
use crate::error::{Error, Result};

/// Retrieves the BeaconStore zone, unwraps its keys with `pcs_keys`, pages the records and decrypts them.
pub async fn fetch_accessories(
    account: Arc<dyn CloudKitAccount>,
    pcs_keys: &[PcsKey],
) -> Result<Vec<DecryptedAccessory>> {
    let client = CloudKitClient::new(account);
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
    let zone_keys = pcs::unwrap_zone(&zone_protection, pcs_keys)?;
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
    let decrypted = beacons::decrypt_records(&records, &zone_keys, &defaults, now);
    Ok(beacons::accessories_from_records(&decrypted.records))
}
