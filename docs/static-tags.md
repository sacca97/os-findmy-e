# Static tags: report freshness, battery and local history

This client supports imported P-224 single-key tags alongside rolling-key accessories. These notes describe the current implementation and its verification limits.

## Report queries

Static tags use `https://gateway.icloud.com/acsnservice/fetch`, one search per imported key. Rolling-key accessories retain the v2 query path. A controlled comparison with the same owned key found the v2 path returning older reports while the legacy path returned newer, authenticated reports. No key change was needed to obtain those reports. The reason for the endpoint divergence is not established.

Transport, authentication and server failures propagate as errors instead of silently becoming an empty history. Successfully decrypted reports are validated against the requested time window. The Python helper defaults to the same static-key endpoint; `--protocol v2` is available for explicit comparisons. `--summary` suppresses coordinates, and HTTP error handling does not dump response headers or bodies.

This observation does not establish a lifetime report limit, a requirement for frequent nearby rekeying, or guaranteed long-term coverage. A refresh queries cached sightings; it cannot make nearby Apple devices generate a new sighting.

## Battery status

The supported vendor's two-byte `GVBAT` notification is a frame marker followed by a status code, rather than a 16-bit voltage reading. Analysis of the original client shows integer equality checks on the second byte and selection of four battery icons:

| Notification | Indicator |
| --- | --- |
| `3D20` | 4 of 4 bars |
| `3D60` | 3 of 4 bars |
| `3DA0` | 2 of 4 bars |
| `3DE0` | 1 of 4 bars, matching the vendor fallback |

Other status codes remain unknown in this client. Unexpected frame types and lengths are rejected. The displayed bars are the vendor's coarse indicator, not a measured voltage or an exact percentage. A normal-battery physical sample has been checked; physical low-battery behaviour remains unverified.

Battery readings require the tag nearby. The UI displays the sampled time and marks samples older than 12 hours as outdated. Remote position queries do not update that timestamp. Samples use atomic local writes and retain up to 90 days or 1,000 observations per key, with the last observation retained. Older single-sample files remain compatible. A failed storage operation is reported instead of silently discarding previous data.

## Location history

Each refresh merges old and new sightings, removes duplicate time/coordinate pairs, retains the better accuracy for overlapping sightings and sorts the trail chronologically. The complete history is encrypted using Android Keystore-backed AES-GCM and saved atomically. Cached history loads before network queries so a failed refresh does not hide the previous trail.

History is bounded to 90 days and 10,000 points per accessory; the last known position is retained even when older. Map windows cover 6 hours, 24 hours, 3 days, 7 days, 30 days and 90 days, ending at the last sighting. The UI shows the visible and saved point counts. Missing sightings and the route between discrete points cannot be reconstructed from this cache.

The background job queries about every 30 minutes with a 5-minute flex window when connected. Android power management can delay execution. The existing unique work name is retained to avoid registering a second periodic job. A worker racing a UI refresh waits for the shared result instead of consuming an empty state.

Removing an accessory prunes its cached trail. Signing out or clearing local location history empties the archive and notification snapshot. An empty archive also acts as a migration marker, preventing an older worker snapshot from restoring cleared points. A temporarily unreadable encrypted archive is not overwritten; new in-memory sightings can merge after storage recovers.

## Storage and diagnostics

Tag credentials and the full trajectory archive use encrypted app-private blobs. The notification worker's latest-point snapshot remains plain JSON in app-private storage; Android backup is disabled. Nearby key management can export the current private key into an app-specific file for local PC tooling. That export is a credential and is not included in the repository.

Debug diagnostics report counts and protocol outcomes without device addresses, advertising-key identifiers, private keys or raw authentication responses. Local machine state, captures, exports, screenshots, compiled APKs, signing material and Apple's CoreADI image are excluded from source publication. Test fixtures use synthetic data.

## Nearby key management

Key rotation is an explicitly confirmed local BLE operation. Normal rotation checks that the advertised key matches an imported key and requires a nearby signal. Recovery mode does not have that ownership match and must only be used for hardware the operator is authorised to manage. The vendor protocol itself does not authenticate ownership.

Neither mode is a remote lost-tag recovery mechanism or a periodic report-refresh requirement. The active list keeps the new key and removes the superseded entry.

## Validation

- Android JVM suite: 235 tests, including overlapping batches, concurrent refresh, restart/offline restoration, corrupt-archive protection, storage retry, accessory removal, migration and cleared-history protection.
- Rust report suite: 11 tests, including static legacy-path decryption, error propagation and valid empty responses.
- Python static-report protocol suite: 3 offline tests.
- Android device checks: successful static-key query, a new nearby battery sample, encrypted history persistence, restart restoration and registration of the 30-minute background job.

Physical low-battery behaviour, moving/lost-item tracking over long periods, unattended authentication renewal and multiple actual background periods remain to be validated. Registration of a periodic task does not prove timely execution under every Android power policy.
