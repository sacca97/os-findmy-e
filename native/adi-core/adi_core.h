/* C interface of adi-core. Every function returns 0 on success, a negative code on failure
 * (message via adi_last_error, per thread). Buffers are allocated by the library: release them
 * with adi_buf_free. Use a handle from one thread at a time. One call is one emulated session. */
#ifndef ADI_CORE_H
#define ADI_CORE_H
#include <stddef.h>
#include <stdint.h>

#define ADI_OK 0
#define ADI_ERR -1
#define ADI_ERR_NOT_PROVISIONED -2
#define ADI_ERR_ALREADY_PROVISIONED -3

typedef struct AdiHandle AdiHandle;
typedef struct { uint8_t *ptr; size_t len; } AdiBuf;

int32_t adi_open(const uint8_t *image, size_t len, AdiHandle **out);
void adi_close(AdiHandle *h);
size_t adi_build_name(AdiHandle *h, char *buf, size_t cap);
size_t adi_last_error(char *buf, size_t cap);
void adi_buf_free(AdiBuf b);

int32_t adi_set_host_uuid(AdiHandle *h, const uint8_t uuid[16]);
int32_t adi_set_frozen_time(AdiHandle *h, int64_t secs); /* tests only; <0 = real clock */

/* store: persist adi_store_export's buffer after headers/provisioning/sync, restore with import */
int32_t adi_store_put(AdiHandle *h, const char *name, const uint8_t *data, size_t len);
int32_t adi_store_export(AdiHandle *h, AdiBuf *out);
int32_t adi_store_import(AdiHandle *h, const uint8_t *data, size_t len);

/* X-Apple-I-MD-M, X-Apple-I-MD, X-Apple-I-MD-RINFO */
int32_t adi_headers(AdiHandle *h, int64_t ds_id, AdiBuf *mid, AdiBuf *otp, uint64_t *routing);

/* provisioning: begin, talk to Apple, finish -- nothing in between */
int32_t adi_provisioning_begin(AdiHandle *h, int64_t ds_id, const uint8_t *spim, size_t spim_len,
                               AdiBuf *cpim, uint32_t *session);
int32_t adi_provisioning_finish(AdiHandle *h, int64_t ds_id, uint32_t session, const uint8_t *ptm,
                                size_t ptm_len, const uint8_t *tk, size_t tk_len, uint64_t routing);

/* resync (Apple's 434 reply) */
int32_t adi_sync(AdiHandle *h, int64_t ds_id, const uint8_t *sim, size_t sim_len, AdiBuf *mid, AdiBuf *srm);
int32_t adi_update_routing(AdiHandle *h, int64_t ds_id, uint64_t routing);
#endif
