/* C smoke test: smoke COREADI HOST_UUID_HEX CLOCK STORE_FILE...   prints mid/otp/routing hex. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../adi_core.h"

static uint8_t *slurp(const char *p, size_t *n) {
    FILE *f = fopen(p, "rb"); if (!f) { perror(p); exit(2); }
    fseek(f, 0, SEEK_END); *n = ftell(f); rewind(f);
    uint8_t *b = malloc(*n ? *n : 1); if (fread(b, 1, *n, f) != *n) exit(2); fclose(f); return b;
}
static void hex(const AdiBuf *b) { for (size_t i = 0; i < b->len; i++) printf("%02x", b->ptr[i]); }
#define CHECK(x) do { int r = (x); if (r) { char m[256]; adi_last_error(m, sizeof m); fprintf(stderr, "%s -> %d: %s\n", #x, r, m); return 1; } } while (0)

int main(int argc, char **argv) {
    if (argc < 4) return 2;
    size_t n; uint8_t *img = slurp(argv[1], &n);
    AdiHandle *h; CHECK(adi_open(img, n, &h));
    uint8_t uuid[16]; for (int i = 0; i < 16; i++) { unsigned v; sscanf(argv[2] + 2 * i, "%2x", &v); uuid[i] = v; }
    CHECK(adi_set_host_uuid(h, uuid));
    CHECK(adi_set_frozen_time(h, atoll(argv[3])));
    for (int i = 4; i < argc; i++) {
        size_t m; uint8_t *d = slurp(argv[i], &m);
        const char *base = strrchr(argv[i], '/'); base = base ? base + 1 : argv[i];
        CHECK(adi_store_put(h, base, d, m)); free(d);
    }
    AdiBuf mid, otp; uint64_t routing;
    for (int i = 0; i < 3; i++) {           /* three sessions, then show the last */
        CHECK(adi_headers(h, -2, &mid, &otp, &routing));
        if (i < 2) { adi_buf_free(mid); adi_buf_free(otp); }
    }
    printf("mid="); hex(&mid); printf("\notp="); hex(&otp); printf("\nrouting=%llu\n", (unsigned long long)routing);
    adi_buf_free(mid); adi_buf_free(otp);
    AdiBuf ex; CHECK(adi_store_export(h, &ex)); fprintf(stderr, "store export: %zu bytes\n", ex.len);
    AdiHandle *h2; CHECK(adi_open(img, n, &h2)); CHECK(adi_store_import(h2, ex.ptr, ex.len)); adi_buf_free(ex);
    int r = adi_headers(h2, -2, &mid, &otp, &routing);
    fprintf(stderr, "second handle (store import, no host uuid): %d\n", r);
    adi_close(h2); adi_close(h);
    char name[128]; return adi_build_name(NULL, name, 0) == 0 ? 0 : 0;
}
