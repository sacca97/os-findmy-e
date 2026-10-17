package dev.osfindmy.adi;

/**
 * Apple's Mac CoreADI, emulated: the source of Anisette headers for a provisioned machine.
 *
 * <p>Usage: {@code open} with the CoreADI file bytes, {@link #setHostUuid} (the same 16 bytes
 * forever for a given store), {@link #importStore} what you saved last time, then call {@link
 * #headers} per request, and persist {@link #exportStore} after every call that can change it
 * ({@code headers}, provisioning, {@code sync}).
 *
 * <p>Each call is one emulated session (about 20 ms once warm; the first takes about 100 ms).
 * Calls are serialised, but use one background thread. Never call this on the main thread.
 */
public final class CoreAdi implements AutoCloseable {
    /** Apple's "no account" pseudo-DSID, the one {@code akd} uses locally. */
    public static final long DS_ID = -2;

    static {
        System.loadLibrary("adi_core");
    }

    /** Values for one request: base64 {@code mid} and {@code otp} to get the two headers. */
    public static final class Headers {
        /** {@code X-Apple-I-MD-M}, raw bytes. */
        public final byte[] mid;
        /** {@code X-Apple-I-MD}, raw bytes. */
        public final byte[] otp;
        /** {@code X-Apple-I-MD-RINFO}. */
        public final long routing;

        Headers(byte[] mid, byte[] otp, long routing) {
            this.mid = mid;
            this.otp = otp;
            this.routing = routing;
        }
    }

    /** Result of {@link #provisioningBegin}: send {@code cpim} to Apple, then call finish. */
    public static final class Provisioning {
        public final byte[] cpim;
        public final int session;

        Provisioning(byte[] cpim, int session) {
            this.cpim = cpim;
            this.session = session;
        }
    }

    /** Result of {@link #sync}: POST both to Apple's syncMachine. */
    public static final class Sync {
        public final byte[] mid;
        public final byte[] srm;

        Sync(byte[] mid, byte[] srm) {
            this.mid = mid;
            this.srm = srm;
        }
    }

    private long handle;

    private CoreAdi(long handle) {
        this.handle = handle;
    }

    /** Load a registered CoreADI build (identified by sha256 of {@code image}). */
    public static CoreAdi open(byte[] image) {
        return new CoreAdi(nativeOpen(image));
    }

    /** Human-readable name of the loaded build. */
    public synchronized String build() {
        return nativeBuild(live());
    }

    /** The machine's host UUID (16 bytes): part of what the MID derives from. */
    public synchronized void setHostUuid(byte[] uuid) {
        nativeSetHostUuid(live(), uuid);
    }

    /** Pin the emulated clock (tests only); a negative value restores the real clock. */
    public synchronized void setFrozenTime(long epochSeconds) {
        nativeSetFrozenTime(live(), epochSeconds);
    }

    public synchronized void importStore(byte[] exported) {
        nativeStoreImport(live(), exported);
    }

    public synchronized byte[] exportStore() {
        return nativeStoreExport(live());
    }

    /** @throws NotProvisionedException if the store holds no provisioning for this host UUID */
    public synchronized Headers headers() {
        byte[][] r = nativeHeaders(live(), DS_ID);
        return new Headers(r[0], r[1], beLong(r[2]));
    }

    /** Provisioning step 1. Finish with {@link #provisioningFinish} and nothing in between. */
    public synchronized Provisioning provisioningBegin(byte[] spim) {
        byte[][] r = nativeProvisioningBegin(live(), DS_ID, spim);
        return new Provisioning(r[0], (int) beLong(r[1]));
    }

    public synchronized void provisioningFinish(int session, byte[] ptm, byte[] tk, long routing) {
        nativeProvisioningFinish(live(), DS_ID, session, ptm, tk, routing);
    }

    /** Answer Apple's resync request ({@code hsc 434}); {@code sim} is from its reply. */
    public synchronized Sync sync(byte[] sim) {
        byte[][] r = nativeSync(live(), DS_ID, sim);
        return new Sync(r[0], r[1]);
    }

    /** Store the routing value ({@code X-Apple-I-MD-RINFO}) Apple returned after a resync. */
    public synchronized void updateRouting(long routing) {
        nativeUpdateRouting(live(), DS_ID, routing);
    }

    @Override
    public synchronized void close() {
        if (handle != 0) {
            nativeClose(handle);
            handle = 0;
        }
    }

    private long live() {
        if (handle == 0) {
            throw new IllegalStateException("CoreAdi is closed");
        }
        return handle;
    }

    private static long beLong(byte[] b) {
        long v = 0;
        for (byte x : b) {
            v = (v << 8) | (x & 0xFF);
        }
        return v;
    }

    private static native long nativeOpen(byte[] image);

    private static native void nativeClose(long h);

    private static native String nativeBuild(long h);

    private static native void nativeSetHostUuid(long h, byte[] uuid);

    private static native void nativeSetFrozenTime(long h, long secs);

    private static native byte[] nativeStoreExport(long h);

    private static native void nativeStoreImport(long h, byte[] data);

    private static native byte[][] nativeHeaders(long h, long ds);

    private static native byte[][] nativeProvisioningBegin(long h, long ds, byte[] spim);

    private static native void nativeProvisioningFinish(
            long h, long ds, int session, byte[] ptm, byte[] tk, long routing);

    private static native byte[][] nativeSync(long h, long ds, byte[] sim);

    private static native void nativeUpdateRouting(long h, long ds, long routing);
}
