import com.sacca.openfinder.adi.CoreAdi;
import java.nio.file.*;
import java.util.Base64;
import java.util.regex.*;

/**
 * Host-JVM check that a .machine.json imports and produces headers.
 *   VerifyMachineFile CoreADI_FILE MACHINE_JSON [CLOCK_SECONDS]
 * With CLOCK_SECONDS the clock is pinned (the OTP then depends only on the store).
 * Needs libadi_core.so on java.library.path (built with --features jni for the host).
 */
public class VerifyMachineFile {
    static String field(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        if (!m.find()) throw new IllegalArgumentException("missing " + key);
        return m.group(1);
    }
    static String hex(byte[] b) { StringBuilder s = new StringBuilder(); for (byte x : b) s.append(String.format("%02x", x)); return s.toString(); }

    public static void main(String[] a) throws Exception {
        String json = Files.readString(Path.of(a[1]));
        byte[] uuid = new byte[16];
        String u = field(json, "host_uuid");
        for (int i = 0; i < 16; i++) uuid[i] = (byte) Integer.parseInt(u.substring(2 * i, 2 * i + 2), 16);
        try (CoreAdi adi = CoreAdi.open(Files.readAllBytes(Path.of(a[0])))) {
            System.out.println("build: " + adi.build());
            adi.setHostUuid(uuid);
            adi.importStore(Base64.getDecoder().decode(field(json, "store_export_b64")));
            if (a.length > 2) adi.setFrozenTime(Long.parseLong(a[2]));
            long t0 = System.nanoTime();
            CoreAdi.Headers h = adi.headers();
            System.out.printf("first headers(): %d ms%n", (System.nanoTime() - t0) / 1_000_000);
            t0 = System.nanoTime();
            for (int i = 0; i < 10; i++) h = adi.headers();
            System.out.printf("next 10: %d ms each%n", (System.nanoTime() - t0) / 10_000_000);
            System.out.println("X-Apple-I-MD-M    = " + Base64.getEncoder().encodeToString(h.mid));
            System.out.println("X-Apple-I-MD      = " + Base64.getEncoder().encodeToString(h.otp));
            System.out.println("X-Apple-I-MD-RINFO= " + h.routing);
            System.out.println("mid hex = " + hex(h.mid));
            System.out.println("otp hex = " + hex(h.otp));
        }
    }
}
