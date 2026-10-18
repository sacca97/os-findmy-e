import com.sacca.openfinder.adi.*;
import java.nio.file.*;

/** Host JVM test of the JNI layer: HostTest COREADI HOST_UUID_HEX CLOCK STORE_FILE... */
public class HostTest {
    static String hex(byte[] b) { StringBuilder s = new StringBuilder(); for (byte x : b) s.append(String.format("%02x", x)); return s.toString(); }
    public static void main(String[] a) throws Exception {
        byte[] uuid = new byte[16];
        for (int i = 0; i < 16; i++) uuid[i] = (byte) Integer.parseInt(a[1].substring(2 * i, 2 * i + 2), 16);
        try (CoreAdi adi = CoreAdi.open(Files.readAllBytes(Path.of(a[0])))) {
            System.out.println("build: " + adi.build());
            adi.setHostUuid(uuid);
            adi.setFrozenTime(Long.parseLong(a[2]));
            try { adi.headers(); System.out.println("FAIL: expected NotProvisionedException"); }
            catch (NotProvisionedException e) { System.out.println("unprovisioned -> " + e.getMessage()); }
            for (int i = 3; i < a.length; i++) {
                Path p = Path.of(a[i]);
                java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
                byte[] n = p.getFileName().toString().getBytes(); byte[] d = Files.readAllBytes(p);
                o.write(n.length >> 8); o.write(n.length); o.writeBytes(n);
                o.write(d.length >>> 24); o.write(d.length >>> 16); o.write(d.length >>> 8); o.write(d.length); o.writeBytes(d);
                adi.importStore(o.toByteArray());
            }
            CoreAdi.Headers h = null;
            long t = System.nanoTime();
            for (int i = 0; i < 20; i++) h = adi.headers();
            System.out.println("20 headers: " + (System.nanoTime() - t) / 1_000_000 + " ms");
            System.out.println("mid=" + hex(h.mid)); System.out.println("otp=" + hex(h.otp)); System.out.println("routing=" + h.routing);
            System.out.println("export bytes: " + adi.exportStore().length);
            try { adi.provisioningBegin(new byte[0]); System.out.println("FAIL: expected AlreadyProvisionedException"); }
            catch (AlreadyProvisionedException e) { System.out.println("begin on provisioned -> " + e.getMessage()); }
            adi.close();
            try { adi.headers(); System.out.println("FAIL: expected IllegalStateException"); }
            catch (IllegalStateException e) { System.out.println("closed -> " + e.getMessage()); }
        }
        try { CoreAdi.open(new byte[] {1, 2, 3}); System.out.println("FAIL: expected AdiException"); }
        catch (AdiException e) { System.out.println("bad image -> " + e.getMessage()); }
    }
}
