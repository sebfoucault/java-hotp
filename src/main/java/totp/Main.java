package totp;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;

import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;

public class Main {

    @Parameter(names = { "-key" }, description = "Secret key", required = true)
    private String encodedKey;

    public static void main(String... argv) throws NoSuchAlgorithmException, InvalidKeyException, InterruptedException {

        Main main = new Main();
        JCommander.newBuilder()
                .addObject(main)
                .build()
                .parse(argv);

        main.run();
    }

    public void run() {

        try {

            TimeBasedOneTimePasswordGenerator totp = new TimeBasedOneTimePasswordGenerator();

            String algorithm = totp.getAlgorithm();

            Key key = fromBase32(encodedKey, algorithm);

            while (true) {

                Instant now = Instant.now();
                System.out.format("Current password: %06d\n", totp.generateOneTimePassword(key, now));
                Thread.sleep(10_000);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static Key fromBase32(String encodedKey, String keyAlgorithm) {
        byte[] decodedKey = (new Base32()).decode(encodedKey);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, keyAlgorithm);
    }

}
