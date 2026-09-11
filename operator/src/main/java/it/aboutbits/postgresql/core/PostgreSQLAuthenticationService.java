package it.aboutbits.postgresql.core;

import com.ongres.scram.common.StringPreparation;
import it.aboutbits.postgresql.crd.role.RoleSpec;
import jakarta.inject.Singleton;
import lombok.extern.slf4j.Slf4j;
import org.jooq.DSLContext;
import org.jooq.exception.DataAccessException;
import org.jspecify.annotations.NullMarked;

import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Locale;

import static it.aboutbits.postgresql.core.infrastructure.persistence.Tables.PG_AUTHID;

@Slf4j
@Singleton
@NullMarked
public final class PostgreSQLAuthenticationService {
    private static final String MD5 = "MD5";
    private static final String SHA_256 = "SHA-256";
    private static final String HMAC_SHA_256 = "HmacSHA256";
    private static final String PBKDF2_WITH_HMAC_SHA256 = "PBKDF2WithHmacSHA256";

    /**
     * PostgreSQL SQLSTATE {@code 42501} (insufficient_privilege). Raised when the current role is
     * not allowed to read {@code pg_authid} (e.g. on AWS RDS, where the password column is hidden
     * even from the master user).
     */
    private static final String SQLSTATE_INSUFFICIENT_PRIVILEGE = "42501";

    /**
     * Result of comparing a desired password against what PostgreSQL currently stores.
     */
    public enum PasswordCheck {
        /** The stored verifier matches the desired password. */
        MATCH,
        /** The stored verifier does not match the desired password (or no usable verifier exists). */
        MISMATCH,
        /** The verifier could not be read (e.g. {@code pg_authid} access denied on RDS). */
        UNVERIFIABLE
    }

    /**
     * Compare the desired password against the verifier PostgreSQL stores in {@code pg_authid}.
     * <p>
     * Returns {@link PasswordCheck#UNVERIFIABLE} when {@code pg_authid} cannot be read (SQLSTATE
     * {@code 42501}), so callers can fall back to a tracked hash instead of treating the situation
     * as a mismatch and rewriting the password on every reconcile.
     */
    public PasswordCheck checkPassword(
            DSLContext dsl,
            RoleSpec spec,
            String expectedPassword
    ) {
        String currentPasswordVerifier;
        try {
            currentPasswordVerifier = dsl
                    .select(PG_AUTHID.ROLPASSWORD)
                    .from(PG_AUTHID)
                    .where(PG_AUTHID.ROLNAME.eq(spec.getName()))
                    .fetchSingle(PG_AUTHID.ROLPASSWORD);
        } catch (DataAccessException e) {
            if (isInsufficientPrivilege(e)) {
                log.debug(
                        "Cannot read pg_authid to verify the password for role [{}]; falling back to tracked hash",
                        spec.getName()
                );
                return PasswordCheck.UNVERIFIABLE;
            }
            throw e;
        }

        if (currentPasswordVerifier == null || currentPasswordVerifier.isBlank()) {
            return PasswordCheck.MISMATCH;
        }

        // PostgreSQL stores either:
        // - SCRAM verifier: SCRAM-SHA-256$<iterations>:<saltB64>$<storedKeyB64>:<serverKeyB64>
        // - or legacy md5: md5<md5(password + username)>
        if (currentPasswordVerifier.startsWith("SCRAM-SHA-256$")) {
            return verifyPostgresScramSha256(currentPasswordVerifier, expectedPassword)
                    ? PasswordCheck.MATCH
                    : PasswordCheck.MISMATCH;
        }

        if (currentPasswordVerifier.startsWith(MD5.toLowerCase(Locale.ROOT))) {
            return verifyPostgresMd5(currentPasswordVerifier, expectedPassword, spec.getName())
                    ? PasswordCheck.MATCH
                    : PasswordCheck.MISMATCH;
        }

        // Unknown format (or plain text, which PG should not store in rolpassword)
        return PasswordCheck.MISMATCH;
    }

    /**
     * Convenience wrapper around {@link #checkPassword}. Returns {@code true} only when the verifier
     * could be read and matched; {@link PasswordCheck#UNVERIFIABLE} is reported as {@code false}.
     */
    public boolean passwordMatches(
            DSLContext dsl,
            RoleSpec spec,
            String expectedPassword
    ) {
        return checkPassword(dsl, spec, expectedPassword) == PasswordCheck.MATCH;
    }

    private static boolean isInsufficientPrivilege(DataAccessException e) {
        if (SQLSTATE_INSUFFICIENT_PRIVILEGE.equals(e.sqlState())) {
            return true;
        }

        // Fall back to inspecting the wrapped SQLException chain, in case the state is not surfaced
        // directly on the jOOQ exception.
        for (Throwable cause = e.getCause(); cause != null; cause = cause.getCause()) {
            if (cause instanceof SQLException sqlException
                    && SQLSTATE_INSUFFICIENT_PRIVILEGE.equals(sqlException.getSQLState())) {
                return true;
            }
        }

        return false;
    }

    private static boolean verifyPostgresScramSha256(String postgresVerifier, String cleartextPassword) {
        // Prepare the cleartext password with SASLprep
        var preparedPassword = StringPreparation.POSTGRESQL_PREPARATION.normalize(
                cleartextPassword.toCharArray()
        );

        // Format: SCRAM-SHA-256$<iterations>:<saltB64>$<storedKeyB64>:<serverKeyB64>
        var afterPrefix = postgresVerifier.substring("SCRAM-SHA-256$".length());
        var dollar = afterPrefix.indexOf('$');
        if (dollar < 0) {
            return false;
        }

        // <iterations>:<saltB64>
        var iterationsAndSalt = afterPrefix.substring(0, dollar);
        // <storedKeyB64>:<serverKeyB64>
        var keys = afterPrefix.substring(dollar + 1);

        var colonIterationsAndSalt = iterationsAndSalt.indexOf(':');
        if (colonIterationsAndSalt < 0) {
            return false;
        }

        int iterations;
        try {
            iterations = Integer.parseInt(iterationsAndSalt.substring(0, colonIterationsAndSalt));
        } catch (NumberFormatException e) {
            log.error("Invalid iterations format in PostgreSQL verifier: %s".formatted(postgresVerifier), e);
            return false;
        }
        if (iterations <= 0) {
            return false;
        }

        var saltB64 = iterationsAndSalt.substring(colonIterationsAndSalt + 1);

        var colonKeys = keys.indexOf(':');
        if (colonKeys < 0) {
            return false;
        }

        var storedKeyB64 = keys.substring(0, colonKeys);

        byte[] salt;
        byte[] currentStoredKey;
        try {
            salt = Base64.getDecoder().decode(saltB64);
            currentStoredKey = Base64.getDecoder().decode(storedKeyB64);
        } catch (IllegalArgumentException e) {
            log.error("Invalid salt or stored key format in PostgreSQL verifier: %s".formatted(postgresVerifier), e);
            return false;
        }

        byte[] saltedPassword = null;
        byte[] clientKey = null;
        byte[] expectedStoredKey = null;
        try {
            // RFC 5802/7677:
            // saltedPassword := Hi(password, salt, iterations) (PBKDF2-HMAC-SHA-256, 32 bytes)
            // clientKey      := HMAC(saltedPassword, "Client Key")
            // storedKey      := H(clientKey)  (SHA-256)
            saltedPassword = pbkdf2HmacSha256(preparedPassword, salt, iterations, 32);
            clientKey = hmacSha256(saltedPassword, "Client Key".getBytes(StandardCharsets.UTF_8));
            expectedStoredKey = sha256(clientKey);

            return MessageDigest.isEqual(
                    currentStoredKey,
                    expectedStoredKey
            );
        } finally {
            if (saltedPassword != null) {
                Arrays.fill(saltedPassword, (byte) 0);
            }
            if (clientKey != null) {
                Arrays.fill(clientKey, (byte) 0);
            }
            if (expectedStoredKey != null) {
                Arrays.fill(expectedStoredKey, (byte) 0);
            }
        }
    }

    private static boolean verifyPostgresMd5(
            String postgresMd5,
            String expectedPassword,
            String username
    ) {
        // PostgreSQL md5 is: "md5" + md5(password + username)
        if (postgresMd5.length() != 3 + 32 || !postgresMd5.regionMatches(true, 0, MD5, 0, 3)) {
            return false;
        }

        byte[] currentDigest;
        try {
            currentDigest = HexFormat.of().parseHex(
                    postgresMd5,
                    3,
                    postgresMd5.length()
            );
        } catch (IllegalArgumentException e) {
            log.error("Invalid MD5 format in PostgreSQL verifier: %s".formatted(postgresMd5), e);
            return false; // not valid hex
        }

        MessageDigest md5;
        try {
            md5 = MessageDigest.getInstance(MD5);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("%s not available".formatted(MD5), e);
        }

        md5.update((expectedPassword + username).getBytes(StandardCharsets.UTF_8));
        var expectedDigest = md5.digest();

        return MessageDigest.isEqual(currentDigest, expectedDigest);
    }

    private static byte[] pbkdf2HmacSha256(
            char[] password,
            byte[] salt,
            int iterations,
            int keyLenBytes
    ) {
        try {
            var secretKeyFactory = SecretKeyFactory.getInstance(PBKDF2_WITH_HMAC_SHA256);
            var spec = new PBEKeySpec(password, salt, iterations, keyLenBytes * 8);
            return secretKeyFactory.generateSecret(spec).getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException("%s not available".formatted(PBKDF2_WITH_HMAC_SHA256), e);
        }
    }

    private static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            var mac = Mac.getInstance(HMAC_SHA_256);
            mac.init(new SecretKeySpec(key, HMAC_SHA_256));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new IllegalStateException("%s not available".formatted(HMAC_SHA_256), e);
        }
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance(SHA_256).digest(data);
        } catch (Exception e) {
            throw new IllegalStateException("%s not available".formatted(SHA_256), e);
        }
    }
}
