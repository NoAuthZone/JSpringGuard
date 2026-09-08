package com.example.demo;

import java.io.InputStream;
import java.io.ObjectInputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Random;

/**
 * Test fixture for JSpringGuard — unsafe deserialization and weak crypto.
 */
public class DeserializationAndCrypto {

    // EXPECT: native Java deserialization (RCE gadget path).
    public Object vulnerableNativeDeserialization(InputStream in) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(in)) {
            return ois.readObject();
        }
    }

    // EXPECT: weak hash for a security purpose.
    public byte[] vulnerableWeakHash(byte[] data) throws Exception {
        return MessageDigest.getInstance("MD5").digest(data);
    }

    // EXPECT: no finding — SHA-256 is acceptable.
    public byte[] safeHash(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    // EXPECT: predictable RNG used where a token is implied.
    public long vulnerableRandomToken() {
        return new Random().nextLong();
    }

    // EXPECT: no finding — SecureRandom is the correct choice.
    public long safeRandomToken() {
        return new SecureRandom().nextLong();
    }

    // EXPECT: no finding — suppressed on purpose, to prove suppression works.
    // sec-check:ignore - fixture only, never reads untrusted input
    public Object suppressedDeserialization(InputStream in) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(in)) {
            return ois.readObject();
        }
    }
}
