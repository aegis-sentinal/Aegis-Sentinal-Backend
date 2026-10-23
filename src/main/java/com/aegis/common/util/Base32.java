package com.aegis.common.util;

import java.util.Arrays;

public final class Base32 {

  private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  private static final int[] DECODE_TABLE = new int[256];

  static {
    Arrays.fill(DECODE_TABLE, -1);
    for (int i = 0; i < ALPHABET.length(); i++) {
      DECODE_TABLE[ALPHABET.charAt(i)] = i;
      DECODE_TABLE[Character.toLowerCase(ALPHABET.charAt(i))] = i;
    }
  }

  private Base32() {}

  public static String encode(byte[] data) {
    StringBuilder result = new StringBuilder();
    int buffer = 0;
    int bitsLeft = 0;

    for (byte b : data) {
      buffer = (buffer << 8) | (b & 0xFF);
      bitsLeft += 8;
      while (bitsLeft >= 5) {
        int index = (buffer >> (bitsLeft - 5)) & 0x1F;
        result.append(ALPHABET.charAt(index));
        bitsLeft -= 5;
      }
    }

    if (bitsLeft > 0) {
      int index = (buffer << (5 - bitsLeft)) & 0x1F;
      result.append(ALPHABET.charAt(index));
    }

    return result.toString();
  }

  public static byte[] decode(String base32) {
    String clean = base32.replaceAll("[= \\s]", "").toUpperCase();
    int buffer = 0;
    int bitsLeft = 0;
    byte[] result = new byte[clean.length() * 5 / 8];
    int count = 0;

    for (int i = 0; i < clean.length(); i++) {
      char c = clean.charAt(i);
      int val = (c < DECODE_TABLE.length) ? DECODE_TABLE[c] : -1;
      if (val < 0) {
        throw new IllegalArgumentException("Invalid Base32 character: " + c);
      }

      buffer = (buffer << 5) | val;
      bitsLeft += 5;

      if (bitsLeft >= 8) {
        result[count++] = (byte) ((buffer >> (bitsLeft - 8)) & 0xFF);
        bitsLeft -= 8;
      }
    }

    return Arrays.copyOf(result, count);
  }
}
