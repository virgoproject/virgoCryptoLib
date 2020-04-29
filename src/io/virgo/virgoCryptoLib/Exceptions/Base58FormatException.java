package io.virgo.virgoCryptoLib.Exceptions;

@SuppressWarnings("serial")
public class Base58FormatException extends IllegalArgumentException {
    public Base58FormatException() {
        super();
    }

    public Base58FormatException(String message) {
        super(message);
    }
}