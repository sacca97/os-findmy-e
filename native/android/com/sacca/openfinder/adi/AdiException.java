package com.sacca.openfinder.adi;

/** The emulated CoreADI (or the emulator around it) failed. */
public class AdiException extends RuntimeException {
    public AdiException(String message) {
        super(message);
    }
}
