package com.sacca.openfinder.adi;

/** The store already holds a provisioned machine; Apple allows one provisioning per device id. */
public class AlreadyProvisionedException extends AdiException {
    public AlreadyProvisionedException(String message) {
        super(message);
    }
}
