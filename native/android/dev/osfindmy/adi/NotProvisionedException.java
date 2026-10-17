package dev.osfindmy.adi;

/** The machine has no provisioning in the store: run the provisioning exchange first. */
public class NotProvisionedException extends AdiException {
    public NotProvisionedException(String message) {
        super(message);
    }
}
