package com.adminsec.jssecrethunter;

public record ScanState(
        Phase phase,
        int queued,
        int inFlight,
        long scanned,
        int findings,
        String message) {

    public enum Phase { IDLE, SCANNING, PAUSED, CANCELLING, STOPPED }

    public ScanState {
        message = message == null ? "" : message;
    }
}
