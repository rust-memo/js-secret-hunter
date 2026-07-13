package com.adminsec.jssecrethunter.model;

public enum Severity {
    CRITICAL(0), HIGH(1), MEDIUM(2), INFO(3);

    private final int rank;
    Severity(int rank) { this.rank = rank; }
    public int rank() { return rank; }
}
