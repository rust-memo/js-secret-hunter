package com.adminsec.jssecrethunter.model;

import java.util.ArrayList;
import java.util.List;

public final class RulePackDocument {
    public int schemaVersion = 1;
    public String version = "unknown";
    public String releasedAt = "";
    public List<RuleDefinition> rules = new ArrayList<>();
}
