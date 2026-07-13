package com.adminsec.jssecrethunter.model;

import java.util.ArrayList;
import java.util.List;

public final class RuleDefinition {
    public String id = "";
    public String name = "";
    public FindingKind kind = FindingKind.SECRET;
    public Severity severity = Severity.MEDIUM;
    public Confidence confidence = Confidence.MEDIUM;
    public List<String> keywords = new ArrayList<>();
    public String regex = "";
    public int secretGroup = 1;
    public double minEntropy = 0;
    public int minLength = 0;
    public String allowlistRegex = "";
    public boolean enabled = true;
}
