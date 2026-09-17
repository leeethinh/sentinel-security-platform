package com.sentinel.dto;

public class SecurityFinding {

    private String type;
    private String severity;
    private String message;

    public SecurityFinding(String type, String severity, String message) {
        this.type = type;
        this.severity = severity;
        this.message = message;
    }

    public String getType() {
        return type;
    }

    public String getSeverity() {
        return severity;
    }

    public String getMessage() {
        return message;
    }
}