package com.ep.security.enums;

public enum ApplicationUserPermission {
    EMPLOYEE_READ("employee:read"), EMPLOYEE_WRITE("employee:write");

    private final String permission;

    ApplicationUserPermission(String permission) {
        this.permission = permission;
    }

    public String getPermission() {
        return permission;
    }
}
