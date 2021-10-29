//go:build windows
// +build windows

package main

import (
	"fmt"

	"golang.org/x/sys/windows"
)

func checkPermissions() error {
	// https://github.com/golang/go/issues/28804#issuecomment-505326268
	var sid *windows.SID

	// https://docs.microsoft.com/en-us/windows/desktop/api/securitybaseapi/nf-securitybaseapi-checktokenmembership
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid)
	if err != nil {
		return fmt.Errorf("error while checking for elevated permissions: %s", err)
	}

	// We must free the sid to prevent security token leaks
	defer windows.FreeSid(sid)
	token := windows.Token(0)

	member, err := token.IsMember(sid)
	if err != nil {
		return fmt.Errorf("error while checking for elevated permissions: %s", err)
	}
	if !member {
		return fmt.Errorf("gof5 needs to run with administrator permissions")
	}

	return nil
}
