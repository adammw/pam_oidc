// Copyright (c) 2021, salesforce.com, inc.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
// For full license text, see the LICENSE.txt file in the repo root or https://opensource.org/licenses/BSD-3-Clause

package main

/*
#cgo CFLAGS: -I.
#cgo LDFLAGS: -lpam -fPIC

#include <stdlib.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#ifdef __linux__
#include <security/pam_ext.h>
#endif

char* argv_i(const char **argv, int i);
void pam_syslog_str(pam_handle_t *pamh, int priority, const char *str);
int pam_conv_go(struct pam_conv *conv, int num_msg, const struct pam_message **msg, struct pam_response **resp);
*/
import "C"

import (
	"context"
	"fmt"
	"log/syslog"
	"runtime"
	"unsafe"
)

func main() {
}

//export pam_sm_authenticate_go
func pam_sm_authenticate_go(pamh *C.pam_handle_t, flags C.int, argc C.int, argv **C.char) C.int {
	ctx := context.Background()

	// Copy args to Go strings
	args := make([]string, int(argc))
	for i := 0; i < int(argc); i++ {
		args[i] = C.GoString(C.argv_i(argv, C.int(i)))
	}

	// Parse config
	cfg, err := configFromArgs(args)
	if err != nil {
		pamSyslog(pamh, syslog.LOG_ERR, "failed to parse config: %v", err)
		return C.PAM_SERVICE_ERR
	}

	// Validate config
	if cfg.Issuer == "" {
		pamSyslog(pamh, syslog.LOG_ERR, "missing required option: issuer")
		return C.PAM_SERVICE_ERR
	} else if cfg.Aud == "" {
		pamSyslog(pamh, syslog.LOG_ERR, "missing required option: aud")
		return C.PAM_SERVICE_ERR
	}

	// Get (or prompt for) user
	var cUser *C.char
	if errnum := C.pam_get_user(pamh, &cUser, nil); errnum != C.PAM_SUCCESS {
		pamSyslog(pamh, syslog.LOG_ERR, "failed to get user: %v", pamStrError(pamh, errnum))
		return errnum
	}

	user := C.GoString(cUser)
	if len(user) == 0 {
		pamSyslog(pamh, syslog.LOG_WARNING, "empty user")
		return C.PAM_USER_UNKNOWN
	}

	var convPtr unsafe.Pointer

	C.pam_get_item(pamh, C.PAM_CONV, &convPtr)

	msg := []*C.struct_pam_message{
		{msg_style: C.PAM_PROMPT_ECHO_OFF, msg: C.CString("JWT (bytes 1-500): ")},
		{msg_style: C.PAM_PROMPT_ECHO_OFF, msg: C.CString("JWT (bytes 500-1000): ")},
		{msg_style: C.PAM_PROMPT_ECHO_OFF, msg: C.CString("JWT (bytes 1000-1500): ")},
		{msg_style: C.PAM_PROMPT_ECHO_OFF, msg: C.CString("JWT (bytes 1500-2000): ")},
	}
	var pinner runtime.Pinner
	for _, m := range msg {
		pinner.Pin(unsafe.Pointer(m))
	}
	defer pinner.Unpin()
	var respPtr *C.struct_pam_response

	if errnum := C.pam_conv_go((*C.struct_pam_conv)(convPtr), C.int(len(msg)), &msg[0], &respPtr); errnum != C.PAM_SUCCESS {
		pamSyslog(pamh, syslog.LOG_ERR, "failed to get conversation response: %v", pamStrError(pamh, errnum))
		return errnum
	}
	defer func() {
		if respPtr != nil {
			C.free(unsafe.Pointer(respPtr))
		}
	}()

	resp := (*[4]C.struct_pam_response)(unsafe.Pointer(respPtr))
	token := ""
	for i := 0; i < len(msg); i++ {
		token += C.GoString(resp[i].resp)
		if resp[i].resp != nil {
			C.free(unsafe.Pointer(resp[i].resp))
		}
	}

	auth, err := discoverAuthenticator(ctx, cfg.Issuer, cfg.Aud, cfg.HTTPProxy, cfg.LocalKeySetPath)
	if err != nil {
		pamSyslog(pamh, syslog.LOG_ERR, "failed to discover authenticator: %v", err)
		return C.PAM_AUTH_ERR
	}
	auth.UserTemplate = cfg.UserTemplate
	auth.GroupsClaimKey = cfg.GroupsClaimKey
	auth.AuthorizedGroups = cfg.AuthorizedGroups
	auth.RequireACRs = cfg.RequireACRs

	if err := auth.Authenticate(ctx, user, token); err != nil {
		pamSyslog(pamh, syslog.LOG_WARNING, "failed to authenticate (tok len=%d): %v", len(token), err)
		return C.PAM_AUTH_ERR
	}

	return C.PAM_SUCCESS
}

//export pam_sm_setcred_go
func pam_sm_setcred_go(pamh *C.pam_handle_t, flags C.int, argc C.int, argv **C.char) C.int {
	return C.PAM_IGNORE
}

func pamStrError(pamh *C.pam_handle_t, errnum C.int) string {
	return C.GoString(C.pam_strerror(pamh, errnum))
}

func pamSyslog(pamh *C.pam_handle_t, priority syslog.Priority, format string, a ...interface{}) {
	cstr := C.CString(fmt.Sprintf(format, a...))
	defer C.free(unsafe.Pointer(cstr))

	C.pam_syslog_str(pamh, C.int(priority), cstr)
}
