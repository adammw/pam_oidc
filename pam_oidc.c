// Copyright (c) 2021, salesforce.com, inc.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
// For full license text, see the LICENSE.txt file in the repo root or https://opensource.org/licenses/BSD-3-Clause

#include <security/pam_appl.h>

#ifdef __linux__
#include <security/pam_ext.h>
#endif

// pam_sm_authenticate lightly wraps pam_sm_authenticate_go because cgo cannot
// natively create a method with 'const char**' as an argument.
int pam_sm_authenticate_go(pam_handle_t *pamh, int flags, int argc, char **argv);
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  // pam_sm_authenticate_go does not modify argv, only copies them to Go strings.
  return pam_sm_authenticate_go(pamh, flags, argc, (char**)argv);
}

// pam_sm_setcred lightly wraps pam_sm_setcred_go because cgo cannot
// natively create a method with 'const char**' as an argument.
int pam_sm_setcred_go(pam_handle_t *pamh, int flags, int argc, char **argv);
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, char **argv) {
  // pam_sm_setcred_go does not modify argv, only copies them to Go strings.
  return pam_sm_setcred_go(pamh, flags, argc, (char**)argv);
}

// pam_conv_go lightly wraps struct pam_conv conv function pointer because cgo
// cannot natively call a function pointer
int pam_conv_go(struct pam_conv *conv, int num_msg, const struct pam_message **msg, struct pam_response **resp) {
  return conv->conv(num_msg, msg, resp, conv->appdata_ptr);
}

// argv_i returns argv[i].
char* argv_i(char **argv, int i) {
  return argv[i];
}

// pam_syslog_str logs str to pam_syslog. Calling variadic functions directly
// is not supported with cgo.
void pam_syslog_str(pam_handle_t *pamh, int priority, const char *str) {
#ifdef __linux__
  pam_syslog(pamh, priority, "%s", str);
#endif
}
