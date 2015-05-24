#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
	int retval;

	const char* pUsername, *rhost;
	retval = pam_get_user(pamh, &pUsername, "User: ");
	

	if (retval != PAM_SUCCESS) {
		return retval;
	}
		
	for(int i=0; i<argc; i++) {
		if (strncmp(pUsername, argv[i], strlen(argv[i])) == 0) {
			if(pam_get_item(pamh, PAM_RHOST, (const void **)&rhost) == PAM_SUCCESS) {
				syslog(LOG_ALERT, "pam_tarpit: Tarpitting user %s from %s", argv[i], rhost);
			}
			sleep(666);
			return PAM_AUTH_ERR;
		}
	}
	
	return PAM_AUTH_ERR;
}