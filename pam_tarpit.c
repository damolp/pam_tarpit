#define _GNU_SOURCE
#define typeof __typeof__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <libiptc/libiptc.h>
#include <arpa/inet.h>

void iptables_flush() {
	struct xtc_handle *h;
	h = iptc_init("filter");
	iptc_flush_entries("INPUT", h);
	iptc_commit(h);
	iptc_free(h);
}

void iptables_drop(const char *ip) {
	struct xtc_handle *h;
	struct {
		struct ipt_entry entry;
		struct xt_standard_target target;
	} entry;
	
	h = iptc_init("filter");
	if(h) {
		memset(&entry, 0, sizeof(entry));
		/* target */
		entry.target.target.u.user.target_size = XT_ALIGN (sizeof (struct xt_standard_target));
		strncpy (entry.target.target.u.user.name, "DROP", sizeof (entry.target.target.u.user.name));

		/* entry */
		entry.entry.target_offset = sizeof (struct ipt_entry);
		entry.entry.next_offset = entry.entry.target_offset + entry.target.target.u.user.target_size;
		
		/* source */
		unsigned int src;
		inet_pton(AF_INET, ip, &src);
		entry.entry.ip.src.s_addr  = src;
      		entry.entry.ip.smsk.s_addr = 0xFFFFFFFF;
      	
 	     	/* add the rule */
 	     	iptc_append_entry("INPUT", (struct ipt_entry *) &entry, h);
      		iptc_commit(h);
      		iptc_free(h);
		
	}
}

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
			//DROP host
			iptables_drop(rhost);
			sleep(666);
			//flush INPUT chain
			iptables_flush();
			return PAM_AUTH_ERR;
		}
	}
	
	return PAM_AUTH_ERR;
}
