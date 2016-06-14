#define _GNU_SOURCE
#define typeof __typeof__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <libiptc/libiptc.h>
#include <arpa/inet.h>
#include <sys/utsname.h>

#define TEXT_TO_DISPLAY \
" ______________________________\n"\ 
"/ Dear %s,                     \\\n"\ 
"|                              |\n"\ 
"| WHAT THE FUCK ARE YOU DOING? |\n"\ 
"|                              |\n"\ 
"\\ GET THE FUCK OUT!!!          /\n"\ 
" ------------------------------\n"\ 
"         \\\n"\ 
"          \\\n"\ 
"            ^__^ \n"\ 
"    _______/(oo)\n"\ 
"/\\/(       /(__)\n"\ 
"   | W----|| |~|\n"\ 
"   ||     || |~|  ~~\n"\ 
"             |~|  ~\n"\ 
"             |_| o\n"\ 
"             |#|/\n"\ 
"            _+#+_"

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
 	     	iptc_append_entry("SSH", (struct ipt_entry *) &entry, h);
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
	char *resp = NULL;


	const char* pUsername, *rhost;
        retval = pam_get_user(pamh, &pUsername, "User: ");

        if (retval != PAM_SUCCESS) {
                return retval;
        }
	if(pam_get_item(pamh, PAM_RHOST, (const void **)&rhost) == PAM_SUCCESS) {
		syslog(LOG_ALERT, "pam_tarpit: Tarpitting user %s from %s", pUsername, rhost);
		retval = pam_info(pamh, TEXT_TO_DISPLAY, rhost);
		if(retval != PAM_CONV_ERR) {
			return PAM_AUTH_ERR;
		}
		iptables_drop(rhost);
		sleep(666);
	}

	return PAM_AUTH_ERR;
}
