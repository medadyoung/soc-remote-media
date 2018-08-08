#include <stdio.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <strings.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>

#include <security/pam_appl.h>
#include <security/pam_misc.h>

#define PAMCONF "remote-media"
#define USERDN "cn=%s,"
#define BINDDN "sed -i 's/\\(binddn\\)/\\1 %s/' /etc/nslcd.conf"
#define BINDPW "sed -i 's/\\(bindpw\\)/\\1 %s/' /etc/nslcd.conf"
#define DELETE "sed -i 's/%s//' /etc/nslcd.conf"
#define ADDURI "sed -i 's/[0-9]\\{1,3\\}\\.[0-9]\\{1,3\\}\\.[0-9]\\{1,3\\}\\.[0-9]\\{1,3\\}/%s/g' /etc/nslcd.conf"

#define START "start-stop-daemon -S -x /usr/sbin/nslcd"
#define STOP  "start-stop-daemon -K -x /usr/sbin/nslcd"

struct pam_response *reply;

int function_conversation(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr)
{
    *resp = reply;
    return PAM_SUCCESS;
}

static const struct pam_conv conv = {
    function_conversation,
    NULL
};

static int ldap_config(const char *path, char *string)
{
    char cmd[256]={0};

    snprintf(cmd, sizeof(cmd), path, string);
    return system(cmd);
}

int auth_pam_ldap(char *username, char *passwd, char *ip)
{
    pam_handle_t *pamh = NULL;
    int retval = -1;
    char binddn[256]={0};

    ldap_config(ADDURI, ip);

    snprintf(binddn, sizeof(binddn), USERDN, username);
    ldap_config(BINDDN, binddn);

    ldap_config(BINDPW, passwd);

    if (ldap_config(START, NULL) < 0) goto done;

    retval = pam_start(PAMCONF, username, &conv, &pamh);
    if (retval == PAM_SUCCESS) {
        reply = (struct pam_response *)malloc(sizeof(struct pam_response));
        reply[0].resp = strdup(passwd);
        reply[0].resp_retcode = 0;
        retval = pam_authenticate(pamh, 0);
        pam_end(pamh, retval);
    }

done:
    ldap_config(DELETE, binddn);
    ldap_config(DELETE, passwd);
    ldap_config(STOP, NULL);
    return retval;
}
