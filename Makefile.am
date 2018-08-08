AUTOMAKE_OPTIONS=foreign
bin_PROGRAMS=Remote-Media-Server
Remote_Media_Server_SOURCES = remote-media-server.c
Remote_Media_Server_LDADD = -lgnutls

if HAVE_PAM
Remote_Media_Server_SOURCES += auth-pam-ldap.c
Remote_Media_Server_LDADD += -lpam -lpam_misc
endif
