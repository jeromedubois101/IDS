
#ifndef PARSER_H

#define PARSER_H
#include "populate.h" //Pour ETHER_FRAME
#include "db_init.h" //Pour Rule et Proto_db
	
void get_application_protocol(int, int, const char*, char *, Protocol *, int);
void rule_matcher(ETHER_Frame*, Rule*, Protocol*, int, int);
int determine_encryption(const char*, Protocol *, int);
int detect_xss(const char *, int);
void get_transport_protocol(int, char *);
int protocol_matcher(const char *, const char*, const char *);

#endif
