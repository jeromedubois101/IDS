#ifndef INIT
#define INIT

#include <stdio.h>
#define MAXLINE 1024

struct protocol
{
	char name[15];
	int port;
	int encrypted;
	char transport_protocol[4];

} typedef Protocol;


struct ids_rule
{
	char action[6];
	char protocol[10];
	char ip_src[16];
	int port_src;
	char ip_dst[16];
	int port_dst;
	char *msg;
	char *content;

} typedef Rule;	


void read_protocols(FILE *, Protocol **, int *);
void read_rules(FILE *, Rule **, int *);
void dump_protocol(Protocol *, char *);
void dump_rule(Rule *, char *);



#endif




