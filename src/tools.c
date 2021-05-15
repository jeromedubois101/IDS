#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "headers/tools.h"



void dynamic_strcpy(char *token, char **dynamic_str)
{
	(*dynamic_str) = NULL;
	
	if(token != NULL)
	{
		(*dynamic_str) = (char*) malloc(strlen(token) + 1);
		snprintf((*dynamic_str), strlen(token) + 1, token);
	}
}


void write_alert_logs(IP_Packet *packet, char *message)
{
	openlog("IDS", LOG_PID|LOG_CONS,LOG_USER);
	syslog(LOG_ALERT, "[%s:%d->%s:%d] %s\n", packet->source_ip, packet->segment.source_port, packet->destination_ip, packet->segment.destination_port, message);
	closelog();
}


int string_in(const char *substring, const char *payload, int payload_length)
{
	int index = 0;
	
	for(int i = 0; i < payload_length; i++)
	{
		if(substring[index] == payload[i])
		{
			index++;
		}
		else
		{
			index = 0;
		}

		if(index == strlen(substring))
		{
			return 0;
		}
	}

 	return 1;
}
