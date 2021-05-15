
#include <stdlib.h>
#include <string.h>

#include "headers/db_init.h"
#include "headers/populate.h"
#include "headers/matcher.h"
#include "headers/tools.h"	


void rule_matcher(ETHER_Frame *frame, Rule *rules_ds, Protocol *protocols_db, int rules_count, int protocols_count)
{
	IP_Packet *packet = &(frame->packet); //On simplifie les noms de variables
	Segment *segment = &(frame->packet.segment);

	char transport_protocol[4] = "";
	get_transport_protocol(packet->protocol, transport_protocol);//On détermine le protocole de couche 4 (UDP ou TCP)

	char application_protocol[20] = "";
	if(strcmp(transport_protocol, "") != 0) //Si pas de proto. transport alors pas de protocole de couche 7
	{
		get_application_protocol(segment->source_port, segment->destination_port, transport_protocol, application_protocol, protocols_db, protocols_count);
	}


	for(int i=0; i < rules_count; i++)
	{
		if(protocol_matcher(application_protocol, transport_protocol, rules_ds[i].protocol) == 0)//On vérif. si un des protocoles match avec celui de la règle
		{
			if(strcmp(rules_ds[i].ip_src, "any") == 0 || strcmp(rules_ds[i].ip_src, packet->source_ip) == 0) //Ip source
			{
				if(rules_ds[i].port_src == -1 || rules_ds[i].port_src == segment->source_port)//Port source, -1 = "any" dans la règle
				{
					if(strcmp(rules_ds[i].ip_dst, "any") == 0 || strcmp(rules_ds[i].ip_dst, packet->destination_ip) == 0)// Ip Dest
					{
						if(rules_ds[i].port_dst == -1 || rules_ds[i].port_dst == segment->destination_port)//Port Dest
						{	
							if(rules_ds[i].content != NULL)//Si la règle vérifie le content
							{
								if((strcmp(application_protocol, "") == 0 || determine_encryption(application_protocol, protocols_db, protocols_count) == 0 ) && 
								   string_in(rules_ds[i].content, (const char*) segment->data, segment->data_length) == 0) //string_in() dans fichier tools.c
								{
									write_alert_logs(packet, rules_ds[i].msg);
								}
							} 
							else 
							{
								write_alert_logs(packet, rules_ds[i].msg);
							}
						}
					}
				}
			}
		}
	}
}


void get_transport_protocol(int transport_ID, char *transport_name)
{
	if(transport_ID == UDP_PROTOCOL)
	{
		strcpy(transport_name, "udp");
	}
	
	if(transport_ID == TCP_PROTOCOL)
	{
		strcpy(transport_name, "tcp");
	}
}


void get_application_protocol(int src_port, int dst_port, const char *transport_protocol, char *application_protocol, Protocol* protocols_db, int protocols_count)
{	
	for(int i=0;i<protocols_count;i++)
	{
		if(src_port == protocols_db[i].port || dst_port == protocols_db[i].port) 
		{
			if(strcmp(transport_protocol, protocols_db[i].transport_protocol) == 0 || strcmp("any", protocols_db[i].transport_protocol) == 0) // Si le protocole de couche supp. (4) correspond bien à celui dans la bdd.
			{
				snprintf(application_protocol, 19, protocols_db[i].name);
			}
		}
	}
}


int protocol_matcher(const char *application_protocol, const char *transport_protocol, const char *rule_protocol)
{
	if(strcmp(rule_protocol, "any") == 0)//Soit le protocole dans la règle == any
	{
		return 0;
	}
	if(strcmp(transport_protocol, rule_protocol) == 0) //Soit le protocole dans la règle == udp ou tcp
	{
		return 0;
	}
	if(strcmp(application_protocol, rule_protocol) == 0)  //Soit le protocole dans la règle == un protocole de notre bdd des protocoles (http etc..)
	{
		return 0;
	}
	
	return 1;//Rien n'a matché
	
}


int determine_encryption(const char *app_protocol, Protocol *protocols_db, int protocols_count)
{
	for(int i=0;i<protocols_count;i++)//On va voir dans la bdd si le protocole est marqué comme chiffré.
	{
		if(strcmp(app_protocol, protocols_db[i].name) == 0)
		{	
			return protocols_db[i].encrypted;
		}
	}

	return 1;//Chiffré par défaut si protocole non trouvé dans notre bdd.
}	

