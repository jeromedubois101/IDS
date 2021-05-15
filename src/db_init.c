#include <stdlib.h>
#include <stdbool.h>

#include "headers/populate.h"
#include "headers/db_init.h"
#include "headers/tools.h"


int convert_str_port(char *string_port)
{
	//Le code ci-bas, converti un port du fichier ids.rules ou ids.protocols en int
	if(string_port != NULL)
	{
		if(strcmp(string_port, "any") == 0)
		{
			return -1;//Si port == any
		}
		else
		{
			return atoi(string_port); 
		}
	}
	return 0; 
}

void dump_rule(Rule *rule, char *line)
{

	snprintf(rule->action, 6, strtok(line, " "));//Action

	snprintf(rule->protocol, 10, strtok(NULL, " ")); //Protocole

	snprintf(rule->ip_src, 16, strtok(NULL, " ")); //Ip source
	
	int src_port = convert_str_port(strtok(NULL, " "));//Port source
	rule->port_src = src_port;

	strtok(NULL, " "); //On passe le "->"

	snprintf(rule->ip_dst, 16, strtok(NULL, " ")); //Ip dest.
		
	int dst_port = convert_str_port(strtok(NULL, " "));//Port dest
	rule->port_dst = dst_port;

	strtok(NULL, "\"");//On passe une fois

	dynamic_strcpy(strtok(NULL, "\""), &(rule->msg));//Message (fonction dans tools.c)

	strtok(NULL, "\"");//On passe à nouveau

	dynamic_strcpy(strtok(NULL, "\""), &(rule->content));//Content
	
}



void read_rules(FILE *file, Rule **rules_db, int *rules_count)
{
	char line[MAXLINE];
	
	while(fgets(line, MAXLINE, file) != NULL)
	{
		if(strcmp(line, "") != 0)//Si la ligne n'est pas vide.
		{
			*rules_db = (Rule*) realloc(*rules_db, sizeof(Rule) * (*rules_count + 1)); //On alloue sizeof(Rule) * rule_nb + 1 octets en plus

			if(*rules_db == NULL)
			{
				printf("Problème lors de l'allocation mémoire pour la règle n°%d\nArrêt du programme.", *rules_count + 1); 
				exit(1);
			}
			dump_rule(&((*rules_db)[*rules_count]), line);//On dump la règle.
			(*rules_count)++;
		}
	}
}



void dump_protocol(Protocol *protocol, char *line)
{

	snprintf(protocol->name, 15, strtok(line, ":"));//Nom protocole couche 7

	int port = convert_str_port(strtok(NULL, ":"));//Port conventionnel
	protocol->port = port;

	char encrypted[15];
	snprintf(encrypted, 15, strtok(NULL, ":")); //Chiffrement, 0 = non, 1 = oui
	if(strcmp(encrypted, "") != 0)
	{
		protocol->encrypted = atoi(encrypted);
	} 
	else 
	{
		protocol->encrypted = 1;//On met chiffré par défaut si pas de str.
	}

	snprintf(protocol->transport_protocol, 4, strtok(NULL, ":"));//Nom protocole couche 4
}


void read_protocols(FILE *file, Protocol **protocols_db, int *protocols_count)
{
	char line[MAXLINE];

    	while (fgets(line, MAXLINE, file) != NULL) 
	{ 
		if(strcmp(line, "") != 0)
		{
			*protocols_db = (Protocol*) realloc(*protocols_db, sizeof(Protocol) * (*protocols_count + 1));
			
			if(*protocols_db == NULL)
			{
				printf("Problème lors de l'allocation mémoire pour la règle n°%d\nArrêt du programme.", *protocols_count + 1); 
				exit(1);
			}
			dump_protocol(&((*protocols_db)[*protocols_count]), line);
			(*protocols_count)++;
		}
       	}

}


