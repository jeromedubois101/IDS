#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "headers/populate.h"
#include "headers/db_init.h"
#include "headers/matcher.h"

#define PROTOCOLS_FILE "ids.protocols"


void my_packet_handler(u_char*, const struct pcap_pkthdr *, const u_char *);
void free_heap(Protocol*, Rule*, int);


int main(int argc, char *argv[]) 
{
	if(argc < 2)
	{
		printf("Pas de nom de fichier spécifié !\n");
		exit(1);
	}
	
	FILE *rules_file = fopen(argv[1], "r"); 
	if(rules_file == NULL)
	{
		printf("L'ouverture du fichier \"%s\" a échouée entrainant l'arrêt du programme.\n", argv[1]);
		exit(1);
	}
	Rule *rules_db = NULL;
	int rules_count = 0;//On devra l'utiliser pour savoir combien d'éléments dans le tableau.
	read_rules(rules_file, &rules_db, &rules_count);//Création BDD des règles
	fclose(rules_file);
	printf("Rules database loaded\n");
	fflush(stdout);



	FILE *proto_file = fopen(PROTOCOLS_FILE, "r"); 
	if(proto_file == NULL)
	{
		printf("L'ouverture du fichier \"%s\" a échouée entrainant l'arrêt du programme.\n", PROTOCOLS_FILE);
		exit(1);
	}
	Protocol *protocols_db = NULL;
	int protocols_count = 0;//On devra l'utiliser pour savoir combien d'éléments dans le tableau.
	read_protocols(proto_file, &protocols_db, &protocols_count);//Création BDD des protocoles.
	fclose(proto_file);
	printf("Protocols database loaded\n");
	fflush(stdout);

	
	
	//Mise en place de l'écoute réseau
	char *device = "eth0";
	char error_buffer[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_create(device,error_buffer);
	pcap_set_timeout(handle,10);
	int success = pcap_activate(handle);
	if(success != 0)
	{
		printf("Impossible d'écouter sur l'interface %s !\n", device);
		exit(1);
	}
	printf("IDS is now listening on %s\n", device);
	fflush(stdout);//On vide le buffer stdout (problèmes d'affichages dû au pcap_loop sinon)


	//On doit contenir des pointeurs (tous de même taille mais pas de même type) dans un tableau, alors on les cast tous vers un type commun (ici void).
	//https://stackoverflow.com/questions/24768543/how-to-pass-multiple-arguments-to-pcap-loop-pcap-handler 
    	void* args_array[4];//Tableau de pointeurs de type void (indéfini)
    	args_array[0] = (void*) rules_db; 
    	args_array[1] = (void*) protocols_db; 
 	args_array[2] = (void*) &rules_count;
	args_array[3] = (void*) &protocols_count;
	
	int total_packet_count = -1;
    	pcap_loop(handle, total_packet_count, my_packet_handler, (u_char*) args_array);
	pcap_close(handle);
	free_heap(protocols_db, rules_db, rules_count);//Libération de tout ce qu'on a déclaré dans le heap (tas)
    	
	return 0;
}


void my_packet_handler(u_char *args_array, const struct pcap_pkthdr *header, const u_char *packet)
{
	void **args = (void**) args_array; //On fait l'opération inverse afin de cast les éléments vers leur type de départ.
	Rule *rules_db = (Rule*)args[0]; 
	Protocol *protocols_db = (Protocol*)args[1];
	int *rules_nb = (int*) args[2];
	int *protocols_count = (int*) args[3];
	
    	ETHER_Frame new_frame; 

    	populate_packet_ds(header, packet, &new_frame);
	
	if(new_frame.ethernet_type == IPV4)//Les règles ne s'appliquent que pour les paquets IPV4
	{	
		rule_matcher(&new_frame, rules_db, protocols_db, *rules_nb, *protocols_count);
	}
}



void free_heap(Protocol *protocols_db, Rule *rules_db, int rules_count)
{
	
	for(int i=0;i<rules_count;i++)//Libération des content
	{
		if(rules_db[i].content != NULL)
		{
			free(rules_db[i].content);
		}
	}

	for(int i=0;i<rules_count;i++)//Libération des messages
	{
		if(rules_db[i].msg != NULL)
		{
			free(rules_db[i].msg);
		}
	}
	free(rules_db);
	free(protocols_db);
}

