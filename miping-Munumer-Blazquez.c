// Practica tema 8, Muñumer Blázquez Sergio
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <string.h>
#include "ip-icmp-ping.h"

#define VERBOSE 	"-v"
#define TYPE 		8
#define CODE 		0
#define PAYLOAD		"Este es el payload"

void makeRequest(ECHORequest *request);
int checkCS(ECHORequest *request);
void checkErrCode(ECHOResponse *response);

int informer;

/*************************************************************

	Metodo para rellenar las peticiones ICMP:
	
		Completa los diferentes campos de la petición,
		ejecuta el algoritmo para calcular el checksum, 
		y llama al metodo "checkCS" para comprobar que 
		dicho calculo es correcto.
		
		Si esta activado el modo verbose retransmite 
		la completacion de los campos.

**************************************************************/
void makeRequest(ECHORequest *request){

	request->icmpHeader.Type = TYPE;	
	request->icmpHeader.Code = CODE;
	request->icmpHeader.Checksum = 0;	
	request->ID = getpid();
	request->SeqNumber = 0;
	strcpy(request->payload, PAYLOAD);
	if(informer)
	{
		printf("-> Generando cabecera ICMP...\n");
		printf("-> Tipo: %d\n-> Codigo: %d\n-> ID: %d\n-> SeqNum: %d\n", 
			request->icmpHeader.Type, request->icmpHeader.Code,  
			request->ID, request->SeqNumber);
		printf("-> Payload: %s\n", request->payload);
	
	}
	int i = 0;
	int numShorts = (sizeof(ECHORequest) / 2);
	unsigned short int *puntero;
	unsigned int acum = 0;
	puntero = (unsigned short int*)request;
	while(i<numShorts){
		acum += (unsigned int) *puntero;
		puntero++;
		i++;
	}
	acum = (acum >> 16) + (acum & 0x0000ffff);
	acum = (acum >> 16) + (acum & 0x0000ffff);
	request->icmpHeader.Checksum = (unsigned short int) ~acum;

	if(!checkCS(request)){
		printf("Fallo en checksum\n");
		exit (EXIT_FAILURE);
	}
	if(informer){ 
		printf("-> Checksum: 0x%x \n", request->icmpHeader.Checksum);
		printf("-> Tamaño total del paquete ICMP: %ld \n", sizeof(*request));
	}

}

/**************************************************************

	Metodo para comprobar el checksum calculado:
		
		Repetimos el algoritmo para calcular el checksum
		y comprobamos si el resultado es 0
		sino lo es, hay un error en el calculo.
	
**************************************************************/
int checkCS(ECHORequest *request){
	int i = 0;
	int flag = 0;
	int numShorts = (sizeof(ECHORequest) / 2);
	unsigned short int *puntero;
	unsigned int acum = 0;
	puntero = (unsigned short int*) request;
	while(i<numShorts){
		acum += (unsigned int) *puntero;
		puntero++;
		i++;
	}
	acum = (acum >> 16) + (acum & 0x0000ffff);
	acum = (acum >> 16) + (acum & 0x0000ffff);
	acum = ~acum;

	if((unsigned short int)acum == 0) flag =  1;

	return flag;
		
}

/**************************************************************

	Metodo para imprimir el mensaje 
	en caso de recibir un error, 
	en funcion de los campos Type y Code
	
**************************************************************/
void checkErrCode(ECHOResponse *response){
	printf("Descripción de la respuesta: ");
	switch(response->icmpHeader.Type){
		
		case 1 : case 2: case 7: case 44: case 255:
				printf("Reserved (type %d, code %d)\n", 
							response->icmpHeader.Type, response->icmpHeader.Code);
				break;
		case 3:
				switch (response->icmpHeader.Code){
					printf("Destination Unreachable: ");
					case 0: 
						printf("Destination network unreachable (type %d, code %d)\n", 
							response->icmpHeader.Type, response->icmpHeader.Code);
						break;
					case 1: 
						printf("Destination host unreachable (type %d, code %d)\n", 
							response->icmpHeader.Type, response->icmpHeader.Code);
						break;
					case 2: 
						printf("Destination protocol unreachable (type %d, code %d)\n", 
							response->icmpHeader.Type, response->icmpHeader.Code);
						break;
					case 3: 
						printf("Destination port unreachable (type %d, code %d)\n", 
							response->icmpHeader.Type, response->icmpHeader.Code);
						break;
					case 4: 
						printf("Fragmentation required, and DF flag set (type %d, code %d)\n", 
							response->icmpHeader.Type, response->icmpHeader.Code);
						break;
					case 5: 
						printf("Source route failed (type %d, code %d)\n", 
							response->icmpHeader.Type, response->icmpHeader.Code);
						break;
					case 6: 
						printf("Destination network unknown (type %d, code %d)\n", 
							response->icmpHeader.Type, response->icmpHeader.Code);
						break;
					case 7: 
						printf("Destination host unknown (type %d, code %d)\n", 
							response->icmpHeader.Type, response->icmpHeader.Code);
						break;
					case 8: 
						printf("Source host isolated (type %d, code %d)\n", 
							response->icmpHeader.Type, response->icmpHeader.Code);
						break;
					case 9: 
						printf("Network administratively prohibited (type %d, code %d)\n", 
							response->icmpHeader.Type, response->icmpHeader.Code);
						break;
					case 10: 
						printf("Host administratively prohibited (type %d, code %d)\n", 
							response->icmpHeader.Type, response->icmpHeader.Code);
						break;
					case 11: 
						printf("Network unreachable for ToS (type %d, code %d)\n", 
							response->icmpHeader.Type, response->icmpHeader.Code);
						break;
					case 12: 
						printf("Host unreachable for ToS (type %d, code %d)\n", 
							response->icmpHeader.Type, response->icmpHeader.Code);
						break;
					case 13: 
						printf("Communication administratively prohibited (type %d, code %d)\n", 
							response->icmpHeader.Type, response->icmpHeader.Code);
						break;
					case 14: 
						printf("Host Precedence Violation (type %d, code %d)\n", 
							response->icmpHeader.Type, response->icmpHeader.Code);
						break;
					case 15: 
						printf("Precedence cutoff in effect (type %d, code %d)\n", 
							response->icmpHeader.Type, response->icmpHeader.Code);
						break;
						
				}
				break;
			case 5:
				printf("Redirect Message: ");
				switch (response->icmpHeader.Code){
					case 0:
							printf("Redirect Datagram for the Network (type %d, code %d)\n", 
								response->icmpHeader.Type, response->icmpHeader.Code);
							break;
					case 1:
							printf("Redirect Datagram for the Host (type %d, code %d)\n", 
								response->icmpHeader.Type, response->icmpHeader.Code);
							break;
					case 2:
							printf("Redirect Datagram for the ToS & network (type %d, code %d)\n", 
								response->icmpHeader.Type, response->icmpHeader.Code);
							break;
					case 3:
							printf("Redirect Datagram for the ToS & host (type %d, code %d)\n", 
								response->icmpHeader.Type, response->icmpHeader.Code);
							break;
				}
				break;
			case 8:
				printf("Echo request (type %d, code %d)\n", 
					response->icmpHeader.Type, response->icmpHeader.Code);
				break;
			case 9:
				printf("Router Advertisement (type %d, code %d)\n", 
					response->icmpHeader.Type, response->icmpHeader.Code);
				break;
			case 10:
				printf("Router Solicitation (type %d, code %d)\n", 
					response->icmpHeader.Type, response->icmpHeader.Code);
				break;
			case 11:
				printf("Time Exceeded : ");
				switch(response->icmpHeader.Code){
					case 0:
							printf("TTL expired in transit (type %d, code %d)\n", 
								response->icmpHeader.Type, response->icmpHeader.Code);
							break;
					case 1: 
							printf("Fragment reassembly time exceeded (type %d, code %d)\n", 
								response->icmpHeader.Type, response->icmpHeader.Code);
							break;
				}
				break;
			case 12:
				printf("Parameter Problem: Bad IP header :");
				switch(response->icmpHeader.Code){
					case 0:
							printf("Pointer indicates the error (type %d, code %d)\n", 
								response->icmpHeader.Type, response->icmpHeader.Code);
							break;
					case 1: 
							printf("Missing a required option (type %d, code %d)\n", 
								response->icmpHeader.Type, response->icmpHeader.Code);
							break;
					case 2:
							printf("Bad length (type %d, code %d)\n", 
								response->icmpHeader.Type, response->icmpHeader.Code);
							break;
				}
				break;
			case 13:
				printf("Timestamp (type %d, code %d)\n", 
					response->icmpHeader.Type, response->icmpHeader.Code);
				break;
			case 14:
				printf("Timestamp reply(type %d, code %d)\n", 
					response->icmpHeader.Type, response->icmpHeader.Code);
				break;
			case 19:
				printf("Reserved for security (type %d, code %d)\n", 
					response->icmpHeader.Type, response->icmpHeader.Code);
				break;
			case 20:
				printf("Reserved for robustness experiment (type %d, code %d)\n", 
					response->icmpHeader.Type, response->icmpHeader.Code);
				break;
			case 42:
				printf("Request Extended Echo (type %d, code %d)\n", 
					response->icmpHeader.Type, response->icmpHeader.Code);
				break;
			case 43:
				printf("Extended Echo Reply: ");
				switch(response->icmpHeader.Code){
					case 0:
							printf("No Error (type %d, code %d)\n", 
								response->icmpHeader.Type, response->icmpHeader.Code);
							break;
					case 1:
							printf("Malformed Query (type %d, code %d)\n", 
								response->icmpHeader.Type, response->icmpHeader.Code);
							break;
					case 2:
							printf("No Such Interface (type %d, code %d)\n", 
								response->icmpHeader.Type, response->icmpHeader.Code);
							break;
					case 3:
							printf("No Such Table Entry (type %d, code %d)\n", 
								response->icmpHeader.Type, response->icmpHeader.Code);
							break;
					case 4:
							printf("Multiple Interfaces Satisfy Query (type %d, code %d)\n", 
								response->icmpHeader.Type, response->icmpHeader.Code);
							break;
				}
				break;
	}
	
}
/**************************************************************

	Metodo Principal
	
**************************************************************/
int main(int argc, char *argv[]) {
	informer = 0;
//Comprobamos si el Num de Args es válido
	if((argc==2) || ((argc==3) && (strcmp(VERBOSE,argv[2])==0))){
//Comprobamos modo verbose
		if((argc==3 && (strcmp(VERBOSE,argv[2])==0))) informer = 1;

		ECHORequest request;
		ECHOResponse response;

//Creación de la estructura para la direccion de destino		
		struct sockaddr_in servaddr;
		servaddr.sin_family=AF_INET;
		inet_aton(argv[1], &servaddr.sin_addr);
		
//Creamos descriptor socket y definimos su tipo		
		int sockfd;
		if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
			perror("\nsocket()");
			exit(EXIT_FAILURE);
		}
//Creamos la estructura local para enlazar con el socket
		struct sockaddr_in client;
		client.sin_family=AF_INET;
		client.sin_port=0;
		client.sin_addr.s_addr= INADDR_ANY;
		socklen_t len;
		len = sizeof(servaddr);
//Hacemos dicho enlaze
		if (bind(sockfd, (struct sockaddr*) &client, sizeof(client)) < 0){
			printf("Fallo al enlazar el socket\n");
			perror("\nbind()");
			exit (EXIT_FAILURE);
		}
//Llamamos al metodo para completar la peticion ICMP
		makeRequest(&request);
//Enviamos la peticion ICMP, comprobando fallo		
		if(sendto(sockfd, &request, sizeof(request),0, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0){
			printf("Fallo en el envio\n");
			perror("\nsendto()");
			exit(EXIT_FAILURE);
		}
		printf("Paquete ICMP enviado a %s\n", inet_ntoa(servaddr.sin_addr));
//Recibimos la respuesta a nuestra peticion
		if(recvfrom(sockfd, &response, sizeof(ECHOResponse), 0,(struct sockaddr*)	&servaddr,	&len) < 0){
			perror("\nrecvfrom()");
			exit(EXIT_FAILURE);
		}
		printf("Respuesta recibida desde %s\n", inet_ntoa(servaddr.sin_addr));
//Si los campos Type y Code de la respuesta son 0, es decir, respuesta correcta
		if(response.icmpHeader.Type == 0 && response.icmpHeader.Code == 0){
			if(informer){
				printf("-> Tamaño de la respuesta: %ld\n-> Payload: %s\n-> Identificador (pid): %d\n-> TTL: %d\n", 
					sizeof(response), response.payload, response.ID, response.ipHeader.TTL);
			}
			printf("Descripción de la respuesta: respuesta correcta (type %d, code %d)\n",
				response.icmpHeader.Type,response.icmpHeader.Code);
		}
//Sino lo son, es una respuesta erronea,
//Llamamos al metodo para comprobar el mensaje de error
		else checkErrCode(&response);	
		
	}
//Si los argumentos introducidos no eran válidos
//Lanzamos error
	else{
			printf("\nError de sintaxis:\n");
			printf("--> ./miping direccion-ip [-v]\n");
			exit(EXIT_FAILURE);			
		}
		
	exit(EXIT_SUCCESS);	
	
//FIN
    return 0;
}
