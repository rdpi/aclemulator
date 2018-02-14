/*
 * This program simulates the functionality of access control lists using
 * of cisco routers
 * Author: Ryan Pitts
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//function delcarations
int ipcmp(int pktip[4], int ip[4], int mask[4]);
int portprtclcmp(int port[2], char prtcl[10]);


int main(int argc, char* argv[]){
	int mode;
	//use -s flag for standard mode, -e for extended mode
	if(argc>1){	
		if(!(strcmp(argv[1],"-s")) || !(strcmp(argv[1],"--standard"))){
			mode = 0;
		}
		else if (!(strcmp(argv[1],"-e")) || !(strcmp(argv[1],"--extended"))){
			mode = 1;
		}
		else if (!(strcmp(argv[1],"-h")) || !(strcmp(argv[1],"--help"))  ){
			printf("usage: aclemulator <mode> [...]\n"
					"modes:\n"
					"\taclemulator {-h, --help}\n"
					"\taclemulator {-s, --standard} accesscontrolist... packetlist...\n"
					"\taclemulator {-e, --extended} accesscontrolist... packetlist...\n");
			return 0;
		}
		else{
			printf("error: no mode specified (use -h for help)\n");
			return 0;
		}
	}
	else{
		printf("error: no mode specified (use -h for help)\n");
		return 0;
	}
	FILE *acl, *packets;
	//Open input files for reading
	packets = fopen(argv[3], "r");
	char entry[100], pord[7], prtcl[10], pktprtcl[10], anycheck1[20], anycheck2[20], *token, *t = " ";
	int pkt[4], pktdst[4], listnum, src[4],dst[4],masksrc[4],maskdest[4],port[2];
	while (1){
		if(!mode){
			fscanf (packets, "%d.%d.%d.%d", &pkt[0],&pkt[1],&pkt[2],&pkt[3]);
		}
		else if(mode){
			fscanf (packets, "%d.%d.%d.%d %d.%d.%d.%d %s", &pkt[0],&pkt[1],&pkt[2],&pkt[3], &pktdst[0],&pktdst[1],&pktdst[2],&pktdst[3], &pktprtcl);
		}
		if(feof(packets))
			break;
		acl = fopen(argv[2], "r");
		while (1){
			fgets(entry, sizeof(entry)-1, acl);
			//if we've gotten to the end of the acl without breaking the loop, the packet ip wasn't found in the acl,
			//and it must be denied
			if(feof(acl)){
				if (!mode)
					printf("deny %d.%d.%d.%d\n", pkt[0],pkt[1],pkt[2],pkt[3]);
				else if (mode)
					
					printf ("deny\t%d.%d.%d.%d\t%d.%d.%d.%d\t%s\n", pkt[0],pkt[1],pkt[2],pkt[3], pktdst[0],pktdst[1],pktdst[2],pktdst[3], pktprtcl);
				break;
			}
			/*
			 * we're not interested in these lines for the sake of this emulator, skip to the next acl statement
			 * if 'interface' or 'ip' are the first token
			 */
			token = strtok(entry, t);
			if((strcmp("interface", token)) && (strcmp("ip", token))){
				//get listnum (we don't need it)
				token = strtok(NULL, t);
				//get permit or deny
				token = strtok(NULL, t);
				strcpy(pord, token);
				if(mode){
					token = strtok(NULL, t);
					strcpy(prtcl,token);
				}
				//get the sourceip and put into int array for easier comparison operations
				token = strtok(NULL, t);
				sscanf(token, "%s", &anycheck1);
				//if the source ip is 'any', set the mask to 255.255.255.255 for the comparison function
				if(!strcmp(anycheck1,"any")){
					masksrc[0] = masksrc[1] = masksrc[2] =  masksrc[3] = 255;
				}
				else{
					sscanf(token, "%d.%d.%d.%d", &src[0], &src[1], &src[2], &src[3]);
					//now get the mask
					token = strtok(NULL, t);
					sscanf(token, "%d.%d.%d.%d", &masksrc[0], &masksrc[1], &masksrc[2], &masksrc[3]);
				}	
				//if in extended mode, get the destination and mask and port range
				if(mode){
					token = strtok(NULL, t);
					//if the destination ip is 'any', set the mask to 255.255.255.255 for the comparison function
					sscanf(token, "%s", &anycheck2);
					if(!strcmp(anycheck2,"any")){
						maskdest[0] = maskdest[1] = maskdest[2] =  maskdest[3] = 255;
					}
					else{
						sscanf(token, "%d.%d.%d.%d", &dst[0], &dst[1], &dst[2], &dst[3]);
						//now get the mask
						token = strtok(NULL, t);
						sscanf(token, "%d.%d.%d.%d", &maskdest[0], &maskdest[1], &maskdest[2], &maskdest[3]);
					}		
					//if the protocol is tcp/udp, get the port
					if(!strcmp(prtcl,"tcp") || !strcmp(prtcl,"udp")){
						token = strtok(NULL, t);
						if (!strcmp(token,"eq")){
							token = strtok(NULL, t);
							sscanf(token, "%d", &port[0]);
							port[1] = port[0];
						}
						else if(!strcmp(token,"range")){
							token = strtok(NULL, t);
							sscanf(token, "%d-%d", &port[0], &port[1]);
						}
					}
					else if(!strcmp(prtcl,"ip")){
						port[0] = port[1] = -1;
					}

				}
				//finally compare the packet, if there's a match we break the loop and move to the next packet
				//standard comparison
				if(!mode){
					if(ipcmp(pkt, src, masksrc)){
							printf("%s\t%d.%d.%d.%d\n", pord, pkt[0],pkt[1],pkt[2],pkt[3]);
							break;
					}
				}
				//extended comparison
				if(mode){
					//if source and destination and prtocol match, break loop
					if(ipcmp(pkt, src, masksrc) && ipcmp(pktdst, dst, maskdest) && portprtclcmp(port, pktprtcl)){
						printf ("%s\t%d.%d.%d.%d\t%d.%d.%d.%d\t%s\n", pord, pkt[0],pkt[1],pkt[2],pkt[3], pktdst[0],pktdst[1],pktdst[2],pktdst[3], pktprtcl);
						break;
					}
				}
				//else we continue looking through the acl
			}

		}
		fclose(acl);

	}
	fclose(packets);
	return 0;
}

//this function will take an ip address and a mask and compare it with another ip
//to see if they match
int ipcmp (int pktip[4], int ip[4], int mask[4]){
	int match = 1;
	if(!mask[0]){
		if(pktip[0] != ip[0])
			match=0;
	}
	if(!mask[1]){
		if(pktip[1] != ip[1])
			match=0;
	}
	if(!mask[2]){
		if(pktip[2] != ip[2])
			match=0;
	}
	if(!mask[3]){
		if(pktip[3] != ip[3])
			match=0;
	}
	return match;
}

//compares a port range to a protocol to see if ports used by common protocols
//fall inside of port range
int portprtclcmp(int port[2], char prtcl[10]){
	int portchk;
	int inrange = 0;

	if (port[0] == -1){
		inrange = 1;
	}
	else if(!strcmp(prtcl,"http")){
		if((port[0] <= 80 && port[1] >= 80))
			inrange = 1;
	}
	else if(!strcmp(prtcl,"https")){
		if((port[0] <= 443 && port[1] >= 443))
			inrange = 1;
	}
	else if(!strcmp(prtcl,"ftp")){
		if((port[0] <= 20 && port[1] >= 21))
			inrange = 1;
	}
	else if(!strcmp(prtcl,"ssh")){
		if((port[0] <= 22 && port[1] >= 22))
			inrange = 1;
	}
	else if(!strcmp(prtcl,"snmp")){
		if((port[0] <= 161 && port[1] >= 161))
			inrange = 1;
	}
	return inrange;	
}
	
