#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <net/ethernet.h>

int nb404 = 0;


void callback(u_char * user, const struct pcap_pkthdr * h, const u_char * buff){
    struct ether_header *ep;
    struct ip *iph;
    unsigned short ether_type;
    int chcnt = 0;
    int len = h->len;
    int i;

    ep = (struct ether_header *)buff;
    ether_type = ntohs(ep->ether_type);

    buff += sizeof(struct ether_header);
    iph = (struct ip *)buff;

    printf("Taille paquet:%d\n",len-16);
    printf("Adresse IP: %s\n", inet_ntoa(iph->ip_dst));
    printf("\n");
    
}

int detectHttp404(char * packet, int taille){
    int cpt;
    for(int i=0;i<taille;i++){
        if(strstr(packet,"48545450") != NULL){
            if(strstr(strstr(packet,"48545450"),"343034") != NULL){
                return 1;
            }
        } 
    }
    return 0;
}

void recu(char * buffer){
    int retour;
    retour = detectHttp404(buffer,(int) strlen(buffer));
    if(retour == 1){
        nb404++;
    }
    printf("%d",retour);
}

void printhttp(char * packet){
    int cpt;
    
    char * sub = strstr(packet, "48545450");
    for(int i=0;i<strlen(sub);i++){
        printf("%c",sub[i]);
    }
}

void alarme(){
    if(nb404==2){
        nb404=0;
        printf("\nattention\n");
    }
}

void convertAndprint(){

}

int main(){
    char tab[] = "4d4854545031343034";
    char tab1[] = "4d4854545031333032";
    char *device;
    char buffer[PCAP_ERRBUF_SIZE];
    pcap_t *link;
    char ip[16];
    char submask[16];
    bpf_u_int32 adrr;
    bpf_u_int32 mask;
    struct in_addr adresse;
    int code;
    char filterd[] = "port 80";
    struct bpf_program filter;
    struct iphdr * ipHeader;

    //printhttp(tab);
    printf("\n");
    recu(tab);
    printf("\n");
    recu(tab);
    alarme();

    device = pcap_lookupdev(device);
    if(device == NULL){
        printf("error\n");
        return 1;
    } else {
        
        code = pcap_lookupnet(device,&adrr,&mask,buffer);
        if(code == -1){
            printf("error");
        }
        printf("success\n");
        
        adresse.s_addr = adrr;
        strcpy(ip,inet_ntoa(adresse));
        if(ip==NULL){
            printf("error ip\n");
        }
        adresse.s_addr = mask;
        strcpy(submask, inet_ntoa(adresse));
        if(submask==NULL){
            printf("error submask\n");
        }
        printf("Device:%s\n",device);
        printf("IP:%s\n",ip);
        printf("MASK:%s\n",submask);

        //ouverture
        link = pcap_open_live(device,1028,0,1000,buffer);
        if(link == NULL){
            fprintf(stderr,"error%s");
        }


        //filter
        if(pcap_compile(link, &filter, filterd, 0, adrr) == -1){
            printf("error compile\n");
            return 1;
        }
        if(pcap_setfilter(link, &filter) == -1){
            printf("error filter\n");
            return 1;
        }

        

        //capture
        pcap_loop(link, 0, callback, NULL);
        
        pcap_close(link);
        
    }

    return 1;
}




