#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>

char * afterHttp(char array[]);
int detectHttp404(char array[]);
void recv_(char * buffer);
int describe_pcap();
void close_pcap(pcap_t * p);
void network_mask();
void filterHttp();
void callback(u_char * user, const struct pcap_pkthdr * h, const u_char * buff);

int cpt = 0;

void main() {
    // Exercice 4
    // char arr4[] = "HTTP/1.0 200 OK";
    // printf("%s \n", afterHttp(arr4));

    // Exercice 5
    // char arr5[] = "HTTP/1.0 404 Not Found";
    // printf("%d \n", detectHttp404(arr5));

    // Exercice 6, 7, 8, 9
    // char arr7[] = "HTTP/1.0 200 OK";
    // char arr7_1[] = "HTTP/1.0 204 No Content";
    // char arr7_2[] = "HTTP/1.0 404 Not Found";
    // recv_(arr7);
    // recv_(arr7_1);
    // recv_(arr7_2);
    // recv_(arr7_2);

    // Exercice 10, 11
    // describe_pcap();

    // Exercice 12
    // printf("%s \n", network_mask());

    // Exercice 13
    filterHttp();
}

char * afterHttp(char array[]) {
    char search[] = "HTTP";
    char *ptr = strstr(array, search);
    
    if (ptr != NULL)
	{
        char *temp = malloc(strlen(array));
        for (int i=strlen(search); i<strlen(ptr); i++) {
            temp[i-strlen(search)] = ptr[i];
        }
        return temp;
	}
	else
	{
		return "no HTTP";
	}
    return ptr;
}

int detectHttp404(char array[]) {
    char *arrNoHttp = afterHttp(array);
    char *ptr = strstr(arrNoHttp, "404");
    
    if (ptr != NULL)
	{
        return 1;
	}
	else
	{
		return 0;
	}
}

void recv_(char * buffer) {
    int retour;
    retour = detectHttp404(buffer);
    cpt += retour;
    if (cpt >= 2) {
        cpt = 0;
        printf("alarme \n");
    }
}

int describe_pcap() {
    pcap_t *handle;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    printf("Device: %s\n", dev);
    return(0);

    handle = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    close_pcap(handle);
}

void close_pcap(pcap_t * p) {
    pcap_close(p);
}

void network_mask() {
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE]; 
    dev = pcap_lookupdev(errbuf);
    bpf_u_int32 mask;   
    bpf_u_int32 ip;    
    struct in_addr ip_addr;
    struct in_addr mask_addr;

    /* Find the properties for the device */
    pcap_lookupnet(dev, &ip, &mask, errbuf);

    ip_addr.s_addr = ip;
    mask_addr.s_addr = mask;

    printf("Network Address: %s\n", inet_ntoa(ip_addr));
    printf("Mask Address: %s\n", inet_ntoa(mask_addr));
}

void filterHttp() {
    char filter[] = "port 80";
    pcap_t *handle;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 addr;   
    bpf_u_int32 mask; 

    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    printf("Device: %s\n", dev);

    pcap_lookupnet(dev, &addr, &mask, errbuf);

    handle = pcap_open_live(dev, 1028, 0, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }

    struct bpf_program result;

    if (pcap_compile(handle, &result, filter, 0, addr)==-1) {
        printf("%s \n", pcap_geterr(handle));
    }
    if (pcap_setfilter(handle, &result)) {
        printf("%s \n", pcap_geterr(handle));
    }
    
    pcap_loop(handle, 0, callback, NULL);
}

void callback(u_char * user, const struct pcap_pkthdr * h, const u_char * buff) {

    struct ip *iph;
    iph = (struct ip *) buff;

    printf("Taille du paquet HTTP : %d \n", h->len);
    printf("Adresse IP: %d \n", iph->ip_dst);
}
