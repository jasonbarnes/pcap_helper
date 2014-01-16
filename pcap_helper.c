#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <assert.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <math.h>

#include "pcap_helper.h"

struct pcap_helper_dat{
	void (*func)(const struct pcap_pkthdr *, const u_char *, struct iphdr *, struct tcphdr *, void*);
	void *func_data;
};

void pcap_helper_loop(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet){
	struct pcap_helper_dat *helper_dat = (struct pcap_helper_dat *)userData;
	int ether_type;
	int ether_offset;
	struct iphdr *ip=NULL;
	struct tcphdr *tcp=NULL;
	char *ptr;
	int ipflag=0;
	ptr = (char *)packet;
	ether_type = ((int)(ptr[12]) << 8) | (int)ptr[13];
	if(ether_type == 0x0800){
		ether_offset = 14;
		ipflag=1;
	}
	else{
		ether_offset = 18;
	}
	ptr += ether_offset;
	if(ipflag == 0){
		helper_dat->func(pkthdr, packet, NULL, NULL, helper_dat->func_data);
		return;
	}
	ip = (struct iphdr *)ptr;
	if(ip->protocol != 6){
		helper_dat->func(pkthdr, packet, ip, NULL, helper_dat->func_data);
		return;
	}
	ptr += sizeof(struct iphdr);
	tcp = (struct tcphdr *)ptr;
	helper_dat->func(pkthdr, packet, ip, tcp, helper_dat->func_data);
	return;
}

extern int pcap_helper_offline(char *filename, void (*func)(const struct pcap_pkthdr *, const u_char *, struct iphdr *, struct tcphdr *, void *), void *func_data){
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_helper_dat *helper_dat;
	helper_dat = (struct pcap_helper_dat *)malloc(sizeof(struct pcap_helper_dat));
	helper_dat->func = func;
	helper_dat->func_data = func_data;
	handle = pcap_open_offline(filename, errbuf);
	if(handle == NULL){
		perror("pcap_helper_offline had pcap_open_offline error");
		return EXIT_FAILURE;
	}
	if(pcap_loop(handle, 0, pcap_helper_loop, (u_char *)helper_dat)){
	}
	pcap_close(handle);
	return EXIT_SUCCESS;
}
