#ifndef __PCAP_HELPER_H__
#define __PCAP_HELPER_H__
/*
This header file includes functions that make 
opening pcap files and reading them packet-by-packet
much easier.
*/
extern int pcap_helper_offline(char *filename, void (*func)(const struct pcap_pkthdr *, const u_char *, struct iphdr *, struct tcphdr *, void *), void *func_data);
#endif
