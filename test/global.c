#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pcap.h>
#include "arp.h"
#include "utils.h"

FILE *control_flow;

FILE *pcap_in;
FILE *pcap_out;
FILE *pcap_demo;

FILE *arp_fin;
FILE *arp_fout;
FILE *arp_log_f;

FILE *ip_fin;
FILE *ip_fout;

FILE *icmp_fin;
FILE *icmp_fout;

FILE *udp_fin;
FILE *udp_fout;

FILE *out_log;
FILE *demo_log;

extern arp_entry_t arp_table[ARP_MAX_ENTRY];
extern arp_buf_t arp_buf;

static char* state[16] = {
        [ARP_PENDING] "pending",
        [ARP_VALID]   "valid  ",
        [ARP_INVALID] "invalid",
        "unknown",
        "unknown",
        "unknown",
        "unknown",
        "unknown",
        "unknown",
        "unknown",
        "unknown",
        "unknown",
        "unknown",
        "unknown",
        "unknown",
        "unknown"
};


char* print_ip(uint8_t *ip)
{
        static char result[32];
        if(ip == 0){
                return "(null)";
        }else{
                sprintf(result,"%d.%d.%d.%d",ip[0],ip[1],ip[2],ip[3]);
                return result;
        }
}

char* print_mac(uint8_t *mac)
{
        static char result[32];
        if(mac == 0){
                return "(null)";
        }else{
                sprintf(result,"%02x:%02x:%02x:%02x:%02x:%02x",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
                return result;
        }
}

void fprint_buf(FILE* f, buf_t* buf)
{
        fprintf(f,"\tbuf:");
        if(buf == 0){
                fprintf(f,"(null)\n");
        }else{
                for(int i = 0; i < buf->len; i++){
                        fprintf(f," %02x",buf->data[i]);
                }
                fprintf(f,"\n");
        }
}

void log_tab_buf(){
        fprintf(arp_log_f, "<====== arp table =======>\n");
        fprintf(arp_log_f, "state  \ttimeout/10^7\tip\t\t\tmac\n");
        for(int i = 0; i < ARP_MAX_ENTRY; i++){
                if(arp_table[i].state != ARP_INVALID){
                        fprintf(arp_log_f, "%s\t%ld\t\t%s\t\t%s\n",
                                state[arp_table[i].state],
                                arp_table[i].timeout/10000000,
                                print_ip(arp_table[i].ip),
                                print_mac(arp_table[i].mac));
                }
        }
        fprintf(arp_log_f, "arp buf: \n");
        fprintf(arp_log_f, "\tvalid: %d\n",arp_buf.valid);
        if(arp_buf.valid){
                fprintf(arp_log_f, "\tbuf:");
                for(int i = 0; i < arp_buf.buf.len; i++){
                        fprintf(arp_log_f, "%02x ",arp_buf.buf.data[i]);
                }
                fprintf(arp_log_f, "\n\tip: %s\n", print_ip(arp_buf.ip));
                fprintf(arp_log_f, "\tprotocol: %04x\n",arp_buf.protocol);
        }
}


int get_round(FILE* f)
{
        char * p = 0;
        size_t n = 0;
        do{
                if(getline(&p,&n,f) == -1)
                        return -1;
        }while(memcmp("Round",p,5));
        if(p) free(p);
        return 0;
}

int check_round()
{
        char *p0 = 0;
        char *p1 = 0;
        size_t n0 = 0;
        size_t n1 = 0;
        int result,len0,len1;
        int line = 0;
CHECK_ROUND_NEXT_LINE:
        line++;
        len0 = getline(&p0,&n0,demo_log);
        len1 = getline(&p1,&n1,out_log);

        if( len0 != len1 ){
                result = 1;
                goto CHECK_ROUND_EXIT;
        }

        if(len0 == -1){
                result = len1 != -1;
                goto CHECK_ROUND_EXIT;
        }

        if(len0 <= 1){
                result = 0;
                goto CHECK_ROUND_EXIT;
        }

        if(memcmp(p0,p1,len0)){
                result = 1;
                goto CHECK_ROUND_EXIT;
        }

        goto CHECK_ROUND_NEXT_LINE;
        
CHECK_ROUND_EXIT:
        if(p0) free(p0);
        if(p1) free(p1);
        return result ? line : 0;
}


int check_log()
{
        int i = 0;
        int ret;
        int result = 0;
        printf("\e[0;34mChecking log file(compare with demo).\n");
        while(get_round(demo_log) == 0){
                i++;
                if(get_round(out_log)){
                        printf("\e[0;31mMissing Round %d\n",i);
                        result = 1;
                        continue;
                }

                if(ret = check_round()){
                        printf("\e[0;31mRound %d: differences found(Line %d of the current round)\n",i,ret);
                        result = 1;
                }else{
                        printf("\e[0;32mRound %d: no differences\n",i);
                }
        }

        while(get_round(out_log) == 0){
                i++;
                result = 1;
                printf("\e[0;31mAdditional Round %d found\n",i);
        }

        if(result){
                printf("\e[1;31m====> Some log rounds are different to the demo.\n");
        }else{
                printf("\e[1;32m====> All log rounds are the same to the demo.\n");
        }
        printf("\e[0m");
        return result;
}

int check_pcap()
{
        char errbuf[PCAP_ERRBUF_SIZE];
        const char *str_exit = "Exiting pcap file check\n";
        printf("\e[0;34mChecking pcap output file(compare with demo).\n");
        pcap_t *pcap0 = pcap_fopen_offline(pcap_demo,errbuf);
        if(pcap0 == 0){
                fprintf(stderr,"\e[1;31mLoad demo output failed:%s\n",errbuf);
                printf("%s",str_exit);
                return -1;
        }
        pcap_t *pcap1 = pcap_fopen_offline(pcap_out,errbuf);
        if(pcap1 == 0){
                fprintf(stderr,"\e[1;31mLoad demo output failed:%s\n",errbuf);
                printf("%s",str_exit);
                return -1;
        }

        int idx = 0;
        int result = 0;
        struct pcap_pkthdr *pkt_hdr0, *pkt_hdr1;
        const uint8_t      *pkt_data0, *pkt_data1;

CHECK_PCAP_NEXT_PACKET:
        idx++;
        int ret0 = pcap_next_ex(pcap0,&pkt_hdr0,&pkt_data0);
        int ret1 = pcap_next_ex(pcap1,&pkt_hdr1,&pkt_data1);

        if(ret0 == -1){
                fprintf(stderr,"\e[1;31mError occured on loading packet %d from demo:%s\n",idx,pcap_geterr(pcap0));
                printf("%s",str_exit);
                goto CHECK_PCAP_EXIT;
        }

        if(ret1 == -1){
                fprintf(stderr,"\e[1;31mError occured on loading packet %d from user output:%s\n",idx,pcap_geterr(pcap1));
                printf("%s",str_exit);
                goto CHECK_PCAP_EXIT;
        }

        if(ret0 == PCAP_ERROR_BREAK){
                if(ret1 == 1){
                        fprintf(stderr,"\e[0;31mAddition packet %d found\n",idx);
                        result = 1;
                        goto CHECK_PCAP_NEXT_PACKET;
                }else if(ret1 == PCAP_ERROR_BREAK){
                        if(result){
                                printf("\e[1;31m====> Some packets are different to the demo.\n");
                        }else{
                                printf("\e[1;32m====> All packets are the same to the demo.\n");
                        }
                        goto CHECK_PCAP_EXIT;
                }else{
                        printf("\e[1;31mUNKNOWN ERROR\n");
                        printf("%s",str_exit);
                        result = 1;
                        goto CHECK_PCAP_EXIT;
                }
        }

        if(ret1 == PCAP_ERROR_BREAK){
                if(ret0 != 1){
                        printf("\e[1;31mUNKNOWN ERROR\n");
                        printf("%s",str_exit);
                        result = 1;
                        goto CHECK_PCAP_EXIT;
                }else{
                        printf("\e[0;31mMissing packet %d\n",idx);
                        result = 1;
                        goto CHECK_PCAP_NEXT_PACKET;
                }
        }

        if(pkt_hdr0->len != pkt_hdr1->len){
                printf("\e[0;31mPacket %d: differences found\n",idx);
                result = 1;
                goto CHECK_PCAP_NEXT_PACKET;
        }

        if(memcmp(pkt_data0,pkt_data1,pkt_hdr0->len)){
                printf("\e[0;31mPacket %d: differences found\n",idx);
                result = 1;
                goto CHECK_PCAP_NEXT_PACKET;
        }
        printf("\e[0;32mPacket %d: no differences\n",idx);
        goto CHECK_PCAP_NEXT_PACKET;
CHECK_PCAP_EXIT:
        pcap_close(pcap0);
        pcap_close(pcap1);
        printf("\e[0m");
        return result;
}
