#include "arp.h"
#include "utils.h"
#include "ethernet.h"
#include "config.h"
#include <string.h>
#include <stdio.h>
#include<stdlib.h>

/**
 * @brief 初始的arp包
 * 
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type = swap16(ARP_HW_ETHER),
    .pro_type = swap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = DRIVER_IF_IP,
    .sender_mac = DRIVER_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表
 * 
 */
arp_entry_t arp_table[ARP_MAX_ENTRY];

/**
 * @brief 长度为1的arp分组队列，当等待arp回复时暂存未发送的数据包
 * 
 */
arp_buf_t arp_buf;

/**
 * @brief 更新arp表
 *        你首先需要依次轮询检测ARP表中所有的ARP表项是否有超时，如果有超时，则将该表项的状态改为无效。
 *        接着，查看ARP表是否有无效的表项，如果有，则将arp_update()函数传递进来的新的IP、MAC信息插入到表中，
 *        并记录超时时间，更改表项的状态为有效。
 *        如果ARP表中没有无效的表项，则找到超时时间最长的一条表项，
 *        将arp_update()函数传递进来的新的IP、MAC信息替换该表项，并记录超时时间，设置表项的状态为有效。
 * 
 * @param ip ip地址
 * @param mac mac地址
 * @param state 表项的状态
 */
void arp_update(uint8_t *ip, uint8_t *mac, arp_state_t state)
{
    // TODO
    time_t now;
    //当前时间  单位为s
    time(&now);
    // 轮询检测ARP表中所有的ARP表项是否有超时，如果有超时，则将该表项的状态改为无效。
    for(int i=0;i<ARP_MAX_ENTRY;i++){
        //timeout记录的是当前时间
        //如果now - arp_table[i].timeout > ARP_TIMEOUT_SEC
        //可设为INVALID
        //即丢弃
        if(now -arp_table[i].timeout > ARP_TIMEOUT_SEC){
            arp_table[i].state=ARP_INVALID;
        }
    }
    //查看ARP表是否有无效的表项
    //如果有，则将arp_update()函数传递进来的新的IP、MAC信息插入到表中，
    //并记录超时时间，更改表项的状态为有效。
    for(int i=0;i<ARP_MAX_ENTRY;i++){
        //找到无效表项
        if(arp_table[i].state == ARP_INVALID){
            //更新
            for(int j=0;j<4;j++)
                arp_table[i].ip[j]=ip[j];
            for(int j=0;j<6;j++)
                arp_table[i].mac[j]=mac[j];
            arp_table[i].state=ARP_VALID;
            arp_table[i].timeout = now;
            return;
        }
    }
    // 如果ARP表中没有无效的表项
    // 则把timeout最小的项目丢弃
    // 即最早进来的项目
    int min_index=0;
    // time_t为64位 
    time_t min=((long)1<<62);
    // 找到timeout最小的项目
    for(int i=0;i<ARP_MAX_ENTRY;i++){
        if(arp_table[i].timeout<min){
            min_index=i;
            min = arp_table[i].timeout;
        } 
    }
    //更新
    for(int i=0;i<4;i++)
        arp_table[min_index].ip[i]=ip[i];
    for(int i=0;i<6;i++)
        arp_table[min_index].mac[i]=mac[i];
    arp_table[min_index].state=ARP_VALID;
    arp_table[min_index].timeout=now;
    return;

}

/**
 * @brief 从arp表中根据ip地址查找mac地址
 * 
 * @param ip 欲转换的ip地址
 * @return uint8_t* mac地址，未找到时为NULL
 */
static uint8_t *arp_lookup(uint8_t *ip)
{
    for (int i = 0; i < ARP_MAX_ENTRY; i++)
        if (arp_table[i].state == ARP_VALID && memcmp(arp_table[i].ip, ip, NET_IP_LEN) == 0)
            return arp_table[i].mac;
    return NULL;
}

/**
 * @brief 发送一个arp请求
 *        你需要调用buf_init对txbuf进行初始化
 *        填写ARP报头，将ARP的opcode设置为ARP_REQUEST，注意大小端转换
 *        将ARP数据报发送到ethernet层
 * 
 * @param target_ip 想要知道的目标的ip地址
 */
static void arp_req(uint8_t *target_ip)
{
    // TODO
    buf_init(&txbuf,28);
    uint8_t *p = txbuf.data;
    //硬件类型
    p[0]=0x00;
    p[1]=0x01;
    //上层协议类型
    p[2]=0x08;
    p[3]=0x00;
    //MAC地址长度
    p[4]=0x06;
    //IP协议地址长度
    p[5]=0x04;
    //操作类型
    p[6]=0x00;
    p[7]=0x01;
    //源MAC地址
    for(int i=0;i<6;i++){
        p[8+i]=net_if_mac[i];
    }
    //源IP地址
    for(int i=0;i<4;i++){
        p[14+i]=net_if_ip[i];
    }
    //目的MAC地址
    for(int i=0;i<6;i++){
        p[18+i]=0x00;
    }
    //目的IP地址
    for(int i=0;i<4;i++){
        p[24+i]=target_ip[i];
    }
    ethernet_out(&txbuf,ether_broadcast_mac,NET_PROTOCOL_ARP);
    
}
/**
 * @brief 处理一个收到的数据包
 *        你首先需要做报头检查，查看报文是否完整，
 *        检查项包括：硬件类型，协议类型，硬件地址长度，协议地址长度，操作类型
 *        
 *        接着，调用arp_update更新ARP表项
 *        查看arp_buf是否有效，如果有效，则说明ARP分组队列里面有待发送的数据包。
 *        即上一次调用arp_out()发送来自IP层的数据包时，由于没有找到对应的MAC地址进而先发送的ARP request报文
 *        此时，收到了该request的应答报文。然后，根据IP地址来查找ARM表项，如果能找到该IP地址对应的MAC地址，
 *        则将缓存的数据包arp_buf再发送到ethernet层。
 * 
 *        如果arp_buf无效，还需要判断接收到的报文是否为request请求报文，并且，该请求报文的目的IP正好是本机的IP地址，
 *        则认为是请求本机MAC地址的ARP请求报文，则回应一个响应报文（应答报文）。
 *        响应报文：需要调用buf_init初始化一个buf，填写ARP报头，目的IP和目的MAC需要填写为收到的ARP报的源IP和源MAC。
 * 
 * @param buf 要处理的数据包
 */
void arp_in(buf_t *buf)
{
    // TODO
    // UDP实验新增
    // 将eth帧头加回来
    buf_add_header(buf,14);
    uint8_t *p=buf->data;
    if(p[12]==0x08 && p[13]==0x00){//p此时指向以太网帧头
        //为IP
        //printf("仅供测试使用，表示收到ip也更新了arp_table\n");
        if(arp_lookup(p+14+12) == NULL)
            arp_update(p+14+12,p+6,ARP_VALID);
        buf_remove_header(buf,14);
        return;
    }
    buf_remove_header(buf,14);
    //以下为原有
    p = buf->data;
    //p指向data
    //p[0]~p[7]为ARP报头
    //p[8]~p[13]为源MAC
    //p[14]~p[17]为源IP
    //p[18]~p[23]为目的MAC
    //p[24]~p[27]为目的IP
    //硬件类型
    if(!(p[0]==0x00 && p[1]==0x01))
        return;
    //上层协议类型
    if(!(p[2]==0x08 && p[3]==0x00))
        return;
    //mac地址长度
    if(!(p[4]==0x06))
        return;
    //协议地址长度
    if(!(p[5]==0x04))
        return;    
    //更新
    arp_update(p+14,p+8,ARP_VALID);
    //操作类型    
    //应答报文
    if(p[6]==0x00 && p[7]==0x02){
        //更新ARP表项
        //查看arp_buf是否有效
        if(arp_buf.valid==1){
            //如果有效，则把buf发送，并将valid置为0
            arp_buf.valid=0;
            arp_out(&(arp_buf.buf),arp_buf.ip,arp_buf.protocol);
            return;
        }
    }
    //request请求报文
    if(p[6]==0x00 && p[7]==0x01){
        for(int i=0;i<4;i++){
            //判断请求报文请求IP的是不是本机IP
            if(!(p[24+i]==net_if_ip[i])){
                return;
            }
                
        }
        //如果请求报文请求的IP是本机IP
        //则发送响应报文
        buf_init(&txbuf,28);
        uint8_t *p2 = txbuf.data;
        //硬件类型
        p2[0]=0x00;
        p2[1]=0x01;            
        //上层协议类型
        p2[2]=0x08;
        p2[3]=0x00;
        //MAC地址长度
        p2[4]=0x06;
        //IP协议地址长度
        p2[5]=0x04;
        //操作类型
        p2[6]=0x00;
        p2[7]=0x02;
        //源MAC地址
        for(int i=0;i<6;i++){
            p2[8+i]=net_if_mac[i];
        }
        //源IP地址
        for(int i=0;i<4;i++){
            p2[14+i]=net_if_ip[i];
        }
        //目的MAC地址
        for(int i=0;i<6;i++){
            p2[18+i]=p[8+i];
        }
        //目的IP地址
        for(int i=0;i<4;i++){
            p2[24+i]=p[14+i];
        }
        ethernet_out(&txbuf,p+8,NET_PROTOCOL_ARP);    
    }
    

}

/**
 * @brief 处理一个要发送的数据包
 *        你需要根据IP地址来查找ARP表
 *        如果能找到该IP地址对应的MAC地址，则将数据报直接发送给ethernet层
 *        如果没有找到对应的MAC地址，则需要先发一个ARP request报文。
 *        注意，需要将来自IP层的数据包缓存到arp_buf中，等待arp_in()能收到ARP request报文的应答报文
 * 
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void arp_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    // TODO
    //查找ARP表
    uint8_t *mac = arp_lookup(ip);
    //找到了IP对于的MAC
    if(mac){
        ethernet_out(buf,mac,protocol);
    }else{//没找到
        //将该报文放到buf中，并将buf的valid置为1
        arp_buf.valid=1;
        arp_buf.protocol=protocol;
        for(int i=0;i<4;i++)
            arp_buf.ip[i]=ip[i];
        arp_buf.buf=*buf;
        arp_req(ip);
    }
}

/**
 * @brief 初始化arp协议
 * 
 */
void arp_init()
{
    for (int i = 0; i < ARP_MAX_ENTRY; i++)
        arp_table[i].state = ARP_INVALID;
    arp_buf.valid = 0;
    arp_req(net_if_ip);
}