#include "ip.h"
#include "arp.h"
#include "icmp.h"
#include "udp.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
/**
 * @brief 处理一个收到的数据包
 *        你首先需要做报头检查，检查项包括：版本号、总长度、首部长度等。
 * 
 *        接着，计算头部校验和，注意：需要先把头部校验和字段缓存起来，再将校验和字段清零，
 *        调用checksum16()函数计算头部检验和，比较计算的结果与之前缓存的校验和是否一致，
 *        如果不一致，则不处理该数据报。
 * 
 *        检查收到的数据包的目的IP地址是否为本机的IP地址，只处理目的IP为本机的数据报。
 * 
 *        检查IP报头的协议字段：
 *        如果是ICMP协议，则去掉IP头部，发送给ICMP协议层处理
 *        如果是UDP协议，则去掉IP头部，发送给UDP协议层处理
 *        如果是本实验中不支持的其他协议，则需要调用icmp_unreachable()函数回送一个ICMP协议不可达的报文。
 *          
 * @param buf 要处理的包
 */
void ip_in(buf_t *buf)
{
    // TODO
    // 8位指针
    uint8_t *p = buf->data;
    // 16位指针   使用16位指针时 使用swap16 交换大小端
    uint16_t *p16 = (uint16_t *)buf->data;
    uint8_t a,b;
    a = p[0] >> 4;//a为高4位
    b = p[0] << 4;//b为低4位
    b = b >> 4;
    //版本号
    if(!(a==0x04))
        return;
    //首部长度最大为60B，最小为20B  单位为4B
    if(b < 20/4)
        return;
    //区分服务  最后1位为0
    a = (p[1] << 7) >> 7;
    if(a != 0)
        return;
    //总长度  46~1500
    uint16_t len = p16[1];
    len = swap16(len);
    /*
        之前为if(len>1500||len<46)
    */
    if(len>1500)
        return;
    //首部校验和
    uint16_t check;
    //b单位为4B
    check = checksum16((uint16_t*)buf->data,(int)b*4/2);
    if(check!=0)
        return;
    //目的IP
    for(int i=0;i<4;i++){
        if(p[16+i]!=net_if_ip[i])
            return;
    }
    //源IP
    uint8_t src_ip[4];
    for(int i=0;i<4;i++)
        src_ip[i]=p[12+i];
    if(p[9]==NET_PROTOCOL_ICMP){
        //ICMP
        //b单位为4B
        buf_remove_header(buf,b*4);
        icmp_in(buf,src_ip);
    }else if(p[9]==NET_PROTOCOL_UDP){
        //UDP
        //b单位为4B
        buf_remove_header(buf,b*4);
        udp_in(buf,src_ip);
    }else{
        //printf("调用icmp_unreachable\n");
        icmp_unreachable(buf,src_ip,ICMP_CODE_PROTOCOL_UNREACH);
    }
    
    
}

/**
 * @brief 处理一个要发送的分片
 *        你需要调用buf_add_header增加IP数据报头部缓存空间。
 *        填写IP数据报头部字段。
 *        将checksum字段填0，再调用checksum16()函数计算校验和，并将计算后的结果填写到checksum字段中。
 *        将封装后的IP数据报发送到arp层。
 * 
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf)
{
    // TODO
    buf_add_header(buf,20);
    uint8_t *p = buf->data;
    // 16位指针   使用16位指针时 使用swap16 交换大小端
    uint16_t *p16 = (uint16_t *)buf->data;
    uint8_t a,b;
    //版本0x4和首部长度20/4=5  即0x5
    p[0] = 0x4;
    p[0] = p[0] << 4;
    p[0] += 0x05;
    //区分服务  最后一位为0
    p[1] = 0;
    //总长度  
    p16[1]=buf->len;
    p16[1] = swap16(p16[1]);
    //标识
    p16[2]=(uint16_t)id;
    p16[2] = swap16(p16[2]);

    //标志 总共3位  位1为保留，位2 DF表示禁止分片  位3 MF表示更多分片
    p[6]=0;
    p[6] |= (mf<<5);   
    //片偏移
    p[7]=0;
    offset = swap16(offset);
    p[6] |= offset;
    p[7] |= offset>>8;
    //生存时间
    p[8] = 64;
    //协议
    p[9] = protocol;
    //源IP
    for(int i=0;i<4;i++){
        p[12+i] = net_if_ip[i];
    }
    //目的IP
    for(int i=0;i<4;i++){
        p[16+i] = ip[i];
    }
    //首部校验和
    p16[5] = 0;
    //当做长度为16位的数计算  所以长度为20/2=10
    p16[5] = checksum16((uint16_t*)buf->data,10);
    p16[5] = swap16(p16[5]);
    arp_out(buf,ip,NET_PROTOCOL_IP);
    
}

/**
 * @brief 处理一个要发送的数据包
 *        你首先需要检查需要发送的IP数据报是否大于以太网帧的最大包长（1500字节 - ip包头长度）。
 *        
 *        如果超过，则需要分片发送。 
 *        分片步骤：
 *        （1）调用buf_init()函数初始化buf，长度为以太网帧的最大包长（1500字节 - ip包头头长度）
 *        （2）将数据报截断，每个截断后的包长度 = 以太网帧的最大包长，调用ip_fragment_out()函数发送出去
 *        （3）如果截断后最后的一个分片小于或等于以太网帧的最大包长，
 *             调用buf_init()函数初始化buf，长度为该分片大小，再调用ip_fragment_out()函数发送出去
 *             注意：最后一个分片的MF = 0
 *    
 *        如果没有超过以太网帧的最大包长，则直接调用调用ip_fragment_out()函数发送出去。
 * 
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    // TODO 
    static uint16_t x =0;
    uint8_t* p = buf->data;
    //offset   单位8B
    uint16_t offset=0;
    //检查需要发送的IP数据报是否大于以太网帧的最大包长（1500字节 - ip包头长度）
    while(buf->len>1480){
        buf_init(&txbuf,1480);
        //拷贝数据
        for(int i=0;i<1480;i++){
            (txbuf.data)[i] = p[i];
        }
        //发送分片
        ip_fragment_out(&txbuf,ip,protocol,x,offset,1);
        buf_remove_header(buf,1480);
        p = buf->data;
        //单位为8B 所以/8
        offset += (1480/8);
    }
    ip_fragment_out(buf,ip,protocol,x,offset,0);
    x++;
}
