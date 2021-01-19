#include "ethernet.h"
#include "utils.h"
#include "driver.h"
#include "arp.h"
#include "ip.h"
#include <string.h>
#include <stdio.h>

/**
 * @brief 处理一个收到的数据包
 *        你需要判断以太网数据帧的协议类型，注意大小端转换
 *        如果是ARP协议数据包，则去掉以太网包头，发送到arp层处理arp_in()
 *        如果是IP协议数据包，则去掉以太网包头，发送到IP层处理ip_in()
 * 
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf)
{
    // TODO
    uint8_t *p; 
    p = buf->data;
    p+=12;
    if(p[0]==0x08 && p[1]==0x00){
        //IP
        buf_remove_header(buf,14);
        //下面一行为UDP实验新增的
        arp_in(buf);
        ip_in(buf);
    }else if(p[0]==0x08 && p[1]==0x06){
        //ARP
        buf_remove_header(buf,14);
        arp_in(buf);
    }
    
}

/**
 * @brief 处理一个要发送的数据包
 *        你需添加以太网包头，填写目的MAC地址、源MAC地址、协议类型
 *        添加完成后将以太网数据帧发送到驱动层
 * 
 * @param buf 要处理的数据包
 * @param mac 目标ip地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol)
{
    // TODO
    buf_add_header(buf,14);
    uint8_t *p1,*p2;
    p1 = buf->data;
    for(int i = 0;i<6;i++){
        *p1++ =*mac++;
    }
    uint8_t mac_addr[6] = DRIVER_IF_MAC;
    p2 = mac_addr;
    for(int i=0;i<6;i++){
        *p1++ = *p2++;
    }
    uint16_t type = (int16_t)protocol;
    uint8_t a = (uint8_t)type;
    uint8_t b = (uint8_t)(type>>8);
    *p1++=b;
    *p1=a;
    driver_send(buf); 
}

/**
 * @brief 初始化以太网协议
 * 
 * @return int 成功为0，失败为-1
 */
int ethernet_init()
{
    buf_init(&rxbuf, ETHERNET_MTU + sizeof(ether_hdr_t));
    return driver_open();
}

/**
 * @brief 一次以太网轮询
 * 
 */
void ethernet_poll()
{
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}
