#include "icmp.h"
#include "ip.h"
#include <string.h>
#include <stdio.h>

int flag = 0;

/**
 * @brief 处理一个收到的数据包
 *        你首先要检查buf长度是否小于icmp头部长度
 *        接着，查看该报文的ICMP类型是否为回显请求，
 *        如果是，则回送一个回显应答（ping应答），需要自行封装应答包。
 * 
 *        应答包封装如下：
 *        首先调用buf_init()函数初始化txbuf，然后封装报头和数据，
 *        数据部分可以拷贝来自接收到的回显请求报文中的数据。
 *        最后将封装好的ICMP报文发送到IP层。  
 * 
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip)
{
    // TODO
    // 检查buf长度是否小于icmp头部长度
    if(buf->len < 8)
        return;
    uint8_t *p = buf->data;
    uint16_t *p_16 = (uint16_t *)buf->data;
    //回显请求
    if(p[0]==8 && p[1]==0){
        //回送回显应答
        buf_init(&txbuf,buf->len);
        uint8_t *p2 = txbuf.data;
        uint16_t *p2_16 = (uint16_t *)txbuf.data;
        //TYPE
        p2[0]=0;
        //CODE
        p2[1]=0;
        //标识符
        p2_16[2] = p_16[2];
        //序列号
        p2_16[3] = p_16[3];
        //可选数据
        for(int i=0;i<buf->len-8;i++){
            p2[8+i]=p[8+i];
        }
        //检验和
        p2_16[1] = 0;
        p2_16[1] =checksum16(p2_16,buf->len/2);
        p2_16[1] =swap16(p2_16[1]);
        ip_out(&txbuf,src_ip,NET_PROTOCOL_ICMP);
    }

}

/**
 * @brief 发送icmp不可达
 *        你需要首先调用buf_init初始化buf，长度为ICMP头部 + IP头部 + 原始IP数据报中的前8字节 
 *        填写ICMP报头首部，类型值为目的不可达
 *        填写校验和
 *        将封装好的ICMP数据报发送到IP层。
 * 
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code)
{
    // TODO
    buf_init(&txbuf,8+20+8);
    uint8_t *p = txbuf.data;
    uint16_t *p_16 = (uint16_t *)txbuf.data;
    uint8_t *p2 = recv_buf->data;
    //TYPE
    p[0]=3;
    //code
    p[1] = code;
    //未使用
    p_16[2]=0;
    p_16[3]=0;
    //IP首部+数据报中数据的前8字节
    for(int i=0;i<20+8;i++){
        p[8+i]=p2[i];
    }
    //检验和
    p_16[1]=0;
    p_16[1]=checksum16(p_16,txbuf.len);
    p_16[1]=swap16(p_16[1]);
    ip_out(&txbuf,src_ip,NET_PROTOCOL_ICMP);
    
}

