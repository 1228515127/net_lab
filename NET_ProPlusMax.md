# 附加实验

为了让**学有余力**的同学对计算机网络协议栈有更深入的了解，我们设计了以下的附加实验。

附加实验仅针对学有余力的同学，没有标准程序作参考，只需要达到实验要求即可；而相应的，实验团队将仅给予**有限的技术支持**。
附加实验需要提交代码及详细的说明文档，文档需要阐述设计思路，展示测试结果，并对具体实验要求进行**逐点说明**。

附加实验将执行**严格的反作弊机制**，对于侦测到的雷同代码不仅不予加分，还可能会影响到基础实验的分数。

## PING

在完成本实验所有实验要求的情况下，实验分加1分（不会超过20分满分）。

在基础实验中，我们实现了ICMP协议的回复和不可达。
在附加实验中，我们希望同学们实现一个主动发起ICMP请求并监听回复的程序，就像PING一样（但是不需要实现PING的DNS解析功能）。
具体实验要求为：

1. 你需要在icmp.h,icmp.c中添加相应的ICMP请求函数，该函数接收一个IP地址作为参数，发起ICMP请求。
2. 你需要在main.c中每隔一秒调用一次ICMP请求函数，至少四次(不要使用sleep，因为这会阻塞主循环，你需要像ARP协议一样判断时间戳)
3. 你需要记录每个ICMP请求的ID和时间戳，并在icmp_in函数中添加对ICMP应答的处理，按照PING的格式进行打印
4. 你需要为每个ICMP请求维护一个生存时间（仿照ARP协议），在超过生存时间后不再继续等待回复，认为其已经超时
5. 你需要在PING执行结束后打印统计信息，报告最小，最大和平均响应时间，及丢包率。

## IP重组

在完成本实验所有实验要求的情况下，实验分加1分（不会超过20分满分）。

在基础实验的网络层，我们实现了IP大包的分片，这是很容易的事情。
但是由于网络环境的复杂性，不同IP包的不同分片可能以乱序到达，同一个IP包的分片可能不等长，部分分片可能丢包。
所以，IP重组是一个复杂的工作，具体的实验要求为：

1. 你可以直接在ip.c的ip_in函数中修改代码，并添加你认为需要添加的其他函数，就像ip_out和ip_fragment_out的关系一样
2. 你需要设计一个数据结构，其可以快速定位并乱序插入单个IP包的不同分片，也能够判断是否已经重组完成
3. 你需要为每个IP包维护一个生存时间（仿照ARP协议），在每次分片到达时更新该时间，在超过生存时间后丢弃整个未完成的IP包，以避免丢包导致的内存泄露
4. 你需要处理多个IP包的分片乱序到达的情况，如A,B两个IP包，各分为两片，到达顺序为A1->B2->B1->A2
5. 你需要处理同一个IP包的分片不等长的情况，这在链路聚合等复杂网络情况下是可能的

## 简易TCP协议

在完成本实验所有实验要求，并且此前完成了所有基础实验的情况下，实验分给予20分满分。

在基础实验的传输层，我们实现了完整的UDP协议，这并不困难。
而另一个在传输层被广泛使用的TCP协议，其完整实现的难度不亚于目前基础实验的整个协议栈。
为了降低难度，我们希望学有余力的同学实现一个简单的TCP协议。
这个简易的协议只需要实现TCP状态转换图中的一个常用的子图，并且不需要实现流量控制机制。
具体的实验要求为：

1. 你需要修改协议栈的结构，添加tcp.c和tcp.h文件，修改net.c的net_init函数（如果你的tcp需要初始化）
2. 你需要实现TCP的双向连接，你的协议既可以作为服务器被动接受连接，也可以作为客户端主动发起连接
3. 你需要实现与上层处理程序交互的过程，可以仿照UDP协议，也可以另辟蹊径
4. 你需要实现TCP三次握手，四次挥手的流程，但错误处理不是必须的，你只需要实现正常的流程
5. 你需要实现拥塞窗口，为了简化实验，其固定大小为4；但注意，实际的发送窗口还需要取决于接收方通告的接收窗口大小
6. 你需要实现接收窗口，并向发送端进行通告，大小也可以为固定的4（在缓冲区未满的情况下）
7. 你需要实现完整的可靠交付机制，包括流式传输，数据包确认，超时重传，这是TCP协议的基础
8. 你的协议至少需要与我们提供的TCP/UDP调试工具在内网中稳定通信，就像UDP协议一样