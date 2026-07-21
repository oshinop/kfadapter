# 快帆新建 TCP隧道的首次大响应会丢失 16 字节

## 问题描述

通过快帆访问下载较大的响应时，新建隧道的首次下行数据可能固定丢失 16 字节。

例如服务器返回：

```http
Content-Length: 9001
```

客户端实际只收到8985 字节

丢失位置固定在解密后数据流的 `8176–8191` 字节。该问题会导致视频黑屏、花屏、播放速度异常；HTTPS 流量通常表现为 TLS 连接失败或重试。

## 复现方法

使用快帆开全局模式连接任意节点，重复执行：

```bash
curl -H 'Range: bytes=0-9000' \
     -H 'Connection: close' \
     -D headers.txt \
     -o body.bin \
     http://speedtest.tele2.net/1MB.zip
wc -c body.bin
```

### 正常结果

```text
Content-Length: 9001
body.bin: 9001
```

### 异常结果

```text
Content-Length: 9001
curl: (18) transfer closed with 16 bytes remaining to read
body.bin: 8985
```

重复执行 8 次通常可以复现。测试使用的深圳直连节点结果为：

```text
正常：3次
丢失16字节：5次
```

## 影响范围

测试 92 个节点：

- 63 个节点至少复现一次；
- 727 个有效响应中，259 个响应丢失 16 字节；
- 5 个节点连续 8 次全部复现。

## 初步原因

疑似服务端首次发送下行数据时使用固定 8192 字节缓冲区，其中 16 字节用于 AES-CFB IV，只加密并发送了前 8176 字节，但错误地消费了全部 8192 字节输入，导致 16 字节未被加密和发送。
