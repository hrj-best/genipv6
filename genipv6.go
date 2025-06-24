package genipv6

import (
	"context"
	"crypto/sha256"
	"net"
	"strings"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

// GenIPv6 插件结构
type GenIPv6 struct {
	Next plugin.Handler
}

// ServeDNS 处理 DNS 查询
func (g GenIPv6) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}

	// 解析客户端 IPv6
	clientIP := net.ParseIP(state.IP()).To16()
	if clientIP == nil {
		return dns.RcodeServerFailure, nil
	}

	// 解析查询的域名，并转换为 ASCII
	domain := strings.TrimSuffix(state.Name(), ".") // 去掉末尾的点
	if domain != "hrjdns.asia" && domain != "qazdns.asia" {
    		w.WriteMsg(r)
		return dns.RcodeSuccess, nil
	}
	domainBytes := []byte(domain)                   // 直接获取域名的二进制 ASCII 字节
	salt := []byte{0xc2, 0x0b, 0x8d, 0x3d, 0xcd, 0xd4, 0x21, 0x27}
	
	// 生成 SHA-256 哈希
	userInput := append(clientIP, domainBytes...) // 拼接 [用户 IP (16 字节) | 域名 ASCII]
	hashInput := append(userInput, salt...)
	hash := sha256.Sum256(hashInput)              // 计算哈希

	// 取哈希的后 64 位
	newSuffix := hash[24:] // 取哈希值的最后 8 字节（64 位）

	// 遍历 Answer 部分，找到 AAAA 记录
	hasAAAA := false
	for _, ans := range r.Answer {
		if aaaaRecord, ok := ans.(*dns.AAAA); ok {
			hasAAAA = true
			// 保留前 64 位
			newIPv6 := make([]byte, 16)
			copy(newIPv6[:8], aaaaRecord.AAAA[:8])

			// 替换后 64 位
			copy(newIPv6[8:], newSuffix)

			// 修改 AAAA 记录
			aaaaRecord.AAAA = net.IP(newIPv6)
		}
	}

	// 如果没有 AAAA 记录，返回错误
	if !hasAAAA {
		return dns.RcodeServerFailure, nil
	}

	// 直接返回修改后的响应
	w.WriteMsg(r)
	return dns.RcodeSuccess, nil
}

// Name 返回插件名称
func (g GenIPv6) Name() string {
	return "genipv6"
}
