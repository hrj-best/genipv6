package genipv6

import (
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

// 初始化插件
func init() {
	plugin.Register("genipv6", setup)
}

// setup 函数用于注册插件
func setup(c *caddy.Controller) error {
	genIPv6 := GenIPv6{}

	// 插入插件到 CoreDNS 处理链
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		genIPv6.Next = next
		return genIPv6
	})

	return nil
}
