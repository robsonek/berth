package steps

import "github.com/robsonek/berth/internal/templates"

// cloudflareConfPath is the global http-context snippet berth writes when any
// site enables cloudflare_only: it restores the real client IP from
// CF-Connecting-IP and defines the $berth_cloudflare geo flag the per-site
// guards test. Lives in conf.d so both supported nginx sources load it (their
// nginx.conf includes /etc/nginx/conf.d/*.conf in the http context).
const cloudflareConfPath = "/etc/nginx/conf.d/berth-cloudflare.conf"

// cloudflareIPRanges are Cloudflare's published edge IP ranges, snapshot
// 2026-06-20. Source: https://www.cloudflare.com/ips-v4 and
// https://www.cloudflare.com/ips-v6. These ranges are extremely stable (the v4
// list has been unchanged for years); refresh on release if Cloudflare publishes
// a change. A baked snapshot keeps the render byte-identical (idempotent) and
// free of any provision-time network dependency.
var cloudflareIPRanges = []string{
	// IPv4
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	// IPv6
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
	"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
}

// renderCloudflareConf renders the managed http-context geo/realip snippet.
func renderCloudflareConf() ([]byte, error) {
	return templates.Render("cloudflare.conf.tmpl", struct{ Ranges []string }{cloudflareIPRanges})
}
