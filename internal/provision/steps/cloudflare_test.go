package steps

import (
	"strings"
	"testing"
)

func TestRenderCloudflareConf(t *testing.T) {
	b, err := renderCloudflareConf()
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	if !strings.HasPrefix(out, "# managed by berth") {
		t.Error("cloudflare conf must carry the managed marker")
	}
	if !strings.Contains(out, "real_ip_header CF-Connecting-IP;") {
		t.Error("must set real_ip_header to CF-Connecting-IP")
	}
	if !strings.Contains(out, "geo $realip_remote_addr $berth_cloudflare {") {
		t.Error("must define the geo map keyed on $realip_remote_addr")
	}
	if len(cloudflareIPRanges) != 22 {
		t.Fatalf("expected 22 Cloudflare ranges (15 IPv4 + 7 IPv6), got %d", len(cloudflareIPRanges))
	}
	var v4, v6 int
	seen := map[string]bool{}
	for _, c := range cloudflareIPRanges {
		if seen[c] {
			t.Errorf("duplicate range %s", c)
		}
		seen[c] = true
		if strings.Contains(c, ":") {
			v6++
		} else {
			v4++
		}
	}
	if v4 != 15 || v6 != 7 {
		t.Errorf("expected 15 IPv4 + 7 IPv6 ranges, got %d v4 / %d v6", v4, v6)
	}
	for _, cidr := range cloudflareIPRanges {
		if !strings.Contains(out, "set_real_ip_from "+cidr+";") {
			t.Errorf("missing set_real_ip_from for %s", cidr)
		}
		if !strings.Contains(out, "    "+cidr+" 1;") {
			t.Errorf("missing geo entry for %s", cidr)
		}
	}
}
