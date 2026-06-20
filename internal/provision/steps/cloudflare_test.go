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
	if len(cloudflareIPRanges) < 20 {
		t.Fatalf("expected the full Cloudflare range list, got %d", len(cloudflareIPRanges))
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
