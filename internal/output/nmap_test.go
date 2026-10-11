package output

import (
	"bytes"
	"strings"
	"testing"

	"bunyip/internal/nmap"
)

func TestOSComponentsListedOnce(t *testing.T) {
	h := nmap.HostReport{Address: "192.0.2.30"}
	for _, port := range []int{135, 139, 389, 445, 593, 636, 3268, 3269, 3389, 5985, 9389, 47001, 49664, 49665, 49666} {
		h.Services = append(h.Services, nmap.ServiceReport{Port: port, Protocol: "tcp", Service: "msrpc",
			Assessment: nmap.OSComponent, Notes: []string{"Windows component: covered by ..."}})
	}
	h.Services = append(h.Services, nmap.ServiceReport{Port: 1433, Protocol: "tcp", Service: "ms-sql-s",
		Assessment: nmap.Unidentified, Notes: []string{"not in the curated product-name map"}})
	var buf bytes.Buffer
	if err := WriteNmapText(&buf, &nmap.Report{Hosts: []nmap.HostReport{h}}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	// No Windows build was seen at all: say how to get one.
	if !strings.Contains(out, "Windows components, not assessed: no Windows build in the scan (run with -sC):") {
		t.Errorf("label:\n%s", out)
	}
	if strings.Count(out, "Windows component") != 1 || strings.Contains(out, "covered by ...") {
		t.Errorf("components repeated:\n%s", out)
	}
	if !strings.Contains(out, "135/tcp msrpc, 139/tcp msrpc") || !strings.Contains(out, "49666/tcp msrpc") {
		t.Errorf("ports missing:\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "/tcp msrpc") && len(line) > 100 || strings.Contains(line, "Windows components") && len(line) > 100 {
			t.Errorf("line not wrapped (%d): %q", len(line), line)
		}
	}
	// Lines break between entries, not inside one.
	for _, line := range strings.Split(out, "\n") {
		if strings.HasSuffix(line, "/tcp") || strings.HasPrefix(strings.TrimSpace(line), "msrpc") {
			t.Errorf("entry split across lines: %q", line)
		}
	}
	// Other services are still printed individually.
	if !strings.Contains(out, "  1433/tcp ms-sql-s") {
		t.Errorf("other service missing:\n%s", out)
	}
}
