package remoteserver

import (
	"encoding/json"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/remote"
)

func TestStatusReportsManagedMode(t *testing.T) {
	f := newHTTPSFixture(t)
	id := f.device(t)
	w := serve(f.handler, f.request(t, "GET", remote.PathStatus, id, remote.DeviceSignatureTag, nil))
	var status remote.StatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil || w.Code != 200 {
		t.Fatalf("status: %d %s", w.Code, w.Body.String())
	}
	if status.Mode != remote.ModeManaged || status.DeviceID != id {
		t.Fatalf("status = %+v, want managed mode for %s", status, id)
	}
}
