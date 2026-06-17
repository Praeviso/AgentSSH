package hostform

import "testing"

func TestValidateNormalizesHostFields(t *testing.T) {
	t.Setenv("USER", "alice")
	result, errs := Validate(Options{
		Name: " web-1 ",
		Addr: " 10.0.0.11 ",
		Tags: []string{"web", "prod"},
	})
	if len(errs) != 0 {
		t.Fatalf("errs = %#v", errs)
	}
	if result.Name != "web-1" || result.Addr != "10.0.0.11" || result.User != "alice" || result.Port != 22 {
		t.Fatalf("result = %#v", result)
	}
	if got := result.Tags; len(got) != 2 || got[0] != "web" || got[1] != "prod" {
		t.Fatalf("tags = %#v", got)
	}
}

func TestValidateAllowsAliasWithoutAddr(t *testing.T) {
	result, errs := Validate(Options{Name: "web-1", Alias: "prod-web"})
	if len(errs) != 0 {
		t.Fatalf("errs = %#v", errs)
	}
	if result.Alias != "prod-web" || result.Addr != "" {
		t.Fatalf("result = %#v", result)
	}
}

func TestValidateRejectsInvalidFields(t *testing.T) {
	existing := map[string]struct{}{"web-1": {}}
	tests := []struct {
		name string
		opts Options
		key  string
	}{
		{name: "missing name", opts: Options{Addr: "10.0.0.11"}, key: "name"},
		{name: "whitespace name", opts: Options{Name: "web 1", Addr: "10.0.0.11"}, key: "name"},
		{name: "duplicate", opts: Options{Name: "web-1", Addr: "10.0.0.11", ExistingNames: existing}, key: "name"},
		{name: "missing addr and alias", opts: Options{Name: "web-2"}, key: "addr"},
		{name: "bad port", opts: Options{Name: "web-2", Addr: "10.0.0.12", Port: 70000}, key: "port"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, errs := Validate(tt.opts)
			if errs[tt.key] == "" {
				t.Fatalf("errs[%q] = %#v", tt.key, errs)
			}
		})
	}
}

func TestSplitTags(t *testing.T) {
	got := SplitTags(" web,prod,, db ")
	want := []string{"web", "prod", "db"}
	if len(got) != len(want) {
		t.Fatalf("tags = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("tags = %#v, want %#v", got, want)
		}
	}
}
