package inventory

// Inventory is the parsed inventory.yaml document.
type Inventory struct {
	Version int              `yaml:"version" json:"version"`
	Hosts   map[string]Host  `yaml:"hosts" json:"hosts"`
	Groups  map[string]Group `yaml:"groups" json:"groups"`
}

// Host describes a named SSH target without storing private keys or passwords.
type Host struct {
	Addr           string   `yaml:"addr" json:"addr"`
	User           string   `yaml:"user" json:"user"`
	Port           int      `yaml:"port" json:"port"`
	SSHConfigAlias string   `yaml:"ssh_config_alias" json:"ssh_config_alias"`
	Tags           []string `yaml:"tags" json:"tags"`
}

// Group selects hosts by tag.
type Group struct {
	Tags []string `yaml:"tags" json:"tags"`
}

// Resolver resolves host or group names into concrete SSH targets.
type Resolver interface {
	Resolve(name string) ([]Host, error)
}
