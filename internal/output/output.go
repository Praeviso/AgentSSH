package output

// FilterResult is the agent-visible output after redaction and truncation.
type FilterResult struct {
	Stdout          string
	Stderr          string
	OutputTruncated bool
	Redactions      int
	SHA256          string
}

// Filter redacts and truncates command output before it is returned to an agent.
type Filter interface {
	Apply(stdout string, stderr string) (FilterResult, error)
}
