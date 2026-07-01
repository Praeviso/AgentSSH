// Package approval implements AgentSSH's optional async approval backend.
//
// It is deliberately out-of-band: run requests that need approval return
// immediately, operators adjudicate later, and execution happens only when the
// agent reruns the command through the normal policy path.
package approval
