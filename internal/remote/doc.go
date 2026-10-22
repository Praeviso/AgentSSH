// Package remote holds the wire contract shared by the AgentSSH client and its
// control planes (agentssh-server, agentssh-gateway): API messages, enrollment
// tokens, the signed configuration bundle, managed-inventory rules, and the
// parser that limits remote signing to SSH publickey user-authentication data.
package remote
