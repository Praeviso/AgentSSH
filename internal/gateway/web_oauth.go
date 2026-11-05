package gateway

import (
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/remote"
)

// oauthRequest validates the client's query on both GET and POST. Neither
// a hidden field nor a device's credential can supply the operator's consent.
func (w *WebUI) oauthRequest(rw http.ResponseWriter, r *http.Request) (AuthorizationRequest, bool) {
	if w.OAuth == nil {
		http.NotFound(rw, r)
		return AuthorizationRequest{}, false
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		http.Error(rw, "malformed authorization request", http.StatusBadRequest)
		return AuthorizationRequest{}, false
	}
	req, err := ParseAuthorization(w.Store, *w.OAuth, query)
	if err == nil {
		allowOAuthCallback(rw, req.RedirectURI)
		return req, true
	}
	var refused *AuthorizationError
	if errors.As(err, &refused) {
		if refused.Redirect != "" {
			allowOAuthCallback(rw, refused.Redirect)
			http.Redirect(rw, r, refused.Redirect, http.StatusSeeOther)
		} else {
			http.Error(rw, refused.Description, http.StatusBadRequest)
		}
	} else {
		storageError(rw, "Client authorization is temporarily unavailable. Reload this page; if this continues, ask a gateway administrator to check storage.", "authorization store unavailable", err)
	}
	return AuthorizationRequest{}, false
}

// Browsers apply form-action to the redirect after a form POST too. Allow
// this validated callback's origin on the consent response; other pages keep
// the default self-only policy. Escape host characters that have CSP meaning
// (notably semicolons and wildcards), retaining IPv6 and explicit ports.
func allowOAuthCallback(rw http.ResponseWriter, callback string) {
	u, _ := url.Parse(callback)
	host := url.QueryEscape(u.Host)
	host = strings.NewReplacer("%3A", ":", "%5B", "[", "%5D", "]").Replace(host)
	origin := u.Scheme + "://" + host
	csp := rw.Header().Get("Content-Security-Policy")
	rw.Header().Set("Content-Security-Policy", strings.Replace(csp, "form-action 'self';", "form-action 'self' "+origin+";", 1))
}

func (w *WebUI) oauthPage(rw http.ResponseWriter, r *http.Request, session WebSession, _ string) {
	if req, ok := w.oauthRequest(rw, r); ok {
		w.renderOAuth(rw, r, session, req, http.StatusOK, "")
	}
}

func (w *WebUI) renderOAuth(rw http.ResponseWriter, r *http.Request, session WebSession, req AuthorizationRequest, status int, message string) {
	devices, err := w.Store.Devices()
	if err != nil {
		storageError(rw, "Devices for client authorization are temporarily unavailable. Reload this page; if this continues, ask a gateway administrator to check storage.", "device store unavailable", err)
		return
	}
	var choices []deviceView
	for _, device := range devices {
		if DeviceKind(device) != remote.DeviceKindToken || device.Status == remote.DeviceRevoked {
			continue
		}
		a, err := DeviceActivation(w.Store, device.ID)
		if err != nil {
			storageError(rw, "Device activation details for client authorization are temporarily unavailable. Reload this page; if this continues, ask a gateway administrator to check storage.", "activation state unavailable", err)
			return
		}
		choices = append(choices, deviceView{Device: device, Active: a.Active(activationNow())})
	}
	w.render(rw, status, "oauth", map[string]any{
		"Title": "Authorize client", "Nav": "devices", "CSRF": session.CSRF, "Operator": session.Operator.Name,
		"Request": req, "Devices": choices, "Resource": w.OAuth.Resource, "Error": message,
		"Action": remote.PathOAuthAuthorize + "?" + r.URL.RawQuery,
	})
}

func (w *WebUI) consentOAuth(rw http.ResponseWriter, r *http.Request, session WebSession, _ string) {
	req, ok := w.oauthRequest(rw, r)
	if !ok {
		return
	}
	switch r.PostFormValue("decision") {
	case "deny":
		http.Redirect(rw, r, Deny(*w.OAuth, req), http.StatusSeeOther)
	case "authorize":
		id := r.PostFormValue("device")
		if id == "" {
			w.renderOAuth(rw, r, session, req, http.StatusBadRequest, "Choose the token device this client may use.")
			return
		}
		redirect, _, err := Authorize(w.Dir, w.Store, *w.OAuth, req, id, operatorLabel(session.Operator.Name), w.now())
		if errors.Is(err, controlplane.ErrNotFound) || errors.Is(err, ErrNotTokenDevice) || errors.Is(err, controlplane.ErrDeviceRevoked) {
			w.renderOAuth(rw, r, session, req, http.StatusBadRequest, "That client or device is no longer available. Choose an available token device, or restart the connection.")
			return
		}
		if err != nil {
			storageError(rw, "Could not confirm client authorization. Check the device's grants before trying again; if this continues, ask a gateway administrator to check storage and the audit log.", "authorization recording error", err)
			return
		}
		http.Redirect(rw, r, redirect, http.StatusSeeOther)
	default:
		w.renderOAuth(rw, r, session, req, http.StatusBadRequest, "Choose Authorize or Deny.")
	}
}

func (w *WebUI) revokeOAuthGrant(rw http.ResponseWriter, r *http.Request, session WebSession, _ string) {
	grant, err := loadGrant(w.Store.DB(), r.PathValue("grant"))
	if errors.Is(err, controlplane.ErrNotFound) || err == nil && grant.DeviceID != r.PathValue("id") {
		http.NotFound(rw, r)
		return
	}
	if err != nil {
		storageError(rw, "Client access details are temporarily unavailable. Reload Devices before trying again; if this continues, ask a gateway administrator to check storage.", "OAuth grant store unavailable", err)
		return
	}
	revoked, err := RevokeGrant(w.Dir, w.Store, grant.ID, operatorLabel(session.Operator.Name), w.now())
	if isAuditPending(err) {
		backToDevices(rw, r, "error", "The grant is revoked; its tokens are refused and audit repair is pending.")
		return
	}
	if err != nil {
		log.Printf("agentssh-gateway: web: revoke OAuth grant: %v", err)
		backToDevices(rw, r, "error", "Could not confirm revocation. Reload Devices and check the grant's state before trying again; if this continues, ask a gateway administrator to check storage and the audit log.")
		return
	}
	if !revoked {
		backToDevices(rw, r, "notice", "This client's grant was already revoked.")
		return
	}
	backToDevices(rw, r, "notice", "Revoked access for "+grant.ClientName+". Its tokens are refused from its next request.")
}
