package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/phayes/freeport"
	"github.com/skratchdot/open-golang/open"
	"golang.org/x/oauth2"
)

var version = "2.0.0"
var alphabet = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func init() {
	rand.Seed(time.Now().UnixNano())
}

func main() {
	var listenHost = flag.String("callback-host", "localhost", "Callback URL hostname")
	var listenPort = flag.Int("callback-port", -1, "Callback URL local port (-1 means pick a free port)")
	var listenUri = flag.String("callback-uri", "/implicit/callback", "Callback URL path")

	var issuerURL = flag.String("issuer", "", "Issuer URL")
	var clientID = flag.String("client-id", "", "Client ID")
	var clientSecret = flag.String("client-secret", "", "Client Secret")
	var scopes = flag.String("scopes", "email,groups,offline_access,profile", "Comma separated scopes to request")

	var openBrowser = flag.Bool("open-browser", true, "Launch the default browser (false means just print the URL)")
	var credentialName = flag.String("set-credentials", "", "If name of credentials is set, kubeoidc configures credentials by executing kubectl")

	var versionMode = flag.Bool("version", false, "Show version (and exit)")
	flag.Parse()

	if *versionMode {
		fmt.Printf("kubeoidc v%s\n", version)
		return
	}

	var port int
	if listenPort != nil && *listenPort != -1 {
		port = *listenPort
	} else {
		freePort, err := freeport.GetFreePort()
		if err != nil {
			log.Fatal(err)
		}
		port = freePort
	}

	server, err := newServer(
		*issuerURL,
		*clientID,
		*clientSecret,
		fmt.Sprintf("http://%s:%d%s", *listenHost, port, *listenUri),
		*credentialName,
		strings.Split(*scopes, ","),
	)

	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc(*listenUri, server.handleCallback)

	listen := fmt.Sprintf("%s:%d", *listenHost, port)
	log.Printf("INFO: Listening %s", listen)
	go func() {
		log.Fatal(http.ListenAndServe(listen, nil))
	}()

	url := server.authURL()
	if *openBrowser {
		log.Printf("INFO: Opening %s", url)
		if err := open.Start(url); err != nil {
			log.Fatal(err)
		}
	} else {
		fmt.Printf("url: %s\n", url)
	}
	server.wait()
}

type server struct {
	oauth2   oauth2.Config
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	waitCh   chan struct{}
	isGoogle bool

	issuerURL      string
	clientID       string
	clientSecret   string
	redirectURL    string
	state          string
	credentialName string
}

func newState() string {
	b := make([]rune, 64)
	for i := range b {
		b[i] = alphabet[rand.Intn(len(alphabet))]
	}
	return string(b)
}

func newServer(issuerURL, clientID, clientSecret, redirectURL, credentialName string, oidcScopes []string) (*server, error) {
	if issuerURL == "" {
		return nil, fmt.Errorf("issuerURL is a required parameter")
	}
	if clientID == "" {
		return nil, fmt.Errorf("clientID is a required parameter")
	}
	if clientSecret == "" {
		return nil, fmt.Errorf("clientSecret is a required parameter")
	}
	if redirectURL == "" {
		return nil, fmt.Errorf("redirectURL is a required parameter")
	}
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, err
	}

	// google does not tolerate "groups" or "offline_access"
	// they have their own peoplev1 specific scopes for obtaining groups
	// and the offline_access needs to be a separate query param
	// https://developers.google.com/identity/protocols/OpenIDConnect#scope-param
	isGoogle := strings.Index(issuerURL, "https://accounts.google.com") == 0
	scopes := []string{oidc.ScopeOpenID}
	scopes = append(scopes, oidcScopes...)

	oauth2Config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopes,
	}

	idTokenVerifier := provider.Verifier(&oidc.Config{ClientID: clientID})

	return &server{
		provider:       provider,
		oauth2:         oauth2Config,
		verifier:       idTokenVerifier,
		isGoogle:       isGoogle,
		issuerURL:      issuerURL,
		clientID:       clientID,
		clientSecret:   clientSecret,
		redirectURL:    redirectURL,
		credentialName: credentialName,
		state:          newState(),
		waitCh:         make(chan struct{}),
	}, nil
}

func (s *server) authURL() string {
	opts := make([]oauth2.AuthCodeOption, 0)
	if s.isGoogle {
		opts = append(opts, oauth2.AccessTypeOffline)
	}
	return s.oauth2.AuthCodeURL(s.state, opts...)
}

func (s *server) handleCallback(w http.ResponseWriter, r *http.Request) {
	err := s._handleCallback(w, r)
	if err != nil {
		log.Printf("ERROR: %s", err)
		w.WriteHeader(500)
	}

	s.waitCh <- struct{}{}
}

func (s *server) _handleCallback(w http.ResponseWriter, r *http.Request) error {
	query := r.URL.Query()
	state := query.Get("state")
	if s.state != state {
		return errors.New("state paremeter mismatch")
	}
	if errorParam := query.Get("error"); errorParam != "" {
		if errorDesc := query.Get("error_description"); errorDesc != "" {
			return fmt.Errorf("%s: %s", errorParam, errorDesc)
		}
		return fmt.Errorf("%s", errorParam)
	}
	oauth2Token, err := s.oauth2.Exchange(context.Background(), query.Get("code"))
	if err != nil {
		return err
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return errors.New("id_token is not a string")
	}

	idToken, err := s.verifier.Verify(context.Background(), rawIDToken)
	if err != nil {
		return err
	}

	var c json.RawMessage
	if err := idToken.Claims(&c); err != nil {
		return err
	}
	log.Printf("%s", c)

	var claims struct {
		Email string `json:"email"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return err
	}

	if s.credentialName == "" {
		fmt.Printf(`---
# Add the following to ~/.kube/config
users:
- name: '%s'
  user:
    auth-provider:
      config:
        client-id: '%s'
        client-secret: '%s'
        id-token: '%s'
        idp-issuer-url: '%s'
        refresh-token: '%s'
      name: oidc
`, claims.Email, s.clientID, s.clientSecret, rawIDToken, s.issuerURL, oauth2Token.RefreshToken)
	} else {
		err := exec.Command("kubectl", "config", "set-credentials", s.credentialName,
			"--auth-provider=oidc",
			fmt.Sprintf("--auth-provider-arg=client-id=%s", s.clientID),
			fmt.Sprintf("--auth-provider-arg=client-secret=%s", s.clientSecret),
			fmt.Sprintf("--auth-provider-arg=id-token=%s", rawIDToken),
			fmt.Sprintf("--auth-provider-arg=idp-issuer-url=%s", s.issuerURL),
			fmt.Sprintf("--auth-provider-arg=refresh-token=%s", oauth2Token.RefreshToken),
		).Run()
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Executed `kubectl config set-credentials %s ...`", s.credentialName)
	}

	w.WriteHeader(200)
	fmt.Fprint(w, "Done. Please go back to the terminal.\n")

	return nil
}

func (s *server) wait() {
	<-s.waitCh
	time.Sleep(time.Second)
}
