package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
)

const (
	authorizeFormat = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?response_type=code&client_id=%s&redirect_uri=%s&state=%s&prompt=select_account&response_mode=query&scope=%s"
	tokenEndpoint   = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token"
	// scopes for a multi-tenant app works for openid, email, other common scopes, but fails when trying to add a token
	// v1 scope like "https://management.azure.com/.default" for ARM access
	scopes   = "https://management.azure.com/.default"
	clientID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46" // Azure CLI client id
	// clientID = "0c8817d6-7e91-4307-b998-8f453f006481" // third party application I created
)

type (
	Token struct {
		Type         string `json:"token_type"`
		Scope        string `json:"scope"`
		ExpiresIn    int    `json:"expires_in"`
		ExtExpiresIn int    `json:"ext_expires_in"`
		AccessToken  string `json:"access_token"`
		Foci         string `json:"foci"`
	}
)

func main() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	queryCh := make(chan url.Values, 1)
	queryHandler := func(_ http.ResponseWriter, r *http.Request) {
		queryCh <- r.URL.Query()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", queryHandler)
	server := &http.Server{Addr: ":8401", Handler: mux}
	go func() {
		if err := server.ListenAndServe(); err != nil {
			fmt.Println(fmt.Errorf("error starting http server with: %w", err))
			os.Exit(1)
		}
	}()

	state := RandomString("", 10)
	//nonce := RandomString("", 10)
	authUrl := fmt.Sprintf(authorizeFormat, clientID, "http://localhost:8401", state, scopes)
	openbrowser(authUrl)

	select {
	case <-sigs:
		return
	case qsValues := <-queryCh:
		data := url.Values{
			"grant_type":   []string{"authorization_code"},
			"client_id":    []string{clientID},
			"code":         qsValues["code"],
			"scope":        []string{scopes},
			"redirect_uri": []string{"http://localhost:8401"},
		}
		res, err := http.Post(tokenEndpoint, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
		if err != nil {
			fmt.Println(fmt.Errorf("token request failed with: %w", err))
			os.Exit(1)
		}

		bits, err := ioutil.ReadAll(res.Body)
		if err != nil {
			panic(err)
		}

		var token Token
		if err := json.Unmarshal(bits, &token); err != nil {
			panic(err)
		}

		fmt.Printf("Heres my token %+v\n", token)
	}

	_ = server.Shutdown(context.TODO())
}

func openbrowser(url string) {
	var err error

	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}
	if err != nil {
		log.Fatal(err)
	}
}
