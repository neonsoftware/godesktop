package godesktop

import (
	"log"
	"os"
    "fmt"
    "net/http"
    "net/url"
	"io/ioutil"
	"strings"
	"bytes"
	"net/http/cookiejar"
	"errors"
	"encoding/json"
)

var Logger *log.Logger = log.New(os.Stdout, "[main] ", log.Lshortfile)


var CookieJar, _ = cookiejar.New(nil)
var Client = &http.Client{
    	Jar: CookieJar,
	}


var globalServerUrlString = ""
var globalServerUrl, _ = url.Parse(globalServerUrlString)



type user_auth_struct struct{
	User string
	Pass string
}


func copy_headers(w http.ResponseWriter, resp *http.Response){
	for k, v := range resp.Header {
        w.Header()[k] = v
    }
}

func getCookieOfType( cookieType string, cookieSlice []*http.Cookie) (cookie *http.Cookie, err error) {

	for _, cookie := range cookieSlice {
		fmt.Println("\nCookie : ", cookie.Name, " - ", cookie.Value, " - ", cookie.Domain, " - ", cookie.Path )
    	if cookie.Name == cookieType {
    		return cookie, nil
        }
	}
    return nil, errors.New("Cookie not found.") 
}


func pingServer() (bool, bool) {

	test_request, err := http.NewRequest("GET", globalServerUrlString + "/ping", nil)
	response, err := Client.Do(test_request)
	
	if (err != nil){
		return false,false
	} 

	isAuthenticated := ( response.Status == "200 OK" )
	isOnline := isAuthenticated || ( response.Status == "401 UNAUTHORIZED"  ) 
	return isOnline, isAuthenticated
}

func requestAuthentication( user string, pass string, loginUrl string ) ( cookie *http.Cookie, err error) {

    sessionId := new (http.Cookie)
	response_get_token, err := http.Get(loginUrl)
	if err != nil {
        return sessionId, err
    }

    csrf_token, err := getCookieOfType( "csrftoken", response_get_token.Cookies())
	if err != nil {
        return sessionId, err
    }

    // Updating the CookieJar for Server URL with just the new csrf_token
	newCookies := [] *http.Cookie{csrf_token}    
    CookieJar.SetCookies(globalServerUrl, newCookies)
	values := make(url.Values)
	values.Set("username", user)
	values.Set("password", pass)                                       
	values.Set("csrfmiddlewaretoken", csrf_token.Value)

	request_get_session, err := http.NewRequest("POST", loginUrl, strings.NewReader(values.Encode()))
	request_get_session.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request_get_session.AddCookie(csrf_token)
	_, err = Client.Do(request_get_session)
	if err != nil{
        return sessionId, err
    }

	sessionId, err = getCookieOfType( "sessionid", CookieJar.Cookies(globalServerUrl))
	if err != nil{
        return sessionId, err
    }

	return sessionId, nil
}

func redirection_to_auth_handler(w http.ResponseWriter, req *http.Request) {

	if ( req.Method == "POST"){

		// Extracting user and password
    	decoder := json.NewDecoder(req.Body)
		var u user_auth_struct
		if decoder.Decode(&u) != nil {
			fmt.Println( "Error decoding !! - Returning 500")
			w.WriteHeader(500)
			return 
		}

		sessionId, err := requestAuthentication( u.User, u.Pass, globalServerUrlString + "/accounts/login/?next=/ping" )
		if err != nil{
        	fmt.Println("\n::::::: MMMMM .... Also trying to establish it failed. I am quite in trouble. - Returning 401\n")
        	w.WriteHeader(401)
    		return
    	}

    	fmt.Println("Returnd SessionID : ", sessionId.Value)
    	w.Header().Set("Content-Type", "application/json")
        fmt.Fprintf(w, "{\"sessionId\" : \"%v\"}", sessionId.Value)
        return
 	}
}

func redirection_to_static_handler(w http.ResponseWriter, req *http.Request) {
	if ( req.Method == "GET"){
		fmt.Println("\n::::::: GET : STATIC FILE : ", req.RequestURI)
 		
 		r, err := http.Get(globalServerUrlString + req.RequestURI)
 		
 		if( err == nil && r.Status == "200 OK" ){
 			copy_headers(w, r)
			defer r.Body.Close()
 			body, _ := ioutil.ReadAll(r.Body)
 			w.Write(body)
 		}else{
 			w.WriteHeader(502)
 		}

 		fmt.Println("\n::::::: END. \n\n\n")
 	}
}

func redirection_to_api_handler(w http.ResponseWriter, req *http.Request) {

	fmt.Println("\n::::::: ", req.Method, " : API : ", req.RequestURI)
	sessionId, err := getCookieOfType( "sessionid", req.Cookies())
	if err != nil{
    	fmt.Println("\n::::::: MMMMM .... There is no session ID in this browser !! Will not be able to access API. Should redirect.  - Returning 401 \n")
		w.WriteHeader(401)
		return
	} 

	defer req.Body.Close()
    body, _ := ioutil.ReadAll(req.Body)
	reqForward, err := http.NewRequest(req.Method, globalServerUrlString + req.RequestURI, bytes.NewBuffer(body))
	reqForward.Header.Set("Content-Type", "application/json")
	reqForward.AddCookie(sessionId)
    r, err := Client.Do(reqForward)

    if err != nil {
    	fmt.Println("::::::: ERROR calling this API. Returning 500 \n\n\n")
    	w.WriteHeader(500)
    	return
    }

    if( r.Status == "200 OK" ){
    	copy_headers(w, r)
		defer r.Body.Close()
		body, _ = ioutil.ReadAll(r.Body)
		w.Write(body)	
    }else{
    	fmt.Println("::::::: Ok ... result is actually not ok. Returning just the status code :  ", r.Status)
		w.WriteHeader(501)
    }

	fmt.Println("::::::: END. \n\n\n")
}


/// Server handlers

func Start( serverName string, wwwDir string ){

	globalServerUrlString = serverName
    globalServerUrl, _ = url.Parse(globalServerUrlString)

	fmt.Println("Starting HTTP Server... at ", wwwDir )
	fmt.Println("Manager : registering handlers")

	http.HandleFunc("/static/", redirection_to_static_handler )
	http.HandleFunc("/accounts/login/", redirection_to_auth_handler )
	http.HandleFunc("/api/", redirection_to_api_handler)
	http.Handle("/", http.StripPrefix("/", http.FileServer(http.Dir(wwwDir))))
	
	listen_at := "127.0.0.1:54007"
	fmt.Printf("Running http server at %s\n", listen_at)
	log.Fatal(http.ListenAndServe(listen_at, nil))
}