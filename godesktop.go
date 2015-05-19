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


// Returned codes : 

// 401 - not authenticated (back-end reachable but user not authenticated --> authenticate first)
// 500 - internal error : golang part failed in something
// 502 - bad gateway : back-end service bug triggered (back-end reachable but the action has triggered a bug, so a bad response --> retry with different request)
// 503 - service unavailable : (back-end service not reachable ----> check your connection or check that back-end is not down)
// 200 or any other - Not the above

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
		//fmt.Println("\nCookie : ", cookie.Name, " - ", cookie.Value, " - ", cookie.Domain, " - ", cookie.Path )
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

func requestAuthentication( user string, pass string, loginUrl string ) ( cookie *http.Cookie, status_code int) {

    sessionId := new (http.Cookie)
	response_get_token, err := http.Get(loginUrl)
	if err != nil {
		fmt.Println("ERROR IN THE INITIAL!!!!!")
        return sessionId, 503
    }

    csrf_token, err := getCookieOfType( "csrftoken", response_get_token.Cookies())
	if err != nil {
		fmt.Println("SERVER UNREACHABLE!!!!!")
        return sessionId, 502
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
        return sessionId, 503
    }

	sessionId, err = getCookieOfType( "sessionid", CookieJar.Cookies(globalServerUrl))
	if err != nil{
		fmt.Println("ERROR IN session extraction !!!! !!!!!")
        return sessionId, 401
    }

	return sessionId, 200
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

		sessionId, status_code := requestAuthentication( u.User, u.Pass, globalServerUrlString + "/accounts/login/?next=/ping" )
		if status_code != 200{
        	fmt.Println("\n::::::: MMMMM .... Also trying to establish it failed. I am quite in trouble. - Returning\n", status_code)
        	w.WriteHeader(status_code)
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
 		if( err != nil ){
 			w.WriteHeader(503)
 			return
 		}

 		// TODO : HERE I SHOULD COPY THE RETURN STATUS CODE, OTHERWISE IT RETURNS 200 WHEN IT SHOULD RETURN 404 OR OTHER
		if ( r.Status == "200 OK" ){
			copy_headers(w, r)
			defer r.Body.Close()
			body, _ := ioutil.ReadAll(r.Body)
			w.Write(body) 	
		}else{
			w.WriteHeader(r.StatusCode)
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
    	fmt.Println("::::::: ERROR calling this API. Returning 503 \n\n\n")
    	w.WriteHeader(503)
    	return
    }

    w.WriteHeader(r.StatusCode)
    copy_headers(w, r)
	defer r.Body.Close()
	body, _ = ioutil.ReadAll(r.Body)
	w.Write(body)	
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