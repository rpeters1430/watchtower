package main

import (
 "crypto/sha256"
 "crypto/subtle"
 "embed"
 "encoding/json"
 "io"
 "log"
 "net/http"
 "net/url"
 "regexp"
 "os"
 "strings"
 "time"
)

//go:embed static/* build-info.json
var assets embed.FS

func env(name, fallback string) string { if v:=os.Getenv(name);v!="" { return v }; return fallback }

type buildInfo struct {
 Version string `json:"version"`
 Revision string `json:"revision"`
 Notes string `json:"notes"`
}

func readBuildInfo(read func(string) ([]byte, error)) buildInfo {
 data, err := read("build-info.json")
 if err != nil { return buildInfo{} }
 var raw map[string]any
 if json.Unmarshal(data, &raw) != nil { return buildInfo{} }
 info := buildInfo{}
 if value, ok := raw["version"].(string); ok { info.Version = value }
 if value, ok := raw["revision"].(string); ok { info.Revision = value }
 if value, ok := raw["notes"].(string); ok { info.Notes = value }
 return info
}

func basicAuthenticator(username, password string) func(http.ResponseWriter, *http.Request) bool {
 return func(w http.ResponseWriter, r *http.Request) bool {
  u, p, ok := r.BasicAuth()
  expectedUser := sha256.Sum256([]byte(username)); userHash := sha256.Sum256([]byte(u))
  expectedPass := sha256.Sum256([]byte(password)); passHash := sha256.Sum256([]byte(p))
  if !ok || subtle.ConstantTimeCompare(userHash[:], expectedUser[:]) != 1 || subtle.ConstantTimeCompare(passHash[:], expectedPass[:]) != 1 {
   w.Header().Set("WWW-Authenticate", `Basic realm="Watchtower Dashboard", charset="UTF-8"`)
   http.Error(w, "Unauthorized", http.StatusUnauthorized)
   return false
  }
  return true
 }
}

func releaseNotesHandler(authenticated func(http.ResponseWriter, *http.Request) bool, read func(string) ([]byte, error)) http.HandlerFunc {
 return func(w http.ResponseWriter, r *http.Request) {
  if !authenticated(w, r) { return }
  w.Header().Set("Cache-Control", "no-store")
  if r.Method != http.MethodGet { http.Error(w, "method not allowed", http.StatusMethodNotAllowed); return }
  w.Header().Set("Content-Type", "application/json")
  _ = json.NewEncoder(w).Encode(readBuildInfo(read))
 }
}

func main() {
 base,err:=url.Parse(env("WATCHTOWER_URL","http://watchtower:8080")); if err!=nil || (base.Scheme!="http" && base.Scheme!="https") || base.Host=="" || base.User!=nil { log.Fatal("invalid WATCHTOWER_URL") }
 token:=os.Getenv("WATCHTOWER_API_TOKEN"); password:=os.Getenv("DASHBOARD_PASSWORD")
 if token=="" || password=="" { log.Fatal("WATCHTOWER_API_TOKEN and DASHBOARD_PASSWORD are required") }
 username:=env("DASHBOARD_USER","admin")
 allowUpdates:=os.Getenv("DASHBOARD_ENABLE_UPDATES")=="true"
 client:=&http.Client{Timeout:10*time.Minute}
 authenticated:=basicAuthenticator(username,password)
 mux:=http.NewServeMux()
 mux.HandleFunc("/healthz",func(w http.ResponseWriter,r *http.Request){ if r.Method!=http.MethodGet {http.Error(w,"method not allowed",405);return}; w.WriteHeader(200);_,_=w.Write([]byte("ok")) })
 mux.HandleFunc("/static/",func(w http.ResponseWriter,r *http.Request){
  if !authenticated(w,r){return}
  http.FileServer(http.FS(assets)).ServeHTTP(w,r)
 })
 mux.HandleFunc("/api/",func(w http.ResponseWriter,r *http.Request){
  if !authenticated(w,r){return}
  w.Header().Set("Cache-Control","no-store")
  route:=strings.TrimPrefix(r.URL.Path,"/api/")
  endpoints:=map[string]string{"containers":"/v1/containers","history":"/v1/history","check":"/v1/check","update":"/v1/update"}
  path,ok:=endpoints[route];if !ok {http.NotFound(w,r);return}
  method:=http.MethodGet; if route=="check"||route=="update" {method=http.MethodPost}
  if r.Method!=method {http.Error(w,"method not allowed",405);return}
  if method==http.MethodPost {
   if r.Header.Get("X-Requested-With")!="WatchtowerDashboard" {http.Error(w,"missing request header",403);return}
   if origin:=r.Header.Get("Origin");origin!="" {u,e:=url.Parse(origin);if e!=nil || !strings.EqualFold(u.Host,r.Host) {http.Error(w,"cross-origin request denied",403);return}}
  }
  if route=="update"&&!allowUpdates {http.Error(w,"manual updates disabled by administrator",403);return}
  query:=r.URL.Query()
  if route=="update" {
    name:=query.Get("name")
    if name=="" || len(query["name"])!=1 {http.Error(w,"container name required",400);return}
    query=url.Values{"container":{"^"+regexp.QuoteMeta(name)+"$"}}
  }
  target:=base.ResolveReference(&url.URL{Path:path,RawQuery:query.Encode()})
  req,err:=http.NewRequestWithContext(r.Context(),method,target.String(),nil);if err!=nil{http.Error(w,"request failed",500);return}
  req.Header.Set("Authorization","Bearer "+token)
  res,err:=client.Do(req);if err!=nil {log.Printf("upstream request failed: %v",err);http.Error(w,"Watchtower API unavailable",502);return}
  defer res.Body.Close()
  w.Header().Set("Content-Type","application/json")
  w.WriteHeader(res.StatusCode)
  _,_=io.Copy(w,io.LimitReader(res.Body,4<<20))
 })
 mux.HandleFunc("/api/release-notes", releaseNotesHandler(authenticated, assets.ReadFile))
 mux.HandleFunc("/",func(w http.ResponseWriter,r *http.Request){
  if !authenticated(w,r){return}
  if r.URL.Path!="/" {http.NotFound(w,r);return}
  b,err:=assets.ReadFile("static/index.html");if err!=nil{http.Error(w,"dashboard unavailable",500);return}
  w.Header().Set("Content-Type","text/html; charset=utf-8");w.Header().Set("Cache-Control","no-store");w.Header().Set("X-Content-Type-Options","nosniff");w.Header().Set("Content-Security-Policy","default-src 'none'; style-src 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
  _,_=w.Write(b)
 })
 addr:=env("DASHBOARD_LISTEN",":8080")
 log.Printf("Dashboard listening on %s (updates enabled: %t)",addr,allowUpdates)
 server:=&http.Server{Addr:addr,Handler:mux,ReadHeaderTimeout:10*time.Second}
 log.Fatal(server.ListenAndServe())
}
