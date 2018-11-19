// Copyright 2017 Tanck. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
   "flag"
   "net/http"
   "fmt"
   "os"
   "time"
   "net"
   "log"
   "io/ioutil"
   "crypto/tls"
   "strings"
   "encoding/json"
   "github.com/spf13/pflag"
   "github.com/bitly/go-simplejson"
)

var (
    argKeyStone     = pflag.IP("keystone-server", net.IPv4(192, 168, 17, 39), "The keystone server address.")
    argAuthPort     = pflag.Int("auth-port", 35357, "The authentication port.")
    argBindAddress  = pflag.IP("bind-address", net.IPv4(0, 0, 0, 0), "The address auth server bind to.")
    argListenPort   = pflag.Int("listen-port", 5012, "The listen port of auth server.")
    argIngress   = pflag.Bool("user-ingress", false, "Expose ingress or not.")
    argDNS   = pflag.String("dns-host", "", "DNS host.")
    argDBImg   = pflag.String("db-img", "", "dashboard images.")
    argCharServer = pflag.String("helm-chart-server", "", "helm-chart-server address")
)

const SERVICE_NAME = "dashboard-larryck"

type TreeSubitem struct {
    Name string  `json:"name"`
    State string  `json:"state"`
}

type TreeItem struct {
    State string `json:"state"`
    Item []TreeSubitem  `json:"item"`
}

var (
  K8S_ADMIN_TREE = map[string]TreeItem{
    "Cluster":{"cluster", []TreeSubitem{{"Namespaces", "namespace.list"}, {"Nodes", "node.list"}, {"Persistent Volumes", "persistentvolume.list"}, {"Roles", "role.list"}, {"Storage Classes", "storageclass.list"}}},
    "Namespace":{},
    "Workloads":{"workload", []TreeSubitem{{"Daemon Sets", "daemonset.list"}, {"Deployments", "deployment.list"}, {"Jobs", "job.list"}, {"Pods", "pod.list"}, {"Replica Sets", "replicaset.list"}, {"Replication Controllers", "replicationcontroller.list"}, {"Stateful Sets", "statefulset.list"}}},
    "Discovery and Load Balancing":{"discovery", []TreeSubitem{{"Ingresses", "ingress.list"}, {"Services", "service.list"}}},
    "Config and Storage":{"config", []TreeSubitem{{"Config Maps", "configmap.list"}, {"Persistent Volume Claims", "persistentvolumeclaim.list"}, {"Secrets", "secret.list"}}},
    "About":{},
    "APP Store":{"appStore", []TreeSubitem{}},
    "repositories":{"repositories", []TreeSubitem{}},
    "release":{"release", []TreeSubitem{}},
    "home":{"home", []TreeSubitem{}},}
  
  K8S_USER_TREE = map[string]TreeItem{
    "Workloads":{"workload", []TreeSubitem{{"Deployments", "deployment.list"}, {"Pods", "pod.list"}, {"Replica Sets", "replicaset.list"}}},
    "Discovery and Load Balancing":{"discovery", []TreeSubitem{{"Services", "service.list"}}},
    "Config and Storage":{"config", []TreeSubitem{{"Config Maps", "configmap.list"}, {"Secrets", "secret.list"}}},
    "APP Store":{"appStore", []TreeSubitem{}},
    "repositories":{"repositories", []TreeSubitem{}},
    "release":{"release", []TreeSubitem{}},
    "home":{"home", []TreeSubitem{}},}
)


func buildTree(role string) map[string]TreeItem {
  switch(role) {
    case "k8s-user":
      return K8S_USER_TREE
    case "k8s-admin":
      return K8S_ADMIN_TREE
  }
  return nil
}

func auth(proj string, user string, passwd string) (role string, id string) {
  keystoneUrl := fmt.Sprintf("https://%s:%d/v2.0/tokens", *argKeyStone, *argAuthPort)
  header := "application/json"

  data := fmt.Sprintf("{\"auth\": {\"tenantName\":\"%s\", \"passwordCredentials\": {\"username\": \"%s\",\"password\": \"%s\"}}}", proj, user, passwd)

  fmt.Println(keystoneUrl)
  fmt.Println(data)

  tr := &http.Transport{
    TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
  }
  client := &http.Client{Transport: tr}
  resp, err := client.Post(keystoneUrl, header, strings.NewReader(data))
  if err != nil {
    fmt.Println(err)
    return "", ""
  }

  defer resp.Body.Close()
  body, err := ioutil.ReadAll(resp.Body)
  if err != nil || resp.StatusCode!=http.StatusOK {
    fmt.Println(err)
    fmt.Println(string(body))
    return "", ""
  }

  fmt.Println(string(body))
  
  //extract role from json with bitly go-simplejson
  js,err := simplejson.NewJson(body)
  if err!=nil {
    fmt.Println(err)
    return "", ""
  }

  user_id := js.Get("access").Get("user").Get("id").MustString()
  roles,_ := js.Get("access").Get("user").Get("roles").Array()
  if len(roles)==0 {
      return "", ""
  }
  roleMap := roles[0].(map[string]interface {})
  for _,v := range roleMap {
    fmt.Println(v.(string))
    return v.(string), user_id
  }

  return "", ""
}

type KeyserverResp struct {
  Status string  `json:"status"`
  Tree map[string]TreeItem   `json:"tree"`
  URL string `json:"url"`
}

func pushTree(tree map[string]TreeItem, url string, w http.ResponseWriter) {
  ksr := &KeyserverResp {"OK", tree, url}
  jn,_ := json.Marshal(ksr)
  fmt.Println(string(jn))
  w.Write(jn)
}

type LogoutResp struct {
  Status string
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
  r.ParseForm()
  // cross domain post
  w.Header().Set("Access-Control-Allow-Origin", "*")

  loR := LogoutResp{"Error"}
  name := r.Form["name"][0]
  namespace := r.Form["namespace"][0]
  if !(len(name)>0 && len(namespace)>0) {
    // return 403 error
    w.WriteHeader(403)
    fmt.Println("Get Name/Namespace error")
    jn,_ := json.Marshal(loR)
    w.Write(jn)
    return
  }


  err := DeleteDashBoard(*argIngress, name, namespace)
  if err!=nil {
    w.WriteHeader(403)
    fmt.Println(err)
    jn,_ := json.Marshal(loR)
    w.Write(jn)
    return
  }
  loR.Status = "OK"
  jn,_ := json.Marshal(loR)
  w.Write(jn)
}

func handleAuth(w http.ResponseWriter, r *http.Request) {
  r.ParseForm()

  // cross domain post
  w.Header().Set("Access-Control-Allow-Origin", "*")

  ksr := KeyserverResp {"ERROR", nil, ""}
  proj := r.PostFormValue("project")
  user := r.PostFormValue("userName")
  passwd := r.PostFormValue("userPassword")

  if !(len(proj)>0 && len(user)>0 && len(passwd)>0) {
    // return 403 error
    w.WriteHeader(403)
    jn,_ := json.Marshal(ksr)
    w.Write(jn)
    return
  }

  role, id := auth(proj, user, passwd)
  if len(role)==0 {
    // return 401, unauthorized
    w.WriteHeader(401)
    jn,_ := json.Marshal(ksr)
    w.Write(jn)
    return
  }

  tree := buildTree(role)

  if tree==nil {
    // return 401, unauthorized
    w.WriteHeader(401)
    fmt.Fprintf(w, "Unauthorized\n")
    jn,_ := json.Marshal(ksr)
    w.Write(jn)
   return
  }


  js_tree,_ := json.Marshal(tree)

  // must have DBImg
  if len(*argDBImg)==0 || *argIngress==true && len(*argDNS)==0 {
    // return 403, unauthorized
    w.WriteHeader(403)
    fmt.Fprintf(w, "Parameters error\n")
    jn,_ := json.Marshal(ksr)
    w.Write(jn)
   return
  }

  // deploy dashboard and service
  ip, err := DeployDashboard(*argCharServer, *argDBImg, *argIngress, *argDNS, SERVICE_NAME, id, "authedDashboard", user, role, string(js_tree))
  if err!= nil {
    // return 403 error
    w.WriteHeader(403)
    jn,_ := json.Marshal(ksr)
    w.Write(jn)
    return
  }

  url := genURL(ip, id)

  // add request service check
  serviceAvailableCheck(*argIngress, url)
  fmt.Println("Dashboard service available")

  pushTree(tree, url, w)
}


func serviceAvailableCheck(use_ingress bool, url string) {
  for i:=0; i<10; i++ {
    ch := make(chan bool)
    go dialService(use_ingress, url, ch)
    if status:= <- ch; status {
      return
    }
  }
}

func dialService(use_ingress bool, url string, chChan chan bool) {
  c := &http.Client{  
    Transport: &http.Transport{
        Dial: (&net.Dialer{
            Timeout:   1 * time.Second,
        }).Dial,
	DisableKeepAlives: true,
    },
  }
  resp, err := c.Get(url)
  if err != nil {
    fmt.Println(err)
    chChan <- false
  }else {
    if use_ingress {
      _, err := ioutil.ReadAll(resp.Body)
      if err != nil {
        fmt.Println(err)
        chChan <- false
      } else if resp.StatusCode!=200 {
	fmt.Println(resp.StatusCode)
	time.Sleep(1 * time.Second)
        chChan <- false
      }else {
	fmt.Println(resp.StatusCode)
        fmt.Println("Get good request")
        resp.Body.Close()
        chChan <- true
      }
    }else{
      fmt.Println("Get good request")
      resp.Body.Close()
      chChan <- true
    }
  }
}


func genURL(ip string, namespace string) string {
  return "http://"+ip+"/#!/deployment?namespace="+namespace
}


func CreateAuthHandler() http.Handler {
  return http.HandlerFunc(handleAuth)
}

func LogoutHandler() http.Handler {
  return http.HandlerFunc(handleLogout)
}

func main() {
  // Set logging output to standard console out
  log.SetOutput(os.Stdout)
  
  pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
  pflag.Parse()
  
  log.Printf("Listen on port %d", *argListenPort)
  log.Printf("Using authentication address: https://%s:%d", *argKeyStone, *argAuthPort)

  http.Handle("/auth",  CreateAuthHandler())
  http.Handle("/logout",  LogoutHandler())

  addr := fmt.Sprintf("%s:%d", *argBindAddress, *argListenPort)
  go log.Fatal(http.ListenAndServe(addr, nil))

  select {}
}
