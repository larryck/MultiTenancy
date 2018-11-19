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
  "log"
  "fmt"

  deplK8s "github.com/kubernetes/dashboard/src/app/backend/resource/deployment"
  "k8s.io/apimachinery/pkg/api/resource"
  "github.com/kubernetes/dashboard/src/app/backend/client"
  clientK8s "k8s.io/client-go/kubernetes"
  api "k8s.io/client-go/pkg/api/v1"
  "k8s.io/apimachinery/pkg/util/intstr"
  extensions "k8s.io/client-go/pkg/apis/extensions/v1beta1"
  "github.com/kubernetes/dashboard/src/app/backend/resource/common"
  metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func handleInternalError(err error) {
  log.Print(err)
}

func NewClientSet() (_client *clientK8s.Clientset, err error) {
  apiserverClient, _, err := client.CreateApiserverClient("", "")
  //apiserverClient, _, err := client.CreateApiserverClient(*argApiserverHost, *argKubeConfigFile)
  if err!=nil {
    handleInternalError(err)
    return nil, nil
  }
  return apiserverClient, nil
}


// Modified from funcion DeployApp of deploy, add sa and return service ip.
func DeployAppWithSa(spec * deplK8s.AppDeploymentSpec, client clientK8s.Interface, sa string) (string, error) {
	log.Printf("Deploying %s application into %s namespace", spec.Name, spec.Namespace)

	annotations := map[string]string{}
	if spec.Description != nil {
		annotations[deplK8s.DescriptionAnnotationKey] = *spec.Description
	}
	labels := deplK8s.KKgetLabelsMap(spec.Labels)
	objectMeta := metaV1.ObjectMeta{
		Annotations: annotations,
		Name:        spec.Name,
		Labels:      labels,
	}

	containerSpec := api.Container{
		Name:  spec.Name,
		Image: spec.ContainerImage,
		SecurityContext: &api.SecurityContext{
			Privileged: &spec.RunAsPrivileged,
		},
		Resources: api.ResourceRequirements{
			Requests: make(map[api.ResourceName]resource.Quantity),
		},
		Env: deplK8s.KKconvertEnvVarsSpec(spec.Variables),
	}

	if spec.ContainerCommand != nil {
		containerSpec.Command = []string{*spec.ContainerCommand}
	}
	if spec.ContainerCommandArgs != nil {
                fmt.Println("ContainerCommandArgs:" + *spec.ContainerCommandArgs)
		containerSpec.Args = []string{*spec.ContainerCommandArgs}
	}

	if spec.CpuRequirement != nil {
		containerSpec.Resources.Requests[api.ResourceCPU] = *spec.CpuRequirement
	}
	if spec.MemoryRequirement != nil {
		containerSpec.Resources.Requests[api.ResourceMemory] = *spec.MemoryRequirement
	}
	podSpec := api.PodSpec{
		Containers: []api.Container{containerSpec},
		ServiceAccountName: sa,
	}
	if spec.ImagePullSecret != nil {
		podSpec.ImagePullSecrets = []api.LocalObjectReference{{Name: *spec.ImagePullSecret}}
	}

	podTemplate := api.PodTemplateSpec{
		ObjectMeta: objectMeta,
		Spec:       podSpec,
	}

	depl := &extensions.Deployment{
		ObjectMeta: objectMeta,
		Spec: extensions.DeploymentSpec{
			Replicas: &spec.Replicas,
			Template: podTemplate,
		},
	}
	_, err := client.Extensions().Deployments(spec.Namespace).Create(depl)

	if err != nil {
		// TODO(bryk): Roll back created resources in case of error.
		return "", err
	}

	if len(spec.PortMappings) > 0 {
		service := &api.Service{
			ObjectMeta: objectMeta,
			Spec: api.ServiceSpec{
				Selector: labels,
			},
		}

		if spec.IsExternal {
			service.Spec.Type = api.ServiceTypeLoadBalancer
		} else {
			service.Spec.Type = api.ServiceTypeClusterIP
		}

		for _, portMapping := range spec.PortMappings {
			servicePort :=
				api.ServicePort{
					Protocol: portMapping.Protocol,
					Port:     portMapping.Port,
					Name:     deplK8s.KKgeneratePortMappingName(portMapping),
					TargetPort: intstr.IntOrString{
						Type:   intstr.Int,
						IntVal: portMapping.TargetPort,
					},
				}
			service.Spec.Ports = append(service.Spec.Ports, servicePort)
		}

		svc, err := client.Core().Services(spec.Namespace).Create(service)

		// TODO(bryk): Roll back created resources in case of error.
		return svc.Spec.ClusterIP, err
	}

	return "", nil
}

// return service ip
func DeployAppAndSvc(argCharServer string, argIngress bool, dns string, name string, namespace string,  img string, ports []deplK8s.PortMapping, labels []deplK8s.Label, user string, role string, tree string) (string, error) {
  client, err := NewClientSet()
  if err!=nil {
    handleInternalError(err)
    return "", err
  }

  hostpath := ""
  // set ingress rules first
  if argIngress {
    //check hostpath exist first
    ing, err := client.Extensions().Ingresses(namespace).Get(name, metaV1.GetOptions{})
    if err==nil {
      hostpath = ing.Spec.Rules[0].Host
    }else {
      //create ingress rules
      _hostpath, err := DeployIngressRules(client, name, 80, namespace, dns)
      hostpath = _hostpath
      if err != nil {
        handleInternalError(err)
        return "", err
      }
    }
  }
 
  //deploy containers
  spec := new(deplK8s.AppDeploymentSpec)
  //set spec
  spec.Name = name
  spec.ContainerImage = img

  spec.PortMappings = ports
  spec.Replicas = 1
  spec.Namespace = namespace
  spec.Labels = labels
  authpath := "login."+dns
  spec.Variables = []deplK8s.EnvironmentVariable{{"DBH_NAME", name}, {"DBH_NAMESAPCE", namespace}, {"DBH_AUTHSERVER", authpath}, {"DBH_USER", user}, {"DBH_ROLE", role}, {"DBH_TREE", tree}}
  // add args for chart server
  chartServer := new(string)
  *chartServer = "--helm-chart-server=" + argCharServer
  spec.ContainerCommandArgs = chartServer

  // check if the dashboard service already exists
  ////get service ip
  ip := ""
  service, err := client.Core().Services(namespace).Get(name, metaV1.GetOptions{})
  if err == nil {
    // service exists
    fmt.Println("Dashboard already deployed")
    //return service.Spec.ClusterIP, nil
    ip=service.Spec.ClusterIP
  }else{
    sa := "dbh-sa"
    _ip, err := DeployAppWithSa(spec, client, sa)
    ip=_ip
    if err != nil {
      handleInternalError(err)
      return "", err
    }
  }

  if argIngress {
    return hostpath, nil
  }
 
  return ip, nil
}

func DeployDashboard(argCharServer string, argDBImg string, argIngress bool, dns string, name string, namespace string, label string, user string, role string, tree string) (ip string, err error) {
  ports := []deplK8s.PortMapping{{80, 9090, "TCP"}}
  labels := []deplK8s.Label{{"app", label}}

  return DeployAppAndSvc(argCharServer, argIngress, dns, name, namespace, argDBImg, ports, labels, user, role, tree)
}


// add delete deployments
func DeleteDashBoard(argIngress bool, name string, namespace string) error {
  client, err := NewClientSet()
  if err!=nil {
    handleInternalError(err)
    return err
  }
  verber := common.NewResourceVerber(client.Core().RESTClient(),
    client.Extensions().RESTClient(), client.Apps().RESTClient(),
    client.Batch().RESTClient(), client.Autoscaling().RESTClient(), client.Storage().RESTClient())

  // set rs=0 for deployment first to clear pods
  depl, err := client.Extensions().Deployments(namespace).Get(name, metaV1.GetOptions{})
  if err != nil {
    fmt.Println("Get deployment error")
    handleInternalError(err)
    return err
  }
  *depl.Spec.Replicas = 0
  _, err = client.Extensions().Deployments(namespace).Update(depl)
  if err != nil {
    fmt.Println("Update deployment error")
    handleInternalError(err)
    return err
  }

  err = verber.Delete("deployment", true, namespace, name)
  if err != nil {
    handleInternalError(err)
    return err
  }

  if argIngress {
    // delete ingress rules first
    err := verber.Delete("ingress", true, namespace, name)
    if err != nil {
      handleInternalError(err)
      return err
    }
  }

  return verber.Delete("service", true, namespace, name)
}


func DeployIngressRules(client *clientK8s.Clientset, name string, port int, namespace string, dns string) (string, error) {
  bd :=  extensions.IngressBackend{name, intstr.FromInt(port)}
  hostpath := namespace+"."+dns
  rule := extensions.IngressRule{
    Host: hostpath, IngressRuleValue: extensions.IngressRuleValue{
      HTTP: &extensions.HTTPIngressRuleValue{
        Paths: []extensions.HTTPIngressPath{{Backend:bd,}, },
      },
    },
  }
  spec := extensions.IngressSpec{Rules: []extensions.IngressRule{rule, }}
  objectMeta := metaV1.ObjectMeta{
  	Name:        name,
  	Namespace:      namespace,
  }


  ingress := extensions.Ingress{
    ObjectMeta: objectMeta,
    Spec: spec,
  }
  _, err := client.Extensions().Ingresses(namespace).Create(&ingress)
  if err!=nil {
    return "", err
  }

  return hostpath, err
}
