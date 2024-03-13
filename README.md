## Overview - Kubernetes Multi-Tenancy
Kubernetes users usually share clusters to meet the demands of multiple teams and multiple customers. As the number of users grow, the need in multi-tenant solution increases as well. There are two ways to handle mult-tenancy - either through dedicated cluster per team or by managing the shared access to the same cluster. In the latter case Kubernetes offers three mechanisms to achieve control plane isolation - through usage of namespaces, RBAC and quotas, with namespace isolation being a driving factor.  

## Problem
In the multi-tenant cluster scenario namespaces become a security isolation controls. For example, two teams sharing the same cluster with access to workloads with varying degree of sensitivity. Or company running SaaS service allocating container / pod for every customer. 
However, there is no native mechanism to monitor the logical crossings of namespaces. There is also no way to detect the attack paths / vectors for potential violations. This is what NamespaceHound is for. Cluster operators can use NamespaceHound to assess the risk of cross-tenant violations in their environment.

## Usage
NamespaceHound is the tool for detecting the risk of potential **namespace crossing violations** in multi-tenant clusters. Given the cluster, NamespaceHound will run analysis and determine all the possible ways to cross the security boundaries between the namespaces. In addition, the tool is inspecting the cluster config for anonymous access opportunities. If given a specific namespace (*-n namespace* parameter), it will focus on this namespace plus anonymous access to find all the possible ways to reach / interfere with the resources from another namespace.

Another instance where NamespaceHound is useful is in helping red-teamers and security researchers to find **lateral movement paths** once they are past the point of initial access into the cluster. Our [2023 Kubernetes Security Report](https://www.wiz.io/blog/key-takeaways-from-the-wiz-2023-kubernetes-security-report) revealed that assuming the successful initial access, the opportunities for lateral movement are abundant and thus should be assessed rigorously. For example, in the cluster with the classic frontend - business logic - database architecture, the most obvious lateral movement direction would be from a frontend pod to a namespace containing pods with data access.

```
>python3 nshound.py -h
usage: nshound.py [-h] [--kubeconfig KUBECONFIG] [-n NAMESPACE | -c] [-o {table,json,csv,html}] [-v]

NamespaceHound is a tool that detects various ways to cross the namespace boundaries within the Kubernetes cluster.

options:
  -h, --help            show this help message and exit
  --kubeconfig KUBECONFIG
                        .kubeconfig file containing the cluster access credentials
  -n NAMESPACE, --namespace NAMESPACE
                        look for escape paths from this namespace only
  -c, --controlplane    show issues from kube-system
  -o {table,json,csv,html}, --output {table,json,csv,html}
                        output format - json, csv or table
  -v, --verbose         increase output verbosity

Run it with an existing kubeconfig file while (optionally) supplying the namespace name you are interested in. For the detailed explanation of the detected risks go to the repo README.
```
If you don't supply the specific namespace, the tool by default will hide the results from kube-system namespace to reduce the noise. Run the tool with *-c / --controlplane* parameter if you do want to see kube-system issues

Sample run:

```
>python3 nshound.py --kubeconfig configs/config.eks.wizard-maker-cluster -n argocd -o table
+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
|                                                                                     Findings Table                                                                                     |
+-----------+----------+------------+-----------------------------------+-----------+------+---------------------------+----------------------------------------------------+------------+
| Namespace | Severity | Confidence | Principals                        | Container | Pod  | Type                      | Description                                        | Neighbours |
+-----------+----------+------------+-----------------------------------+-----------+------+---------------------------+----------------------------------------------------+------------+
| argocd    | LOW      | MEDIUM     | None                              | None      | None | DOS_NO_QUOTA              | There is no resource limits on this namespace - if | None       |
|           |          |            |                                   |           |      |                           | attacker controls resource creation it can cause   |            |
|           |          |            |                                   |           |      |                           | DoS in other namespaces.                           |            |
| argocd    | HIGH     | HIGH       | ['argocd-application-controller'] | None      | None | RBAC_SECRETS_STEALING     | Principals can read secrets from another           | None       |
|           |          |            |                                   |           |      |                           | namespace.                                         |            |
| argocd    | HIGH     | HIGH       | ['argocd-application-controller'] | None      | None | RBAC_WORKLOAD_CREATION    | Principals can create workloads in another         | None       |
|           |          |            |                                   |           |      |                           | namespace.                                         |            |
| argocd    | HIGH     | HIGH       | ['argocd-application-controller'] | None      | None | RBAC_POD_EXECUTION        | Principals can exec/attach to pods in another      | None       |
|           |          |            |                                   |           |      |                           | namespace.                                         |            |
| argocd    | MEDIUM   | HIGH       | ['argocd-application-controller'] | None      | None | RBAC_CONFIGMAP_SMASHING   | Principals can update configmap in another         | None       |
|           |          |            |                                   |           |      |                           | namespace.                                         |            |
| argocd    | HIGH     | HIGH       | ['argocd-application-controller'] | None      | None | RBAC_WEBHOOK_MANIPULATION | Principals can update                              | None       |
|           |          |            |                                   |           |      |                           | mutatingwebhookconfigurations and potentially      |            |
|           |          |            |                                   |           |      |                           | inject a sidecar container.                        |            |
| argocd    | HIGH     | HIGH       | ['argocd-application-controller'] | None      | None | RBAC_SECRETS_SMASHING     | Principals can update                              | None       |
|           |          |            |                                   |           |      |                           | validatingwebhookconfigurations and potentially    |            |
|           |          |            |                                   |           |      |                           | steal secrets.                                     |            |
| argocd    | MEDIUM   | HIGH       | ['argocd-application-controller'] | None      | None | RBAC_WORKLOAD_DELETION    | Principals can delete workloads in another         | None       |
|           |          |            |                                   |           |      |                           | namespace.                                         |            |
| argocd    | MEDIUM   | HIGH       | ['argocd-application-controller'] | None      | None | RBAC_SHARED_URLS          | Principals can access {'*'} - URLs that            | None       |
|           |          |            |                                   |           |      |                           | potentially contain information from other         |            |
|           |          |            |                                   |           |      |                           | namespaces.                                        |            |
| argocd    | HIGH     | HIGH       | ['argocd-server']                 | None      | None | RBAC_SECRETS_STEALING     | Principals can read secrets from another           | None       |
|           |          |            |                                   |           |      |                           | namespace.                                         |            |
| argocd    | HIGH     | HIGH       | ['argocd-server']                 | None      | None | RBAC_WORKLOAD_CREATION    | Principals can create workloads in another         | None       |
|           |          |            |                                   |           |      |                           | namespace.                                         |            |
| argocd    | MEDIUM   | HIGH       | ['argocd-server']                 | None      | None | RBAC_CONFIGMAP_SMASHING   | Principals can update configmap in another         | None       |
|           |          |            |                                   |           |      |                           | namespace.                                         |            |
| argocd    | HIGH     | HIGH       | ['argocd-server']                 | None      | None | RBAC_WEBHOOK_MANIPULATION | Principals can update                              | None       |
|           |          |            |                                   |           |      |                           | mutatingwebhookconfigurations and potentially      |            |
|           |          |            |                                   |           |      |                           | inject a sidecar container.                        |            |
| argocd    | HIGH     | HIGH       | ['argocd-server']                 | None      | None | RBAC_SECRETS_SMASHING     | Principals can update                              | None       |
|           |          |            |                                   |           |      |                           | validatingwebhookconfigurations and potentially    |            |
|           |          |            |                                   |           |      |                           | steal secrets.                                     |            |
| argocd    | MEDIUM   | HIGH       | ['argocd-server']                 | None      | None | RBAC_WORKLOAD_DELETION    | Principals can delete workloads in another         | None       |
|           |          |            |                                   |           |      |                           | namespace.                                         |            |
+-----------+----------+------------+-----------------------------------+-----------+------+---------------------------+----------------------------------------------------+------------+
```
### Security and Privacy
To function properly, NamespaceHound requires K8s API read permissions on all of the resources types. That is the minimal set. Of course principals mapped to *admin*, *cluster-admin* roles and *system:maters* group will work as well.

NamespaceHound does not save any data about the target cluster locally. It does not build graph and does not save object material - upon every run, NamespaceHound establishes a new connection with the cluster and performes API server querying in the same capacity.

## Library - Types of Namespace Crossings

| Name    | Severity | Confidence | Description | Method |
| -------- | ------- | -------- | ------- | ------- |
| DOS_NO_QUOTA  | LOW | MEDIUM | No resource quota on this namespace. Over-resourced workload can take take other namespace' resources. | Querying API for resource quotas |
| RBAC_POD_EVICTION | LOW | HIGH | A service account from this namespace can evict pods in another namespace. | Querying RBAC API |
| RBAC_ANONYMOUS_ACCESS_TO_RESOURCES | MEDIUM | HIGH | Anonymous user has access to resources. Applies to any namespace. | Querying RBAC API |
| RBAC_SHARED_URLS | MEDIUM | HIGH | A service account from this namespace has access to the non-trivial URLs that potentially include other namespaces data. | Querying RBAC API |
| RBAC_SECRETS_STEALING | HIGH | HIGH | A service account from this namespace has access to secrets in another namespace. | Querying RBAC API |
| RBAC_CONFIGMAP_SMASHING | MEDIUM | HIGH | A service account from this namespace can manipulate a configmap from another namespace, which may result in secret stealing, data exfiltration and execution in the context of another namespace. | Querying RBAC API |
| RBAC_LOG_EXFILTRATION | HIGH | HIGH | A service account from this namespace can redirect and control fluentbit logs and executions in another namespace, which results in secret stealing, data exfiltration and execution in the context of another namespace. | Querying RBAC API |
| RBAC_WORKLOAD_CREATION | HIGH | HIGH | A service account from this namespace can create workloads in another namespace. | Querying RBAC API |
| RBAC_WORKLOAD_DELETION | MEDIUM | HIGH | A service account from this namespace can delete workloads in another namespace. | Querying RBAC API |
| RBAC_POD_EXECUTION | HIGH | HIGH | A service account from this namespace can exec/attach to pods in another namespace. | Querying RBAC API |
| RBAC_WEBHOOK_MANIPULATION | HIGH | MEDIUM | A service account from this namespace can manipulate the global mutating webhook, which may result in security control compromise, secret stealing, data exfiltration and execution in the context of another namespace. | Querying RBAC API |
| RBAC_SECRETS_SMASHING | HIGH | MEDIUM | A service account from this namespace can manipulate the global validating webhook, which may result in security control compromise, secret stealing and data exfiltration. | Querying RBAC API |
| POD_ACCESS_TO_NPD_CONFIG | HIGH | HIGH | Pod has RW access to the node problem detector (NPD) config, which is equal to cluster admin due to powerful NPD execution. | Inspecting pod's host mounts. |
| POD_ESCAPE_CORE_PATTERN | HIGH | HIGH | Pod can escape to host / has writable access to host through sensitive volume mount. | Inspecting pod's host mounts. |
| POD_ACCESS_TO_LOGS | HIGH | HIGH | Pod has access to other pods logs through volume mount. | Inspecting pod's host mounts. |
| POD_ACCESS_TO_HOST | HIGH | MEDIUM | Pod has access to host through sensitive volume mount. | Inspecting pod's host mounts. |
| CONTAINER_PRIVILEGED_ACCESS_TO_HOST | HIGH | HIGH | Container is privileged and thus can escape to worker node and access shared secrets. | Inspecting container's capabilities and namespace sharing. |
| CONTAINER_POWERFUL_CAPABILITIES | HIGH | MEDIUM | Container has powerful capabilities and thus can escape to worker node and access shared secrets. | Inspecting container's capabilities and namespace sharing. |
| CONTAINER_PTRACE_CAPABILITY | HIGH | HIGH | Container has SYS_PTRACE capability allowing control of other namespace processes running on the same worker node. | Inspecting container's capabilities and namespace sharing. |
| CONTAINER_BPF_CAPABILITY | HIGH | HIGH | Container has SYS_BPF capability allowing kernel-level access to other process resources, (f.e. packet capture and secret stealing). | Inspecting container's capabilities and namespace sharing. |
| CONTAINER_IPC_CAPABILITY | HIGH | HIGH | Container has IPC_OWNER capability allowing control of other namespace processes running on the same worker node. | Inspecting container's capabilities and namespace sharing. |

## References
- https://www.cncf.io/blog/2022/11/09/multi-tenancy-in-kubernetes-implementation-and-optimization/
- https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/

## License
This project is licensed under the Apache-2.0 License.