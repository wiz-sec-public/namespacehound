from enum import Enum
import json


class SetEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        return json.JSONEncoder.default(self, obj)


# global structures
namespaces = {}
findings = dict(allnamespaces=[])
node_residency_table = dict()

cluster_flavor = {}


class ClusterFlavor(str, Enum):
    AKS = "AKS"
    EKS = "EKS"
    GKE = "GKE"
    OTHER = "OTHER"


class OutputFormat(Enum):
    table = 'table'
    json = 'json'
    csv = 'csv'
    html = 'html'

    def __str__(self):
        return self.value


class Finding(str, Enum):
    DOS_NO_QUOTA = "DOS_NO_QUOTA"
    RBAC_ANONYMOUS_ACCESS_TO_RESOURCES = "RBAC_ANONYMOUS_ACCESS_TO_RESOURCES"
    RBAC_GOOGLE_USER_ACCESS_TO_RESOURCES = "RBAC_GOOGLE_USER_ACCESS_TO_RESOURCES"
    RBAC_SHARED_URLS = "RBAC_SHARED_URLS"
    RBAC_SECRETS_STEALING = "RBAC_SECRETS_STEALING"
    RBAC_CONFIGMAP_SMASHING = "RBAC_CONFIGMAP_SMASHING"
    RBAC_LOG_EXFILTRATION = "RBAC_LOG_EXFILTRATION"
    RBAC_WORKLOAD_CREATION = "RBAC_WORKLOAD_CREATION"
    RBAC_WORKLOAD_DELETION = "RBAC_WORKLOAD_DELETION"
    RBAC_POD_EXECUTION = "RBAC_POD_EXECUTION"
    RBAC_POD_EVICTION = "RBAC_POD_EVICTION"
    RBAC_WEBHOOK_MANIPULATION = "RBAC_WEBHOOK_MANIPULATION"
    RBAC_SECRETS_SMASHING = "RBAC_SECRETS_SMASHING"
    POD_ACCESS_TO_NPD_CONFIG = "POD_ACCESS_TO_NPD_CONFIG"
    POD_ESCAPE_CORE_PATTERN = "POD_ESCAPE_CORE_PATTERN"
    POD_ACCESS_TO_LOGS = "POD_ACCESS_TO_LOGS"
    POD_ACCESS_TO_HOST = "POD_ACCESS_TO_HOST"
    CONTAINER_PRIVILEGED_ACCESS_TO_HOST = "CONTAINER_PRIVILEGED_ACCESS_TO_HOST"
    CONTAINER_POWERFUL_CAPABILITIES = "CONTAINER_POWERFUL_CAPABILITIES"
    CONTAINER_PTRACE_CAPABILITY = "CONTAINER_PTRACE_CAPABILITY"
    CONTAINER_BPF_CAPABILITY = "CONTAINER_BPF_CAPABILITY"
    CONTAINER_IPC_CAPABILITY = "CONTAINER_IPC_CAPABILITY"


# constants
help_string = "Run it with an existing kubeconfig file while (optionally) supplying the namespace name you are interested in. For the detailed explanation of the detected risks go to the repo README."
sensitive_volumes = {"/", "/boot", "/boot/", "/dev", "/dev/", "/etc", "/etc/", "/home", "/home/", "/proc", "/proc/",
                     "/lib", "/lib/", "/root", "/root/", "/run", "/run/", "/seLinux", "/seLinux/", "/srv", "/srv/", 
                     "/var", "/var/", "/var/lib", "/var/lib/", "/var/lib/kubelet", "/var/lib/kubelet/"}
core_pattern_escape_volumes = {"/", "/proc", "/proc/", "/proc/sys", "/proc/sys/","/proc/sys/kernel", "/proc/sys/kernel/"}
log_volumes = {"/var/log", "/var/log/"}
sensitive_npd_volumes_on_gke = {"/", "/home", "/home/", "/home/kubernetes", "/home/kubernetes/", 
                                "/home/kubernetes/node-problem-detector", 
                                "/home/kubernetes/node-problem-detector/",
                                "/home/kubernetes/node-problem-detector/config",
                                "/home/kubernetes/node-problem-detector/config/"}
sensitive_npd_volumes_on_aks = {"/", "/etc", "/etc/", "/etc/node-problem-detector.d", "/etc/node-problem-detector.d/", 
                                "/etc/node-problem-detector.d/custom-plugin-monitor",
                                "/etc/node-problem-detector.d/custom-plugin-monitor/",
                                "/etc/node-problem-detector.d/system-stats-monitor",
                                "/etc/node-problem-detector.d/system-stats-monitor/",
                                "/etc/node-problem-detector.d/system-log-monitor",
                                "/etc/node-problem-detector.d/system-log-monitor/"}
powerful_standalone_capabilities = {"SYS_ADMIN", "SYS_RAWIO", "DAC_READ_SEARCH", "DAC_OVERRIDE", "SYS_BOOT",
                            "SETUID", "SETGID", "KILL", "SYS_MODULE"}
ptrace_capability = "SYS_PTRACE"
bpf_capability = "SYS_BPF"
ipc_capability = "IPC_OWNER"

read_verbs = {"*", "watch", "get", "list"}
secret_resources = {"*", "secrets"}
create_verbs = {"*", "create", "update", "patch"}
delete_verbs = {"*", "delete", "deletecollection"}
workload_resources = {"*", "pods", "daemonsets", "deployments", "replicasets", "jobs", "cronjobs", "replicationcontrollers", "statefulsets"}