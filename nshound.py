#!/usr/bin/env python3
import argparse
import logging
import sys
import json
import csv
from prettytable import prettytable
import globals
from kubernetes import client, config

# TODOs
# 1. Make it into Krew plugin
# 2. Add cgroupsv1 escape
# 3. Add sysfs escape


# file the finding - both to the output and to the findings array
def fileFinding(type, namespace_name, description, container=None,
                pod=None, principals=None, severity="HIGH", confidence="HIGH", neighbours=None):
    line = f"{type} - "
    if container is not None: 
        line += f"container {container} in "
    if pod is not None: 
        line += f"pod {pod}"
    if principals is not None:
        line += f"{principals}"
    line += f" in {namespace_name}"
    line += f" - {description}"
    if neighbours is not None:
        line += f" Pods from following namespaces reside on the same worker node: {neighbours}"
    logging.warning("FINDING: " + line)
    finding = {}
    finding['type'] = type
    finding['severity'] = severity
    finding['confidence'] = confidence
    finding['principals'] = principals
    finding['container'] = container
    finding['pod'] = pod
    finding['description'] = description
    finding['neighbours'] = neighbours
    globals.findings[namespace_name].append(finding)


def inspectContainer(p, c, ns):

    # privileged container is a game over
    if c.security_context and c.security_context.privileged is True:
        fileFinding(type=globals.Finding.CONTAINER_PRIVILEGED_ACCESS_TO_HOST,
                    severity="HIGH",
                    confidence="HIGH",
                    container=c.name,
                    pod=p.metadata.name,
                    namespace_name=ns.metadata.name,
                    neighbours=globals.node_residency_table[p.spec.node_name] - {ns.metadata.name},
                    description="Container is privileged and thus can escape to worker node and access shared secrets.")

    if c.security_context and c.security_context.capabilities is not None and c.security_context.capabilities.add is not None:

        # capabilities that dont need additional conditions to escape
        if globals.powerful_standalone_capabilities & set(c.security_context.capabilities.add):
            fileFinding(type=globals.Finding.CONTAINER_POWERFUL_CAPABILITIES, 
                        severity="HIGH",
                        confidence="MEDIUM",
                        container=c.name,
                        pod=p.metadata.name,
                        namespace_name=ns.metadata.name,
                        neighbours=globals.node_residency_table[p.spec.node_name] - {ns.metadata.name},
                        description="Container has powerful capabilities and thus can escape to worker node and access shared secrets.")

        # bpf capability means kernel-level access
        if globals.bpf_capability in c.security_context.capabilities.add:
            fileFinding(type=globals.Finding.CONTAINER_BPF_CAPABILITY,
                        severity="HIGH",
                        confidence="HIGH",
                        container=c.name,
                        pod=p.metadata.name,
                        namespace_name=ns.metadata.name,
                        neighbours=globals.node_residency_table[p.spec.node_name] - {ns.metadata.name},
                        description="Container has SYS_BPF capability allowing kernel-level access to other process resources, (f.e. packet capture and secret stealing).")

        # ptrace requires shared pid namespace
        if globals.ptrace_capability in c.security_context.capabilities.add and p.spec.host_pid == True:
            fileFinding(type=globals.Finding.CONTAINER_PTRACE_CAPABILITY,
                        severity="HIGH",
                        confidence="HIGH",
                        container=c.name,
                        pod=p.metadata.name,
                        namespace_name=ns.metadata.name,
                        neighbours=globals.node_residency_table[p.spec.node_name] - {ns.metadata.name},
                        description="Container has SYS_PTRACE capability allowing control of other namespace processes running on the same worker node.")

        # ipc requires shared ipc namespace
        if globals.ipc_capability in c.security_context.capabilities.add and p.spec.host_ipc is True:
            fileFinding(type=globals.Finding.CONTAINER_IPC_CAPABILITY,
                        severity="HIGH",
                        confidence="HIGH",
                        container=c.name,
                        pod=p.metadata.name,
                        namespace_name=ns.metadata.name,
                        neighbours=globals.node_residency_table[p.spec.node_name] - {ns.metadata.name},
                        description="Container has IPC_OWNER capability allowing control of other namespace processes running on the same worker node.")


def inspectPod(pod, ns):
    logging.info(f"\tInspecting pod {pod.metadata.name}")
    # prep pod volume mounts
    host_volumes = [v for v in pod.spec.volumes if v.host_path is not None]

    # on the other side prep all container mouns
    container_mounts = [v for c in pod.spec.containers if c.volume_mounts is not None for v in c.volume_mounts]
    if pod.spec.init_containers:
        container_mounts += [v for c in pod.spec.init_containers if c.volume_mounts is not None for v in c.volume_mounts]

    # privileged pod can escape immediately
    for c in pod.spec.containers:
        inspectContainer(pod, c, ns)
    if pod.spec.init_containers:
        for c in pod.spec.init_containers:
            inspectContainer(pod, c, ns)
    # not going to go over ephemeral cotainers as its unclear whether attacker can reliably use them

    # look for interesting volumes
    for volume in host_volumes:

        # look for NPD compromise on GKE - must be RW
        if cluster_flavor == globals.ClusterFlavor.GKE and volume.host_path.path in globals.sensitive_npd_volumes_on_gke:
            for vm in container_mounts:
                if vm.name == volume.name and (vm.read_only is False or vm.read_only is None):
                    fileFinding(type=globals.Finding.POD_ACCESS_TO_NPD_CONFIG,
                                severity="HIGH",
                                confidence="HIGH",
                                pod=pod.metadata.name,
                                namespace_name=ns.metadata.name,
                                neighbours=globals.node_residency_table[pod.spec.node_name] - {ns.metadata.name},
                                description="Pod has RW access to the node problem detector config which is equal to cluster admin.")

        # look for NPD compromise on GKE - must be RW
        if cluster_flavor == globals.ClusterFlavor.AKS and volume.host_path.path in globals.sensitive_npd_volumes_on_aks:
            for vm in container_mounts:
                if vm.name == volume.name and (vm.read_only is False or vm.read_only is None):
                    fileFinding(type=globals.Finding.POD_ACCESS_TO_NPD_CONFIG,
                                severity="HIGH",
                                confidence="HIGH",
                                pod=pod.metadata.name,
                                namespace_name=ns.metadata.name,
                                neighbours=globals.node_residency_table[pod.spec.node_name] - {ns.metadata.name},
                                description="Pod has RW access to the node problem detector config which is equal to cluster admin.")

        # look for writable mount allowing core pattern container escape
        if volume.host_path.path in globals.core_pattern_escape_volumes:
            for vm in container_mounts:
                if vm.name == volume.name and (vm.read_only is False or vm.read_only is None):
                    fileFinding(type=globals.Finding.POD_ESCAPE_CORE_PATTERN,
                                severity="HIGH",
                                confidence="HIGH",
                                pod=pod.metadata.name,
                                namespace_name=ns.metadata.name,
                                neighbours=globals.node_residency_table[pod.spec.node_name] - {ns.metadata.name},
                                description=f"Pod has access to host through sensitive volume mount {volume.host_path.path}.")

        # look for readable log mount allowing reading other pod logs
        if volume.host_path.path in globals.log_volumes:
            for vm in container_mounts:
                if vm.name == volume.name:
                    fileFinding(type=globals.Finding.POD_ACCESS_TO_LOGS,
                                severity="HIGH",
                                confidence="HIGH",
                                pod=pod.metadata.name,
                                namespace_name=ns.metadata.name,
                                neighbours=globals.node_residency_table[pod.spec.node_name] - {ns.metadata.name},
                                description=f"Pod has access to other pods logs through volume mount {volume.host_path.path}.")

        # look for general sensitive mounts allowing either escape or token/secret lookup
        if volume.host_path.path in globals.sensitive_volumes:
            fileFinding(type=globals.Finding.POD_ACCESS_TO_HOST,
                        severity="HIGH",
                        confidence="MEDIUM",
                        pod=pod.metadata.name,
                        namespace_name=ns.metadata.name,
                        neighbours=globals.node_residency_table[pod.spec.node_name] - {ns.metadata.name},
                        description=f"Pod has access to host through sensitive volume mount {volume.host_path.path}.")


if __name__ == '__main__':
    # Argument parsing
    parser = argparse.ArgumentParser(
        description='NamespaceHound is a tool that detects various ways to cross the namespace boundaries within the Kubernetes cluster.',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=globals.help_string)
    parser.add_argument("--kubeconfig", help=".kubeconfig file containing the cluster access credentials")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-n", "--namespace", help="look for escape paths from this namespace only")
    group.add_argument("-c", "--controlplane", help="show issues from kube-system", action='store_true')
    parser.add_argument("-o", "--output", help="output format - json, csv or table", type=globals.OutputFormat, choices=list(globals.OutputFormat))
    parser.add_argument("-v", "--verbose", action="store_true", help="increase output verbosity")

    args = parser.parse_args()

    # deal with verbosity print until the end of the program
    if args.verbose:
        level = logging.INFO
    else:
        level = logging.ERROR
    logging.basicConfig(format="%(message)s", level=level)

    try:
        # Configs can be set in Configuration class directly or using helper utility
        if args.kubeconfig:
            config.load_kube_config(config_file=args.kubeconfig)
        else:
            config.load_kube_config()

        # Create an instance of the Kubernetes API client
        api_client = client.ApiClient()

        # Create a CoreV1Api instance to interact with pods
        v1 = client.CoreV1Api(api_client)
        rbac_v1_api = client.RbacAuthorizationV1Api(api_client)
        version = client.VersionApi()

        # General
        logging.info(f"Cluster version: \n\t{version.get_code()}")

        # ----------------------------------
        # Cluster flavor for future
        # ----------------------------------
        try:
            nodes = v1.list_node()
            kubelet_version = nodes.items[0].status.node_info.kubelet_version
            kernel_version = nodes.items[0].status.node_info.kernel_version
            if "gke" in kubelet_version:
                cluster_flavor = globals.ClusterFlavor.GKE
            elif "eks" in kubelet_version:
                cluster_flavor = globals.ClusterFlavor.EKS
            elif "aks" in kernel_version:
                cluster_flavor = globals.ClusterFlavor.AKS
            else:
                cluster_flavor = globals.ClusterFlavor.OTHER
        except Exception:
            cluster_flavor = globals.ClusterFlavor.OTHER
        logging.info(f"Cluster flavor: {cluster_flavor}")

        # ----------------------------------
        # Prepare the node residency table
        # ----------------------------------
        all_pods = v1.list_pod_for_all_namespaces()
        for node in nodes.items:
            globals.node_residency_table[node.metadata.name] = set()
            for pod in all_pods.items:
                if pod.spec.node_name == node.metadata.name:
                    globals.node_residency_table[node.metadata.name].add(pod.metadata.namespace)

        # ----------------------------------
        # Check global anonymous access first
        # ----------------------------------
        try:
            # first real connection
            cluster_role_bindings = rbac_v1_api.list_cluster_role_binding()
        except client.ApiException:
            logging.error("Found configfile, but can't connect. No permissions?")
            sys.exit(1)

        for cluster_role_binding in cluster_role_bindings.items:
            subjects = cluster_role_binding.subjects
            if subjects is None:
                continue
            user_names = [u.name for u in subjects if u.kind == "User"]
            group_names = [g.name for g in subjects if g.kind == "Group"]

            # evaluate dangerous conditions
            anonymous_condition = "system:anonymous" in user_names or "system:unauthenticated" in group_names
            authenticated_condition = "system:authenticated" in group_names and cluster_flavor == globals.ClusterFlavor.GKE

            if not anonymous_condition and not authenticated_condition:
                continue

            role_name = cluster_role_binding.role_ref.name
            # now find out whether this role can do something non-trivial
            try:
                role = rbac_v1_api.read_cluster_role(name=role_name)
            except Exception as e:
                logging.info(f"Error: {str(e)}")
                continue

            role_rules = role.rules
            for rule in role_rules:
                rule_non_resource_urls = None if rule.non_resource_ur_ls is None else set(rule.non_resource_ur_ls)
                rule_verbs = None if rule.verbs is None else set(rule.verbs)
                rule_resources = None if rule.resources is None else set(rule.resources)

                # check for meaningful url access
                if rule_non_resource_urls is not None:
                    meaningful_urls = rule_non_resource_urls - {"/configz", "/healthz", "readiness", "/version", "/livez", "/readyz", "/version/"}
                    if len(meaningful_urls) > 0:
                        if anonymous_condition:
                            fileFinding(type=globals.Finding.RBAC_ANONYMOUS_ACCESS_TO_RESOURCES,
                                        severity="MEDIUM",
                                        confidence="LOW",
                                        namespace_name="allnamespaces",
                                        description=f"Anonymous user can {rule_verbs} {meaningful_urls} that potentially contain information from other namespaces.")
                        if authenticated_condition:
                            fileFinding(type=globals.Finding.RBAC_GOOGLE_USER_ACCESS_TO_RESOURCES,
                                        severity="MEDIUM",
                                        confidence="LOW",
                                        namespace_name="allnamespaces",
                                        description=f"Any Google user can {rule_verbs} {meaningful_urls} that potentially contain information from other namespaces.")
                    continue

                # check for reading secrets from another namespace
                if globals.read_verbs & rule_verbs and globals.secret_resources & rule_resources:
                    if anonymous_condition:
                        fileFinding(type=globals.Finding.RBAC_ANONYMOUS_ACCESS_TO_RESOURCES,
                                    severity="HIGH",
                                    confidence="HIGH",
                                    namespace_name="allnamespaces",
                                    description="Anonymous user can read secrets from any namespace.")
                    if authenticated_condition:
                        fileFinding(type=globals.Finding.RBAC_GOOGLE_USER_ACCESS_TO_RESOURCES,
                                    severity="HIGH",
                                    confidence="HIGH",
                                    namespace_name="allnamespaces",
                                    description="Any Google user can read secrets from any namespace.")

                # check for creation of workloads in another namespace
                if globals.create_verbs & rule_verbs and globals.workload_resources & rule_resources:
                    if anonymous_condition:
                        fileFinding(type=globals.Finding.RBAC_ANONYMOUS_ACCESS_TO_RESOURCES,
                                    severity="HIGH",
                                    confidence="HIGH",
                                    namespace_name="allnamespaces",
                                    description="Anonymous user can create workloads in any namespace.")
                    if authenticated_condition:
                        fileFinding(type=globals.Finding.RBAC_GOOGLE_USER_ACCESS_TO_RESOURCES,
                                    severity="HIGH",
                                    confidence="HIGH",
                                    namespace_name="allnamespaces",
                                    description="Any Google user can create workloads in any namespace.")

                # check for execution into pods from other namespaces
                if {"*", "create"} & rule_verbs and {"*", "pods/exec", "pods/attach"} & rule_resources:
                    if anonymous_condition:
                        fileFinding(type=globals.Finding.RBAC_ANONYMOUS_ACCESS_TO_RESOURCES,
                                    severity="HIGH",
                                    confidence="HIGH",
                                    namespace_name="allnamespaces",
                                    description="Anonymous user can exec/attach to pods in any namespace.")
                    if authenticated_condition:
                        fileFinding(type=globals.Finding.RBAC_GOOGLE_USER_ACCESS_TO_RESOURCES,
                                    severity="HIGH",
                                    confidence="HIGH",
                                    namespace_name="allnamespaces",
                                    description="Any Google user can exec/attach to pods in any namespace.")

                # rest of the operations - less severe
                if rule_resources is not None:
                    if anonymous_condition:
                        fileFinding(type=globals.Finding.RBAC_ANONYMOUS_ACCESS_TO_RESOURCES,
                                    severity="MEDIUM",
                                    confidence="HIGH",
                                    namespace_name="allnamespaces",
                                    description=f"Anonymous user can {rule_verbs} {rule_resources} in any namespace.")
                    if authenticated_condition:
                        fileFinding(type=globals.Finding.RBAC_GOOGLE_USER_ACCESS_TO_RESOURCES,
                                    severity="MEDIUM",
                                    confidence="HIGH",
                                    namespace_name="allnamespaces",
                                    description=f"Any Google user can {rule_verbs} {rule_resources} in any namespace.")

        # ----------------------------------
        # Separate check for fluentbit
        # ----------------------------------
        configmaps = v1.list_config_map_for_all_namespaces()
        fluentbit_configmaps = [c.metadata.name for c in configmaps.items if ("fluentbit" in c.metadata.name or "ama-logs" in c.metadata.name or "fluent-bit" in c.metadata.name or "fluentd" in c.metadata.name)]

        # Check for namespace existence
        try:
            if args.namespace:
                v1.read_namespace(name=args.namespace)
        except client.ApiException:
            logging.error(f"No such namespace {args.namespace}")

        # ----------------------------------
        # Main namespaces loop
        # ----------------------------------
        namespaces = v1.list_namespace()
        for ns in namespaces.items:

            # If namespace specified - skip all others
            if args.namespace and ns.metadata.name != args.namespace:
                continue

            # If namespace specified - skip all others
            if not args.controlplane and ns.metadata.name == "kube-system":
                continue

            logging.info(f"\nInspecting namespace {ns.metadata.name}")
            globals.findings[ns.metadata.name] = []

            # First check for resource quotas against DOS
            resource_quotas = v1.list_namespaced_resource_quota(namespace=ns.metadata.name)
            quota_exists = False
            for quota in resource_quotas.items:
                if quota.spec.hard:
                    quota_exists = True
                    break
            # assumption here the lack of any hard quota equals problem
            if not quota_exists:
                fileFinding(type=globals.Finding.DOS_NO_QUOTA,
                            severity="LOW",
                            confidence="MEDIUM",
                            namespace_name=ns.metadata.name,
                            description="There is no resource limits on this namespace - if attacker controls resource creation it can cause DoS in other namespaces.")

            # Check the anonymous access to this namespace resources
            role_bindings = rbac_v1_api.list_namespaced_role_binding(namespace=ns.metadata.name)
            for role_binding in role_bindings.items:
                subjects = role_binding.subjects
                role_name = role_binding.role_ref.name
                if subjects is None:
                    continue
                user_names = [u.name for u in subjects if u.kind == "User"]
                group_names = [g.name for g in subjects if g.kind == "Group"]

                if "system:anonymous" not in user_names and "system:unauthenticated" not in group_names:
                    continue

                # now find out whether this role can do something non-trivial
                try:
                    role = rbac_v1_api.read_namespaced_role(name=role_name, namespace=ns.metadata.name)
                except Exception as e:
                    logging.info(f"Error: {str(e)}")
                    continue

                role_rules = role.rules
                for rule in role_rules:
                    rule_verbs = None if rule.verbs is None else set(rule.verbs)
                    rule_resources = None if rule.resources is None else set(rule.resources)

                    # check for reading secrets from another namespace
                    if globals.read_verbs & rule_verbs and globals.secret_resources & rule_resources:
                        fileFinding(type=globals.Finding.RBAC_ANONYMOUS_ACCESS_TO_RESOURCES,
                                    severity="HIGH",
                                    confidence="HIGH",
                                    namespace_name=ns.metadata.name,
                                    principals=active_principals,
                                    description=f"Anonymous user can read secrets from {ns.metadata.name} namespace.")

                    # check for creation of workloads in another namespace
                    if globals.create_verbs & rule_verbs and globals.workload_resources & rule_resources:
                        fileFinding(type=globals.Finding.RBAC_ANONYMOUS_ACCESS_TO_RESOURCES,
                                    severity="HIGH",
                                    confidence="HIGH",
                                    principals=active_principals,
                                    namespace_name=ns.metadata.name,
                                    description=f"Anonymous user can create workloads in {ns.metadata.name} namespace.")

                    # check for execution into pods from other namespaces
                    if {"*", "create"} & rule_verbs and {"*", "pods/exec", "pods/attach"} & rule_resources:
                        fileFinding(type=globals.Finding.RBAC_ANONYMOUS_ACCESS_TO_RESOURCES,
                                    severity="HIGH",
                                    confidence="HIGH",
                                    principals=active_principals,
                                    namespace_name=ns.metadata.name,
                                    description=f"Anonymous user can exec/attach to pods in {ns.metadata.name} namespace.")

                    # rest of the operations - less severe
                    if rule_resources is not None:
                        fileFinding(type=globals.Finding.RBAC_ANONYMOUS_ACCESS_TO_RESOURCES,
                                    severity="MEDIUM",
                                    confidence="HIGH",
                                    namespace_name=ns.metadata.name,
                                    description=f"Anonymous user can {rule_verbs} {rule_resources} in {ns.metadata.name} namespace.")

            # Roles
            # role_bindings = rbac_v1_api.list_namespaced_role_binding(namespace=ns.metadata.name)
            namespace_service_accounts = v1.list_namespaced_service_account(namespace=ns.metadata.name)

            # Find the relavant bindings for this namespace
            for sa in namespace_service_accounts.items:
                for cluster_role_binding in cluster_role_bindings.items:
                    subjects = cluster_role_binding.subjects
                    role_name = cluster_role_binding.role_ref.name
                    if subjects is None:
                        continue
                    service_account_names = [sa.name for sa in subjects if sa.kind == "ServiceAccount"]
                    user_names = [u.name for u in subjects if u.kind == "User"]
                    group_names = [g.name for g in subjects if g.kind == "Group"]

                    # skip the irrelevant clusterrolebindings
                    if sa.metadata.name not in service_account_names:
                        continue

                    active_principals = []
                    if service_account_names:
                        logging.info(f"\t\tClusterRole: {role_name}")
                        logging.info(f"\t\tService Accounts: {', '.join(service_account_names)}")
                        active_principals.extend(service_account_names)
                    if user_names:
                        logging.info(f"\t\tClusterRole: {role_name}")
                        logging.info(f"\t\tUsers: {', '.join(user_names)}")
                        active_principals.extend(user_names)
                    if group_names:
                        logging.info(f"\t\tClusterRole: {role_name}")
                        logging.info(f"\t\tGroups: {', '.join(group_names)}")
                        active_principals.extend(group_names)

                    # now find out what this role can do
                    try:
                        role = rbac_v1_api.read_cluster_role(name=role_name)
                    except Exception as e:
                        logging.info(f"Error: {str(e)}")
                        continue

                    role_rules = role.rules
                    for rule in role_rules:
                        if rule.resource_names is not None:
                            logging.info(f"\t\t\tThis role can {rule.verbs} {rule.resources}, but only on {rule.resource_names} ")
                        elif rule.non_resource_ur_ls is not None:
                            logging.info(f"\t\t\tThis role can {rule.verbs} {rule.non_resource_ur_ls} URLs")
                        else:
                            logging.info(f"\t\t\tThis role can {rule.verbs} {rule.resources}")

                        # prepare all the permission sets for analysis
                        rule_verbs = None if rule.verbs is None else set(rule.verbs)
                        rule_resources = None if rule.resources is None else set(rule.resources)
                        rule_non_resource_urls = None if rule.non_resource_ur_ls is None else set(rule.non_resource_ur_ls)
                        rule_resource_names = None if rule.resource_names is None else set(rule.resource_names)

                        # check for the existence of "interesting" URLs, not just /healthz etc.
                        if rule_non_resource_urls:
                            if len(rule_non_resource_urls - {"/configz", "/healthz", "/readiness", "/version", "/livez", "/readyz", "/version/"}) > 0:
                                fileFinding(type=globals.Finding.RBAC_SHARED_URLS,
                                            severity="MEDIUM",
                                            confidence="HIGH",
                                            namespace_name=ns.metadata.name,
                                            principals=active_principals,
                                            description=f"Principals can access {rule_non_resource_urls} - URLs that potentially contain information from other namespaces.")
                                continue

                        # check for reading secrets from another namespace
                        if globals.read_verbs & rule_verbs and globals.secret_resources & rule_resources:
                            fileFinding(type=globals.Finding.RBAC_SECRETS_STEALING,
                                        severity="HIGH",
                                        confidence="HIGH",
                                        namespace_name=ns.metadata.name,
                                        principals=active_principals,
                                        description="Principals can read secrets from another namespace.")

                        # check for creation of workloads in another namespace
                        if globals.create_verbs & rule_verbs and globals.workload_resources & rule_resources:
                            fileFinding(type=globals.Finding.RBAC_WORKLOAD_CREATION,
                                        severity="HIGH",
                                        confidence="HIGH",
                                        principals=active_principals,
                                        namespace_name=ns.metadata.name,
                                        description="Principals can create workloads in another namespace.")

                        # check for execution into pods from other namespaces
                        if {"*", "create"} & rule_verbs and {"*", "pods/exec", "pods/attach"} & rule_resources:
                            fileFinding(type=globals.Finding.RBAC_POD_EXECUTION,
                                        severity="HIGH",
                                        confidence="HIGH",
                                        principals=active_principals,
                                        namespace_name=ns.metadata.name,
                                        description="Principals can exec/attach to pods in another namespace.")

                        # check for execution into pods from other namespaces
                        if {"create"} & rule_verbs and {"pods/eviction"} & rule_resources:
                            fileFinding(type=globals.Finding.RBAC_POD_EVICTION,
                                        severity="LOW",
                                        confidence="HIGH",
                                        principals=active_principals,
                                        namespace_name=ns.metadata.name,
                                        description="Principals can evict pods in another namespace.")

                        # check for creation / update of configmap in another namespace
                        if globals.create_verbs & rule_verbs and {"*", "configmaps"} & rule_resources:
                            # if the rule is constrained on the specific CM names we need to see whether they belong to this NS or another
                            if rule_resource_names:
                                for name in rule_resource_names:
                                    try:
                                        v1.read_namespaced_config_map(namespace=ns.metadata.name, name=name)
                                    except Exception:
                                        # this means the configmap is owned by a different namespace
                                        fileFinding(type=globals.Finding.RBAC_CONFIGMAP_SMASHING,
                                                    severity="MEDIUM",
                                                    confidence="HIGH",
                                                    principals=active_principals,
                                                    namespace_name=ns.metadata.name,
                                                    description=f"Principals can create / update configmap in another namespace, but only on {rule_resource_names}.")
                                        continue
                                if rule_resource_names & fluentbit_configmaps and cluster_flavor != globals.ClusterFlavor.GKE:
                                    fileFinding(type=globals.Finding.RBAC_LOG_EXFILTRATION,
                                                severity="HIGH",
                                                confidence="HIGH",
                                                principals=active_principals,
                                                namespace_name=ns.metadata.name,
                                                description="Principals can redirect and control fluentbit logs and executions in another namespace.")
                            else:
                                fileFinding(type=globals.Finding.RBAC_CONFIGMAP_SMASHING,
                                            severity="MEDIUM",
                                            confidence="HIGH",
                                            principals=active_principals,
                                            namespace_name=ns.metadata.name,
                                            description="Principals can update configmap in another namespace.")
                                if len(fluentbit_configmaps) > 0 and cluster_flavor != globals.ClusterFlavor.GKE:
                                    fileFinding(type=globals.Finding.RBAC_LOG_EXFILTRATION,
                                                severity="HIGH",
                                                confidence="HIGH",
                                                principals=active_principals,
                                                namespace_name=ns.metadata.name,
                                                description="Principals can redirect and control fluentbit logs and executions in another namespace.")

                        # check for creation / update of mutatingwebhookconfigurations as a possible sidecar injection attack
                        if globals.create_verbs & rule_verbs and {"*", "mutatingwebhookconfigurations"} & rule_resources:
                            if rule_resource_names:
                                fileFinding(type=globals.Finding.RBAC_WEBHOOK_MANIPULATION,
                                            severity="HIGH",
                                            confidence="MEDIUM",
                                            principals=active_principals,
                                            namespace_name=ns.metadata.name,
                                            description=f"Principals can update mutatingwebhookconfigurations and potentially inject a sidecar container, but only on {rule_resource_names}.")
                            else:
                                fileFinding(type=globals.Finding.RBAC_WEBHOOK_MANIPULATION,
                                            severity="HIGH",
                                            confidence="HIGH",
                                            principals=active_principals,
                                            namespace_name=ns.metadata.name,
                                            description="Principals can update mutatingwebhookconfigurations and potentially inject a sidecar container.")

                        # check for creation / update of validatingwebhookconfigurations as a possible sidecar secret exfiltration attack
                        if globals.create_verbs & rule_verbs and {"*", "validatingwebhookconfigurations"} & rule_resources:
                            if rule_resource_names:
                                fileFinding(type=globals.Finding.RBAC_SECRETS_SMASHING,
                                            severity="HIGH",
                                            confidence="MEDIUM",
                                            principals=active_principals,
                                            namespace_name=ns.metadata.name,
                                            description=f"Principals can update validatingwebhookconfigurations and potentially steal secrets, but only on {rule_resource_names}.")
                            else:
                                fileFinding(type=globals.Finding.RBAC_SECRETS_SMASHING,
                                            severity="HIGH",
                                            confidence="HIGH",
                                            principals=active_principals,
                                            namespace_name=ns.metadata.name,
                                            description="Principals can update validatingwebhookconfigurations and potentially steal secrets.")

                        # check for deletion of workloads
                        if globals.delete_verbs & rule_verbs and globals.workload_resources & rule_resources:
                            if rule_resource_names:
                                fileFinding(type=globals.Finding.RBAC_WORKLOAD_DELETION,
                                            severity="MEDIUM",
                                            confidence="HIGH",
                                            principals=active_principals,
                                            namespace_name=ns.metadata.name,
                                            description=f"Principals can delete workloads in another namespace but only {rule_resource_names}.")
                            else:
                                fileFinding(type=globals.Finding.RBAC_WORKLOAD_DELETION,
                                            severity="MEDIUM",
                                            confidence="HIGH",
                                            principals=active_principals,
                                            namespace_name=ns.metadata.name,
                                            description="Principals can delete workloads in another namespace.")

            # ----------------------------------
            # Main pods loop
            # ----------------------------------
            pods = v1.list_namespaced_pod(namespace=ns.metadata.name)
            for pod in pods.items:
                inspectPod(pod, ns)
            logging.info("")

        # ----------------------------------
        # Deduplication - its better to go through once than check every time before filing
        # ----------------------------------
        for ns in globals.findings.keys():
            new_list = []
            for finding in globals.findings[ns]:
                if finding not in new_list:
                    new_list.append(finding)
            globals.findings[ns] = new_list

        if args.output == globals.OutputFormat.table or args.output == globals.OutputFormat.html:
            headers = ['Namespace', 'Severity', 'Confidence', 'Principals', 'Container', 'Pod', 'Type', 'Description', 'Neighbours']
            t = prettytable.PrettyTable(headers)
            t.title = 'Findings Table'
            t.align = 'l'
            t.valign = 't'
            t.max_width = 50
            for ns in globals.findings.keys():
                for finding in globals.findings[ns]:
                    t.add_row(row=[ns, finding['severity'], finding['confidence'], finding['principals'], finding['container'], finding['pod'], finding['type'].value, finding['description'], finding['neighbours']])
            if args.output == globals.OutputFormat.html:
                to_save = t.get_html_string(format=True)
                print(to_save)
            else:
                print(t)
        elif args.output == globals.OutputFormat.csv:
            w = csv.writer(sys.stdout)
            w.writerow(['Namespace', 'Severity', 'Confidence', 'Principals', 'Container', 'Pod', 'Type', 'Description', 'Neighbours'])
            for ns in globals.findings.keys():
                for finding in globals.findings[ns]:
                    w.writerow([ns, finding['severity'], finding['confidence'], finding['principals'], finding['container'], finding['pod'], finding['type'].value, finding['description'], finding['neighbours']])
        else:
            print(json.dumps(globals.findings, indent=4, cls=globals.SetEncoder))

    except Exception as e:
        logging.error(f"Error: {str(e)}")
        sys.exit(1)
