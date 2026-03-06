#!/usr/bin/env python3
r"""
Container Vulnerability Report
-------------------------------------------------------------------

Report on all vulnerabilities in running containers with focus on CVSS severity:
  1. Critical CVSS score vulnerabilities (CVSS >= 9.0)
  2. High CVSS score vulnerabilities (CVSS >= 7.0 and < 9.0)
  3. Pod labels from Kubernetes pod API
  4. Node labels and annotations from node API
  5. Host/node vulnerabilities (Critical and High CVSS)
  6. Generates CSV and JSON reports

Required API Scopes:
  - Kubernetes Protection: READ
  - Falcon Container Image: READ
  - Falcon Container CLI: READ
  - Vulnerabilities: READ
  - Detections: READ (optional, for malware)

"""
import os
import sys
import json
import logging
import time
from datetime import datetime
from argparse import ArgumentParser, RawTextHelpFormatter, Namespace
from collections import defaultdict
from typing import Dict, List, Set, Optional, Tuple, Callable, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import wraps

try:
    import pandas as pd
except ImportError as no_pandas:
    raise SystemExit(
        "The pandas library must be installed.\n"
        "Install it with: python3 -m pip install pandas"
    ) from no_pandas

try:
    from tqdm import tqdm
except ImportError as no_tqdm:
    raise SystemExit(
        "The tqdm library must be installed.\n"
        "Install it with: python3 -m pip install tqdm"
    ) from no_tqdm

try:
    from falconpy import (
        KubernetesProtection,
        ContainerVulnerabilities,
        ContainerImages,
        ContainerDetections,
        SpotlightVulnerabilities,
        APIError
    )
except ImportError as no_falconpy:
    raise SystemExit(
        "The CrowdStrike FalconPy library must be installed.\n"
        "Install it with: python3 -m pip install crowdstrike-falconpy"
    ) from no_falconpy


# ============================================================================
# CONSTANTS
# ============================================================================

LIMIT_CONTAINER = 200
LIMIT_POD = 200
LIMIT_NODE = 200
LIMIT_IMAGE = 100
LIMIT_VULN = 400
LIMIT_SPOTLIGHT = 400

# CVSS Thresholds
CVSS_CRITICAL = 9.0
CVSS_HIGH = 7.0

# Retry configuration
MAX_RETRIES = 3
INITIAL_BACKOFF = 1.0  # seconds
MAX_BACKOFF = 60.0  # seconds

# Parallel processing
MAX_WORKERS = 10  # Number of concurrent API calls


# ============================================================================
# RETRY DECORATOR WITH EXPONENTIAL BACKOFF
# ============================================================================

def retry_with_backoff(max_retries: int = MAX_RETRIES,
                       initial_backoff: float = INITIAL_BACKOFF,
                       max_backoff: float = MAX_BACKOFF,
                       retryable_errors: Tuple = (Exception,)):
    """
    Decorator to retry a function with exponential backoff on failure.

    Args:
        max_retries: Maximum number of retry attempts
        initial_backoff: Initial backoff delay in seconds
        max_backoff: Maximum backoff delay in seconds
        retryable_errors: Tuple of exception types to retry on

    Returns:
        Decorated function with retry logic
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            backoff = initial_backoff
            last_exception = None

            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except retryable_errors as e:
                    last_exception = e

                    if attempt == max_retries:
                        logging.error(f"{func.__name__} failed after {max_retries} retries: {e}")
                        raise

                    # Calculate backoff with jitter
                    sleep_time = min(backoff * (2 ** attempt), max_backoff)
                    logging.warning(
                        f"{func.__name__} failed (attempt {attempt + 1}/{max_retries}), "
                        f"retrying in {sleep_time:.1f}s: {e}"
                    )
                    time.sleep(sleep_time)

            raise last_exception

        return wrapper
    return decorator


# ============================================================================
# COMMAND LINE PARSING
# ============================================================================

def parse_command_line() -> Namespace:
    """Parse and return command line arguments."""
    parser = ArgumentParser(description=__doc__, formatter_class=RawTextHelpFormatter)

    req = parser.add_argument_group("Required arguments")
    req.add_argument("-k", "--client_id",
                     help="CrowdStrike API client ID",
                     default=os.getenv("FALCON_CLIENT_ID")
                     )
    req.add_argument("-s", "--client_secret",
                     help="CrowdStrike API client secret",
                     default=os.getenv("FALCON_CLIENT_SECRET")
                     )

    parser.add_argument("-o", "--output",
                        help="Output file prefix (default: container_vuln_cvss_v2_report)",
                        default="container_vuln_cvss_v2_report"
                        )
    parser.add_argument("-b", "--base_url",
                        help="CrowdStrike base URL (US1, US2, EU1, USGOV1, AUTO)",
                        default="AUTO"
                        )
    parser.add_argument("-n", "--namespace",
                        help="Filter by specific namespace(s), comma-separated",
                        default=None
                        )
    parser.add_argument("-c", "--cluster",
                        help="Filter by specific cluster name(s), comma-separated",
                        default=None
                        )
    parser.add_argument("-v", "--verbose",
                        help="Enable verbose logging",
                        action="store_true",
                        default=False
                        )
    parser.add_argument("-d", "--debug",
                        help="Enable API debugging",
                        action="store_true",
                        default=False
                        )
    parser.add_argument("--csv-only",
                        help="Generate CSV output only (skip JSON)",
                        action="store_true",
                        default=False
                        )
    parser.add_argument("--json-only",
                        help="Generate JSON output only (skip CSV)",
                        action="store_true",
                        default=False
                        )
    parser.add_argument("--max-workers",
                        help=f"Maximum parallel workers (default: {MAX_WORKERS})",
                        type=int,
                        default=MAX_WORKERS
                        )
    parser.add_argument("--no-progress",
                        help="Disable progress bars",
                        action="store_true",
                        default=False
                        )

    parsed = parser.parse_args()

    if not parsed.client_id or not parsed.client_secret:
        parser.error("You must provide CrowdStrike API credentials")

    return parsed


# ============================================================================
# LOGGING SETUP
# ============================================================================

def setup_logging(verbose: bool, debug: bool):
    """Configure logging with appropriate level."""
    level = logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING)
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


# ============================================================================
# API CONNECTION
# ============================================================================

def connect_apis(client_id: str, client_secret: str, base_url: str, debug: bool):
    """
    Initialize API connections with error handling.

    Returns:
        Tuple of API service objects
    """
    logging.info("Connecting to CrowdStrike APIs...")

    common_args = {
        "client_id": client_id,
        "client_secret": client_secret,
        "base_url": base_url,
        "debug": debug
    }

    try:
        kube = KubernetesProtection(**common_args)
        vuln = ContainerVulnerabilities(**common_args)
        images = ContainerImages(**common_args)
        detections = ContainerDetections(**common_args)
        spotlight = SpotlightVulnerabilities(**common_args)

        logging.info("Successfully connected to all APIs")
        return kube, vuln, images, detections, spotlight
    except APIError as e:
        logging.error(f"Failed to connect: {e}")
        raise SystemExit(f"API connection failed: {e}")


# ============================================================================
# CONTAINER FETCHING
# ============================================================================

@retry_with_backoff(max_retries=3)
def fetch_containers_batch(kube: KubernetesProtection,
                           fql_filter: str,
                           offset: int,
                           limit: int) -> Tuple[List[Dict], int]:
    """
    Fetch a single batch of containers with retry logic.

    Returns:
        Tuple of (containers_list, total_count)
    """
    response = kube.read_containers_combined(
        filter=fql_filter,
        limit=limit,
        offset=offset
    )

    if response["status_code"] != 200:
        raise APIError(response["status_code"], response["body"].get("errors"))

    batch = response["body"].get("resources", [])
    total = response["body"]["meta"]["pagination"]["total"]
    return batch, total


def fetch_running_containers(kube: KubernetesProtection,
                             namespace_filter: Optional[str] = None,
                             cluster_filter: Optional[str] = None,
                             show_progress: bool = True) -> List[Dict]:
    """
    Retrieve all running containers with progress indication.

    Args:
        kube: KubernetesProtection API object
        namespace_filter: Comma-separated namespace filter
        cluster_filter: Comma-separated cluster filter
        show_progress: Whether to show progress bar

    Returns:
        List of container dictionaries
    """
    logging.info("Fetching running containers...")

    # Build filter query
    filters = ["running_status:'true'"]
    if namespace_filter:
        namespaces = namespace_filter.split(",")
        ns_filter = ",".join([f"'{ns.strip()}'" for ns in namespaces])
        filters.append(f"namespace:[{ns_filter}]")
    if cluster_filter:
        clusters = cluster_filter.split(",")
        cl_filter = ",".join([f"'{cl.strip()}'" for cl in clusters])
        filters.append(f"cluster_name:[{cl_filter}]")

    fql_filter = "+".join(filters)

    # Fetch first batch to get total count
    containers, total = fetch_containers_batch(kube, fql_filter, 0, LIMIT_CONTAINER)

    # Set up progress bar
    pbar = tqdm(total=total, desc="Fetching containers", disable=not show_progress, unit="containers")
    pbar.update(len(containers))

    # Fetch remaining batches
    offset = LIMIT_CONTAINER
    while len(containers) < total:
        try:
            batch, _ = fetch_containers_batch(kube, fql_filter, offset, LIMIT_CONTAINER)
            containers.extend(batch)
            pbar.update(len(batch))
            offset += LIMIT_CONTAINER
        except APIError as e:
            logging.error(f"Failed to fetch containers at offset {offset}: {e}")
            break  # Continue with what we have

    pbar.close()
    logging.info(f"Total running containers found: {len(containers)}")
    return containers


# ============================================================================
# POD LABEL FETCHING
# ============================================================================

def fetch_pod_labels(kube: KubernetesProtection,
                    pod_ids: Set[str],
                    show_progress: bool = True) -> Dict[str, Dict]:
    """
    Fetch pod labels for given pod IDs with progress indication.

    Args:
        kube: KubernetesProtection API object
        pod_ids: Set of pod IDs to fetch labels for
        show_progress: Whether to show progress bar

    Returns:
        Dictionary mapping pod_id to labels dict
    """
    logging.info(f"Fetching labels for {len(pod_ids)} pods...")

    pod_labels_map = {}
    offset = 0
    total = 1

    # Progress bar for pod fetching
    pbar = tqdm(total=total, desc="Fetching pod labels", disable=not show_progress, unit="pods")

    while offset < total:
        try:
            response = kube.read_pods_combined(
                limit=LIMIT_POD,
                offset=offset
            )

            if response["status_code"] == 200:
                pods = response["body"].get("resources", [])
                total = response["body"]["meta"]["pagination"]["total"]
                pbar.total = total
                pbar.refresh()

                # Extract labels for matching pods
                for pod in pods:
                    pod_id = pod.get("pod_id")
                    if pod_id in pod_ids:
                        pod_labels_map[pod_id] = pod.get("labels", {})

                offset += LIMIT_POD
                pbar.update(len(pods))
            else:
                logging.warning(f"Failed to fetch pods: {response['body'].get('errors')}")
                break
        except Exception as e:
            logging.error(f"Error fetching pods at offset {offset}: {e}")
            break

    pbar.close()
    logging.info(f"Found labels for {len(pod_labels_map)} pods")
    return pod_labels_map


# ============================================================================
# NODE METADATA FETCHING
# ============================================================================

def fetch_node_metadata(kube: KubernetesProtection,
                       node_names: Set[str],
                       show_progress: bool = True) -> Dict[str, Dict]:
    """
    Fetch node labels and annotations for given node names.

    Args:
        kube: KubernetesProtection API object
        node_names: Set of node names to fetch metadata for
        show_progress: Whether to show progress bar

    Returns:
        Dictionary mapping node_name to metadata dict (labels, annotations, agent_id)
    """
    logging.info(f"Fetching metadata for {len(node_names)} nodes...")

    node_metadata = {}
    offset = 0
    total = 1

    pbar = tqdm(total=total, desc="Fetching node metadata", disable=not show_progress, unit="nodes")

    while offset < total:
        try:
            response = kube.read_nodes_combined(
                limit=LIMIT_NODE,
                offset=offset
            )

            if response["status_code"] == 200:
                nodes = response["body"].get("resources", [])
                total = response["body"]["meta"]["pagination"]["total"]
                pbar.total = total
                pbar.refresh()

                # Extract metadata for matching nodes
                for node in nodes:
                    node_name = node.get("node_name")
                    if node_name in node_names:
                        node_metadata[node_name] = {
                            "labels": node.get("labels", {}),
                            "annotations": node.get("annotations_list", []),
                            "agent_id": node.get("agents", [{}])[0].get("aid", "") if node.get("agents") else ""
                        }

                offset += LIMIT_NODE
                pbar.update(len(nodes))
            else:
                logging.warning(f"Failed to fetch nodes: {response['body'].get('errors')}")
                break
        except Exception as e:
            logging.error(f"Error fetching nodes at offset {offset}: {e}")
            break

    pbar.close()
    logging.info(f"Found metadata for {len(node_metadata)} nodes")
    return node_metadata


# ============================================================================
# IMAGE DIGEST TO UUID MAPPING
# ============================================================================

def map_digests_to_uuids(images_api: ContainerImages,
                         image_digests: Set[str],
                         show_progress: bool = True) -> Dict[str, str]:
    """
    Map image digests to UUIDs by querying the images API.

    Args:
        images_api: ContainerImages API object
        image_digests: Set of image digests to map
        show_progress: Whether to show progress bar

    Returns:
        Dictionary mapping original digest to UUID
    """
    logging.info(f"Mapping {len(image_digests)} image digests to UUIDs...")

    # Normalize digests (strip sha256: prefix for matching)
    normalized = {}
    for d in image_digests:
        if d:
            norm = d.replace("sha256:", "") if d.startswith("sha256:") else d
            normalized[norm] = d  # Map normalized -> original

    digest_to_uuid = {}
    offset = 0
    total = 1

    pbar = tqdm(total=total, desc="Mapping image digests", disable=not show_progress, unit="images")

    while len(digest_to_uuid) < len(normalized) and offset < total:
        try:
            response = images_api.get_combined_detail(
                limit=LIMIT_IMAGE,
                offset=offset
            )

            if response["status_code"] == 200:
                images = response["body"].get("resources", [])
                total = response["body"]["meta"]["pagination"]["total"]
                pbar.total = total
                pbar.refresh()

                # Match digests to UUIDs
                for img in images:
                    img_digest = img.get("digest", "")  # Hex without sha256: prefix
                    uuid = img.get("uuid", "")

                    if img_digest in normalized and uuid:
                        original_digest = normalized[img_digest]
                        digest_to_uuid[original_digest] = uuid

                offset += LIMIT_IMAGE
                pbar.update(len(images))
            else:
                logging.warning(f"Failed to fetch images: {response['body'].get('errors')}")
                break
        except Exception as e:
            logging.error(f"Error mapping digests at offset {offset}: {e}")
            break

    pbar.close()
    logging.info(f"Mapped {len(digest_to_uuid)} digests to UUIDs")
    return digest_to_uuid


# ============================================================================
# IMAGE VULNERABILITY FETCHING (WITH PARALLEL PROCESSING)
# ============================================================================

@retry_with_backoff(max_retries=2)
def fetch_single_image_vulnerabilities(vuln: ContainerVulnerabilities,
                                       uuid: str) -> List[Dict]:
    """
    Fetch vulnerabilities for a single image with retry logic.

    Args:
        vuln: ContainerVulnerabilities API object
        uuid: Image UUID

    Returns:
        List of vulnerability dictionaries
    """
    response = vuln.read_combined_vulnerability_detail(
        id=uuid,
        limit=LIMIT_VULN
    )

    if response["status_code"] == 200:
        return response["body"].get("resources", [])
    else:
        logging.warning(f"Failed to fetch vulns for UUID {uuid}")
        return []


def fetch_all_vulnerabilities(vuln: ContainerVulnerabilities,
                              digest_to_uuid: Dict[str, str],
                              max_workers: int = MAX_WORKERS,
                              show_progress: bool = True) -> Dict[str, List[Dict]]:
    """
    Fetch ALL vulnerabilities for images using parallel processing.

    Args:
        vuln: ContainerVulnerabilities API object
        digest_to_uuid: Dictionary mapping digest to UUID
        max_workers: Maximum number of parallel workers
        show_progress: Whether to show progress bar

    Returns:
        Dictionary mapping digest to list of vulnerabilities
    """
    logging.info(f"Fetching ALL vulnerabilities for {len(digest_to_uuid)} images...")

    image_vulns = {}

    # Use ThreadPoolExecutor for parallel API calls
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_digest = {
            executor.submit(fetch_single_image_vulnerabilities, vuln, uuid): digest
            for digest, uuid in digest_to_uuid.items()
        }

        # Process results with progress bar
        pbar = tqdm(total=len(future_to_digest),
                   desc="Fetching image vulnerabilities",
                   disable=not show_progress,
                   unit="images")

        for future in as_completed(future_to_digest):
            digest = future_to_digest[future]
            try:
                vulns = future.result()
                if vulns:
                    image_vulns[digest] = vulns
                    logging.debug(f"Image {digest[:16]}...: {len(vulns)} total CVEs")
            except Exception as e:
                logging.error(f"Error fetching vulns for digest {digest[:16]}...: {e}")

            pbar.update(1)

        pbar.close()

    logging.info(f"Found {len(image_vulns)} images with vulnerabilities")
    return image_vulns


# ============================================================================
# HOST VULNERABILITY FETCHING (OPTIMIZED WITH BATCHING)
# ============================================================================

def fetch_host_vulnerabilities(spotlight: SpotlightVulnerabilities,
                                agent_ids: Set[str],
                                show_progress: bool = True) -> Dict[str, List[Dict]]:
    """
    Fetch host vulnerabilities for given agent IDs (nodes) - Critical and High CVSS.
    Optimized to query only specific agent IDs in batches.

    Args:
        spotlight: SpotlightVulnerabilities API object
        agent_ids: Set of agent IDs to fetch vulnerabilities for
        show_progress: Whether to show progress bar

    Returns:
        Dictionary mapping agent_id to list of vulnerabilities
    """
    logging.info(f"Fetching host vulnerabilities for {len(agent_ids)} nodes...")

    host_vulns = defaultdict(list)

    if not agent_ids:
        logging.warning("No agent IDs provided, skipping host vulnerability fetch")
        return dict(host_vulns)

    # Split agent IDs into batches to avoid filter length limits
    aid_list = list(agent_ids)
    batch_size = 100
    num_batches = (len(aid_list) + batch_size - 1) // batch_size

    pbar = tqdm(total=num_batches,
               desc="Fetching host vulnerabilities",
               disable=not show_progress,
               unit="batches")

    for i in range(0, len(aid_list), batch_size):
        batch = aid_list[i:i+batch_size]
        aid_filter = ",".join([f"'{aid}'" for aid in batch])
        # Filter by agent IDs AND CVSS score (>= 7.0 includes both Critical and High)
        filter_str = f"aid:[{aid_filter}]+cve.base_score:>='7.0'+status:!'closed'"

        logging.debug(f"  Fetching host vulns for batch {i//batch_size + 1}/{num_batches} ({len(batch)} nodes)")

        after = None

        try:
            while True:
                params = {
                    "filter": filter_str,
                    "limit": LIMIT_SPOTLIGHT
                }
                if after:
                    params["after"] = after

                response = spotlight.query_vulnerabilities_combined(**params)

                if response["status_code"] == 200:
                    resources = response["body"].get("resources", [])

                    # Process vulnerabilities for this batch
                    for vuln in resources:
                        aid = vuln.get("aid", "")
                        cve_data = vuln.get("cve", {})
                        cvss_score = float(cve_data.get("base_score", 0) or 0)

                        host_vulns[aid].append({
                            "cve_id": cve_data.get("id", "Unknown"),
                            "severity": vuln.get("severity", "Unknown"),
                            "cvss_score": cvss_score,
                            "cvss_category": "Critical" if cvss_score >= CVSS_CRITICAL else "High",
                            "exploited_status": cve_data.get("exploited_status", 0)
                        })

                    # Check for pagination
                    pagination = response["body"].get("meta", {}).get("pagination", {})
                    after = pagination.get("after")

                    if not after:
                        break
                else:
                    logging.warning(f"Failed to fetch host vulns for batch: {response['body'].get('errors')}")
                    break
        except Exception as e:
            logging.error(f"Error fetching host vulns for batch {i//batch_size + 1}: {e}")

        pbar.update(1)

    pbar.close()
    logging.info(f"Found host vulnerabilities for {len(host_vulns)} nodes")
    return dict(host_vulns)


# ============================================================================
# CONTAINER DETECTION FETCHING
# ============================================================================

def fetch_container_detections(detections: ContainerDetections) -> Dict[str, List[Dict]]:
    """
    Fetch malware/runtime detections for containers.

    Args:
        detections: ContainerDetections API object

    Returns:
        Dictionary mapping container_id to list of detections
    """
    logging.info("Fetching container detections...")

    container_detections = defaultdict(list)

    try:
        response = detections.read_combined_detections(
            filter="severity:['Critical','High']",
            limit=LIMIT_VULN
        )

        if response["status_code"] == 200:
            detection_list = response["body"].get("resources", [])
            for det in detection_list:
                container_id = det.get("container_id")
                if container_id:
                    container_detections[container_id].append({
                        "description": det.get("description", "Unknown"),
                        "severity": det.get("severity", "Unknown"),
                        "tactic": det.get("tactic", "Unknown")
                    })
            logging.info(f"Found detections for {len(container_detections)} containers")
        else:
            logging.warning(f"Failed to fetch detections")
    except Exception as e:
        logging.error(f"Error fetching detections: {e}")

    return dict(container_detections)


# ============================================================================
# CVE CATEGORIZATION BY CVSS SCORE
# ============================================================================

def categorize_cve_by_cvss(cve_id: str,
                           severity: str,
                           cps_rating: str,
                           cvss_score: float,
                           package: str) -> Tuple[str, str]:
    """
    Categorize a CVE and format its details based on CVSS score.

    Args:
        cve_id: CVE identifier
        severity: Severity string
        cps_rating: CPS rating
        cvss_score: CVSS score (as float)
        package: Package name and version

    Returns:
        Tuple of (category, detail_string) where category is 'critical', 'high', or 'other'
    """
    detail = f"{cve_id}|{severity}|CPS:{cps_rating}|CVSS:{cvss_score}|Pkg:{package}"

    if cvss_score >= CVSS_CRITICAL:
        return 'critical', detail
    elif cvss_score >= CVSS_HIGH:
        return 'high', detail
    else:
        return 'other', detail


# ============================================================================
# PROCESS CONTAINER IMAGE VULNERABILITIES
# ============================================================================

def process_container_image_cves(image_digest: str,
                                 image_vulns: Dict[str, List[Dict]]) -> Tuple[List[str], List[str], List[str], List[str], List[str], List[str]]:
    """
    Process vulnerabilities for a single container image and categorize by CVSS.

    Args:
        image_digest: Container image digest
        image_vulns: Dictionary of image vulnerabilities

    Returns:
        Tuple of (all_cves, critical_cves, high_cves, cve_details, critical_details, high_details)
    """
    all_cves = []
    critical_cvss_cves = []
    high_cvss_cves = []
    cve_details = []
    critical_cvss_details = []
    high_cvss_details = []

    if image_digest in image_vulns:
        for vuln in image_vulns[image_digest]:
            # Extract vulnerability data
            cve_id = vuln.get("cve_id", "Unknown")
            severity = vuln.get("severity", "Unknown")
            cps_rating = vuln.get("cps_current_rating", "Unknown")
            cvss_score = float(vuln.get("cvss_score", 0) or 0)  # Ensure float conversion
            package = vuln.get("package_name_version", "Unknown")

            # Add to all CVEs
            all_cves.append(cve_id)

            # Categorize by CVSS score
            category, detail = categorize_cve_by_cvss(cve_id, severity, cps_rating, cvss_score, package)
            cve_details.append(detail)

            if category == 'critical':
                critical_cvss_cves.append(cve_id)
                critical_cvss_details.append(detail)
            elif category == 'high':
                high_cvss_cves.append(cve_id)
                high_cvss_details.append(detail)

    return all_cves, critical_cvss_cves, high_cvss_cves, cve_details, critical_cvss_details, high_cvss_details


# ============================================================================
# PROCESS HOST VULNERABILITIES
# ============================================================================

def process_host_vulnerabilities(node_agent_id: str,
                                 host_vulns: Dict[str, List[Dict]]) -> Tuple[List[str], List[str], List[str], List[str]]:
    """
    Process host vulnerabilities and categorize by CVSS.

    Args:
        node_agent_id: Agent ID of the node
        host_vulns: Dictionary of host vulnerabilities

    Returns:
        Tuple of (host_critical_cves, host_high_cves, host_critical_details, host_high_details)
    """
    host_critical_cves = []
    host_high_cves = []
    host_critical_details = []
    host_high_details = []

    if node_agent_id in host_vulns:
        for host_vuln in host_vulns[node_agent_id]:
            cve_id = host_vuln["cve_id"]
            cvss_score = host_vuln["cvss_score"]
            detail = f"{cve_id}|CVSS:{cvss_score}|Exploited:{host_vuln['exploited_status']}"

            if cvss_score >= CVSS_CRITICAL:
                host_critical_cves.append(cve_id)
                host_critical_details.append(detail)
            else:
                host_high_cves.append(cve_id)
                host_high_details.append(detail)

    return host_critical_cves, host_high_cves, host_critical_details, host_high_details


# ============================================================================
# BUILD REPORT DATA (REFACTORED INTO SMALLER FUNCTIONS)
# ============================================================================

def build_container_record(container: Dict,
                           pod_labels_map: Dict[str, Dict],
                           node_metadata: Dict[str, Dict],
                           image_vulns: Dict[str, List[Dict]],
                           host_vulns: Dict[str, List[Dict]],
                           container_detections: Dict[str, List[Dict]]) -> Dict:
    """
    Build a single container report record with all vulnerability data.

    Args:
        container: Container dictionary
        pod_labels_map: Pod labels mapping
        node_metadata: Node metadata mapping
        image_vulns: Image vulnerabilities mapping
        host_vulns: Host vulnerabilities mapping
        container_detections: Container detections mapping

    Returns:
        Dictionary representing a single container report record
    """
    # Extract basic container info
    container_id = container.get("container_id", "")
    pod_id = container.get("pod_id", "")
    node_name = container.get("node_name", "")
    image_digest = container.get("image_digest", "")

    # Get pod labels
    pod_labels = pod_labels_map.get(pod_id, {})

    # Get node metadata
    node_meta = node_metadata.get(node_name, {})
    node_labels = node_meta.get("labels", {})
    node_annotations = node_meta.get("annotations", [])
    node_agent_id = node_meta.get("agent_id", "")

    # Process container image CVEs
    all_cves, critical_cves, high_cves, cve_details, critical_details, high_details = \
        process_container_image_cves(image_digest, image_vulns)

    # Process host vulnerabilities
    host_critical_cves, host_high_cves, host_critical_details, host_high_details = \
        process_host_vulnerabilities(node_agent_id, host_vulns)

    # Process malware detections
    malware_desc = ""
    if container_id in container_detections:
        detections = container_detections[container_id]
        malware_desc = "; ".join([f"{d['description']} ({d['severity']})" for d in detections])

    # Build the complete record
    record = {
        "container_id": container_id,
        "container_name": container.get("container_name", "Unknown"),
        "pod_name": container.get("pod_name", "Unknown"),
        "namespace": container.get("namespace", "Unknown"),
        "pod_labels": json.dumps(pod_labels),
        "node_name": node_name,
        "node_labels": json.dumps(node_labels),
        "node_annotations": json.dumps(node_annotations),
        "cluster_name": container.get("cluster_name", "Unknown"),
        "image_registry": container.get("image_registry", "Unknown"),
        "image_repository": container.get("image_repository", "Unknown"),
        "image_tag": container.get("image_tag", "Unknown"),
        "image_digest": image_digest or "Unknown",
        "total_cves": len(all_cves),
        "critical_cvss_cve_count": len(critical_cves),
        "critical_cvss_cves": "; ".join(critical_cves) if critical_cves else "None",
        "critical_cvss_cve_details": " || ".join(critical_details) if critical_details else "None",
        "high_cvss_cve_count": len(high_cves),
        "high_cvss_cves": "; ".join(high_cves) if high_cves else "None",
        "high_cvss_cve_details": " || ".join(high_details) if high_details else "None",
        "all_cves": "; ".join(all_cves) if all_cves else "None",
        "all_cve_details": " || ".join(cve_details) if cve_details else "None",
        "host_critical_cvss_cve_count": len(host_critical_cves),
        "host_critical_cvss_cves": "; ".join(host_critical_cves) if host_critical_cves else "None",
        "host_critical_cvss_cve_details": " || ".join(host_critical_details) if host_critical_details else "None",
        "host_high_cvss_cve_count": len(host_high_cves),
        "host_high_cvss_cves": "; ".join(host_high_cves) if host_high_cves else "None",
        "host_high_cvss_cve_details": " || ".join(host_high_details) if host_high_details else "None",
        "malware_detections": malware_desc if malware_desc else "None",
        "report_timestamp": datetime.now().isoformat()
    }

    return record


def build_report_data(containers: List[Dict],
                      pod_labels_map: Dict[str, Dict],
                      node_metadata: Dict[str, Dict],
                      image_vulns: Dict[str, List[Dict]],
                      host_vulns: Dict[str, List[Dict]],
                      container_detections: Dict[str, List[Dict]],
                      show_progress: bool = True) -> List[Dict]:
    """
    Build report data for ALL containers with CVSS-based filtering.
    Uses parallel processing for better performance.

    Args:
        containers: List of container dictionaries
        pod_labels_map: Pod labels mapping
        node_metadata: Node metadata mapping
        image_vulns: Image vulnerabilities mapping
        host_vulns: Host vulnerabilities mapping
        container_detections: Container detections mapping
        show_progress: Whether to show progress bar

    Returns:
        List of container report records
    """
    logging.info("Building CVSS-based report data...")

    report_data = []

    # Process containers with progress bar
    pbar = tqdm(containers,
               desc="Building report records",
               disable=not show_progress,
               unit="containers")

    for container in pbar:
        try:
            record = build_container_record(
                container,
                pod_labels_map,
                node_metadata,
                image_vulns,
                host_vulns,
                container_detections
            )
            report_data.append(record)
        except Exception as e:
            logging.error(f"Error building record for container {container.get('container_id', 'unknown')}: {e}")

    pbar.close()
    logging.info(f"Report contains {len(report_data)} containers")
    return report_data


# ============================================================================
# REPORT GENERATION
# ============================================================================

def generate_csv_report(report_data: List[Dict], output_prefix: str) -> str:
    """Generate CSV report from report data."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_filename = f"{output_prefix}_{timestamp}.csv"

    logging.info(f"Generating CSV report: {csv_filename}")
    df = pd.DataFrame(report_data)
    df.to_csv(csv_filename, index=False)

    logging.info(f"CSV report saved: {csv_filename}")
    return csv_filename


def generate_json_report(report_data: List[Dict], output_prefix: str) -> str:
    """Generate JSON report from report data with metadata."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_filename = f"{output_prefix}_{timestamp}.json"

    logging.info(f"Generating JSON report: {json_filename}")

    report = {
        "report_metadata": {
            "generated_at": datetime.now().isoformat(),
            "total_containers": len(report_data),
            "containers_with_vulns": sum(1 for r in report_data if r["total_cves"] > 0),
            "containers_with_critical_cvss": sum(1 for r in report_data if r["critical_cvss_cve_count"] > 0),
            "containers_with_high_cvss": sum(1 for r in report_data if r["high_cvss_cve_count"] > 0),
            "containers_with_host_vulns": sum(1 for r in report_data if r["host_critical_cvss_cve_count"] > 0 or r["host_high_cvss_cve_count"] > 0)
        },
        "containers": report_data
    }

    with open(json_filename, 'w') as f:
        json.dump(report, f, indent=2)

    logging.info(f"JSON report saved: {json_filename}")
    return json_filename


def print_summary(report_data: List[Dict]):
    """Print summary statistics to console."""
    total = len(report_data)
    with_vulns = sum(1 for r in report_data if r["total_cves"] > 0)
    with_critical_cvss = sum(1 for r in report_data if r["critical_cvss_cve_count"] > 0)
    with_high_cvss = sum(1 for r in report_data if r["high_cvss_cve_count"] > 0)
    with_host_critical = sum(1 for r in report_data if r["host_critical_cvss_cve_count"] > 0)
    with_host_high = sum(1 for r in report_data if r["host_high_cvss_cve_count"] > 0)
    with_malware = sum(1 for r in report_data if r["malware_detections"] != "None")

    print("\n" + "="*70)
    print("CVSS-BASED CONTAINER VULNERABILITY REPORT SUMMARY (v2)")
    print("="*70)
    print(f"Total running containers:                  {total}")
    print(f"Containers with ANY vulnerabilities:       {with_vulns}")
    print(f"Containers with Critical CVSS CVEs:        {with_critical_cvss}")
    print(f"Containers with High CVSS CVEs:            {with_high_cvss}")
    print(f"Containers on nodes with Critical CVSS:    {with_host_critical}")
    print(f"Containers on nodes with High CVSS:        {with_host_high}")
    print(f"Containers with malware detections:        {with_malware}")
    print("="*70)


# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Main execution routine with improved structure and error handling."""
    args = parse_command_line()
    setup_logging(args.verbose, args.debug)

    show_progress = not args.no_progress

    print("\n" + "="*70)
    print("CrowdStrike Falcon Container Vulnerability Report v2.0 - CVSS BASED")
    print("="*70 + "\n")

    try:
        # Connect to APIs
        kube, vuln, images, detections, spotlight = connect_apis(
            args.client_id,
            args.client_secret,
            args.base_url,
            args.debug
        )

        # Step 1: Fetch containers
        containers = fetch_running_containers(kube, args.namespace, args.cluster, show_progress)

        if not containers:
            logging.warning("No running containers found. Exiting.")
            return

        # Step 2: Extract unique identifiers
        pod_ids = set(c.get("pod_id") for c in containers if c.get("pod_id"))
        node_names = set(c.get("node_name") for c in containers if c.get("node_name"))
        image_digests = set(c.get("image_digest") for c in containers if c.get("image_digest"))

        logging.info(f"Unique pods: {len(pod_ids)}")
        logging.info(f"Unique nodes: {len(node_names)}")
        logging.info(f"Unique images: {len(image_digests)}")

        # Step 3: Fetch pod labels and node metadata
        pod_labels_map = fetch_pod_labels(kube, pod_ids, show_progress)
        node_metadata = fetch_node_metadata(kube, node_names, show_progress)

        # Step 4: Map image digests to UUIDs
        digest_to_uuid = map_digests_to_uuids(images, image_digests, show_progress)

        # Step 5: Fetch ALL image vulnerabilities (with parallel processing)
        image_vulns = fetch_all_vulnerabilities(vuln, digest_to_uuid, args.max_workers, show_progress)

        # Step 6: Extract agent IDs from nodes hosting containers
        agent_ids = set(meta.get("agent_id") for meta in node_metadata.values() if meta.get("agent_id"))

        # Step 7: Fetch host vulnerabilities (Critical and High CVSS) - optimized with batching
        host_vulns = fetch_host_vulnerabilities(spotlight, agent_ids, show_progress)

        # Step 8: Fetch container detections
        container_detections = fetch_container_detections(detections)

        # Step 9: Build report data
        report_data = build_report_data(
            containers,
            pod_labels_map,
            node_metadata,
            image_vulns,
            host_vulns,
            container_detections,
            show_progress
        )

        # Step 10: Generate reports
        csv_file = None
        json_file = None

        if not args.json_only:
            csv_file = generate_csv_report(report_data, args.output)

        if not args.csv_only:
            json_file = generate_json_report(report_data, args.output)

        # Step 11: Print summary
        print_summary(report_data)

        if csv_file:
            print(f"\nCSV Report: {csv_file}")
        if json_file:
            print(f"JSON Report: {json_file}")

        print("\nReport generation complete!\n")

    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
