#!/bin/bash

set -e

# Check for required input arguments: namespace and pod name
if [ $# -ne 2 ]; then
  echo "Usage: $0 <namespace> <pod_name>"
  exit 1
fi

NAMESPACE="$1"
POD_NAME="$2"
OUTPUT_FILE="baseline_${POD_NAME}.json"
echo "{}" > "$OUTPUT_FILE"

# Wait for pod to be created
echo "[*] Waiting for pod '$POD_NAME' in namespace '$NAMESPACE' to be created..."
while ! kubectl get pod "$POD_NAME" -n "$NAMESPACE" &>/dev/null; do
  sleep 1
done

# Function to add pod execution profile to JSON
add_to_json() {
  local POD_NAME=$1
  local PROFILE=$2
  jq --arg pod "$POD_NAME" --argjson data "$PROFILE" '.[$pod] = $data' "$OUTPUT_FILE" > tmp.$$.json && mv tmp.$$.json "$OUTPUT_FILE"
}

# Function to profile a pod
profile_pod() {
  local POD_NAME=$1
  echo "[*] Profiling pod: $POD_NAME"

  # Get container ID from the pod's status
  local CONTAINER_ID=$(kubectl get pod "$POD_NAME" -n "$NAMESPACE" -o jsonpath='{.status.containerStatuses[0].containerID}' | cut -d '/' -f3)
  [ -z "$CONTAINER_ID" ] && { echo "Error: No container ID for pod $POD_NAME"; return; }

  # Get container main PID using crictl
  local PID=$(crictl inspect "$CONTAINER_ID" | jq '.info.pid')
  [ -z "$PID" ] && { echo "Error: No PID for container $CONTAINER_ID"; return; }

  echo "Container main PID: $PID"
 
  # Get cgroup path to find the container's PIDs
  local CGROUP_PATH=$(awk -F':' '{print $3}' /proc/$PID/cgroup)
  local FULL_CGROUP_PROCS="/sys/fs/cgroup${CGROUP_PATH}/cgroup.procs"

  # Fallback to an alternate path if the first one doesn't exist
  # Reason: cgroup layout varies by runtime and OS (e.g., cgroup v1 vs v2), so the path may differ.
  
  if [ ! -f "$FULL_CGROUP_PROCS" ]; then
    FULL_CGROUP_PROCS="/sys/fs/cgroup/pids$(grep "pids" /proc/"$PID"/cgroup | awk -F ':' '{print $3}')/tasks"
    if [ ! -f "$FULL_CGROUP_PROCS" ]; then
      echo "Error: cgroup.procs file not found for pod $POD_NAME in either location"
      echo "$FULL_CGROUP_PROCS"
      return
    fi
  fi

  local POD_PROCESSES="[]"

  while read -r TASK_PID; do
    [ -z "$TASK_PID" ] && continue

    # Extract execution attributes
    local EXE=$(cat /proc/$TASK_PID/cmdline | tr '\0' '\n' | head -n 1)
    local EXEPATH=$(readlink /proc/$TASK_PID/exe 2>/dev/null || echo "unknown")
    local PROCNAME=$(cat /proc/$TASK_PID/comm 2>/dev/null || echo "unknown")
    local CWD=$(readlink /proc/$TASK_PID/cwd 2>/dev/null || echo "unknown")
    if [ "$CWD" != "unknown" ]; then
       CWD="${CWD%/}/"
    fi
    
    local EXE_INO="unknown"
    if [ -n "$EXEPATH" ] && [ "$EXEPATH" != "unknown" ]; then
      EXE_INO=$(stat -c '%i' "/proc/$TASK_PID/root/$EXEPATH" 2>/dev/null || echo "unknown")
    fi

    # Append execution attributes to pod profile
    if [ -n "$EXE" ] && [ "$EXEPATH" != "unknown" ]; then
      POD_PROCESSES=$(echo "$POD_PROCESSES" | jq --arg exe "$EXE" --arg exepath "$EXEPATH" --arg procname "$PROCNAME" --arg cwd "$CWD" --arg exeino "$EXE_INO" '. + [{exe: $exe, exepath: $exepath, procname: $procname, cwd: $cwd, exe_inode: $exeino}]')
    fi
  done < "$FULL_CGROUP_PROCS"

  add_to_json "$POD_NAME" "$POD_PROCESSES"
}

# Wait for pod to be Ready
READY=""
echo "[*] Waiting for pod '$POD_NAME' to become Ready..."
while [ "$READY" != "True" ]; do
  READY=$(kubectl get pod "$POD_NAME" -n "$NAMESPACE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "False")
  sleep 1
done

echo "[+] Pod $POD_NAME is Ready."
profile_pod "$POD_NAME"
echo "Baseline saved to $OUTPUT_FILE"
