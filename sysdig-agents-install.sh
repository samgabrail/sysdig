#Update the access_key below
access_key=

echo "*******************Creating namespace sysdig-agents*******************"
kubectl create namespace sysdig-agents

echo "*******************creating secret for access_key*******************"
kubectl create secret generic sysdig-agent --from-literal=access-key=$access_key -n sysdig-agents

echo "*******************creating clusterrole*******************"
kubectl apply -f sysdig-agent-clusterrole.yaml -n sysdig-agents

echo "*******************creating service account*******************"
kubectl create serviceaccount sysdig-agent -n sysdig-agents

echo "*******************Creating clusterrole binding*******************"
kubectl create clusterrolebinding sysdig-agent --clusterrole=sysdig-agent --serviceaccount=sysdig-agents:sysdig-agent

echo "*******************Deploying Agent Config*******************"
kubectl apply -f sysdig-agent-configmap.yaml -n sysdig-agents

echo "*******************Deploying Agents*******************"
kubectl apply -f sysdig-agent-daemonset-v2.yaml -n sysdig-agents

echo "*******************It will take about two minutes for the agents to come up.  HAPPY HACKING*******************"
