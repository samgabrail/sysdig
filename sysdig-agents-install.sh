#Update the access_key below
access_key=

msg "*******************Creating namespace sysdig-agents*******************"
kubectl create namespace sysdig-agents

msg "*******************creating secret for access_key*******************"
kubectl create secret generic sysdig-agent --from-literal=access-key=$access_key -n sysdig-agents

msg "*******************creating clusterrole*******************"
kubectl apply -f agents/sysdig-agent-clusterrole.yaml -n sysdig-agents

msg "*******************creating service account*******************"
kubectl create serviceaccount sysdig-agent -n sysdig-agents

msg "*******************Creating clusterrole binding*******************"
kubectl create clusterrolebinding sysdig-agent --clusterrole=sysdig-agent --serviceaccount=sysdig-agents:sysdig-agent

msg "*******************Deploying Agent Config*******************"
kubectl apply -f agents/sysdig-agent-configmap.yaml -n sysdig-agents

msg "*******************Deploying Agents*******************"
kubectl apply -f agents/sysdig-agent-daemonset-v2.yaml -n sysdig-agents

msg "*******************It will take about two minutes for the agents to come up.  HAPPY HACKING*******************"
