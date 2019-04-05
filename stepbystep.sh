#!/bin/bash

# Sysdig Cloud installer. This utility, can operate in three differene modes - AWS Instance bring up, 
# Kube environment installation and Sysdigcloud platform installation.  

##############################
###### Installer Params ######
##############################
saved_args="$@"
instance_name=""
script_name=$(basename "$0")
export LC_ALL=en_US.utf8
_dist=rhel
##############################
### Sysdig platform Params ###
##############################
api_port="30443"
collector_port="31443"
mysql_pod=""
install_agent=0
license_file="license.txt"
backend_version=""
agent_version=""
# By Default we are going to bring up an AWS instance, install K8s and then Sysdig
install_type="sdc"

####################################

##########################################################################################################################
# K8S Env Bringup
# 1. This part assume running on the target host
# 2. Local PV will be used for any stateful service. PV and PVC will be created on the fly 
##########################################################################################################################

pv_template_txt="
apiVersion: v1
kind: PersistentVolume
metadata:
  name: <PV-NAME>
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: <PV-NAME>
  capacity:
    storage: <PV-SIZE>
  hostPath:
    path: /mnt/data/sdc/<PV-NAME>/
"



##########################################################################################################################
# Helper functions
##########################################################################################################################

function env_cleanup()
{
    echo " Cleaning up any kube remains and setting up a single master Kube..."
    $pkg_update
    $pkg_remove draios-agent
    kubeadm reset -f
    $pkg_remove kubeadm kubectl kubelet
}


function cmd_running_pods()
{
    kubectl get pods  | grep Running 2>&1 >/dev/null
}

function cmd_mysql_pod_running()
{
    kubectl get pods | grep mysql | grep Running 2>&1 >/dev/null
}


function exec_mysql_cmd()
{
    kubectl  exec $mysql_pod -- mysql --password=change_me --database=draios -e "$1" 2>/tmp/sysdig_util.err | tail -1  
}

sp="/-\|"
sc=0
function spin() {
    printf "\b${sp:sc++:1}"
    ((sc==${#sp})) && sc=0
}
function endspin() {
    printf "\r%s\n" "$@"
    sp="/-\|"
    sc=0
}

function wait_for_cmd()
{
    str=$(echo $1 | sed 's/cmd_//g')
    echo "Waiting for the following command - $str"

    eval $1 >/dev/null 2>&1
    x=$?
    while [ $x -ne 0 ]; do
        eval $1 >/dev/null 2>&1
        x=$?
        spin
        sleep 2
    done
    endspin
}

function fn_exists()
{
    LC_ALL=C type $1 | grep -q 'shell function' 
}

function create_pv()
{
    file=$1
    s="${file%/*}"
    pv_name="pv-${s##*/}"
    pv_size=$(grep storage: $file | cut -d":" -f2)
    echo "Creating PV $pv_name with size $pv_size for file $file"
    mkdir -p /mnt/data/sdc/$pv_name
    cat ../pv_template.yaml | sed -e "s/<PV-NAME>/$pv_name/g" | sed -e "s/<PV-SIZE>/$pv_size/g" | kubectl ${NS_OPTS} create -f -    >/dev/null
    sed -i -e "s/<INSERT_YOUR_STORAGE_CLASS_NAME>/$pv_name/g" $1
}

function k8s_apply()
{
    [ ! -f $1 ] && echo "Skipping k8s apply for non existing file - ${1}! " && return
    grep "<INSERT_YOUR_STORAGE_CLASS_NAME>" $1 > /dev/null && create_pv $1
    # For a one-box poc, only one replica for now
    sed -E -i.bak 's/replicas:[ ]*[0-9]+/replicas: 1/g' $1
    kubectl create -f $1  > /dev/null
    [ $? -ne 0 ] && echo "Error $? - something bad happened. Exiting!" && exit 1
}



#function main()

pkg_update='sudo yum -y -q update'
pkg_install='sudo yum -y -q install'
pkg_remove='sudo yum -y -q remove'

$pkg_install psmisc
sleep 10
#env_cleanup
echo "Updating pkg manager and installing deps"

$pkg_update >/dev/null 2>&1
$pkg_install jq  >/dev/null 2>&1
$pkg_install figlet >/dev/null 2>&1

### Setup Kube per platform ###  
$pkg_install epel-release -y 
$pkg_install install firewalld jq git figlet wget
cat <<EOF > /etc/yum.repos.d/kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=https://packages.cloud.google.com/yum/repos/kubernetes-el7-x86_64
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://packages.cloud.google.com/yum/doc/yum-key.gpg https://packages.cloud.google.com/yum/doc/rpm-package-key.gpg
exclude=kube*
EOF

# Set SELinux in permissive mode (effectively disabling it)
setenforce 0
sed -i 's/^SELINUX=enforcing$/SELINUX=permissive/' /etc/selinux/config

sudo yum install -y kubelet kubeadm kubectl --disableexcludes=kubernetes

sudo systemctl enable --now kubelet 
cat <<EOF >  /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
EOF
sysctl --system
sudo yum install -y yum-utils device-mapper-persistent-data lvm2

yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
yum-config-manager --disable download.docker.com_linux_centos_docker-ce.rpm
sudo yum update -y
sudo yum install –y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
yum-config-manager --enable rhui-REGION-rhel-server-extras
sudo yum install -y docker-ce
local cmd=""
cmd+=${_dist} 
cmd+="_env_setup"
local to_exec=`echo $cmd | tr '[:upper:]' '[:lower:]'`
!fn_exists $cmd  && echo "Error! $cmd not implemented yet" && exit 1
echo "Setting up kube using - $to_exec"
$to_exec
###############################

figlet -c -f big Sysdig Platform POC Box Installer 

### Setup Docker ###
echo "Installing Docker..."

curl -fsSL https://get.docker.com -o get-docker.sh  
sh get-docker.sh  >/dev/null 2>&1
usermod -aG docker $USER  >/dev/null 2>&1
sudo systemctl unmask docker.service  >/dev/null 2>&1
sudo systemctl unmask docker.socket   >/dev/null 2>&1
sudo systemctl enable docker.service  >/dev/null 2>&1
sudo systemctl start docker.service   >/dev/null 2>&1

echo "Waiting for Docker to load"
sleep 10

echo "Setting up Kube..."
kubeadm reset -f >/dev/null

sudo systemctl enable kubelet.service
sudo systemctl start kubelet.service
kubeadm init     >/dev/null

mkdir -p $HOME/.kube
cp -f  /etc/kubernetes/admin.conf $HOME/.kube/config
chown $(id -u):$(id -g) $HOME/.kube/config
kubectl taint nodes --all node-role.kubernetes.io/master-  >/dev/null

echo "Setting up kube net..."
sysctl net.bridge.bridge-nf-call-iptables=1
wget  -O net.yaml https://cloud.weave.works/k8s/net?k8s-version=$(kubectl version | base64 | tr -d '\n') 2>/dev/null

kubectl apply -f ./net.yaml > /dev/null

sudo systemctl enable kubelet.service

echo "Cleaning up....and installing Sysdigcloud"
#Clean up first
rm -rf sysdigcloud-kubernetes
kubectl delete daemonsets,replicasets,services,deployments,pods,configmaps,secret,pvc,rc,sc,pv --all  > /dev/null
kubectl delete namespace sysdigcloud > /dev/null

kubectl create namespace sysdigcloud  > /dev/null
kubectl config set-context --current --namespace sysdigcloud > /dev/null

echo "Downloading sysdigcloud-k8s..."
git clone https://github.com/draios/sysdigcloud-kubernetes.git -q
pushd sysdigcloud-kubernetes
    git checkout v1630 -q
popd

license_key=$(grep license $license_file | cut -d ':' -f 2 | sed 's/ //g')
pull_secret=$(grep pull $license_file | cut -d ':' -f 2 | sed 's/ //g')

sed -i.bak 's/sysdigcloud.license: ""/sysdigcloud.license: '"${license_key}"'/' sysdigcloud-kubernetes/sysdigcloud/config.yaml
sed -i.bak 's/<PULL_SECRET>/'"${pull_secret}"'/g' sysdigcloud-kubernetes/sysdigcloud/pull-secret.yaml

pushd sysdigcloud-kubernetes
    echo "Setting secrets"

    k8s_apply sysdigcloud/config.yaml
    k8s_apply sysdigcloud/pull-secret.yaml
    k8s_apply ./sysdigcloud/scanning-secrets.yaml
    k8s_apply ./sysdigcloud/anchore-secrets.yaml

    openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 -subj "/C=US/ST=CA/L=SanFrancisco/O=ICT/CN=onprem.sysdigcloud.com" -keyout server.key -out server.crt   >/dev/null 2>&1
    kubectl create secret tls sysdigcloud-ssl-secret --cert=server.crt --key=server.key > /dev/null
    echo "Deploying datastores"
    # We deploy MySQL first
    k8s_apply datastores/as_kubernetes_pods/manifests/mysql/mysql-deployment.yaml

    # wait for pods to come up
    kubectl get pods | grep mysql | grep Running 2>&1 >/dev/null

    # Cassandra replicas number will be reduced to 1 as part of the apply process. PV will be created on the fly
    k8s_apply datastores/as_kubernetes_pods/manifests/cassandra/cassandra-service.yaml
    k8s_apply datastores/as_kubernetes_pods/manifests/cassandra/cassandra-statefulset.yaml

    k8s_apply datastores/as_kubernetes_pods/manifests/elasticsearch/elasticsearch-service.yaml
    # Yet another hack - we need to align the number below with the replicas num, and since we are limiting the replicas to 1, this needs 
    # to change as well. PV will be created on the fly
    sed -i.bak 's/value: "3"/value: "1"/g' datastores/as_kubernetes_pods/manifests/elasticsearch/elasticsearch-statefulset.yaml
    k8s_apply datastores/as_kubernetes_pods/manifests/elasticsearch/elasticsearch-statefulset.yaml

    k8s_apply datastores/as_kubernetes_pods/manifests/redis/redis-deployment.yaml

    k8s_apply ./datastores/as_kubernetes_pods/manifests/postgres/postgres-service.yaml
    k8s_apply ./datastores/as_kubernetes_pods/manifests/postgres/postgres-statefulset.yaml
    # Ugly hack for now. This needs to be replaced with a command to make sure the datastores are available. 
    # Init containers would be a better approach here, till then... we will wait.  
    echo "Initializing Datastores..."
    sleep 20

    #wait for pods to come up
    kubectl get pods  | grep Running 2>&1 >/dev/null
    echo " Setting up core backend components"
    k8s_apply sysdigcloud/sdc-api.yaml
    k8s_apply sysdigcloud/sdc-collector.yaml
    k8s_apply sysdigcloud/sdc-worker.yaml

    k8s_apply ./sysdigcloud/api-clusterip-service.yaml
    # Map the default collector port to a local 31443 port
    sed -i.bak 's/.*6443.*/&'$'\\\n      nodePort: 31443/' ./sysdigcloud/collector-nodeport-service.yaml
    k8s_apply ./sysdigcloud/collector-nodeport-service.yaml

    if [ ! -z $backend_version ]; then
        echo " Deploying backend version ${backend_version}!"
        kubectl -n sysdigcloud set image deployment/sysdigcloud-api api=quay.io/sysdig/sysdigcloud-backend:${backend_version}
        kubectl -n sysdigcloud set image deployment/sysdigcloud-collector collector=quay.io/sysdig/sysdigcloud-backend:${backend_version}
        kubectl -n sysdigcloud set image deployment/sysdigcloud-worker worker=quay.io/sysdig/sysdigcloud-backend:${backend_version}
    fi
    echo " Setting up scanning"

    k8s_apply ./sysdigcloud/anchore-core-config.yaml
    k8s_apply ./sysdigcloud/anchore-core-deployment.yaml
    k8s_apply ./sysdigcloud/anchore-worker-config.yaml
    k8s_apply ./sysdigcloud/anchore-worker-deployment.yaml
    k8s_apply ./sysdigcloud/anchore-service.yaml
    k8s_apply ./sysdigcloud/scanning-api-deployment.yaml
    k8s_apply ./sysdigcloud/scanning-alertmgr-deployment.yaml
    k8s_apply ./sysdigcloud/scanning-service.yaml
    k8s_apply ./sysdigcloud/haproxy-config.yaml
    k8s_apply ./sysdigcloud/haproxy-deployment.yaml
    # Map 443 to host port (30443)
    sed -i.bak 's/.*443.*/&'$'\\\n      nodePort: 30443/' ./sysdigcloud/haproxy-nodeport-service.yaml
    k8s_apply ./sysdigcloud/haproxy-nodeport-service.yaml
popd

rm -rf sysdigcloud-kubernetes

# check on pods running
kubectl get pods | grep mysql | grep Running 2>&1 >/dev/null
api_port=$(kubectl  get service -o json | jq -r '.items[].spec.ports[] | select(.name == "https") | .nodePort')
collector_port=$(kubectl  get service -o json | jq -r '.items[].spec.ports[].nodePort' | grep -v null | head -1)
mysql_pod=$(kubectl get pods  | grep mysql | grep Running | head -1 | awk '{print $1}')

echo "Applications parameters - API port: $api_port   Collector port: $collector_port  MySQL pod:  $mysql_pod "
exec_mysql_cmd "CREATE DATABASE IF NOT EXISTS \`sysdig_scanning\`;"
exec_mysql_cmd "CREATE USER 'scanninguser'@'%' IDENTIFIED BY 'change_me' ;"
exec_mysql_cmd "GRANT ALL ON \`sysdig_scanning\`.* TO 'scanninguser'@'%' ;"
exec_mysql_cmd "FLUSH PRIVILEGES ;"

echo "On first install, accessing the API might take 5-10 min. Please hold."
[ `curl -s -o /dev/null -w "%{http_code}"  -m 3 -k -X POST -H "X-Sysdig-Product: SDC" -H "Content-Type:application/json" -H "Accept: application/json, text/javascript" -d '{"username":"test@sysdig.com","password":"test"}' https://127.0.0.1:${api_port}/api/login` -eq '200' ]

# Ugly hack. We are waiting for the backend to initialize so we can fetch the access key. The command above (cmd_access_api) should have taken care of that
# but to be on the safe side, we are waiting 2 more seconds.  
sleep 2

access_key=$(kubectl  exec $mysql_pod -- mysql --password=change_me --database=draios -e "select access_key from customer_access_keys"    2>/dev/null | tail -1 )

echo "Access Key - $access_key"
[ -z $access_key ] && echo "Access Key could not be fetched." && install_agent=1 

#public_ip=$(curl http://169.254.169.254/latest/meta-data/public-ipv4)
public_ip=$(curl http://169.254.169.254/latest/meta-data/local-ipv4)

echo "Installing Sysdig Agent"
#curl -s https://s3.amazonaws.com/download.draios.com/stable/install-agent | bash -s -- --access_key $access_key --collector_port $collector_port --collector 127.0.0.1 --secure true -cc false >/dev/null  2>&1
# Grab current config for the collector in the configmap to be replaced
cce=$(grep collector: agents/sysdig-agent-configmap.yaml)
ccp=$(grep collector_port: agents/sysdig-agent-configmap.yaml)

echo "*******************Fixing collector in yaml*******************"
sed -i -e "s/$cce/     collector: 127.0.0.1/g" agents/sysdig-agent-configmap.yaml
sed -i -e "s/$ccp/     collector_port: ${collector_port}/g" agents/sysdig-agent-configmap.yaml

echo "*******************Creating namespace sysdig-agents*******************"
kubectl create namespace sysdig-agents

echo "*******************creating secret for access_key*******************"
kubectl create secret generic sysdig-agent --from-literal=access-key=$access_key -n sysdig-agents

echo "*******************creating clusterrole*******************"
kubectl apply -f agents/sysdig-agent-clusterrole.yaml -n sysdig-agents

echo "*******************creating service account*******************"
kubectl create serviceaccount sysdig-agent -n sysdig-agents

echo "*******************Creating clusterrole binding*******************"
kubectl create clusterrolebinding sysdig-agent --clusterrole=sysdig-agent --serviceaccount=sysdig-agents:sysdig-agent

echo "*******************Deploying Agent Config*******************"
kubectl apply -f agents/sysdig-agent-configmap.yaml -n sysdig-agents

echo "*******************Deploying Agents*******************"
kubectl apply -f agents/sysdig-agent-daemonset-v2.yaml -n sysdig-agents

echo "*******************It will take about two minutes for the agents to come up.  HAPPY HACKING*******************"


printf "\n\n\n\n
    ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------        
            Sysdigcloud address: https://${public_ip}:${api_port}/  
            Collector address:  ${public_ip}:${collector_port}        
            Default user: test@sysdig.com                                    
            Default pass: test                                                  
            Ssh: ssh -i <pem key> ubuntu@${public_ip}           
            Additional agents can be installed using the following command - 
            'curl -s https://s3.amazonaws.com/download.draios.com/stable/install-agent | bash -s -- --access_key $access_key --collector_port ${collector_port} --collector ${public_ip} --secure true -cc false'
    ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------        
    "
