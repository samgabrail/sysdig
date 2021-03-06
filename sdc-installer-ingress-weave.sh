#!/bin/bash

# Sysdig Cloud installer. This utility, can operate in three differene modes - AWS Instance bring up, 
# Kube environment installation and Sysdigcloud platform installation.  

##############################
###### Installer Params ######
##############################
saved_args="$@"
instance_name=""
script_name=$(basename "$0")
script_full_path=''
export LC_ALL=en_US.utf8
_dist="ubuntu"
pkg_update='apt-get -qq update'
pkg_install='apt-get -qq install -y'
pkg_remove='apt-get -qq -y remove'
##############################
### Sysdig platform Params ###
##############################
api_port="443"
collector_port="31443"
mysql_pod=""
install_agent=0
license_file="license.txt"
backend_version=""
agent_version=""
# By Default we are going to bring up an AWS instance, install K8s and then Sysdig
install_type="all"
conf_branch="v1765-hotfix-scanning"
kube_version="1.13.5"
docker_version="18.06.3"
k8s_net="weave"
k8s_adm_opts=""
##############################
###        AWS Params      ###
##############################
pem_file=""
instance_id=""
date=$(date +%Y-%m-%d)
date_in_one_month=""
owner=$(whoami)
ec2_instance_id=""
status="busy"
key_name=""
aws_os="ubuntu"
# AWS instance_typeFree. E.g free Tier - t2.micro. This is right now a static conf to accomodate Sysdig Platform needs
instance_type="m5.4xlarge"
# Ubuntu 18.04 ami ID ami-0ac019f4fcb7cb7e6 in us-east-1
ami_id="ami-0ac019f4fcb7cb7e6"
aws_volume_size=250
# Default Security group will be used if this is empty. Security group string will look something like -  sg-0212e5efe95533439
sec_group_id=""
region="us-east-1"
export AWS_DEFAULT_REGION=$region
availability_zone=""
dry_run=0
ssh_user="ubuntu"
####################################

function main()
{   
    # Process user args
    process_args "$@"

    if [ $install_type = "all" ]; then
        aws_preflight_checks
        aws_instance_bringup
        # This will copy the files to the target VM and run installer with the sdc option
        setup_sysdig_on_ec2_instance
    elif [ $install_type = "aws" ]; then
        aws_preflight_checks
        aws_instance_bringup
    elif [ $install_type = "sdc" ]; then
        check_sudo
        check_hw_resources
        detect_linux_distribution
        check_detection_output

        k8s_bringup
        sysdigcloud_setup
    fi

    exit 0
}

function usage()
{
    printf "Usage: $0
        -t <all (default. bringup AWS instance and install the platform), aws (only AWS instance), sdc (only the sysdig platform)> 
        -d <Dry run>
        -r <AWS region>
        -o <AWS OS - only ubuntu, centos, rhel for now>
        -a <AWS availability zone>
        -n <AWS instance name>
        -p <AWS pem file name>
        -i <AWS instance type, e.g t2.micro>
        -f <AWS sysdig platform onebox name>  - ec2 machine with the given name prefixed with sdc-onebox will be created>
        -s <AWS security group ID> - if provided will be used as the security group for a newly created instance
        -v <backend version - latest tested version will be used if nothing is provided>\n
License file (license.txt) with the following format is needed. Please make sure the file exists in the same directory as the install script - 
  sysdigcloud.license:<license string>
  pull.secret: <pull secret string> \n" 1>&2;
    exit 1;
}

function process_args()
{
    if [ ! -f $license_file ]; then 
        msg "Missing license.txt file! Please create a license file with the following format in the same dir as the install script  - 
        sysdigcloud.license:<license string>
        pull.secret: <pull secret string>" 
        exit 1
    fi
    
    while getopts ":hn:p:f:i:v:t:s:a:r:o:d" o; do
        case "${o}" in
            t)
                install_type=${OPTARG}
                ;;
            n)
                instance_name=${OPTARG}
                ;;
            p)
                pem_file=${OPTARG}
                key_name=$(echo $pem_file | sed 's/.pem//')
                ;;
            s)
                sec_group_id=${OPTARG}
                ;;
            f)
                instance_name="sdc-pocbox-${OPTARG}"
                ;;
            i)
                instance_type=${OPTARG}
                ;;
            v)
                backend_version=${OPTARG}
                ;;
            r)
                region=${OPTARG}
                export AWS_DEFAULT_REGION=$region
                ;;
            o)
                aws_os=${OPTARG}
                ;;
            a) 
                availability_zone=${OPTARG}
                ;;
            d) 
                dry_run=1
                ;;
            *)
                usage
                ;;
        esac
    done
    shift $((OPTIND-1))
}

function aws_preflight_checks()
{
    aws --version >/dev/null 2>&1
    [ $? -ne 0 ] && msg "Error! aws cli command seems to be missing or not function correctly. Exiting."

    local aws_version=$(aws --version | awk '{print $1}' | cut -d / -f2)
    [ -z $aws_version ] && msg "Can't determine AWS version. At least 1.11.178 is needed" && return
    msg "AWS CLI Version - $aws_version"
    local major_num=`echo $aws_version | cut -d . -f1`
    local minor_num=`echo $aws_version | cut -d . -f2`
    local patch_num=`echo $aws_version | cut -d . -f3`
    [ -z $major_num ] || [ -z $minor_num ] || [ -z $patch_num ] &&  msg "Can't determine AWS version. At least 1.11.178 is needed" && return
    if [ $major_num -eq 0 ] ||  ( [ $major_num -eq 1 ] && [ $minor_num -lt 11 ] ) || ( [ $major_num -eq 1 ] && [ $minor_num -eq 178 ] &&  [ $patch_num -lt 178 ] )
    then
        msg "aws cli version too low. At least 1.11.178 is required" 
        exit 1
    fi

    if [ -z $instance_name ]; then
        msg "Error! For AWS based installs, instance name must be provided."
        exit 1
    fi

    if [ ! -f $pem_file ]; then
        msg "Error! For AWS based installs, PEM file must exist in the same dir as the install script."
        exit 1
    fi

    if [ -z $availability_zone ]; then 
        availability_zone=$(aws ec2 describe-availability-zones | jq -r '.AvailabilityZones[].ZoneName' | head -1)
        [ $? -ne 0 ] && msg "Error! Can't get availability_zone" && exit 1
    fi
}

##########################################################################################################################
# AWS Instance bring up                      
# 1) Providing an existing Pem key created prior is recommended, but if not provided, one can be created by the script
# 2) TBD - configurable OS type                                                                               
##########################################################################################################################

# Region is set by the aws env variable and defaults to us-east-1. 
function aws_get_ami_id()
{
    which jq >/dev/null
    [ $? -ne 0 ] && msg "Error! Can't find the jq utility. Please install and re-run."

    case "$aws_os" in
    ubuntu)
        local ami_name="ubuntu/images/hvm-ssd/ubuntu-bionic-18.04-amd64-server-????????"
        ssh_user="ubuntu"
        ami_id=$(aws ec2 describe-images  --filters "Name=name,Values=${ami_name}" 'Name=state,Values=available' --output json | jq -r '.Images | sort_by(.CreationDate) | last(.[]).ImageId')
        
        ;;
    centos)
        ssh_user="centos"
        ami_id=$(aws ec2 describe-images --owners aws-marketplace --filters Name=product-code,Values=aw0evgkw8e5c1q413zgy5pjce | jq '.Images |=sort_by(.CreationDate) | .Images[-1].ImageId')       
        ;;
    rhel)
        ssh_user="ec2-user"
        ami_id=$(aws ec2 describe-images --owners 309956199498 --query 'Images[*].[ImageId]' --filters "Name=name,Values=RHEL-7.?*GA*" --filters "Name=ena-support,Values=true"  --region us-east-1 --output table | sort -r | head -1  | tr -d '|' | tr -d ' ')
        ;;
    *)
        msg "Unsupported AWS OS!"
        exit 1
        ;;
    esac

    [ $? -ne 0 ] && msg "Error! Could not get AMI ID. Exiting" && exit 1
    [ -z "$ami_id" ] && msg "Error! AMI ID is empty. Exiting" && exit 1
}

function aws_instance_bringup()
{
    aws_get_ami_id
    update_date_label

    # In case an instance with the same name exists, we want to make sure the user want to re-install everything from scratch
    if instance_exists; then
        handle_existing_instance
    else
    # Otherwise, we will create a new instance
        spinup_new_instance
    fi

    # We need to make sure all the updates and init scripts has completed before starting the sysdig installation
    wait_for_instance_to_load
}

function update_date_label()
{
    case "$(uname -s)" in
    Darwin)
        date_in_one_month=$(date -v+1m +%Y-%m-%d)
        ;;
    Linux)
        date_in_one_month=$(date +%F -d "$(date) + 1 month")
        ;;
    *)
        msg "unsupported operating system"
        exit 1
        ;;
    esac
}

function get_instance_ip()
{
    instance_ip=$(aws ec2 describe-instances --filters "Name=tag:Name,Values=${instance_name}" | jq -r ".Reservations[].Instances[].PublicIpAddress")
    if [ $? -ne 0 ]; then exit 1; fi
}

function setup_sysdig_on_ec2_instance()
{
    [ ! ssh_key_exists ] && exit 1
    get_instance_ip
    msg "Setting up Sysdigcloud on instance ID: $instance_id,  with IP: $instance_ip"

    scp -oStrictHostKeyChecking=no -i ${pem_file} ${script_name} license.txt pv_template.yaml ${ssh_user}@${instance_ip}:~/  > /dev/null
    msg "Wait a minute for the package manager to wrap up..." && sleep 10

    # Ugly tweaking of the install type. When executing over SSH, only one option is available - installing the platform
    # so we are overriding the type parameter originally passed
    ssh -oStrictHostKeyChecking=no -i ${pem_file} ${ssh_user}@${instance_ip} "sudo ~/${script_name} ${saved_args} -t sdc"
}

function wait_for_instance_to_load()
{
    msg "EC2 Status is $status"
    until [ "$status" == "ok" ]; do
        status=$(aws ec2 describe-instance-status --instance-ids $instance_id | jq -r '.InstanceStatuses[].InstanceStatus.Status')
        if [ $? -ne 0 ]; then exit 1; fi
        spin
        sleep 2
    done
    endspin
    
    msg "EC2 Status is $status - done waiting"
}

function instance_exists()
{
    ec2_instance_id=$(aws ec2 describe-instances --filters "Name=tag:Name,Values=${instance_name}" | jq ".Reservations[].Instances[].InstanceId")
    if [ $? -ne 0 ]; then exit 1; fi
    if [ "$ec2_instance_id" != "" ]; then
        return 0
    fi
    return 1
}

function handle_existing_instance()
{
    msg "Instance with the same name exists"
    read -r -p "Reset current Ec2 instance state? [y/N] " response
    case "$response" in [yY][eE][sS]|[yY])
        msg "About to reinstall everything from scratch!"
        ;;
    *)
        exit 0
        ;;
    esac
    instance_id=$(echo $ec2_instance_id | sed 's/"//g')
    key_name=$(aws ec2 describe-instances --instance-ids $instance_id | jq -r  '.Reservations[].Instances[].KeyName')
    if [ $? -ne 0 ]; then exit 1; fi

    pem_file="${key_name}.pem"
}

function ssh_key_exists()
{
    if [ ! -f ${pem_file} ]; then
        msg "SSH Pem file not found in current directory: $pem_file"
        return 1
    fi
    chmod 400 ${pem_file}
    return 0
}

function spinup_new_instance()
{
    create_key_pair
    msg "Creating new AWS: ${instance_name} 
            KeyName: ${key_name}
            VolumeSize: ${aws_volume_size}
            AvailabilityZone: ${availability_zone}
            InstanceType: ${instance_type}
            (Sysdig Internal SG): $sec_group_id
        "

    local cmd="aws ec2 run-instances  
        --image-id $ami_id  
        --block-device-mapping \"DeviceName=/dev/sda1,Ebs={VolumeSize=${aws_volume_size}}\" 
        --count 1 
        --placement AvailabilityZone=\"${availability_zone}\" 
        --associate-public-ip-address 
        --instance-type ${instance_type} 
        --key-name ${key_name}
        --tag-specifications \"ResourceType=instance,Tags=[{Key=Name,Value=${instance_name}},{Key=description,Value=Auto generated Sysdig Instance for internal usage},{Key=terminationdate,Value=${date_in_one_month}},{Key=owner,Value=${owner}}]\" "

    [ ! -z $sec_group_id ] && cmd+=" --security-group-ids ${sec_group_id} "    
    msg " Spinning up AWS instance using the following command - "
    msg " $cmd "
    [ $dry_run -eq 1 ] && msg "Dry Run!" && exit 0 

    eval $cmd > instance.out

    if [ $? -ne 0 ]; then exit 1; fi

    instance_id=$(cat instance.out| jq -r '.Instances[].InstanceId')
    rm -f instance.out
}

function create_key_pair()
{
    if [ ! -z ${pem_file} ]; then
        msg "Pem filename provided - $pem_file"
        return
    fi

    local owner_keys_num=$(aws ec2 describe-key-pairs | jq '.KeyPairs[].KeyName' | grep -i ${owner} | wc -l)
    if [ $? -ne 0 ]; then exit 1; fi

    echo $owner_keys_num
    if [ $owner_keys_num -gt 1 ]; then
        msg "Owner $owner has more than 2 keys already configured. To avoid polluting Sysdig's AWS account, please use your previous keys."

        aws ec2 describe-key-pairs | jq '.KeyPairs[].KeyName' | grep -i $owner
        if [ $? -ne 0 ]; then exit 1; fi

        read -p "Are you sure you want to create a new key? " -n 1 -r
        if [[ ! $REPLY =~ ^[Yy]$ ]]
        then
            echo
            msg "Thanks! Please provide your previous key by running the script with '-p <key file name>'"
            exit 1
        fi
    fi

    key_name="${owner}-${date}-$((RANDOM))"
    msg "Creating key pair name: ${key_name}"
    aws ec2 create-key-pair --key-name "${key_name}" --query 'KeyMaterial' --output text > "${key_name}".pem
    if [ $? -ne 0 ]; then exit 1; fi

    pem_file="${key_name}.pem"
    chmod 0400 $pem_file
}

##########################################################################################################################
# K8S Env Bringup
# 1. This part assume running on the target host
# 2. Local PV will be used for any stateful service. PV and PVC will be created on the fly 
##########################################################################################################################

function k8s_apply()
{
    [ ! -f $1 ] && msg "Skipping k8s apply for non existing file - ${1}! " && return
    grep "<INSERT_YOUR_STORAGE_CLASS_NAME>" $1 > /dev/null && create_pv $1
    # For a one-box poc, only one replica for now
    sed -E -i.bak 's/replicas:[ ]*[0-9]+/replicas: 1/g' $1
    kubectl create -f $1  > /dev/null
    [ $? -ne 0 ] && msg "Error $? - something bad happened. Exiting!" && exit 1
}

function extract_text_to_file()
{
    local marker=$1
    local filename=$2
    local cmd="sed -n \"/.*"
    cmd+=${marker}
    cmd+="=\\\"/,/#"
    cmd+=${marker}
    cmd+="/p\" ${script_full_path}  | grep -v $marker > "
    cmd+=${filename}
    eval $cmd
    [ $? -ne 0 ] && msg "Error! Can't geneate file ${filename}!" && exit 1
}

function create_pv()
{
    file=$1
    s="${file%/*}"
    pv_name="pv-${s##*/}"
    pv_size=$(grep storage: $file | cut -d":" -f2)
    msg "Creating PV $pv_name with size $pv_size for file $file"
    mkdir -p /mnt/data/sdc/$pv_name
    extract_text_to_file pv_template_yaml_file ../pv_template.yaml
    #sed -n "/.*pv_template_yaml_file=\"/,/#pv_template_yaml_file/p" ../${script_name}  | grep -v pv_template_yaml_file > ../pv_template.yaml
    cat ../pv_template.yaml | sed -e "s/<PV-NAME>/$pv_name/g" | sed -e "s/<PV-SIZE>/$pv_size/g" | kubectl ${NS_OPTS} create -f -    >/dev/null
    sed -i -e "s/<INSERT_YOUR_STORAGE_CLASS_NAME>/$pv_name/g" $1
}

function k8s_bringup()
{
    $pkg_install psmisc
    pkg_mgr_is_locked
    env_cleanup
    env_setup
}

function pkg_mgr_is_locked()
{
    #TBD - per platform check - (e.g ubuntu - fuser /var/lib/dpkg/lock)
    sleep 10
}

function is_loading()
{
   active=$(service $1 status | grep "Active: active (running)")
   if [ -z "$active" ]; then
      true
   else
      false
   fi

   return $?
}

function is_running()
{
    systemctl status $1 | grep "active (running)"
    if [ $? -eq 0 ] ; then
        msg "$1 is running!"
        return 0
    fi
    return 1
}

# The below is taken from here - https://kubernetes.io/docs/setup/independent/create-cluster-kubeadm/
function setup_k8s_net()
{
    msg "Setting up kube net..."

    case "$k8s_net" in

    kube_router)
        sysctl net.bridge.bridge-nf-call-iptables=1
        # Lean kube router for now
        KUBECONFIG=/etc/kubernetes/admin.conf kubectl apply -f https://raw.githubusercontent.com/cloudnativelabs/kube-router/master/daemonset/kubeadm-kuberouter.yaml
        k8s_adm_opts="--pod-network-cidr=192.168.0.0/16"
        ;;
    calico)
        k8s_adm_opts="--pod-network-cidr=192.168.0.0/16"
        kubectl apply -f https://docs.projectcalico.org/v3.3/getting-started/kubernetes/installation/hosted/rbac-kdd.yaml
        kubectl apply -f https://docs.projectcalico.org/v3.3/getting-started/kubernetes/installation/hosted/kubernetes-datastore/calico-networking/1.7/calico.yaml
        ;;
    weave)
        sysctl net.bridge.bridge-nf-call-iptables=1
        wget  -O net.yaml https://cloud.weave.works/k8s/net?k8s-version=$(kubectl version | base64 | tr -d '\n') 2>/dev/null
        kubectl apply -f ./net.yaml > /dev/null
        ;;
    esac

    [ $? -ne 0 ] && msg "ERROR - Can't install k8s netowrk!" && exit 1
}

function setup_kube()
{
    is_running kubelet &&
        kversion=$(kubectl version -o json | jq -r '.serverVersion.major +"."+ .serverVersion.minor') &&
        msg "K8s already installed. Version - $kversion" && return

    msg "Setting up Kube..."
    kubeadm reset -f >/dev/null

    systemctl enable kubelet.service
    systemctl start kubelet.service
    kubeadm init $k8s_adm_opts  >/dev/null 
    mkdir -p $HOME/.kube
    cp -f  /etc/kubernetes/admin.conf $HOME/.kube/config
    [ $? -ne 0 ] && msg "ERROR - admin conf file does not exist - /etc/kubernetes/admin.conf" && exit 1
    chown $(id -u):$(id -g) $HOME/.kube/config
    kubectl taint nodes --all node-role.kubernetes.io/master-  >/dev/null

    setup_k8s_net
  
    systemctl enable kubelet.service
}

function ubuntu_env_setup()
{
    curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add -
    echo deb http://apt.kubernetes.io/ kubernetes-xenial main | tee /etc/apt/sources.list.d/kubernetes.list
    $pkg_update
    $pkg_install kubelet=${kube_version}-00 kubeadm=${kube_version}-00 kubectl=${kube_version}-00
}

function centos_env_setup()
{
    $pkg_install epel-release 
    $pkg_install install firewalld jq git figlet wget

    systemctl restart dbus
    systemctl start firewalld
    systemctl enable firewalld
    systemctl restart firewalld

    setenforce 0
    sed -i --follow-symlinks 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/sysconfig/selinux
    local array=( "443" "6443" "2379-2380" "10250" "10251" "10252" "10255" "30443" "31443")
    for i in "${array[@]}"; do 
        firewall-cmd --permanent --add-port=${i}/tcp >/dev/null
    done
    firewall-cmd --reload
    
    modprobe br_netfilter
    echo '1' > /proc/sys/net/bridge/bridge-nf-call-iptables

cat <<EOF >  /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
EOF
sysctl --system

    cat <<EOF > /etc/yum.repos.d/kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=https://packages.cloud.google.com/yum/repos/kubernetes-el7-x86_64
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://packages.cloud.google.com/yum/doc/yum-key.gpg        
https://packages.cloud.google.com/yum/doc/rpm-package-key.gpg
EOF

    $pkg_update
    $pkg_install --nogpgcheck kubelet-${kube_version}-0 kubeadm-${kube_version}-0 kubectl-${kube_version}-0 --disableexcludes=kubernetes
    yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    yum-config-manager --disable download.docker.com_linux_centos_docker-ce.rpm
    $pkg_update
    $pkg_install docker-ce docker-ce-cli containerd.io
    systemctl start docker
    systemctl enable docker
}

function rhel_env_setup()
{ 
   msg "Setting up RHEL environment"
   $pkg_install wget
   #wget http://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
   rpm -ivh epel-release-latest-7.noarch.rpm
   $pkg_update
   $pkg_install firewalld jq git figlet

   # For now, we need to be violent with firewalld 
   systemctl stop firewalld
   systemctl disable firewalld
   
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

    $pkg_install -y kubelet-${kube_version}-0 kubeadm-${kube_version}-0 kubectl-${kube_version}-0 --disableexcludes=kubernetes
    systemctl enable --now kubelet 

    modprobe br_netfilter
    cat <<EOF >  /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
EOF
    sysctl --system
    yum install -y yum-utils device-mapper-persistent-data lvm2

    yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    yum-config-manager --disable download.docker.com_linux_centos_docker-ce.rpm
    $pkg_update
    yum-config-manager --enable rhui-REGION-rhel-server-extras
    $pkg_install docker-ce-${docker_version}.ce-3.el7 
    $pkg_install docker-ce-cli containerd.io
    systemctl start docker
    systemctl enable docker

}

## This should be per platform.
function env_setup()
{
    msg "Updating pkg manager and installing deps"
    $pkg_update
    $pkg_install >/dev/null 2>&1
    $pkg_install jq  >/dev/null 2>&1
    $pkg_install figlet >/dev/null 2>&1
    ### Setup Kube per platform ###  
    local cmd=""
    cmd+=${_dist} 
    cmd+="_env_setup"
    local to_exec=`echo $cmd | tr '[:upper:]' '[:lower:]'`
    type $cmd >/dev/null 2>&1
    [ $? -ne 0 ] && msg "Error! $cmd not implemented yet" && exit 1    [ $? -ne 0 ]  && msg "Error! $cmd not implemented yet" && exit 1
    msg "Setting up kube. Env - $to_exec"
    $to_exec
    ###############################
    which jq; [ $? -ne 0 ] && msg "Error! Can't find jq" && exit 1

    figlet -c -f big Sysdig Platform POC Box Installer 
    msg "Using configuration branch - $conf_branch"

    ### Setup Docker ###
    msg "Installing Docker..."
    is_running docker
    #if [ $? -ne 0 ]; then 
    #    curl -fsSL https://get.docker.com -o get-docker.sh  
    #    VERSION=${docker_version} sh get-docker.sh  >/dev/null 2>&1
    #    usermod -aG docker $USER  >/dev/null 2>&1
    #    systemctl unmask docker.service  >/dev/null 2>&1
    #    systemctl unmask docker.socket   >/dev/null 2>&1
    #    systemctl enable docker.service  >/dev/null 2>&1
    #    systemctl start docker.service   >/dev/null 2>&1
    #fi

    msg "Waiting for Docker to load"
    while is_loading docker; do true; sleep 2; done

    setup_kube
}

function env_cleanup()
{
    msg " Cleaning up any kube remains and setting up a single master Kube..."
    $pkg_update
    $pkg_remove draios-agent
    kubeadm reset -f
    $pkg_remove kubeadm kubectl kubelet
}

##########################################################################################################################
# Sysdig Platform Bringup
##########################################################################################################################

function cmd_running_pods()
{
    kubectl get pods  | grep Running 2>&1 >/dev/null
}

function cmd_mysql_pod_running()
{
    kubectl get pods | grep mysql | grep Running 2>&1 >/dev/null
}

function cmd_access_api()
{
    [ `curl -s -o /dev/null -w "%{http_code}"  -m 3 -k -X POST -H "X-Sysdig-Product: SDC" -H "Content-Type:application/json" -H "Accept: application/json, text/javascript" -d '{"username":"test@sysdig.com","password":"test"}' https://127.0.0.1:${api_port}/api/login` -eq '200' ]
}

function update_license_and_pull_secret()
{
    license_key=$(grep license $license_file | cut -d ':' -f 2 | sed 's/ //g')
    pull_secret=$(grep pull $license_file | cut -d ':' -f 2 | sed 's/ //g')

    sed -i.bak 's/sysdigcloud.license: ""/sysdigcloud.license: '"${license_key}"'/' sysdigcloud-kubernetes/sysdigcloud/config.yaml
    sed -i.bak 's/<PULL_SECRET>/'"${pull_secret}"'/g' sysdigcloud-kubernetes/sysdigcloud/pull-secret.yaml
}

# This should be removed as soon as scanning is an integral part of the platform
function setup_scanning_user()
{
    exec_mysql_cmd "CREATE DATABASE IF NOT EXISTS \`sysdig_scanning\`;"
    exec_mysql_cmd "CREATE USER 'scanninguser'@'%' IDENTIFIED BY 'change_me' ;"
    exec_mysql_cmd "GRANT ALL ON \`sysdig_scanning\`.* TO 'scanninguser'@'%' ;"
    exec_mysql_cmd "FLUSH PRIVILEGES ;"
}

function exec_mysql_cmd()
{
    kubectl  exec $mysql_pod -- mysql --password=change_me --database=draios -e "$1" 2>/tmp/sysdig_util.err | tail -1  
}

function update_global_vars()
{
    #api_port=$(kubectl  get service -o json | jq -r '.items[].spec.ports[] | select(.name == "https") | .nodePort')
    #collector_port=$(kubectl  get service -o json | jq -r '.items[].spec.ports[].nodePort' | grep -v null | head -1)
    mysql_pod=$(kubectl get pods  | grep mysql | grep Running | head -1 | awk '{print $1}')

    msg "Applications parameters - API port: $api_port   Collector port: $collector_port  MySQL pod:  $mysql_pod "
    setup_scanning_user

    msg "On first install, accessing the API might take 5-10 min. Please hold."
    wait_for_cmd cmd_access_api

    # Ugly hack. We are waiting for the backend to initialize so we can fetch the access key. The command above (cmd_access_api) should have taken care of that
    # but to be on the safe side, we are waiting 2 more seconds.  
    sleep 2

    access_key=$(kubectl  exec $mysql_pod -- mysql --password=change_me --database=draios -e "select access_key from customer_access_keys"    2>/dev/null | tail -1 )
    [ $? -ne 0 ] && exit 1

    msg "Access Key - $access_key"
    [ -z $access_key ] && msg "Access Key could not be fetched." && install_agent=1
}

function install_agent()
{
    if [ $install_agent -eq 0 ]; then 
        msg "Installing Sysdig Agent"
        curl -s https://s3.amazonaws.com/download.draios.com/stable/install-agent | bash -s -- --access_key $access_key --collector_port $collector_port --collector 127.0.0.1 --secure true -cc false >/dev/null  2>&1
    else
        msg "Can't auto install Agent since access key could not be extracted. Agent can still be manually installed."
    fi
}

function install_agent_daemonset()
{
    if [ $install_agent -eq 0 ]; then 
        msg "Installing Sysdig Agent Daemonset"
        
        # In case the update fetched new kernels 
        $pkg_install kernel-headers kernel-devel
        # For the current running kernel
        $pkg_install "kernel-devel-uname-r == $(uname -r)"
        extract_text_to_file sysdig-agent-configmap_yaml sysdig-agent-configmap.yaml
        extract_text_to_file sysdig-agent-clusterrole_yaml sysdig-agent-clusterrole.yaml
        extract_text_to_file sysdig-agent-daemonset-v2_yaml sysdig-agent-daemonset-v2.yaml

        kubectl create namespace sysdig-agent
        kubectl create secret generic sysdig-agent --from-literal=access-key=$access_key -n sysdig-agent
        kubectl apply -f sysdig-agent-clusterrole.yaml -n sysdig-agent
        kubectl create serviceaccount sysdig-agent -n sysdig-agent
        kubectl create clusterrolebinding sysdig-agent --clusterrole=sysdig-agent --serviceaccount=sysdig-agent:sysdig-agent
        kubectl apply -f sysdig-agent-configmap.yaml -n sysdig-agent
        kubectl apply -f sysdig-agent-daemonset-v2.yaml -n sysdig-agent
        
    else
        msg "Can't auto install Agent since access key could not be extracted. Agent can still be manually installed."
    fi
}

function setup_scanning()
{
    msg " Setting up scanning"

    k8s_apply ./sysdigcloud/anchore-service.yaml
    k8s_apply ./sysdigcloud/anchore-core-config.yaml
    k8s_apply ./sysdigcloud/anchore-core-deployment.yaml
    k8s_apply ./sysdigcloud/anchore-worker-config.yaml
    k8s_apply ./sysdigcloud/anchore-worker-deployment.yaml
    k8s_apply ./sysdigcloud/scanning-api-deployment.yaml
    k8s_apply ./sysdigcloud/scanning-alertmgr-deployment.yaml
    k8s_apply ./sysdigcloud/scanning-service.yaml
}

function deploy_datastores()
{
    msg "Deploying datastores"

    # Cassandra replicas number will be reduced to 1 as part of the apply process. PV will be created on the fly
    k8s_apply datastores/as_kubernetes_pods/manifests/cassandra/cassandra-service.yaml
    k8s_apply datastores/as_kubernetes_pods/manifests/cassandra/cassandra-statefulset.yaml

    k8s_apply datastores/as_kubernetes_pods/manifests/elasticsearch/elasticsearch-service.yaml
    # Yet another hack - we need to align the number below with the replicas num, and since we are limiting the replicas to 1, this needs 
    # to change as well. PV will be created on the fly
    sed -i.bak 's/value: "3"/value: "1"/g' datastores/as_kubernetes_pods/manifests/elasticsearch/elasticsearch-statefulset.yaml
    k8s_apply datastores/as_kubernetes_pods/manifests/elasticsearch/elasticsearch-statefulset.yaml
    
    # MySQL 
    k8s_apply datastores/as_kubernetes_pods/manifests/mysql/mysql-deployment.yaml
    wait_for_cmd cmd_mysql_pod_running
    
    k8s_apply datastores/as_kubernetes_pods/manifests/redis/redis-deployment.yaml

    k8s_apply ./datastores/as_kubernetes_pods/manifests/postgres/postgres-service.yaml
    k8s_apply ./datastores/as_kubernetes_pods/manifests/postgres/postgres-statefulset.yaml


    # Ugly hack for now. This needs to be replaced with a command to make sure the datastores are available. 
    # Init containers would be a better approach here, till then... we will wait.  
    msg "Initializing Datastores..."
    sleep 20
    wait_for_cmd cmd_running_pods
}

function setup_backend()
{
    deploy_datastores
    msg " Setting up core backend components"
    k8s_apply sysdigcloud/api-deployment.yaml
    sleep 20
    k8s_apply sysdigcloud/collector-deployment.yaml
    k8s_apply sysdigcloud/worker-deployment.yaml
    # Following the docs...
    sleep 20

    k8s_apply ./sysdigcloud/api-headless-service.yaml
    # Map the default collector port to a local 31443 port
    k8s_apply ./sysdigcloud/collector-headless-service.yaml

    if [ ! -z $backend_version ]; then
        msg " Deploying backend version ${backend_version}!"
        kubectl -n sysdigcloud set image deployment/sysdigcloud-api api=quay.io/sysdig/sysdigcloud-backend:${backend_version}
        kubectl -n sysdigcloud set image deployment/sysdigcloud-collector collector=quay.io/sysdig/sysdigcloud-backend:${backend_version}
        kubectl -n sysdigcloud set image deployment/sysdigcloud-worker worker=quay.io/sysdig/sysdigcloud-backend:${backend_version}
    fi
}

function setup_secrets()
{
    msg "Setting secrets"

    k8s_apply ./sysdigcloud/config.yaml
    k8s_apply ./sysdigcloud/pull-secret.yaml
    k8s_apply ./sysdigcloud/scanning-secrets.yaml
    k8s_apply ./sysdigcloud/anchore-secrets.yaml  
    openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 -subj "/C=US/ST=CA/L=SanFrancisco/O=ICT/CN=onprem.sysdigcloud.com"   -keyout server.key -out server.crt   >/dev/null 2>&1
    kubectl create secret tls sysdigcloud-ssl-secret --cert=server.crt --key=server.key > /dev/null
}

function setup_ingress()
{
    pushd sysdigcloud/ingress_controller
        sed -i.bak 's/<namespace>/sysdigcloud/' ingress-clusterrolebinding.yaml
        kubectl -n sysdigcloud create -f ingress-clusterrole.yaml
        kubectl -n sysdigcloud create -f ingress-clusterrolebinding.yaml
        kubectl -n sysdigcloud create -f ingress-role.yaml
        kubectl -n sysdigcloud create -f ingress-rolebinding.yaml
        kubectl -n sysdigcloud create -f ingress-serviceaccount.yaml
        kubectl -n sysdigcloud create -f default-backend-service.yaml
        kubectl -n sysdigcloud create -f default-backend-deployment.yaml
        kubectl -n sysdigcloud create -f ingress-configmap.yaml
        sed -i.bak 's/"6443"/"31443"/' ingress-tcp-services-configmap.yaml
        kubectl -n sysdigcloud create -f ingress-tcp-services-configmap.yaml
        kubectl -n sysdigcloud create -f ingress-daemonset.yaml
        
    popd
    # Remove DNS requirments
    sed -i.bak '/.*<EXTERNAL-DNS-NAME>/d' sysdigcloud/api-ingress-with-secure.yaml
    sed -i.bak '/.*hosts/d' sysdigcloud/api-ingress-with-secure.yaml
    sed -i.bak 's/http:/- http:/' sysdigcloud/api-ingress-with-secure.yaml
    sed -i.bak 's/secretName:/- secretName:/' sysdigcloud/api-ingress-with-secure.yaml
    sed -i.bak 's/paths:/  paths:/' sysdigcloud/api-ingress-with-secure.yaml
    kubectl -n sysdigcloud create -f sysdigcloud/api-ingress-with-secure.yaml
}

function sysdigcloud_setup()
{
    msg "Cleaning up...."
    #Clean up first
    rm -rf sysdigcloud-kubernetes
    kubectl delete daemonsets,replicasets,services,deployments,pods,configmaps,secret,pvc,rc,sc,pv --all  > /dev/null
    kubectl delete namespace sysdigcloud > /dev/null
    kubectl delete namespace sysdig-agent > /dev/null
    
    kubectl create namespace sysdigcloud  > /dev/null
    kubectl config set-context --current --namespace sysdigcloud > /dev/null

    msg "Downloading sysdigcloud-k8s..."
    git clone https://github.com/draios/sysdigcloud-kubernetes.git -q
    pushd sysdigcloud-kubernetes
        git checkout $conf_branch -q
    popd

    update_license_and_pull_secret

    pushd sysdigcloud-kubernetes
        setup_secrets
        setup_backend
        setup_scanning
        setup_ingress
    popd

    rm -rf sysdigcloud-kubernetes

    wait_for_cmd cmd_mysql_pod_running
    update_global_vars 
    install_agent_daemonset

    #public_ip=$(curl http://169.254.169.254/latest/meta-data/public-ipv4)
    public_ip=$(curl http://169.254.169.254/latest/meta-data/private-ipv4)

    printf "\n\n\n\n
        ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------        
                Sysdigcloud address: https://${public_ip}:${api_port}/  
                Collector address:  ${public_ip}:${collector_port}        
                Default user: test@sysdig.com                                    
                Default pass: test                                                  
                Ssh: ssh -i $pem_file ${ssh_user}@${public_ip}           
                Additional agents can be installed using the following command - 
                'curl -s https://s3.amazonaws.com/download.draios.com/stable/install-agent | bash -s -- --access_key $access_key --collector_port ${collector_port} --collector ${public_ip} --secure true -cc false'
        ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------        
    "
    [ "rhel" = "$_dist" ] && msg "(!) - When using RHEL, sometimes VM reboot is required for the Agent to load due to a kernel update"

}


##########################################################################################################################
# Helper functions
##########################################################################################################################

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
    msg "Waiting for the following command - $str"

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

function msg()
{
    printf "[sdc_log]  %s\n" "$1"
}

function detect_linux_distribution() {
    _error_msg="Cannot determine linux distribution, there is no /etc/os-release"
    LSB_DISTRIBUTION="unknown"
    LSB_MAJOR="unknown"
    LSB_MINOR="unknown"
    
    if [ -f /etc/os-release ] && [ -r /etc/os-release ]; then
        _dist="$(. /etc/os-release && echo "$ID")"
        if [ "amzn" = "$_dist" ] ; then
            amzn_version_tags="$(. /etc/os-release && echo $VERSION | wc -w)"
            if [ "$amzn_version_tags" -eq 1 ] ; then
                amzn_version="1"
            elif [ "$amzn_version_tags" -eq 2 ] ; then
                amzn_version="$(. /etc/os-release && echo $VERSION_ID )"
            fi
            _dist="$_dist$amzn_version"
            _version="$(. /etc/os-release && echo $VERSION )"
            _major_version="$(echo "$_version" | cut -d " " -f2 | tr -d "()" | cut -d "." -f1 )"
            _minor_version="$(echo "$_version" | cut -d " " -f2 | tr -d "()" | cut -d "." -f2 )"
        elif [ "ubuntu" = "$_dist" ] || [ "rhel" = "$_dist" ] || [ "sles" = "$_dist" ] ; then
            _version="$(. /etc/os-release && echo "$VERSION_ID")"
            _major_version="$(echo "$_version" | cut -d "." -f1)"
            _minor_version="$(echo "$_version" | cut -d "." -f2)"
            if [ "rhel" = "$_dist" ]; then
                pkg_update="yum -y -q -x 'kernel*' update"
                pkg_install='yum -y -q install'
                pkg_remove='yum -y -q remove'
                ssh_user="ec2-user"
            fi
        elif [ "centos" = "$_dist" ] ; then
            if [ -f /etc/centos-release ] && [ -r /etc/centos-release ]; then
                _dist="$(cut -d" " -f1 < /etc/centos-release)"
                _version="$(awk '{ print $(NF-1) }' < /etc/centos-release)"
                _major_version="$(echo "$_version" | cut -d "." -f1)"
                _minor_version="$(echo "$_version" | cut -d "." -f2)"
            fi

            pkg_update="yum -y -q -x 'kernel*' update"
            pkg_install='yum -y -q install'
            pkg_remove='yum -y -q remove'

            ssh_user="centos"
        elif [ "debian" = "$_dist" ] ; then
            _version="$(cat /etc/debian_version)"
            _major_version="$(echo "$_version" | cut -d "." -f1)"
            _minor_version="$(echo "$_version" | cut -d "." -f2)"
        fi
        if [ -z "$_dist" ] && [ -z "$_major_version" ] && [ -z "$_minor_version" ] ; then
           _error_msg="can't determine distribution, major and minor number, error"
        else
           _error_msg=
           LSB_DISTRIBUTION="$_dist"
           LSB_MAJOR="$_major_version"
           LSB_MINOR="$_minor_version"
        fi
    else
        _error_msg="Cannot determine linux distribution, there is no /etc/os-release"
    fi

    _dist=`echo $_dist | tr '[:upper:]' '[:lower:]'`
    msg "OS identified - ${_dist}"
    if [ $_dist != "ubuntu" ] && [ $_dist != "centos" ] && [ $_dist != "rhel" ]; then 
        msg "Unsupported platform. Only Ubuntu for now."
    fi
}

function check_detection_output() {
   if [ ! -z "$_error_msg" ] ; then
      echo "$_error_msg, exiting"
      exit 1
   fi

   if [ "unknown" = "$LSB_DISTRIBUTION" ] ; then
      echo "unable to detect linux distribution, exiting"
      exit 1
   fi

   if [ "rhel" != "$LSB_DISTRIBUTION" ] && [ "CentOS" != "$LSB_DISTRIBUTION" ] && [ "amzn2" != "$LSB_DISTRIBUTION" ] && [ "ubuntu" != "$LSB_DISTRIBUTION" ] && [ "debian" != "$LSB_DISTRIBUTION" ] ; then
      echo "distribution $LSB_DISTRIBUTION $LSB_MAJOR $LSB_MINOR not supported, exiting"
      exit 1
   fi
}

function check_hw_resources() {
   total_memory_kbits=$(cat /proc/meminfo |grep MemTotal|awk '{ print $2 }')
   total_memory_gb="$(( ${total_memory_kbits} / 1024 / 1024 ))"

   if [[ $total_memory_gb -lt 24 ]]; then
      echo "This machine does not have enough memory. Please use a machine that has 32G"
      exit 1
   fi

   total_cores=$(cat /proc/cpuinfo |egrep 'processor.*: ' | wc -l)
   if [[ $total_cores -lt 8 ]]; then
      echo "This machine does not have enough cpu. Please use a machine that has 8 cores"
      exit 1
   fi
}

function check_sudo()
{
    if [ "$EUID" -ne 0 ] ; then
        echo "This script needs to be run as sudo"
        echo "Usage: sudo ./${script_name} <options>"
        exit 1
    fi
}

function get_full_path()
{
    echo $(cd $(dirname "$1") && pwd -P)/$(basename "$1")
}

##########################################################################################################################
# Main
##########################################################################################################################


script_full_path=$(get_full_path $script_name)
main "$@"
exit 0


#################################################################################################
# Embedded Files - quick hack to package the needed Yaml files into the same runtime script
#################################################################################################

pv_template_yaml_file="
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
" #pv_template_yaml_file

sysdig-agent-clusterrole_yaml="
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: sysdig-agent
rules:
- apiGroups:
  - ""
  resources:
  - pods
  - replicationcontrollers
  - services
  - events
  - limitranges
  - namespaces
  - nodes
  - resourcequotas
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - apps
  resources:
  - daemonsets
  - deployments
  - replicasets
  - statefulsets
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - autoscaling
  resources:
  - horizontalpodautoscalers
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - batch
  resources:
  - cronjobs
  - jobs
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - extensions
  resources:
  - daemonsets
  - deployments
  - ingresses
  - replicasets
  verbs:
  - get
  - list
  - watch
" #sysdig-agent-clusterrole_yaml

sysdig-agent-configmap_yaml="
apiVersion: v1
kind: ConfigMap
metadata:
  name: sysdig-agent
data:
  dragent.yaml: |
    ### Agent tags
    #tags: 

    # Sysdig collector address
     collector: 127.0.0.1

     #Collector TCP port
     collector_port: 31443

     #Whether collector accepts ssl
     ssl: true

    # collector certificate validation
     ssl_verify_certificate: false
     #log:
     #  file_priority: debug 
     new_k8s: true
     k8s_cluster_name: SysdigBackend
     percentiles: [50, 95, 99]
     app_checks_limit: 1000
     prometheus:
       enabled: true
       interval: 10
       log_errors: true
     jmx:
       limit: 3000
     statsd:
       limit: 1000
     app_checks_always_send: true
     
    security:
       enabled: true
     commandlines_capture:
       enabled: true
     nmemdump:
       enabled: true
" #sysdig-agent-configmap_yaml

sysdig-agent-daemonset-v2_yaml="
apiVersion: extensions/v1beta1
kind: DaemonSet
metadata:
  name: sysdig-agent
  labels:
    app: sysdig-agent
spec:
  updateStrategy:
    type: RollingUpdate
  template:
    metadata:
      labels:
        app: sysdig-agent
    spec:
      volumes:
      - name: dshm
        emptyDir:
          medium: Memory
      - name: docker-sock
        hostPath:
          path: /var/run/docker.sock
      - name: dev-vol
        hostPath:
          path: /dev
      - name: proc-vol
        hostPath:
          path: /proc
      - name: boot-vol
        hostPath:
          path: /boot
      - name: modules-vol
        hostPath:
          path: /lib/modules
      - name: usr-vol
        hostPath:
          path: /usr
      - name: sysdig-agent-config
        configMap:
          name: sysdig-agent
          optional: true
      - name: sysdig-agent-secrets
        secret:
          secretName: sysdig-agent
      hostNetwork: true
      hostPID: true
      tolerations:
        - effect: NoSchedule
          key: node-role.kubernetes.io/master
      ### OPTIONAL: If using OpenShift or Kubernetes RBAC you need to uncomment the following line
      serviceAccount: sysdig-agent
      containers:
      - name: sysdig-agent
        image: sysdig/agent:0.89.5-rc
        imagePullPolicy: Always
        securityContext:
          privileged: true
        resources:
          # Resources needed are subjective on the actual workload
          # please refer to Sysdig Support for more info about it
          requests:
            cpu: 100m
            memory: 512Mi
          limits:
            memory: 1024Mi
        readinessProbe:
          exec:
            command: [ \"test\", \"-e\", \"/opt/draios/logs/draios.log\" ]
          initialDelaySeconds: 10
        volumeMounts:
        - mountPath: /host/var/run/docker.sock
          name: docker-sock
          readOnly: false
        - mountPath: /host/dev
          name: dev-vol
          readOnly: false
        - mountPath: /host/proc
          name: proc-vol
          readOnly: true
        - mountPath: /host/boot
          name: boot-vol
          readOnly: true
        - mountPath: /host/lib/modules
          name: modules-vol
          readOnly: true
        - mountPath: /host/usr
          name: usr-vol
          readOnly: true
        - mountPath: /dev/shm
          name: dshm
        - mountPath: /opt/draios/etc/kubernetes/config
          name: sysdig-agent-config
        - mountPath: /opt/draios/etc/kubernetes/secrets
          name: sysdig-agent-secrets
" #sysdig-agent-daemonset-v2_yaml

##############################

