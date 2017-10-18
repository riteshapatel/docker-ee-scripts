#!/bin/sh
##################################
# USAGE: ./install-ucp-dtr.sh \
#           ucp_asg_name \
#           dtr_asg_name \
#           ucp_elb_name \
#           ucp_elb_url \
#           dtr_elb_name \
#           dtr_elb_url \
#           key_name
# @param1 ucp scaling group name
# @param2 dtr scaling group name
# @param3 ucp elb name
# @param4 ucp elb url
# @param5 dtr elb name
# @param6 dtr elb url
# @param7 ssh key name

# @requirements
# Manual execution: Client machine must have AWS CLI installed and configured
#
#
# @description
  # This script will get instances from an auto scaling group, parse aws cli response and
  # extract leader, manager and worker nodes for docker setup. In the process, leader and
  # manager nodes are added to UCP ELB whereas worker nodes are added to DTR ELB. Script proceeds
  # by installing UCP on a leader node, and DTR with replicas on worker nodes.
# @author Ritesh Patel
# @date 09/26/2017
# @version 1.0
##################################
# variables
##################################
username=admin
password=d0cker4G0vC10ud!2017
ucp_asg_name=$1
dtr_asg_name=$2
ucp_elb=$3
ucp_url=$4
dtr_elb=$5
dtr_url=$6
dev_key=$7
# leader, workers and managers
nodes=
leader=
managers=
workers=

# public & private ip addresses
leader_public_ip=
leader_private_ip=

manager_public_ips=
manager_private_ips=

worker_public_ips=
worker_private_ips=
primary_dtr_node=
replicas=
replica_id=7265706c690a
treasury_domain='treasury.local'
#################################
# export variables
#################################
# @Note: If running script manually then you must
# set and export these parameters else aws cli will fail.
# For automation, cli will be configured to access resources via roles. This role will be attached to the control machine.
# AWS Region is still set as an env varible
################################
#export AWS_ACCESS_KEY_ID='<access_key_id>'
#export AWS_SECRET_ACCESS_KEY='<secret_access_key>'
#export AWS_DEFAULT_REGION='<default_region>'
#################################

###########################################
# Retrieves manager instances from auto scaling group
# Globals:
#   $managers
# Arguments:
#   None
# Returns:
#   None
###########################################
function set_manager_nodes () {
    instances=$(aws autoscaling describe-auto-scaling-groups --auto-scaling-group-name $ucp_asg_name --output text --query 'AutoScalingGroups[0].Instances[*].InstanceId')
    arr=( $instances )
    arrlen="${#arr[@]}"

    # extract leader
    leader="${arr[@]:0:1}"

    # rest are managers
    managers="${arr[@]:1}"
}

###########################################
# Retrieves worker instances from auto scaling group
# Globals:
#   $workers
# Arguments:
#   None
# Returns:
#   None
###########################################
function set_worker_nodes () {
  dtrnodes=$(aws autoscaling describe-auto-scaling-groups --auto-scaling-group-name $dtr_asg_name --output text --query 'AutoScalingGroups[0].Instances[*].InstanceId')
  arr=( $dtrnodes )
  workers="${arr[@]}"
}

###########################################
# Adds leader, worker and manager nodes to elb(s)
# Globals:
#   $ucp_elb
#   $dtr_elb
#   $leader
#   $managers
#   $workers
# Arguments:
#   None
# Returns:
#   None
###########################################
function set_elb () {
    # add leader to UCP elb
    leaderlen=${#leader}
    if [ $leaderlen -gt 0 ]
    then
      # add leader to ucp elb
      echo 'Adding leader to elb ' $leader
      output=$(aws elb register-instances-with-load-balancer --load-balancer-name $ucp_elb --instances $leader --output text --query 'Instances[*].InstanceId')
    fi

    # add managers to UCP elb
    managerlen=${#managers[@]}
    if [ $managerlen -gt 0 ]
    then
      echo 'Adding managers to elb ' $managers
      output=$(aws elb register-instances-with-load-balancer --load-balancer-name $ucp_elb --instances $managers --output text --query 'Instances[*].InstanceId')
    fi

    # add workers to DTR elb
    workerlen=${#workers[@]}
    if [ $workerlen -gt 0 ]
    then
      echo 'Adding workers to dtr elb ' $workers
      output=$(aws elb register-instances-with-load-balancer --load-balancer-name $dtr_elb --instances $workers --output text --query 'Instances[*].InstanceId')
    fi

}

###########################################
# Retrieves public and private ip of leader node
# Globals:
#   $workers
# Arguments:
#   None
# Returns:
#   None
###########################################
function set_leader_ips () {
  # set leader public and private ip addresses
    leaderlen=${#leader}
    if [ $leaderlen -gt 0 ]
    then
      # add leader to ucp elb
      output=$(aws ec2 describe-instances --instance-ids $leader --output text --query 'Reservations[0].Instances[0].[PublicIpAddress, PrivateIpAddress]')

      iparr=( $output )
      outputlen=${#iparr[@]}

      if [ $outputlen -gt 0 ]
      then
        # store public ip
        leader_public_ip="${iparr[@]:0:1}"
        echo '\nleader public ip' $leader_public_ip

        # store private ip
        leader_private_ip="${iparr[@]:1:1}"
        echo 'leader private ip' $leader_private_ip
      fi
    fi
}

###########################################
# Retrieves public and private ip of manager nodes
# Globals:
#   $workers
# Arguments:
#   None
# Returns:
#   None
###########################################
function set_manager_ips () {
    managerlen=${#managers[@]}
    if [ $managerlen -gt 0 ]
    then
      manager_public_ips=$(aws ec2 describe-instances --instance-ids $managers --output text --query 'Reservations[*].Instances[*].PublicIpAddress')
      manager_private_ips=$(aws ec2 describe-instances --instance-ids $managers --output text --query 'Reservations[*].Instances[*].PrivateIpAddress')

      echo '\nManager Public IPs: ' $manager_public_ips
      echo 'Manager Private IPs: ' $manager_private_ips
    fi
}

###########################################
# Retrieves public and private ip of worker nodes
# Globals:
#   $workers
# Arguments:
#   None
# Returns:
#   None
###########################################
function set_worker_ips () {
    workerlen=${#workers[@]}
    if [ $workerlen -gt 0 ]
    then
      worker_public_ips=$(aws ec2 describe-instances --instance-ids $workers --output text --query 'Reservations[*].Instances[*].PublicIpAddress')
      worker_private_ips=$(aws ec2 describe-instances --instance-ids $workers --output text --query 'Reservations[*].Instances[*].PrivateIpAddress')

      echo '\nWorker Public IPs: ' $worker_public_ips
      echo 'Worker Private IPs: ' $worker_private_ips
      echo '\n'
    fi
}

###########################################
# Check if nodes are accessible through ssh
# Globals:
#   $dev_key
#   $leader_private_ip
# Arguments:
#   None
# Returns:
#   boolean
###########################################
function check_ssh () {
  # check leader
  leaderok=1
  leaderok=$(ssh -o StrictHostKeyChecking=no ConnectTimeout=1 -i $dev_key ec2-user@$leader_private_ip 'exit' 2>&1 | grep 'timed out' | wc -l)
  if [ $leaderok -eq 0 ]
  then
    echo 'ssh to ('$leader_private_ip') is ok\n'
  else
    leaderok=1
  fi

  # check managers
  managerok=1
  for i in ${manager_private_ips[@]}
  do
    managerok=$(ssh -o StrictHostKeyChecking=no ConnectTimeout=1 -i $dev_key ec2-user@$i 'exit' 2>&1 | grep 'timed out' | wc -l)
    if [ $managerok -eq 0 ]
    then
      echo 'ssh to ('$i') is ok'
    else
      managerok=1
      break;
    fi
  done
  echo '\n'

  # check workers
  workerok=1
  for i in ${worker_private_ips[@]}
  do
    workerok=$(ssh -o StrictHostKeyChecking=no ConnectTimeout=1 -i $dev_key ec2-user@$i 'exit' 2>&1 | grep 'timed out' | wc -l)
    if [ $workerok -eq 0 ]
    then
      echo 'ssh to ('$i') is ok'
    else
      workerok=1
      break;
    fi
  done
  echo '\n\n'

  # all statuses must be ok else return false (1)
  if [ $leaderok -eq 0 -a $managerok -eq 0 -a $workerok -eq 0 ]
  then
    return 0
  else
    return 1
  fi
}

###########################################
# Check if docker is installed on all nodes
# Globals:
#   $dev_key
#   $leader_private_ip
#   $manager_public_ip
#   $worker_public_ip
# Arguments:
#   None
# Returns:
#   boolean
###########################################
function is_docker_installed () {
  # check leader
  leader_has_docker=1
  leader_has_docker=$(ssh -o StrictHostKeyChecking=no ConnectTimeout=1 -i $dev_key ec2-user@$leader_private_ip "docker --version" 2>&1)
  if [[ "$leader_has_docker" =~ "command not found" ]]
  then
    leader_has_docker=1
  else
    leader_has_docker=0
  fi

  # check managers
  manager_has_docker=1
  for i in ${manager_private_ips[@]}
  do
    manager_has_docker=$(ssh -o StrictHostKeyChecking=no ConnectTimeout=1 -i $dev_key ec2-user@$i "docker --version" 2>&1)
    if [[ "$manager_has_docker" =~ "command not found" ]]
    then
      manager_has_docker=1
    else
      manager_has_docker=0
    fi
  done


  # check workers
  worker_has_docker=1
  for i in ${worker_private_ips[@]}
  do
    worker_has_docker=$(ssh -o StrictHostKeyChecking=no ConnectTimeout=1 -i $dev_key ec2-user@$i "docker --version" 2>&1)
    if [[ "$worker_has_docker" =~ "command not found" ]]
    then
      worker_has_docker=1
    else
      worker_has_docker=0
    fi
  done

  # all statuses must be ok else return false (1)
  if [ $leader_has_docker -eq 0 -a $manager_has_docker -eq 0 -a $worker_has_docker -eq 0 ]
  then
    return 0
  else
    return 1
  fi
}

##############################
# installs ucp on a leader node
##############################
function install_ucp () {
  echo 'installing ucp...'
  ssh -t -o StrictHostKeyChecking=no -i $dev_key ec2-user@$leader_private_ip "sudo docker run --rm -it --name ucp -v /var/run/docker.sock:/var/run/docker.sock docker/ucp install --host-address $leader_private_ip  --admin-username $username  --admin-password $password  --san $ucp_url >> ucp-install.log" 2>&1
  sleep 120
}

##############################
# get ucp status
##############################
function get_ucp_status () {
  sleep 30s # wait for 30 seconds before pinging the ucp
  ucpok=$(curl --insecure https://$leader_private_ip/_ping)
  echo $ucpok
}

##############################
# joins manager nodes
# Arguments:
#   $mgrtoken
##############################
function join_manager_nodes () {
  echo 'joining manager nodes...'
  for i in ${manager_private_ips[@]}
  do
    ssh -t -o StrictHostKeyChecking=no -i $dev_key ec2-user@$i "sudo docker swarm join --token $1 --advertise-addr $i $leader_private_ip:2377" 2>&1
    sleep 120
  done;
}

##############################
# joins worker nodes
# Arguments:
#   $workertoken
##############################
function join_worker_nodes () {
  echo 'joining worker nodes...'
  for i in ${worker_private_ips[@]}
  do
    ssh -t -o StrictHostKeyChecking=no -i $dev_key ec2-user@$i "sudo docker swarm join --token $1 --advertise-addr $i $leader_private_ip:2377" 2>&1
    sleep 120
  done;
}

##############################
# installs dtr to primary node
##############################
function install_dtr () {
  echo 'preparing dtr install...'
  arr=( $workers )
  worker="${arr[@]:0:1}"
  primary_dtr_node=$worker # will be used to extract this node out of workers
  iparr=( $worker_private_ips )
  #worker_ip="${iparr[@]:0:1}"
  worker_ip=$(aws ec2 describe-instances --instance-id $worker --output text --query 'Reservations[0].Instances[0].PrivateIpAddress')
  hostname=$(aws ec2 describe-instances --instance-id $worker --output text --query 'Reservations[0].Instances[0].PrivateDnsName')
  hostname=$(cut -d '.' -f1 <<< $hostname)
  hostname=$hostname.treasury.local
  echo 'host name ' $hostname
  if [ ${#hostname} -gt 0 ]
  then
    echo 'installing dtr...'
    ssh -t -o StrictHostKeyChecking=no -i $dev_key ec2-user@$worker_ip "sudo docker run --rm -it docker/dtr install --dtr-external-url $dtr_url  --ucp-node $hostname --ucp-insecure-tls  --ucp-url $leader_private_ip --ucp-username $username --ucp-password $password --replica-id $replica_id >> dtr-install.log" 2>&1
  fi
  sleep 120
}

##############################
# joins dtr nodes
##############################
function join_dtr () {
  echo 'preparing nodes to join existing replica...' $replica_id
  workerarr=( $workers )
  workerlen="${#workerarr[@]}"

  if [ $workerlen -gt 1 ]
  then
    replicas=$(echo $workers | sed  "s/$primary_dtr_node //g")
    arr=( $replicas )
    arrlen=${#arr[@]}

    if [ $arrlen -gt 0 ]
    then
      for i in  ${replicas[@]}
      do
        dtr_ip=$(aws ec2 describe-instances --instance-ids $i --output text --query 'Reservations[*].Instances[0].PrivateIpAddress')
        hostname=$(aws ec2 describe-instances --instance-id $i --output text --query 'Reservations[0].Instances[0].PrivateDnsName')
        hostname=$(cut -d '.' -f1 <<< $hostname)
        hostname=$hostname.treasury.local

        echo $dtr_ip
        echo $hostname
        echo 'joining node existing replica...'
        ssh -t -o StrictHostKeyChecking=no -i $dev_key ec2-user@$dtr_ip "sudo docker run -it --rm docker/dtr join --ucp-node $hostname --ucp-insecure-tls --ucp-username $username --ucp-password $password --existing-replica-id $replica_id --ucp-url $leader_private_ip >> dtr-join.log" 2>&1
        sleep 120s
      done;
    fi
  else
    echo 'Cluster needs more than 1 workers to install additional replicas'
  fi
}

##############################
# function calls
#############################
set_manager_nodes # set manager nodes
set_worker_nodes # set worker nodes
set_elb # attaches instances to load balancer(s)
set_leader_ips # set leader ips (public and private)
set_manager_ips # set manager ips (public and private)
set_worker_ips # set worker ips (public and private)
ssh_status=$(check_ssh) # checks ssh status for each node

if [ $? -eq 0 ]
then
  echo 'ssh success (all nodes)'
else
  echo 'error in ssh'
fi

docker_status=$(is_docker_installed) #checks docker install on each node

if [ $? -eq 0 ]
then
  install_ucp # installs ucp
  ucp_status=$(get_ucp_status) #checks ucp status

  if [ $ucp_status = OK ]
  then
    # get manager token
    mgrtoken=$(ssh -o StrictHostKeyChecking=no -i $dev_key ec2-user@$leader_private_ip "sudo docker swarm join-token -q manager" 2>&1)
    echo 'Manager token' $mgrtoken

    # get worker token
    workertoken=$(ssh -o StrictHostKeyChecking=no -i $dev_key ec2-user@$leader_private_ip "sudo docker swarm join-token -q worker" 2>&1)
    echo 'Worker token' $workertoken

    # join manager nodes to UCP
    join_manager_nodes $mgrtoken
    sleep 120

    # join worker nodes to UCP
    join_worker_nodes $workertoken
    sleep 120

    # install DTR and log primary_dtr_node
    install_dtr

    # join remaining worker nodes to existing replica
    join_dtr

    #complete
    echo 'Docker EE install complete...'
  else
    echo 'error installing ucp. install failed.'
  fi
else
  echo 'docker is not installed'
fi
