#!/bin/bash
set -e

# Set variables
PROJECT_NAME="perry"
INSTANCE_QUOTA=-1
CPU_QUOTA=-1
RAM_QUOTA=-1

KEY_NAME="beluga1"
KEY_FILE="~/.ssh/id_ed25519.pub"
IMAGE_NAME="Ubuntu24"
IMAGE_FILE="$(dirname "$0")/ubuntu24.qcow2"
KALI_IMAGE_NAME="Kali"
KALI_IMAGE_FILE="$(dirname "$0")/kali_attacker.qcow2"
IMAGE_FORMAT="qcow2"
ADMIN_USER="admin"
ROLE_NAME="admin" # Change if you want to use a different role for the admin user in the project

# Source the OpenStack credentials
export OS_CLOUD=admin

# External network
EXTERNAL_NETWORK_NAME="external"        # Name of the external network
SUBNET_NAME="ext-subnet"              # Name of the subnet
CIDR="192.168.1.0/24"               # CIDR for the subnet
GATEWAY="192.168.1.1"                 # Gateway for the subnet
DNS_SERVER="8.8.8.8"                  # DNS server
PHYSICAL_NETWORK="physnet1"

openstack network create \
  --external \
  --provider-network-type flat \
  --provider-physical-network $PHYSICAL_NETWORK \
  $EXTERNAL_NETWORK_NAME
  
openstack subnet create \
  --network "$EXTERNAL_NETWORK_NAME" \
  --subnet-range "$CIDR" \
  --gateway "$GATEWAY" \
  --dns-nameserver "$DNS_SERVER" \
  --no-dhcp \
  "$SUBNET_NAME"

# Create a project named "perry" with 100 CPU and 100GB RAM quota
openstack project create --description "Project Perry" "$PROJECT_NAME"
PROJECT_ID=$(openstack project show "$PROJECT_NAME" -f value -c id)
openstack quota set --cores $CPU_QUOTA --ram $RAM_QUOTA --instances $INSTANCE_QUOTA "$PROJECT_ID"
echo "Created project '$PROJECT_NAME' with CPU quota of $CPU_QUOTA and RAM quota of $RAM_QUOTA MB."

# Add the "admin" user to the "perry" project with the "admin" role
openstack role add --project "$PROJECT_NAME" --user "$ADMIN_USER" "$ROLE_NAME"
echo "Added user '$ADMIN_USER' to project '$PROJECT_NAME' with role '$ROLE_NAME'."

# Add SSH key "beluga1" from a file
openstack keypair create --public-key "$KEY_FILE" "$KEY_NAME"
echo "Added SSH key '$KEY_NAME' from file '$KEY_FILE'."

# Create p1.tiny flavor
FLAVOR_NAME="p2.tiny"
FLAVOR_CPU=1
FLAVOR_RAM=1024 # In MB
FLAVOR_DISK=5   # In GB
openstack flavor create "$FLAVOR_NAME" --vcpus "$FLAVOR_CPU" --ram "$FLAVOR_RAM" --disk "$FLAVOR_DISK"
echo "Created flavor '$FLAVOR_NAME' with $FLAVOR_CPU CPU, $FLAVOR_RAM MB RAM, and $FLAVOR_DISK GB disk."

# m1.small flavor
FLAVOR_NAME="m1.small"
FLAVOR_CPU=1
FLAVOR_RAM=2048 # In MB
FLAVOR_DISK=20  # In GB
openstack flavor create "$FLAVOR_NAME" --vcpus "$FLAVOR_CPU" --ram "$FLAVOR_RAM" --disk "$FLAVOR_DISK"
echo "Created flavor '$FLAVOR_NAME' with $FLAVOR_CPU CPU, $FLAVOR_RAM MB RAM, and $FLAVOR_DISK GB disk."

# m2.medium flavor
openstack flavor create m2.medium --vcpus 2 --ram 4096 --disk 20
echo "Created flavor 'm2.medium'."

# m2.large flavor
openstack flavor create m2.large --vcpus 4 --ram 8192 --disk 40
echo "Created flavor 'm2.large'."

# m2.huge flavor
openstack flavor create m2.huge --vcpus 8 --ram 16384 --disk 80
echo "Created flavor 'm2.huge'."

# Upload an image and make it public
openstack image create "$IMAGE_NAME" --file "$IMAGE_FILE" --disk-format "$IMAGE_FORMAT" --public
echo "Uploaded image '$IMAGE_NAME' from '$IMAGE_FILE' and made it public."

# Upload an image and make it public
openstack image create "$KALI_IMAGE_NAME" --file "$KALI_IMAGE_FILE" --disk-format "$IMAGE_FORMAT" --public
echo "Uploaded image '$KALI_IMAGE_NAME' from '$KALI_IMAGE_FILE' and made it public."
