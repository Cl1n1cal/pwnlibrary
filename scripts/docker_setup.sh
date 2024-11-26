#!/bin/bash

# Parse command line args
if [[ "$#" -ne 1 ]]; then
    echo "[!] Error: docker_setup.sh"
    echo "[!] usage ./docker_setup.sh <chall name>"
    exit 1
fi

echo "[+] Stopping and removing all containers"
sudo docker stop $(sudo docker ps -q) && sudo docker rm $(sudo docker ps -a -q)


# Specify the image name (replace with your image name)
IMAGE_NAME="$1"

# Check if the image exists by looking for it in the output of 'docker images'
if sudo docker images -q "$IMAGE_NAME" > /dev/null 2>&1; then
    echo "[+] Image '$IMAGE_NAME' exists. Removing it..."
    sudo docker rmi "$IMAGE_NAME"
else
    echo "Image '$IMAGE_NAME' does not exist."
fi

echo "[+] Running docker_setup.sh"

echo "[+] Building image"
sudo docker build -t $1 .

echo "[+] Starting container in the background"
sudo docker run -d $1

# Get the container ID of the running container created from the image
container_id=$(sudo docker ps -q -f ancestor="$IMAGE_NAME")

# Check if the container ID was found
if [ -n "$container_id" ]; then
    echo "Container ID for image '$IMAGE_NAME': $container_id"
else
    echo "No running container found for image '$IMAGE_NAME'."
fi

echo "[+] Copying linker"
sudo docker cp $container_id:/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 .

echo "[+] Copying libc"
sudo docker cp $container_id:/lib/x86_64-linux-gnu/libc.so.6 .

#echo "[+] Setting executable permissions +x"
#sudo chmod +x libc.so.6
#sudo chmod +x ld-linux-x86-64.so.2

echo "[+] Running pwninit"
cp $HOME/misc/pwninit .
./pwninit --bin $1 --ld ld-linux-x86-64.so.2 --libc libc.so.6

echo "[+] Removing unnecessary files"
rm pwninit

echo "[+] docker_setup.sh finished!"