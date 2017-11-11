## :wrench: **Build Tutorial** - **Setting up a CCIE R&S lab in KVM**

This in-depth build tutorial provides a step-by-step process to deploy the INE R&S v5(.1) topology on a Linux QEMU/KVM node. It includes detailed instructions for preparing the environment, patching the Linux kernel, configuring the appropriate network settings, deploying QEMU/KVM linked clones, creating the IOS on Unix (IOU) environment and configuring remote management. Lastly it includes a section on how to automate the deployment process.

This build tutorial mainly focuses on building the INE lab topology as show below, however, with minor modifications any arbitrary lab environment can be created.

![INE Physical Lab Topology](https://d1hx5100zal7gj.cloudfront.net/images/ine/ine-ccie-lab-topology.jpg "INE Lab Environment")

In this tutorial a Debian-based system is assumed. More specifically, all commands have been tested on Ubuntu 16.04.3 LTS. RHEL based systems may require slightly different packages and/or configurations. Your mileage may vary. Furthermore, during this tutorial the KVM node will commonly be referenced to as the 'host machine'. Similarly, the routers and switches running on the host machine will be referred to as the 'guest nodes'. 

----------

### **Table of Contents**

* [<strong>Build Tutorial</strong> - <strong>Setting up a CCIE R&amp;S lab in KVM</strong>](#build-tutorial---setting-up-a-ccie-rs-lab-in-kvm)
   * [<strong>Table of Contents</strong>](#table-of-contents)
   * [<strong>1 - Setting up prerequisites</strong>](#1---setting-up-prerequisites)
      * [<strong>1.1 - Define environment variables</strong>](#11---define-environment-variables)
      * [<strong>1.2 - Installing prerequisites</strong>](#12---installing-prerequisites)
   * [<strong>2 - Compiling the custom Linux kernel</strong>](#2---compiling-the-custom-linux-kernel)
      * [<strong>2.1 - Downloading, patching and compiling sources</strong>](#21---downloading-patching-and-compiling-sources)
   * [<strong>3 - Setting up bridging</strong>](#3---setting-up-bridging)
   * [<strong>4 - Creating linked clone virtual machine(s)</strong>](#4---creating-linked-clone-virtual-machines)
      * [<strong>4.1 - Creating the base image file</strong>](#41---creating-the-base-image-file)
      * [<strong>4.2 - Deploying the base VM</strong>](#42---deploying-the-base-vm)
   * [<strong>5 - Set up IOS on Unix (IOU) environment</strong>](#5---set-up-ios-on-unix-iou-environment)
      * [<strong>5.1 - Performing initial setup of the environment</strong>](#51---performing-initial-setup-of-the-environment)
      * [<strong>5.2 - Writing the NETMAP file</strong>](#52---writing-the-netmap-file)
      * [<strong>5.3 - Deploying the IOU network</strong>](#53---deploying-the-iou-network)
      * [<strong>5.4 - Wrapping the IOU nodes</strong>](#54---wrapping-the-iou-nodes)
   * [<strong>6 - Enabling remote connections to the lab environment</strong>](#6---enabling-remote-connections-to-the-lab-environment)
      * [<strong>6.1 - Modify the firewall</strong>](#61---modify-the-firewall)
      * [<strong>6.2 - (Optional) Generate connection aliases</strong>](#62---optional-generate-connection-aliases)
   * [<strong>7 - Automating lab deployments</strong>](#7---automating-lab-deployments)
      * [<strong>7.1 - Deploying CSR routers</strong>](#71---deploying-csr-routers)
      * [<strong>7.2 - Coupling the IOU environment</strong>](#72---coupling-the-iou-environment)
      * [<strong>7.3 - Saving and restoring the configuration</strong>](#73---saving-and-restoring-the-configuration)
      * [<strong>7.4 - Capturing traffic</strong>](#74---capturing-traffic)


----------

### **1 - Setting up prerequisites**
The recommended virtual R&S v5.1 environment uses a mix of CSR 1000v routers and IOS on Unix (IOU) switches. Prior to installing any packages, the appropriate images should be made available on the host machine.

#### **1.1 - Define environment variables**
Although the images provided above are recommended for the R&S lab, different images may be used. If you happen to change the version, update the variables below as they will be referenced during the installation process various times. Additionally, make sure that the CSR image is a `.iso` and that the OUI L2 image is unpacked to a `.bin`. 

The latest stable version of the Linux kernel is assumed during this tutorial by exporting the `KERNEL_VER`. If you prefer a different kernel version override the environment variable manually.

```shell
# The CCIE R&S V5 lab uses IOS 15.3M&T for its routers. The image referenced below comes very close in terms of the required features and is the recommended version by INE. 
export CSR_IMG="~/images/csr1000v-universalk9.03.15.04.S.155-2.S4-std.iso"

# Although the CCIE R&S V5.1 lab uses IOS 15.0SE for its switches, the IOU image below is the most complete in terms of featureset and is therefore the recommended version.       
export IOU_IMG="~/images/i86bi-linux-l2-adventerprisek9-15.2d.bin"                                       

# Define the mainline version of the current stable Linux kernel
export KERNEL_VER=$(curl -s https://www.kernel.org/ | grep -A 1 'latest_link' | sed -e 's/<[^>]*>//g' | tail -n1 | cut -d '.' -f 1-2 | tr -d '[:blank:]')
```

#### **1.2 - Installing prerequisites**
To create virtual machines in QEMU/KVM various packages are required. Additionally, various packages and libraries are required for building the kernel and for the correct operation of IOU. 
```shell
sudo apt update -y && sudo apt install -y \
  qemu-kvm \
  libvirt-bin \
  virtinst \
  bridge-utils \
  cpu-checker \
  build-essential \
  build-dep linux-image-$(uname -r)
```

### **2 - Compiling the custom Linux kernel**
Deploying several CSR 1000v routers is a memory intensive operation. In order to increase the scalability of the host machine, memory deduplication should be employed. However, the default Kernel Samepage Merging (KSM) process in the Linux kernel does not provide sufficient deduplication. Ultra Kernel Samepage Merging (UKSM) improves upon the default KSM process and allows for an efficient memory deduplication method which works similarly to VMware's Transparent Page Sharing (TPS) feature. Because UKSM is not included in the mainline kernel by default, a custom kernel has to be built with patched sources.

#### **2.1 - Downloading, patching and compiling sources**
The commands below retrieve, unpack and patch the latest stable kernel with the matching UKSM patch. **NOTE:** If a kernel version is promoted to stable, it might occur that there is no matching UKSM patch available yet. If this were to happen, downgrade to the previous stable kernel and use the latest patch. Also, manually update the environment variable `KERNEL_VER` in section. 

```shell
# Create a working directory
mkdir ~/kernel && cd $_ 

# Retrieve and download the latest kernel version 
STABLE_LINK=$(curl -s https://www.kernel.org/ | grep -A1 'latest_link' | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*")
wget $STABLE_LINK -O stable_kernel.tar.xz

# Unpack the sources and apply the UKSM patch
tar -xf stable_kernel.tar.xz -C ~/kernel

# Download and apply the UKSM patch
wget https://github.com/dolohow/uksm/blob/master/uksm-"$KERNEL_VER".patch
patch -p1 < uksm-"$KERNEL_VER".patch
```

At this point the kernel is ready to be compiled from source. Compiling the kernel is a time-consuming process and may take up to approximately an hour depending on CPU capacity. The `make` command below is suffixed with the `-j9` flag which starts 9 simultaneous jobs. Although this significantly speeds up the build process it also severely deteriorates the usability of the host during compilation. Lower this number if you want to keep using your machine during compilation. Additionally, kernel debugging information can optionally be disabled during the build process to speed up compilation. 

```shell
# Copy the current kernel config
cp /boot/config-`uname -r` .config
make olddefconfig

# Speed up compile time by disabling debugging
scripts/config --disable DEBUG_INFO

# Compile the kernel with a 'uksm' suffix. (Timing the build is optional)
time make -j9 bindeb-pkg LOCALVERSION=-uksm

# Finally, install the compiled binaries
sudo dpkg -i linux-*.deb
```
After installing the binaries, `GRUB` is automatically updated to include the new kernel as a boot entry. 

### **3 - Setting up bridging**
By default Ubuntu performs dynamic naming of network interfaces. You can optionally revert to a more human-readable scheme of e.g. `ethX` and `wlanX` by changing the `GRUB_CMDLINE_LINUX` line in `/etc/default/grub`:

```shell
# (Optional) Disable dynamic naming of network interfaces on host machine
sed -i '/GRUB_CMDLINE_LINUX/{s/\"\"/\"net\.ifnames\=0\"/g;s/#//g}' /etc/default/grub **&& reboot**
```
After rebooting the host machine, make sure you select the correct kernel when booting. Next, `brctl` is used to create a virtual bridge to which all CSR nodes connect. **NOTE:** If you didn't change the dynamic naming convention, make sure you select the correct interface to add to the bridge. 

```shell
# Create a virtual bridge and add interfaces
brctl addbr virbr0
brctl addif virbr0 eth0         
```

The connection of the IOU switch(es) to the newly created bridge is handled later by defining the `NETMAP` file. For IOU, refer to [Section 5](#5-set-up-ios-on-unix-iou-environment). 

### **4 - Creating linked clone virtual machine(s)**
A full scale R&S lab may have up to 20 CSR 1000v routers running simultaneously. In order to prevent reconfiguring every CSR router on boot and to save space on the host machine a *golden image* is created. Subsequently deployed routers will be linked clones based on the golden image. Note that any and every change made to the golden image logically applies to every deployed router onwards.

At this point it may be interesting understand the relationship between QEMU and KVM. As explained by Ignacio Vazquez-Abrams on ServerFault:
> "When working together, KVM arbitrates access to the CPU and memory, and QEMU emulates the hardware resources (hard disk, video, USB, etc.). When working alone, QEMU emulates both CPU and hardware.

For our lab scenario this means that we will be creating a series of Copy-On-Write (`cow`) hard disks in QEMU which will allow for only storing incremental changes in the linked clone. Subsequently, the hard disks will be used in creating KVM virtual machines. This way each router will receive hardware acceleration assuming your processor supports this feature. You can check whether your CPU supports KVM hardware acceleration by running the command `kvm-ok`:

```shell
$ kvm-ok
INFO: /dev/kvm exists
KVM acceleration can be used
```

#### **4.1 - Creating the base image file**
First we need to create a blank image file which will serve as the container for the base router. Note that the disk image is thin provisioned. 

```shell
qemu-img create -f qcow2 golden_image.qcow2 8G
```

Subsequently the CSR 1000v `.iso` has to be installed in the newly created container image. This can be done with the command below. **NOTE:** After running the command below **IMMEDIATELY** hit <kbd>Enter</kbd>. After that, choose the serial console. If you happen to miss the prompt, kill the installation and restart. Your `golden_image.qcow2` file will be unchanged. Wait for the VM to fully boot and hit <kbd>Enter</kbd> when prompted. Then select the serial console again and wait for the VM to boot for a second time.

```shell
qemu-system-x86_64 -nographic -drive file=golden_image.qcow2,if=virtio,bus=0,unit=0,cache=none -machine type=pc-1.0,accel=kvm -serial mon:stdio -nographic -nodefconfig -nodefaults -rtc base=utc -cdrom $CSR_IMG -boot order=dc -m 3072 
```

When the Router has fully booted for the second time, you have the option to make changes to the golden image. I personally suggest changing the license level and leaving the rest default.

```
Router(config)# license boot level ax
Router(config)# do wr
``` 

At this point the installation is finished and you can close the terminal (thus killing the `qemu-system-x86_64` process). Also note that your `golden_image.qcow2` file has significantly grown in size:

```shell
-rw-r--r-- 1 user 1,7G okt  9 19:38 golden_image.qcow2
```

The `qemu-img` command can then be used to create an identical copy of the golden image:

```shell 
qemu-img create -f qcow2 -b golden_image.qcow2 linked_clone1.qcow2
```

The created linked image file can now be coupled to a KVM virtual machine. [Section 7](#7-automating-lab-deployments) of this tutorial discusses methods for automating this creation process and automatically spinning up a series of routers. 


#### **4.2 - Deploying the base VM**
With the linked clone created, a KVM virtual machine can be deployed. The command below creates a VM with the name `RTR1` with a base image of `linked_clone1.qcow2`. Each guest node will have a connection to the previously created virtual bridge `virbr0`. Additionally `virt-install` binds a TCP port on the host machine to the guest node. 

```shell
virt-install \
 --connect=qemu:///system \
 --name=RTR1 \
 --os-type=linux \
 --os-variant=rhel4 \
 --arch=x86_64 \
 --cpu host \
 --vcpus=1,sockets=1,cores=1,threads=1 \
 --hvm \
 --ram=3072 \
 --import \
 --disk path=linked_clone1.qcow2,bus=ide,format=qcow2 \
 --network bridge=virbr0,model=virtio \
 --serial tcp,host=:2001,mode=bind,protocol=telnet \
 --noreboot
```

Finally, the newly created VM can be started with `virsh`:
```shell
virsh start RTR1
```

The VM is manageable over telnet by connecting to the TCP port on the host machine:
```shell 
telnet localhost 2001
```

Again, refer to [Section 7](#7-automating-lab-deployments) for a description of how to automate this deployment process. 

### **5 - Set up IOS on Unix (IOU) environment**
Up next is the switched environment. The switches will run on the IOU platform which -although not perfect- support most of the required features for the CCIE R&S exam. 

#### **5.1 - Performing initial setup of the environment**
IOU images are designed to be used by Cisco internally and include a call home feature in their code. Although the destination `xml.cisco.com` is unreachable at the time of writing, it may be for the best to blackhole any traffic to this host. 
 
```shell
# Disable call home feature of IOU images
echo '127.0.0.1 xml.cisco.com' >> /etc/hosts
```
In order to run IOU images a valid license file is required. The command below utilizes a Python script to generate a license and installs it in `~/.iourc`. **NOTE:** The license file is coupled to the hostname, meaning that if you were to change the hostname of your KVM host, the license file has to be recreated.  

```shell
curl -s 'https://gist.githubusercontent.com/paalfe/8edd82f780c650ae2b4a/raw/bd7b6b8a81c338359e6de4ff0ed0def9f7dc9146/CiscoKeyGen.py' | python | grep 'echo -e' | bash
```

In theory it is possible to manually start the IOU node if the binary image is made executable. However, it is tedious to manually start every IOU node and to create the virtual links between them. Therefor we will use `ioulive86` which functions as a wrapper for IOU and allows for defining a `NETMAP` file. The `NETMAP` defines which nodes are connected to each other via which links. `ioulive86` then allows for automatically deploying the switched network. 

The command below clones, builds and installs the `ioulive86` binary in `/usr/bin`, making it executable from anywhere (assuming `/usr/bin` is still in your `$PATH`, which it should be).     

```shell
cd ~ & git clone 'https://github.com/jlgaddis/ioulive86.git' && make 2> /dev/null && sudo cp ioulive86 /usr/bin/
```

#### **5.2 - Writing the NETMAP file**
The `NETMAP` file defines a series of nodes (by ID number) and specifies to which node (by ID number) it is connected. For example, the first line below indicates that a node, identified with ID number '1' is connected to another node with ID number '2' on its `Eth0/0` interface.

```shell
/* Point-to-Point connection */
1:0/0 2:0/0
``` 
The INE lab uses a topology as shown below. Building on the basic concept as explained above, the command below generates the `NETMAP` file associated to the INE switch topology. Note that SW4 has no links defined in the `NETMAP` as all links are created bidirectionally. The last line is special in that it connects the `Eth1/2` interface on SW1 to a virtual interface on the host machine. More on this in the following subsection. 

![Sample lab environment](https://i.imgur.com/wS3t4u8.png)

```shell
cat <<EOF >> NETMAP

/* SW1 interconnections */
1:0/0 2:0/0 
1:0/1 2:0/1
1:0/2 4:0/2 
1:0/3 4:0/3
1:1/0 3:1/0
1:1/1 3:1/1
    
/* SW2 interconnections */
2:0/2 3:0/2
2:0/3 3:0/3
2:1/0 4:1/0
2:1/1 4:1/1

/* SW3 interconnections */
3:0/0 4:0/0
3:0/1 4:0/1

/* Host connection */
1:1/2@$(hostname) 999:0@$(hostname)

EOF
```

#### **5.3 - Deploying the IOU network**
Deploying the nodes would be as simple as executing the instances of the IOU binary suffixed with the appropriate ID:

```shell
     # Image path                                      # ID
sudo ~/images/i86bi-linux-l2-adventerprisek9-15.2d.bin 1
sudo ~/images/i86bi-linux-l2-adventerprisek9-15.2d.bin 2
sudo ~/images/i86bi-linux-l2-adventerprisek9-15.2d.bin 3
sudo ~/images/i86bi-linux-l2-adventerprisek9-15.2d.bin 4
```
To create the bridged connection from SW1 to `virbr0`,  run:

```shell
sudo ioulive86 -i virbr0 999
```
This creates a virtual network device in `/tmp/netio1000` and links the interfaces together. Testing the connection can be done by assigning an IP address to the `virbr0` interface and pinging the `Eth0/0` interface on SW1. 

```shell
# SW1
SW1(config)#int eth0/0
SW1(config-if)#no switchport
SW1(config-if)#ip add 192.168.1.1 255.255.255.0

# Host machine
ifconfig virbr0 192.168.1.2 netmask 255.255.255.0
```

**Verification**:
```shell
$ ping 192.168.1.2
PING 192.168.1.2 (192.168.1.2) 56(84) bytes of data.
64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=0.033 ms
64 bytes from 192.168.1.1: icmp_seq=2 ttl=64 time=0.057 ms
```
If the connection is not working, make sure that you initiate `ioulive86` with the correct ID number and that you are running the IOU instances with elevated privileges.

#### **5.4 - Wrapping the IOU nodes**
At this point the IOU devices are up and running, but there is no TCP port associated to the nodes. This means that (remote) management would be tedious. A preferable situation would be to make the devices manageable via a telnet session (just like the CSR routers). In order to assign a TCP port to the individual switches we use `wrapper-linux`. The commands below download and compile the binary and make it executable.

```shell
mkdir ~/wrapper-linux && cd $_
curl -s https://raw.githubusercontent.com/dainok/iou-web/master/wrapper/wrapper-linux.c > wrapper-linux.c 
curl -s https://raw.githubusercontent.com/dainok/iou-web/master/wrapper/Makefile > Makefile
make && sudo cp wrapper-linux /usr/bin
```

Quite literally, `wrapper-linux` 'wraps around' the IOU process. The command below shows how to start an IOU node via the wrapper. It references the IOU binary and assigns TCP port 2002 to the node. Flags passed after the `--` are destined for the IOU binary.  The flag `-s` indicates the amount of serial interface modules to be inserted in the node and similarly `-e` indicates the amount of Ethernet interface modules. The second `1` in the command indicates the node ID number which is referenced in the `NETMAP`. 
```shell
sudo wrapper-linux -m ~/images/i86bi-linux-l2-adventerprisek9-15.2d.bin -p 2002 -- -s 0 -e 1 1 2> /dev/null &
```

In order to prevent the IOU instance to spike to 100% CPU utilization, add the following line to the `/etc/sysctl.conf` file:

```shell
echo 'net.unix.max_dgram_qlen = 2000000'  | sudo tee --append /etc/systctl.conf
```

### **6 - Enabling remote connections to the lab environment**


#### **6.1 - Modify the firewall**
Assuming you deploy your lab environment on a remote server it is advisable to allow only the connections to the assigned TCP ports (and SSH for host management). The `iptables` rules below should get you started. 

```shell
sudo iptables -F
sudo iptables -P INPUT DROP
sudo iptables -A INPUT -i lo -p all -j ACCEPT
sudo iptables -A INPUT -i virbr0 -p all -j ACCEPT
sudo iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT 
sudo iptables -A INPUT -p tcp -m tcp --dport 2001 -j ACCEPT 
sudo iptables -A INPUT -p tcp -m tcp --dport 2002 -j ACCEPT 
sudo iptables -A INPUT -j DROP
```

#### **6.2 - (Optional) Generate connection aliases**
To quickly connect to the created devices I suggest adding a series of device specific aliases. Assuming you use `bash` (default), you can add aliases to your `~/.bash_aliases` file which is loaded by `~/.bash_rc` on boot by default. 

```shell
cat <<EOT >> ~/.bash_aliases
alias R1="telnet $(hostname) 2001"
alias SW1="telnet $(hostname) 2002"
# Repeat for additional nodes
EOT
```

### **7 - Automating lab deployments [WIP]**
Deploying the full topology by hand is a time-consuming process. Creating the linked clones, deploying the KVM virtual machines, deploying and bridging the IOU environment and defining the aliases and firewall rules adds up. For this purpose I created `labber`. 

First, install the prerequisites:

```shell
sudo apt install libvirt-dev
sudo pip3 install libvirt-python
```

#### **7.1 - Deploying CSR routers**
[WIP]

#### **7.2 - Coupling the IOU environment**
[WIP]

#### **7.3 - Saving and restoring the configuration**
[WIP]

#### **7.4 - Capturing traffic**
[WIP]
