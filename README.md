```
                ___.     .__                       __     .__             ___.
                \_ |__   |  |   _____      ____   |  | __ |  |   _____    \_ |_
                 | __ \  |  |   \__  \   _/ ___\  |  |/ / |  |   \__  \    | __ \ 
                 | \_\ \ |  |__  / __ \_ \  \___  |    <  |  |__  / __ \_  | \_\ \
                 |___  / |____/ (____  /  \___  > |__|_ \ |____/ (____  /  |___  /
                     \/              \/       \/       \/             \/       \/ 
                             
                       My Cheap Virtual Homelab Setup With KVM Hypervisor

```

Introduction
------------

The following is a detail description of my virtualized homelab lab with
[KVM] hypervisor to supplement my hands-on labs for information security.

I don't have powerful hardware at disposal so I decide to reuse my old laptop
for this purpose.Therefore I intend to maintain this repo up-to-date whenever 
there's a hardware change/upgrade. 

Homelab Overview
---------------- 
The overview of the homelab setup and devices description

![Homelab Preview](https://i.imgur.com/9PrGCx1.png)

- KVM host (laptop) 

   ```
	System Information
		Manufacturer: SAMSUNG ELECTRONICS CO., LTD.
		Product Name: 300E4Z/300E5Z/300E7Z
		Version: 0.1
		Family: HuronRiver System
	System Memory
		Capacity: 6GB
	Processor 
		Intel(R) Celeron(R) CPU B815 @ 1.60GHz
	Operating System
		Debian GNU/Linux 9 (stretch)
	Hypervisor 
		KVM
   ```
- Workstation (laptop)

   ```
	System Information
		Manufacturer: LENOVO
		Product Name: 20FES1H260
		Version: ThinkPad S1Yoga(2ndGen)
	System Memory
		Capacity: 8GB
	Processor 
		Intel(R) Core(TM) i7-6500U CPU @ 2.50GHz
	Operating System
		Qubes OS (R4.0)
   ```

- Raspberry Pi 3 Model B+


Setting Up KVM Host
-------------------
In this section we will briefly discuss the following:
+ KVM installation
+ Network setup for the VMs

#### KVM installation
I'll be using Debian minimal as my KVM host which I have already installed.

+ Install KVM.
 
   ```
    $ sudo apt install qemu-kvm libvirt-clients libvirt-daemon-system bridge-utils libguestfs-tools virtinst libosinfo-bin
   ```

+ Allow normal user to manage virtual machines.

   ```
   $ sudo adduser mohabaks libvirt && sudo adduser c0b4l7 libvirt-qemu
   $ newgrp libvirt && newgrp libvirt-qemu # Reload group membership
   ```

+ Verify KVM is Installed.

   ```
    $ egrep --color 'vmx|svm' /proc/cpuinfo
   ```

+ Configure bridge network.

  Bridge will act as a WAN for pfSense.

  ```
  auto enp2s0
  #make sure we don't get addresses on our raw device
  iface enp2s0 inet manual
  iface enp2s0 inet6 manual

  #set up bridge and give it a static ip
  auto br0
  iface br0 inet static
                address 192.168.100.5
                netmask 255.255.255.0
                gateway 192.168.100.1

                bridge_ports enp2s0
                bridge_stp off
                bridge_fd 0
                dns-nameservers 8.8.8.8

  iface br0 inet6 auto
                accept_ra 1

  ```
+ Access KVM host remotely with virt-manager. `File->Add Connection..`

  ![virt-Manager](https://imgur.com/voz3NfJ.png)

  `blacklab` could be the IP address of our KVM host.

Bonus setting up [prometheus] and [grafana] to monitor our lab.

+ Downloading _prometheus, node_exporter, grafana_ with this [script].
+ Update `/etc/prometheus/prometheus.yml` with this contents to scrape node
exporter.

    ```yml
	global:
	  scrape_interval: 15s

	scrape_configs:
	  - job_name: 'prometheus'
	    scrape_interval: 5s
	    static_configs:
	      - targets: ['localhost:9090']
	  - job_name: 'node_exporter'
	    scrape_interval: 5s
	    static_configs:
	      - targets: ['localhost:9100']
   ```
+ Create `/etc/systemd/system/prometheus.service` to start/stop prometheus.

```
[Unit]
Description=Prometheus
Wants=network-online.target
After=network-online.target

[Service]
User=prometheus
Group=prometheus
Type=simple
ExecStart=/usr/local/bin/prometheus \
    --config.file /etc/prometheus/prometheus.yml \
    --storage.tsdb.path /var/lib/prometheus/ \
    --web.console.templates=/etc/prometheus/consoles \
    --web.console.libraries=/etc/prometheus/console_libraries

[Install]
WantedBy=multi-user.target
```
+ Create `/etc/systemd/system/node_exporter.service` to start/stop
node_exporter.

```
[Unit]
Description=Node Exporter
Wants=network-online.target
After=network-online.target

[Service]
User=node_exporter
Group=node_exporter
Type=simple
ExecStart=/usr/local/bin/node_exporter

[Install]
WantedBy=multi-user.target
```
+ Enable/Start prometheus and node_exporter services

   + Reload systemd 
     
     ```
     $ sudo systemctl daemon-reload
     ```

   + Enable and start prometheus
     
     ```
     $ sudo systemctl enable prometheus
     $ sudo systemctl start prometheus
     ```
   + Enable and start node_exporter
     
     ```
     $ sudo systemctl enable node_exporter
     $ sudo systemctl start node_exporter
     ```
+ Securing prometheus

  ```
  $ # downloading dependecies
  $ sudo apt-get update && sudo apt-get install nginx apache2-utils
  $ # set password for prometheus
  $ sudo htpasswd -c /etc/nginx/.htpasswd mohabaks
  ```
+ Additional settings for web access besides localhost
  
  Since will be using FQDN to access prometheus and grafana services. We
create the following files:
  + `/etc/nginx/sites-available/grafana.blacknetwork.local`
  
     ```
      server {
	listen 80 default_server;
	listen [::]:80 default_server;
	root /var/www/grafana.blacknetwork.local/html;

	# Add index.php to the list if you are using PHP
	index index.html index.htm index.nginx-debian.html;

	server_name grafana.blacknetwork.local;

	location / {
    		proxy_pass http://localhost:3000;
        	proxy_http_version 1.1;
        	proxy_set_header Upgrade $http_upgrade;
        	proxy_set_header Connection 'upgrade';
        	proxy_set_header Host $host;
        	proxy_cache_bypass $http_upgrade;
	}

      }
     ```
  + `/etc/nginx/sites-available/prometheus.blacknetwork.local`
   
    ```
    server {
	listen 80;
	listen [::]:80;

	root /var/www/prometheus.blacknetwork.local/html;

	# Add index.php to the list if you are using PHP
	index index.html index.htm index.nginx-debian.html;

	server_name prometheus.blacknetwork.local;

	location / {
		# First attempt to serve request as file, then
		# as directory, then fall back to displaying a 404.
		#try_files $uri $uri/ =404;
                auth_basic "Prometheus server authentication";
        	auth_basic_user_file /etc/nginx/.htpasswd;
        	proxy_pass http://localhost:9090;
        	proxy_http_version 1.1;
        	proxy_set_header Upgrade $http_upgrade;
        	proxy_set_header Connection 'upgrade';
        	proxy_set_header Host $host;
        	proxy_cache_bypass $http_upgrade;
	}
     }
    ```
  + Create a symbolic link for each domain we created
    
    ```
    $ sudo ln -s /etc/nginx/site-avalable/grafana.blacknetwork.local /etc/nginx/site-enabled/
    $ sudo ln -s /etc/nginx/site-avalable/prometheus.blacknetwork.local /etc/nginx/site-enabled/
    ```
  + Copy the contents of the `/var/www/html` to above root directory specified
e.g `/var/www/grafana.blacknetwork.local`
  + Check for systnax error and reload nginx
 
    ```
    $ sudo nginx -t
    $ sudo systemctl reload nginx
    ```
  + Additional changes needed to be made for `/etc/grafana/grafana.ini` to
work with our domain.
   
    ```
    [server]
    domain = grafana.blacknetwork.local
    ```
    + Reload grafana: 
      
      ```
      $ sudo systemctl restart grafana-server.service
      ```
  + Now we should be able to access both domains.
   
    + `http://prometheus.blacknetwork.local` login with the password we
created.
      
      ![prometheus](https://i.imgur.com/cWT0nDc.png)
    
    + `http://grafana.blacknetwork.local` login with default creds
`admin:admin` and add new data source prometheus.
      
      ![grafana](https://i.imgur.com/SuMfpti.png)

#### Network setup for the VMs
The lab will have several virtual networks that will be managed by [pfSense].

The following are the description of the networks that we will create using
virt-manager.

1. __WAN__ 
 
     This is a bridge interface that has internet access and acts as a WAN for
     the __pfSense__.

     + __Network Address__
        
         + 192.168.100.0/24

2. __Management__

     This network is used for accessing __pfSense__ via vpn and also for testing 
     various __IPS/IDS/SIEM__ such as _ossec,wazuh,snort,suricata,bro,securityonion etc_

     + __Network Address__

         + 172.20.201.0/24

3. __BootToRoot__

     This network is for running __Boot To Root__ vulnerable machines such as
     those collected from [vulnhub], [ExploitExercises].

     + __Network Address__

         + 192.168.1.0/24

4. __WindowsAD__

     This network I use when making my hands dirty with Windows Active Directory (AD)
     . Mainly running Windows Server 2008/2012 and Windows 7/8/10.

     + __Network Address__

         + 192.168.2.0/24

5. __POC__
 
     This network is for testing various Linux/Unix Administration such as
     application deployment,LDAP,DNS etc or other security POC e.g [SeedLabs]

     + __Network Address__

         + 172.16.30.0/24

+ Add Virtual Network with `Virt-Manager`

  + `Edit->Connection Details->VirtualNetworks->Add`

  Make sure to unchek `Enable Ipv4 Network Address ` and select it as `Isolated
  Network`

  ![Add Networks](https://i.imgur.com/hzUv6Gb.gif)


Setting Up pfSense VM
---------------------

### Installation

1. Download [pfSense](https://www.pfsense.org/download/) e.g
   `pfSense-CE-2.4.4-RELEASE-amd64.iso.gz`

2. Decompress downloaded file.
   
   ```
   $ gunzip pfSense-CE-2.4.4-RELEASE-amd64.iso.gz
   ```
3. From Virt-Manager `File->New Virtual Machine`. Choose `Local Install media`
   and browser to decompressed file and follow the rest of steps.
   
   + Make sure to select the network `br0` before the installation. This will
help us do the rest of the settings.

4. Once the installation has finished reboot and configure `WAN` only and
   ignore `VLAN` and `LAN` that can be done later.

   ![initial pfSense Settings](https://imgur.com/c3vHOIG.png)

   `NOTE` to setup WAN there will be only one interface since that what we
   added initially `Bridge br0`.

   ![final settings](https://imgur.com/HaFcG7v.png)

   Now you can finish the reset of the setting by accessing the URL
   `https://DHCP4_IP` and login with default creds `admin:pfsense`

   ![pfsense login](https://imgur.com/cZYIdTM.png)

5. Once you're done with setting;go back to virt-manager and add the rest of the
   network we created before.`Show Virtual Console->Show Virtual Hardware
   Details->Add Hardware->Network`. After making the changes reboot.

   ![Add networks](https://imgur.com/qvljT4O.png)

#### Adding Additional Network Interface with pfSense
Navigate to `interfaces->Assignments->Add` compare the pfSense interface MAC 
address with the one added from the virt-manager. Make sure not to add gateway for the networks.

![pfSense Networks](https://i.imgur.com/EUtl0Qz.gif)


#### Accessing the pfSense
In order to access lab we need to configure openvpn with pfSense.Then
export the config `ovpn` file so we can access the isolated networks for any
new VMs that we deploy.

1. Navigate to `VPN->OpenVPN->Wizards`
2. Add user that will connect with vpn. `System->User Manager->Add` Make sure
   to check `Certificate` to create the user certificate.
3. `VPN->OpenVPN-Servers->Add` on the `Tunnel Settings->IPv4 Local network(s)`
   add the list of our isolated network separated by `,` e.g `192.168.1.0/24 ,192.168.2.0/24 ,172.16.30.0/24 ,172.16.31.0/24 ,172.20.201.0/24,10.152.152.0/24`
4. Download `openvpn-client-export` for exporting client config file.
   `System->Package Manager->Available Packages`

Once you have openvpn configured you should be able to access the isolated
network(s).

![pfSense OpenVPN](https://i.imgur.com/OVxhZ9p.gif)

__NOTE__: This pfSense VM is always running.

Other VMs
----------
The following is a list of VMs that I run frequently.

### Pi-hole VM
[Pi-hole] for network-wide Ad Blocking. It's using the `br0` interface and I
have my home WiFi router and pfSense primary DNS server set to pi-hole
IP.

I also use this to resolve my FQDNs e.g grafana.blacknetwork.local

![Pi-hole](https://imgur.com/FtLE3uh.png)

__Running-Status__: Always

### EVE-NG VM
[EVE-NG] for implementing basic Enterprise Infrastructure.
Also using `br0` interface.

![eve-ng](https://imgur.com/CJqMwLv.png)

__Running-Status__: When needed

### Vyatta VM
Currently [VyOS] for learnig various concepts for routing, network pentest
etc. Configured to use `br0` interface.

![Vyatta](https://i.imgur.com/HWhAFJq.png)

__Running-Status__: When needed

### Windows VM
I only use this when I need to compile windows binaries for tools written in
C#, VB, .NET etc;sometimes for attacking Active Directory for various
challenges such as [HackTheBox] and [TryHackMe]. Configured to use `WAD`
interface managed by pfSense.

![Windows](https://i.imgur.com/jAyBjGm.png)

__Running-Status__: When needed


Raspberry Pi B+
---------------
The main purpose for this raspberry is for learning __WiFi Penetration
Testing__ and other projects.

Currently running a [plex] media server.

![plex server](https://imgur.com/UtDRrRs.png)

[HackTheBox]: https://www.hackthebox.eu/
[TryHackMe]: https://tryhackme.com/
[VyOS]: https://www.vyos.io/
[Pi-hole]: https://https://pi-hole.net/
[KVM]: https://www.linux-kvm.org/page/Documents
[docker]: https://www.docker.com/
[plex]: https://www.plex.tv/
[LXC]: https://linuxcontainers.org/
[EVE-NG]: http://www.eve-ng.net/
[pfSense]: https://www.pfsense.org/
[vulnhub]: https://www.vulnhub.com/
[ExploitExercises]: https://exploit-exercises.lains.space/
[SeedLabs]: https://github.com/onlurking/awesome-infosec#laboratories 
[prometheus]: https://prometheus.io/
[grafana]: https://prometheus.io/
[script]: https://github.com/mohabaks/blacklab/blob/master/scripts/prometheus_grafana_quick_install
