#cloud-config
package_update: true
package_upgrade: true
apt_sources:
  - source: "ppa:wireguard/wireguard"
packages:
  - wireguard-dkms
  - wireguard-tools
  - awscli
write_files:
  - path: /etc/wireguard/wg0.conf
    content: |
      [Interface]
      Address = 192.168.124.1
      PrivateKey = ${wg_server_private_key}
      ListenPort = 51820
      PostUp   = /etc/wireguard/wg-up.sh
      PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

      ${peers}

  - path: /etc/wireguard/wg-up.sh
    content: |
      #!/bin/bash
      iptables -P FORWARD DROP
      for port in 443 6443; do
        iptables -A FORWARD -i eth0 -o wg0 -p tcp --syn --dport $port -m conntrack --ctstate NEW -j ACCEPT
        iptables -t nat -A PREROUTING -i eth0 -p tcp --dport $port -j DNAT --to-destination 192.168.124.2
        iptables -t nat -A POSTROUTING -o wg0 -p tcp --dport $port -d 192.168.124.2 -j SNAT --to-source 192.168.124.1
      done
      iptables -A FORWARD -i eth0 -o wg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
      iptables -A FORWARD -i wg0 -o eth0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

      
runcmd:
  - export INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
  - export REGION=$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | grep -oP '\"region\"[[:space:]]*:[[:space:]]*\"\K[^\"]+')
  - aws --region $${REGION} ec2 associate-address --allocation-id ${eip_id} --instance-id $${INSTANCE_ID}
  - chown -R root:root /etc/wireguard/
  - chmod -R og-rwx /etc/wireguard/*
  - chmod +x /etc/wireguard/wg-up.sh
  - sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
  - sysctl -p
  - systemctl enable wg-quick@wg0.service
  - systemctl start wg-quick@wg0.service
  
  
#  - ufw allow ssh
#  - ufw allow 51820/udp
#  - ufw --force enable
