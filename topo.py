import os
import time
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.examples.linuxrouter import LinuxRouter
from mininet.term import makeTerm


class QUICPoCTopo(Topo):
  def build(self):
    fw = self.addHost('fw', cls=LinuxRouter, ip=None)

    # create switch
    s1 = self.addSwitch('s1')

    client = self.addHost('client', ip='10.0.0.2/24', defaultRoute='via 10.0.0.1')
    server = self.addHost('server', ip='10.0.1.2/24', defaultRoute='via 10.0.1.1')

    self.addLink(client, fw)
    
    self.addLink(fw, s1)
    self.addLink(server, s1)

def configure_router(net):
  fw = net.get('fw')
  # Assign IPs manually on router interfaces
  fw.cmd("ip addr add 10.0.0.1/24 dev fw-eth0")
  fw.cmd("ip link set dev fw-eth0 promisc on")
  fw.cmd("ip link set dev fw-eth0 up")
  fw.cmd("ip addr add 10.0.1.1/24 dev fw-eth1")
  fw.cmd("ip link set dev fw-eth1 up")

def enable_ip_forwarding(net):
  fw = net.get('fw')
  fw.cmd("sysctl -w net.ipv4.ip_forward=1")


def start_serverQUIC_xterm(net):
  serverQUIC = net.get('server')
  cert_path = "certs/cert.pem"
  key_path = "certs/key.pem"

  # Prepare the command to run inside the xterm
  cmd = (
      f"python3 quic_server/http3_server.py "
      f"--certificate {cert_path} --private-key {key_path} "
      f"--host 10.0.1.2 --port 443"
  )

  # Launch xterm running the command
  makeTerm(serverQUIC, cmd=cmd, title="QUIC serverQUIC")


def start_tls_server_xterm(net):
  serverTCP = net.get('server')
  cert_path = "certs/cert.pem"
  key_path = "certs/key.pem"
  cmd = "python3 tcp_server/https_server.py"

  makeTerm(serverTCP, cmd=cmd, title="TCP/TLS Server")

def start_tcpdump(net):
  fw = net.get('fw')
  cmd = "tcpdump -i fw-eth0 -w ./tcpdump.pcap"
  makeTerm(fw, cmd=cmd, title="tcpdump")

def run():
  setLogLevel('info')
  topo = QUICPoCTopo()
  net = Mininet(topo=topo)
  net.start()
  configure_router(net)
  enable_ip_forwarding(net)

  start_serverQUIC_xterm(net)
  start_tls_server_xterm(net)
  start_tcpdump(net)

  info("[INFO] Ready to test QUIC vs TLS filtering!\n")
  CLI(net)

  net.stop()


if __name__ == '__main__':
  run()
