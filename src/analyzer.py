# analyzer.py
from packet import Packet
from scapy.all import sniff
from scapy.layers.l2 import Ether

class EthernetAnalyzer:
    def __init__(self):
        print("Analisador Ethernet inicializado (pronto para scapy).")

    def analyze_scapy_packet(self, scapy_packet):
        """
        Analisa um objeto de pacote REAL do scapy e o transforma no nosso objeto Packet.
        """
        try:
            # Garante que é um pacote Ethernet (Camada 2)
            if Ether in scapy_packet:
                eth_layer = scapy_packet[Ether]
                
                # Extrai dados do pacote scapy
                packet_data = {
                    "source": eth_layer.src,
                    "destination": eth_layer.dst,
                    "type": hex(eth_layer.type)
                }

                # Usa a nossa classe Packet para formatar a saída
                packet = Packet(
                    source_mac=packet_data["source"],
                    destination_mac=packet_data["destination"],
                    eth_type=packet_data["type"]
                )
                
                # Pede para a Pamela (Estrutura de dados e logs) implementar a função de log aqui!
                # print(f"Pacote bruto do Scapy: {scapy_packet.summary()}")
                print("-" * 40)
                print(f"Pacote Capturado: {packet}")
                print("-" * 40)

        except Exception as e:
            print(f"Erro ao analisar pacote scapy: {e}")
            
    def start_capture(self, iface="Intel(R) Wireless-AC 9462", count=5, bpf_filter="ether"):
        """
        Inicia a captura de pacotes na interface especificada com um filtro BPF.
        O filtro padrão é 'ether' (Camada 2). Use 'arp' para Pacotes ARP ou 'ip' para IPv4.
        """
        print(f"\nIniciando a captura na interface '{iface}'. Aguardando {count} pacote(s) com filtro '{bpf_filter}'...")
        
        # O argumento 'filter' agora usa a variável bpf_filter
        sniff(iface=iface, count=count, prn=self.analyze_scapy_packet, filter=bpf_filter, store=0)
        
        print("Captura finalizada.")
