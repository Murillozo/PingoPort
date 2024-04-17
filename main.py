import scapy
import os
import socket
import fcntl
import struct
import netifaces
import subprocess
import select
import sys
import re
from colorama import Fore, Back, Style, init


def banner():
    print("\033[94m        .::::.           \033[0m \033[37;1m______    __  ___  ___  ______  _______\033[0m          ")
    print("\033[94m  _____::O:::::           \033[0m\033[37;1m|     |   oo  |  \ | | |   __|  |  __  |\033[0m         ")
    print("\033[94m  -''''::::::' ::         \033[0m\033[37;1m| |___|  | |  | \ \| | |  |__|  | |__| |\033[0m         ")
    print("\033[94m      \'|'':..:::         \033[0m\033[37;1m |_|      |_|  |_|\___| |_____|  |______|\033[0m         ")
    print("\033[94m       | ::::::::         \033[0m\033[37;1m                                        \033[0m        ")
    print("\033[94m      | ::::::::::        \033[0m\033[37;1m _____    ______   _____   ____________ \033[0m        ")
    print("\033[94m      | ::::::::::        \033[0m\033[37;1m|     |   |  _  | |  _  |  |___    ___| \033[0m        ")
    print("\033[94m      | :::::::::::       \033[0m\033[37;1m| |___|   | |_| | | |\| |      |  |    \033[0m         ")
    print("\033[94m      | :::: ::::::       \033[0m\033[37;1m|_|       |_____| |_|  \|      |__|    \033[0m         ")
    print("\033[94m      | :::: ::::::                                                       \033[0m")
    print("\033[94m      | ::: .::::::                                                       \033[0m")
    print("\033[94m      | ::: :::::::                                                       \033[0m")
    print("\033[94m      | :: :::::::                                                        \033[0m")
    print("\033[94m      | : ::::::'                                                         \033[0m")
    print("\033[94m       .: :::::::                                               \033[0m   \033[91mBy:Coringão - verison: 1,0\033[0m")
    print("\033[94m                                                                          \033[0m")


def My_IP():      # Obtém o endereço IP local
    ip = socket.gethostbyname(socket.gethostname())
    return ip

def get_mac_address(interface):     # Obtém o endereço Mac wlan e lo
    try:
        mac = netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr']
        return mac
    except:
        return "Não foi possível obter o endereço MAC"

# Interface lo
interface_lo = 'lo'
mac_lo = get_mac_address(interface_lo)

# Interface wlan0
interface_wlan0 = 'wlan0'  
mac_wlan0 = get_mac_address(interface_wlan0)


def ip_da_wlan0(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15].encode('utf-8'))
    )[20:24])

ip_wlan0 = ip_da_wlan0('wlan0')


def ip_do_roteador():
    with open('/proc/net/route', 'r') as f:
        for line in f.readlines():
            fields = line.strip().split()
            if fields[1] == '00000000':  # Verifica se é o gateway padrão
                return socket.inet_ntoa(int(fields[2], 16).to_bytes(4, byteorder='little'))
            

def tipo_de_IPv():
    # Obtém o tipo de rede (IPv4 ou IPv6)
    ip = My_IP()
    if '.' in ip:
        return "IPv4"
    elif ':' in ip:
        return "IPv6"
    else:
        return "Desconhecido"
    
def modelo_de_rede_wlan0():
    tipo_rede_wlan0 = ip_da_wlan0('wlan0')

    if tipo_rede_wlan0.startswith("192"):
        return "Domestica"

    elif tipo_rede_wlan0.startswith("10.0"):
        return "Empresarial"
        
    else:
        return "Indefinida"

#PAINEL DE ENTRADA SOBRE DETALHES DA REDE:
def detalhes_da_rede():
    tipo_rede_wlan0 = modelo_de_rede_wlan0()

    print(f"{Fore.WHITE}{Style.BRIGHT}MAC Address:{Style.RESET_ALL} {Fore.LIGHTBLUE_EX}{interface_wlan0}{Style.RESET_ALL} -----> {Fore.GREEN + Style.BRIGHT}{mac_wlan0}{Style.RESET_ALL} ") 
    print(f"             {Fore.WHITE}{Style.BRIGHT}{interface_lo} -------->{Style.RESET_ALL} {Fore.GREEN + Style.BRIGHT}{mac_lo}{Style.RESET_ALL} ")
    print(f"                                                   ")

    print(f"{Fore.WHITE}{Style.BRIGHT}IPs:{Style.RESET_ALL}         {Fore.LIGHTBLUE_EX}Wlan0{Style.RESET_ALL} -----> \033[36m{ip_wlan0}\033[0m")
    print(f"             {Fore.WHITE}{Style.BRIGHT}Local(lo) ->{Style.RESET_ALL} \033[36m{My_IP()} -> {tipo_de_IPv()}\033[0m")
    if tipo_rede_wlan0 == "Empresarial":
        print(f"             Router ----> \033[36m{ip_do_roteador()}\033[0m ---> Modelo de rede: {Fore.RED}{tipo_rede_wlan0}{Style.RESET_ALL}")
    elif tipo_rede_wlan0 == "Domestica":
        print(f"             \033[91;1mRouter\033[0m ----> \033[36m{ip_do_roteador()}\033[0m ---> Modelo de rede: {Fore.LIGHTBLUE_EX}{tipo_rede_wlan0}{Style.RESET_ALL}")


def verifica_e_cria_diretorios(*args):
    output_dirs = {}

    for name_file in args:
        # Verifica se o diretório "Output" existe. Se não existir, crie-o.
        if not os.path.exists("Output"):
            os.makedirs("Output")

        # Cria o caminho para o novo diretório com base no name_file
        output_dir = os.path.join("Output", name_file)

        # Verifica se o diretório para o name_file existe. Se não existir, crie-o.
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        output_dirs[name_file] = output_dir

    return output_dirs




#painel 
def ler_listas_de_ips():
    print("lendo")


def extrair_ips_e_mac(arquivo):
    with open(arquivo, 'r') as f:
        texto = f.read()
        ips_macs = re.findall(r'Nmap scan report for (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\n.*?MAC Address: ([0-9A-Fa-f:]+)', texto, re.DOTALL)
        return ips_macs


#PAINEL ANONIMATO:
def alterar_endereco_mac_aleatorio():
    subprocess.run(['sudo', 'ifconfig', 'wlan0', 'down'])
    subprocess.run(['sudo', 'macchanger', '-r', 'wlan0'])
    subprocess.run(['sudo', 'ifconfig', 'wlan0', 'up'])
        


def alterar_endereco_mac_especifico():
    subprocess.run(["sudo", "ifconfig", "wlan0", "down"])

    novo_mac = input("Digite o novo endereço MAC (formato XX:XX:XX:XX:XX:XX): ")

    # Executar o comando macchanger para mudar o endereço MAC
    try:
        output = subprocess.check_output(["sudo", "macchanger", "-m", novo_mac, "wlan0"], stderr=subprocess.STDOUT)
        print(output.decode())
        print("Endereço MAC alterado com sucesso!")
    except subprocess.CalledProcessError as e:
        print("Erro ao alterar o endereço MAC:", e.output.decode())

    subprocess.run(["sudo", "ifconfig", "wlan0", "up"])

def voltando_mac_original():
    subprocess.run(['sudo', 'ifconfig', 'wlan0', 'down'])
    subprocess.run(['sudo', 'macchanger', '-p', 'wlan0'])
    subprocess.run(['sudo', 'ifconfig', 'wlan0', 'up'])



#PAINEL DE ATAQUES:

#Opção1

def run_nmap_scan(network, scan_type, output_file):
    print("Se quiser cancelar o processo, pressione a tecla 'q' !!!")
    command = ["nmap", scan_type, network, "-oN", output_file, "-O"]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    while True:
        if select.select([sys.stdin], [], [], 0.1)[0]:  # Verifica se há entrada disponível no stdin
            key = sys.stdin.read(1)  # Lê a tecla pressionada
            if key == 'q':
                process.terminate()  # Cancela o processo se a tecla 'q' for pressionada
                print("Scan cancelado. Retornando ao menu...")
                painel_de_ataques()
                return

        if process.poll() is not None:  # Verifica se o processo terminou
            break

    output, error = process.communicate()
    return output.decode(), error.decode()

def enumerar_hosts_Agressivo(name_file_agressivo):
    verifica_e_cria_diretorios(name_file_agressivo)
    ip = ip_da_wlan0('wlan0')

    if ip.startswith("192"):
        network = "192.168.0.0/24"
    elif ip.startswith("10.0"):
        network = "10.0.0.0/8"
    else:
        print("Endereço IP não reconhecido")
        return

    scan_result_sn, error_sn = run_nmap_scan(network, "-sn", name_file_agressivo + "_sn.txt")
    scan_result_sS, error_sS = run_nmap_scan(network, "-sS", name_file_agressivo + "_sS.txt")
    scan_result_sU, error_sU = run_nmap_scan(network, "-sU", name_file_agressivo + "_sU.txt")

    if error_sn:
        print("Erro ao executar o scan -sn:", error_sn)
    else:
        print("Resultado do scan -sn:", scan_result_sn)

    if error_sS:
        print("Erro ao executar o scan -sS:", error_sS)
    else:
        print("Resultado do scan -sS:", scan_result_sS)

    if error_sU:
        print("Erro ao executar o scan -sU:", error_sU)
    else:
        print("Resultado do scan -sU:", scan_result_sU)

    output_dirs = verifica_e_cria_diretorios(name_file_agressivo)
    for scan_type, result in [("sn", scan_result_sn), ("sS", scan_result_sS), ("sU", scan_result_sU)]:
        scan_dir = os.path.join(output_dirs[name_file_agressivo], scan_type)
        if not os.path.exists(scan_dir):
            os.makedirs(scan_dir)
        output_file = os.path.join(scan_dir, f"{name_file_agressivo}_{scan_type}.txt")
        with open(output_file, "w") as file:
            file.write(f"Resultado do scan -{scan_type}:\n{result}\n\n")




def enumerar_host_Passivo(name_file_passivo):  #so o -sn so por meio de"PING"
    verifica_e_cria_diretorios(name_file_passivo)

    ip = ip_da_wlan0('wlan0')

    if ip.startswith("192"):
        network = "192.168.0.0/24"
    elif ip.startswith("10.0"):
        network = "10.0.0.0/8"
    else:
        print("Endereço IP não reconhecido")
        return

    command = ["nmap", "-sn", network]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()

    if error:
        print("Erro ao executar o scan -sn:", error.decode())
    else:
        print("Resultado do scan -sn realizado com sucesso !!!")

    with open(f"Output/{name_file_passivo}/{name_file_passivo}_sn.txt", "w") as file:
        file.write(f"Resultado do scan -sn:\n{output.decode()}\n\n")





def HTTP_FTP_SMTP_DNS_SNMP(name_file_service_webs):
    output_dirs = verifica_e_cria_diretorios(name_file_service_webs)

    network = ip_da_wlan0('wlan0')

    if network.startswith("192"):
        network = "192.168.0.0/24"
    elif network.startswith("10.0"):
        network = "10.0.0.0/8"
    else:
        print("Endereço IP não reconhecido")
        return

    nmap_commands = [
        f'nmap --script=http-enum {network}',
        f'nmap --script=ftp-enum-servers {network}',
        f'nmap --script=smtp-enum-users {network}',
        f'nmap --script=dns-zone-transfer {network}',
        f'nmap --script=snmp-enum {network}'
    ]

    for i, command in enumerate(nmap_commands):
        output_file = os.path.join(output_dirs[name_file_service_webs], f"{name_file_service_webs}_{i+1}.txt")
        with open(output_file, 'w') as f:
            result = subprocess.run(command, shell=True, stdout=f, text=True)
            print(f"Saída do comando '{command}' salva em '{output_file}'")




    
def scan_smb_vuln_ms(name_file_smb_vuln_ms):
    verifica_e_cria_diretorios(name_file_smb_vuln_ms)

    network = ip_da_wlan0('wlan0')

    if network.startswith("192"):
        network = "192.168.0.0/24"
    elif network.startswith("10.0"):
        network = "10.0.0.0/8"
    else:
        print("Endereço IP não reconhecido")
        return
    
    nmap_command = f'nmap --script=smb-vuln-ms {network}'

    with open(f'Output/{name_file_smb_vuln_ms}/{name_file_smb_vuln_ms}.txt', 'w') as f:
        result = subprocess.run(nmap_command, shell=True, stdout=f, text=True)
        print(f"Saída do comando '{nmap_command}' salva em 'Output/{name_file_smb_vuln_ms}/{name_file_smb_vuln_ms}.txt'")


def escanear_pacotes_fragmentados(name_file_pacote_fragmentados):
    verifica_e_cria_diretorios(name_file_pacote_fragmentados)

    network = ip_da_wlan0('wlan0')

    if network.startswith("192"):
        network = "192.168.0.0/24"
    elif network.startswith("10.0"):
        network = "10.0.0.0/8"
    else:
        print("Endereço IP não reconhecido")
        return

    nmap_command = f'nmap {network} -v -sS -Pn -f'

    with open(f'Output/{name_file_pacote_fragmentados}/{name_file_pacote_fragmentados}.txt', 'w') as f:
        result = subprocess.run(nmap_command, shell=True, stdout=f, text=True)
        print(f"Saída do comando '{nmap_command}' salva em 'Output/{name_file_pacote_fragmentados}/{name_file_pacote_fragmentados}.txt'")


def scan_avancado_agressivo_completo(name_file_scan_avancado):
    verifica_e_cria_diretorios(name_file_scan_avancado)

    network = ip_da_wlan0('wlan0')

    if network.startswith("192"):
        network = "192.168.0.0/24"
    elif network.startswith("10.0"):
        network = "10.0.0.0/8"
    else:
        print("Endereço IP não reconhecido")
        return
    
    nmap_command = f'nmap -sS -T4 -A {network}'

    with open(f'Output/{name_file_scan_avancado}/{name_file_scan_avancado}.txt', 'w') as f:
        resultado = subprocess.run(nmap_command, shell=True, stdout=f, text=True)
        print(f"Saída do comando '{nmap_command}' salva em 'Output/{name_file_scan_avancado}/{name_file_scan_avancado}.txt'.")

    print("Escaneamento completo.")


def descorberta_de_routers_na_rede(name_file_routers_rede):
    verifica_e_cria_diretorios(name_file_routers_rede)

    network = ip_da_wlan0('wlan0')

    if network.startswith("192"):
        target = "192.168.0.0/24"
    elif network.startswith("10.0"):
        target = "10.0.0.0/8"
    else:
        print("Endereço IP não reconhecido")
        return

    with open(f'Output/{name_file_routers_rede}/{name_file_routers_rede}_broadcast-rip-discover.txt', "w") as f:
        subprocess.run(["nmap", "--script", "broadcast-rip-discover", target], stdout=f)

    with open(f'Output/{name_file_routers_rede}/{name_file_routers_rede}_broadcast-pim-discovery.txt', "w") as f:
        subprocess.run(["nmap", "--script", "broadcast-pim-discovery", target], stdout=f)

    print("Escaneamento completo.")





# PAINEL ANONIMATO:
def painel_ficar_anonimo():
    while True:
        menu_A = input(f"""\n\033[91;1mEscolha o Scan ANONIMATO:\033[0m
            \033[97;1m1)\033[0m Alterar Mac \033[92;1m(Macchanger)\033[0m ---> mais recomendado
            \033[97;1m2)\033[0m Alterar O IP
            \033[97;1m3)\033[0m Através do \033[103m\033[30m\033[1mProxy\033[0m
                       
            Pressione \033[97;1mEnter\033[0m para o menu de \033[91;1m(SCANS)\033[0m
            \n""")

        # Verifica se o usuário pressionou Enter sem inserir nada
        if not menu_A.strip():
            painel_principal_menu()
            break
        
        if menu_A == '1':
            menu_Mac = input("""\n\033[92;1mMACCHANGER:\033[0m 
                \033[97;1m1)\033[0m Gerar o Mac aleatorio
                \033[97;1m2)\033[0m Definir um Mac especifico
                \033[97;1m3)\033[0m Voltar para o Mac original  \n""")
            if menu_Mac == '1':
                alterar_endereco_mac_aleatorio()
            elif menu_Mac == '2':
                alterar_endereco_mac_especifico()
            elif menu_Mac == '3':
                voltando_mac_original()
        elif menu_A == '2':
            print("alteramdo ip.....")

        elif menu_A == '3':
            print("ativando o proxy.....")
        else:
            painel_principal_menu()


#PAINEL PRINCIPAL DO PROGRAMA:

def painel_principal_menu():
    menu = input("""\n\033[97;1mMenu de \033[91;1mSCANS:\033[0m
            \033[97;1m1)\033[0m \033[91;1mModelos de SCANS\033[0m
            \033[97;1m2)\033[0m \033[91;1mSCANS:\033[0m : \033[97;1msobre uma lista de Ips\033[0m
            \033[97;1m3)\033[0m \033[97;1mExtrair Ips e Mac do arquivo de Scan\033[0m (recomendado: [nome do arquivo]all.txt)  \n""")

    if menu == '1':
        painel_de_ataques()
    elif menu == '2':
        name_file_list_ips = input("Digite o nome do arquivo da lista de Ips.txt: ")
        ler_listas_de_ips(name_file_list_ips)
    elif menu == '3':

        arquivo = input("Digite o nome do arquivo: ")
        ips_macs = extrair_ips_e_mac(arquivo)
        # Salvar os IPs em um arquivo
        with open('ips.txt', 'w') as f_ips:
            for ip, _ in ips_macs:
                f_ips.write(ip + '\n')
        # Salvar os MACs em um arquivo

        with open('macs.txt', 'w') as f_macs:
            for ip, mac in ips_macs:
                f_macs.write(mac + ' - ' + ip + '\n')
        print("Endereços IP foram salvos em ips.txt")
        print("Endereços MAC foram salvos em macs.txt")
    else:
        print("Opção inválida. Escolha entre 1, 2 ou 3.\n")

def painel_de_ataques():
    tipo_de_ataque = input("""\nSelcione o modelo de \033[91;1mSCANS\033[0m:
            \033[97;1m1)\033[0m Hosts ativos na rede
            \033[97;1m2)\033[0m Enumerar serviços HTTP, FTP, SMTP, DNS e SNMP 
            \033[97;1m3)\033[0m Exploração de Vulnerabilidades(smb_windowns) 
            \033[97;1m4)\033[0m Escaneamento de pacotes fragmentados (Firewal_IDS)                           
            \033[97;1m5)\033[0m Escaneamento de Rede Avançado Completo (+ Agressivo +Barulhento)
            \033[97;1m6)\033[0m Descoberta de roteadores
                           \n""")

    if tipo_de_ataque == "1":
        modelo_de_SCAN = input("""\nSelecione o modelo de scan: 
            1) Apenas os ativos na rede (ping)
            2) -sn -sS -sU(OS, Portas, Subdominios, TCP SYN, UDP)
            
            x - Voltar ao menu
             \n""")

        if modelo_de_SCAN == "1":
            name_file_passivo = input("Nome do arquivo para salvar os resultados passivos: ")
            enumerar_host_Passivo(name_file_passivo)

        elif modelo_de_SCAN == "2":
            name_file_agressivo = input("Nome do arquivo para salvar os resultados agressivos: ")
            enumerar_hosts_Agressivo(name_file_agressivo)
        elif modelo_de_SCAN == "x":
            painel_de_ataques()
        else:
            print("Opção inválida! Retornando ao menu.....\n")

    elif tipo_de_ataque == "2":
        name_file_service_webs = input("Nome para salvar os resultados serviços HTTP, FTP, SMTP, DNS e SNMP:")
        HTTP_FTP_SMTP_DNS_SNMP(name_file_service_webs)
    elif tipo_de_ataque == "3":
        name_file_smb_vuln_ms = input("Nome do arquivo para salvar smb: ")
        scan_smb_vuln_ms(name_file_smb_vuln_ms)
    elif tipo_de_ataque == "4":
        name_file_pacote_fragmentados = input("nome dosPacotes fragmentados: ")
        escanear_pacotes_fragmentados(name_file_pacote_fragmentados)
    elif tipo_de_ataque == "5":
        name_file_scan_avançado = input("Nome do Scan avançado (COMPLETO): ")
        scan_avancado_agressivo_completo(name_file_scan_avançado)
    elif tipo_de_ataque == "6":
        name_file_routers_rede = input("Nome do arquivo para salva os roteadores: ")
        descorberta_de_routers_na_rede(name_file_routers_rede)
    else:
        print("\033[91;1mOpção inválida!!!\033[0m Escolha entre 1 a 6. Retornando ao menu.....\n")

    if input("Pressione \033[91;1m'q'\033[0m para sair ou \033[91;1m'Enter'\033[0m para retornar ao menu: ").lower() == 'q':
        sys.exit()

#Exibe as funções so aparece apenas uma vez
banner()
detalhes_da_rede()
painel_ficar_anonimo()
painel_principal_menu()
# Entra no loop principal do programa
while True:
    painel_principal_menu()
  






