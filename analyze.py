import subprocess

f = input('Pcap File : ')

while True:

    print(
        '\n 1> Visited Sites \n 2> User-Agents \n 3> Connection details(TCP, UDP, ICMP, IP, SMTP, SMB, ARP) \n 4> Grep Mode \n 5> IP List \n 6> Ports Present')

    i = input('\n>Your Command Number : ')

    if i =='exit':
        break

    elif int(i) == 1:
        result = subprocess.run(
            ['tshark', '-r', f, '-Y', 'http.request', '-T', 'fields', '-e', 'http.host'],
            stdout=subprocess.PIPE).stdout.decode('utf-8')
        r = result.split('\n')
        r = list(dict.fromkeys(r))
        for k in r:
            print(k)

    elif int(i) == 2:
        result = subprocess.run(
            ['tshark', '-r', f, '-Y', 'http.request', '-T', 'fields', '-e', 'http.user_agent'],
            stdout=subprocess.PIPE).stdout.decode('utf-8')
        r = result.split('\n')
        r = list(dict.fromkeys(r))
        for k in r:
            print(k)

    elif int(i) == 3:
        result = subprocess.run(
            ("tshark -r "+f+" -T fields -e ip.src -e ip.dst -e udp.srcport -e udp.dstport -e tcp.srcport -e tcp.dstport -e _ws.col.Protocol").split(' '),
            stdout=subprocess.PIPE).stdout.decode('utf-8')
        r = result.split('\n')
        r.pop(len(r) - 1)
        for j in r:
            k = j.split('\t')
            if k[0] != '':
                k = list(filter(('').__ne__, k))
                prot = k[-1]
                srcIP = k[0]
                destIP = k[1]
                if prot == 'ICMP':
                    print(
                        'Protocol: ' + prot + '  -  Source: ' + srcIP + ' ----> Destination: ' + destIP)
                else:
                    srcPort = k[2]
                    destPort = k[3]
                    print(
                        'Protocol: ' + prot + '  -  Source: ' + srcIP + ' - PORT: ' + srcPort + ' ----> Destination: ' + destIP + ' - PORT: ' + destPort)

    elif int(i) == 4:
        search = input('Search String : ')
        with open(f, 'rb') as reader:
            for line in reader:
                if line.__contains__(search.encode()):
                    print(line)

    elif int(i) == 5:
        result = subprocess.run(
            ['tshark', '-r', f, '-Y', 'http.request', '-T', 'fields', '-e', 'ip.dst'],
            stdout=subprocess.PIPE).stdout.decode('utf-8')
        r = result.split('\n')
        r = list(dict.fromkeys(r))
        for k in r:
            print(k)

    elif int(i) == 6:
        result = subprocess.run(
            ("tshark -r "+f+" -T fields -e udp.srcport -e udp.dstport -e tcp.srcport -e tcp.dstport").split(
                ' '),
            stdout=subprocess.PIPE).stdout.decode('utf-8')
        r = result.split('\n')
        r.pop(len(r) - 1)
        for j in r:
            k = j.split('\t')
            k = list(filter(('').__ne__, k))
            if k != [] :
                srcPort = k[0]
                destPort = k[1]
                print('Source Port : ' + srcPort + ' Destination port : ' + destPort)



