#! /usr/bin/python
#Moduly, se kterymi budeme pracovat
import sys
import re
import socket
import select
import struct
import time
import curses

############################################
## PROMENNE
###########################################
#Listy ip adres jez sme zadali jako argumenty, adresy se kterymi skutecne chceme komunikovat a list socketu (ipv4 a ipv6)
ipList = []
ipListControl = sys.argv[1:]
socketList = []
#Slovniky pro zdroje, PID, typ, pomocny zdroj pro bandwidth u ES
dict_sources = {}
dict_PID = {}
dict_type = {}
dict_bandwidth_pid = {}
#Slovniky pro pocty UDP paketu a MPEG-TS bloku
dict_ip_udp = {}
dict_ip_mpeg = {}
dict_ip_udp_total = {}
dict_ip_mpeg_total = {}
#Pomocne slovniky pro vypocet out-of-sync
dict_pid_cc = {}
dict_pid_cc_first = {}
dict_pid_cc_bad_count = {}
#Slovniky pro jitter
dict_pid_UDP = {}
dict_pid_time = {}
dict_time_delivered = {}
dict_delay1 = {}
dict_pid_jitter = {}
dict_pid_max_jitter = {}
dict_pid_jitter_counter = {}
dict_pid_jitter_sum = {}

#Promenna pro refresh
seconds = 0
#Kontrola, jesli se dana ip adresa nachazi v multicast skupine, pokud ne, tak se proste vyhodi
for ip in ipListControl:
    #Vyskyt multicast ipv4 adresy
    if re.search('2(?:2[4-9]|3\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d?|0)){3}', ip):
        ipList.append(ip)
    #Vyskyt multicast ipv6 adresy
    if re.search('^ff',ip):
        ipList.append(ip)


#Vytvoreni socketu pro ipv4
try:
    s4 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    socketList.append(s4)
except socket.error as msg:
    print('Socket nemohl byt vytvoren: ' + str(msg[0]) + ' Zprava: ' + msg[1])
    sys.exit()

#Vytvoreni socketu pro ipv6
try:
    s6 = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_UDP)
    socketList.append(s6)

except socket.error as msg:
    print('Socket nemohl byt vytvoren: ' + str(msg[0]) + ' Zprava: ' + msg[1])
    sys.exit()

#Nastaveni socketu podle danych ipv4/ipv6 adres a inicializace slovniku pro pocitani paketu
for ip in ipList:
    if re.search('2(?:2[4-9]|3\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d?|0)){3}', ip):
        mreq = struct.pack("4sl", socket.inet_aton(ip), socket.INADDR_ANY)
        s4.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        dict_ip_udp[ip] = 0
        dict_ip_mpeg[ip] = 0
        dict_ip_mpeg_total[ip] = 0
        dict_ip_udp_total[ip] = 0
    else:
        mreq = struct.pack("16sl", socket.inet_pton(socket.AF_INET6, str(ip)), socket.INADDR_ANY)
        s6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
        dict_ip_udp[ip] = 0
        dict_ip_mpeg[ip] = 0
        dict_ip_mpeg_total[ip] = 0
        dict_ip_udp_total[ip] = 0



#Nastaveni jednotlivych poli pro select
read_sockets, write_sockets, error_sockets = select.select(socketList, [], [])
is_jitter = 0
is_ip_udp = False

#Nastava monitorovani IPTV pres nekonecny cyklus
while True:
    #nastavime si cas
    startTime = time.time()
    #nejak si to nastavim pro ten select


    for sock in read_sockets:

        is_ip_value = False
        is_source_value = False
        is_pid_value = False
        is_pid_source_value = False
        is_type_value = False
        is_pid1_value = False
        is_pid_cc_value = False
        is_pid_cc_control_value = False
        is_ip = False


        if (sock == s4):
            packet = sock.recvfrom(65000)

            packet = packet[0]

            timeReceived = time.time() - startTime
            seconds = seconds + timeReceived  # pocitadlo sekund
            #Vytahneme si z paketu ipv4 hlavicku
            ipIndex = read_sockets.index(sock)
            ip_header = packet[0:20]
            #Rozbalime hlavicku
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            #Potrebujeme skutecnou delku hlavicky kvuli spravnemu posunu na udp hlavicku
            version_ihl = iph[0]
            #V prvnim Bytu je jak verze, tak i delka, proto musime udelat bitovy posun a operaci AND
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            iph_length = ihl * 4
            #Ziskame zdrojovou i cilovou adresu
            s_addr = socket.inet_ntoa(iph[8])
            d_addr = socket.inet_ntoa(iph[9])

            # Preskocime UDP hlavicku, protoze v ni nic nepotrebujeme a jdeme rovnou k datum, kde by mely byt mpeg-ts bloky
            h_size = 8 + iph_length
            udp_data = packet[h_size:]

        if (sock == s6):

            packet, addr = sock.recvfrom(65000)
            timeReceived = time.time() - startTime
            seconds = seconds + timeReceived  # pocitadlo sekund
            s_addr = addr
            s_addr = re.sub('%.*','',str(s_addr))
            s_addr = re.sub('\(\'', '', str(s_addr))
            d_addr = "ff15::1"
            h_size = 8
            udp_data = packet[h_size:]

        #Zjistime, k jake ip adresse se ma dany UDP paket pricist
        for ip in ipList:
            if (d_addr == ip):
                dict_ip_udp[d_addr] = dict_ip_udp[d_addr] + 1
        #Vytvorime si pomocne pole, jez nam udava, na jake pozici by se mely nachazet mpeg-ts bloky
        controlForMPEG = [0, 188, 376, 564, 569, 752, 940, 1128]
        startList = []
        #Najdeme si vsechny potencialni mpeg-ts bloky, (blok zacina sync bytem jez ma v hex hodnotu 47 a ulozime si do startlistu indexy zacatku jejich pozic)
        r = re.compile("\x47")
        for m in r.finditer(str(udp_data)):
            startList.append(m.start())

        #inicializuji si pole PIDcek
        pid_in_udp = []
        #Nyni kontroluji startList, kde jsem si ulozil pozice, s controlForMPEG, pokud je pozice nalezena, vim, ze se jedna o MPEG-TS blok
        for control in controlForMPEG:
            for start in startList:
                if (control == start):
                    #############################################################
                    ## Ziskani slovniku sources                                ##
                    #############################################################
                    #Nejprve vlozime do slovniku zdrojovou adresu
                    for source_key, ip_value in dict_sources.items():
                        #Pokud se tam uz zdroj vyskytuje musim nastavit boolovkou promenou na True, abych nic nepridaval
                        if (s_addr == source_key):
                            is_source_value = True
                        #Pokud je krome zdroje tam i cilova ip adresa stejna, udelam to same
                            if (ip_value == d_addr):
                                is_ip_value = True
                    #Jelikoz tam zdroj neni, tak vytvorim pole, protoze pro jeden zdroj muze byt vice cilovych ip adres
                    if (is_source_value == False):
                        dict_sources[s_addr] = []
                    #Take se musi zkontrolovat, jestli je tam stejna cilova ip adresa, nebo ne
                    for source_key, ip_value in dict_sources.items():
                        for ip_value in dict_sources[source_key]:
                            if (ip_value == d_addr):
                                is_ip_value = True
                    #Kdyz se ve zdroji ip adresa nevyskytuje, tak naplnim zdroj cilovou ip adresou
                        if (is_ip_value == False):
                            dict_sources[source_key].append(d_addr)

                    #Na zacatku opet pripocitam jeden, uz MPEG-TS blok, ke spravne ip adrese
                    for ip in ipList:
                        if (d_addr == ip):
                            dict_ip_mpeg[d_addr] = dict_ip_mpeg[d_addr] + 1

                    #############################################################
                    ## Ziskani MPEG-TS hlavicky                                ##
                    #############################################################
                    #Vytahneme si postupne z paketu MPEG-TS hlavicky
                    udp_data1 = udp_data[start:start + 4]
                    mpeg_ts_header = struct.unpack('!BHB', udp_data1)
                    mpeg_ts_data = udp_data[start + 4:start + 8]

                    #Ziskame si PID, nyni staci udelat diky spravne pozici ve strukture AND
                    pid_neco = mpeg_ts_header[1]
                    pid = pid_neco & 0x1FFF
                    pid_in_udp.append(pid)
                    #Ziskame pusi, abychom mohli zjistit o jaky typ PID se jedna
                    pusi = (pid_neco >> 14) & 0x001
                    #Ziskame si take CC, opet musime udelat AND
                    cc_else = mpeg_ts_header[2]
                    cc = cc_else & 0xf

                    #############################################################
                    ## Ziskani PID -- propojeno s ip adresou                   ##
                    #############################################################
                    #Princip je stejny, jako byl u vlozeni zdroje, jenom jednodussi, predpokladam ze jedno PID nema vice adres, JESTE DOLEPSIT


                    for PID_key, dest_value in dict_PID.items():
                        if (pid == PID_key):
                            is_pid_value = True

                    if (is_pid_value == False):
                        dict_PID[pid] = d_addr

                    ##############################################################
                    ## musim ziskat udp k danemu pid, podle toho se rozhoduji

                    #############################################################
                    ## Ziskani hodnot pro zjisteni bandwidth ES + out-of-sync  ##
                    #############################################################
                    for PID_key5, dest_value in dict_bandwidth_pid.items():
                        if (pid == PID_key5):
                            is_pid1_value = True
                            dict_bandwidth_pid[pid] = dict_bandwidth_pid[pid] + 1
                            dict_pid_cc[pid] = dict_pid_cc[pid] + 1

                    #Pokud neni PID v bandwidth, nastavim ho na 1,aby nam ten jeden blok nechybel, to same udelam u pic_cc
                    #boolovska hodnota je nastavena kvuli tomu, aby se ulozil pouze a jenom prvni CC kazdeho PID
                    if (is_pid1_value == False):
                        dict_bandwidth_pid[pid] = 1
                        dict_pid_cc[pid] = 1
                        is_pid_cc_control_value = True

                    #############################################################
                    ## Pocitani spatnych MPEG-TS bloku                         ##
                    #############################################################
                    #Zjistim si prvni CC a nastavim si slovnik pro pocet chybnych bloku
                    for PID01, CCcontrol in dict_bandwidth_pid.items():
                        if (pid == PID01):
                            if (is_pid_cc_control_value == True):
                                if (dict_bandwidth_pid[pid] == 1):
                                    dict_pid_cc_first[pid] = cc - 1
                                    dict_pid_cc_bad_count[pid] = 0
                                    dict_pid_max_jitter[pid] = 0
                                    dict_pid_jitter_counter[pid] = 1
                                    dict_pid_jitter_sum[pid] = 0
                            #Porovnavam zbytek souctu prvniho CC a x-teho PID,po deleni se zbytkem 16-ti s CC, jez by mel nastat
                            #Pokud se nerovnaji, inkrementuje se dict_pid_cc[pid] a zaroven se pricte chyba
                            #POZOR: muze nastat situace zduplikovanych bloku, ale tento algoritmus udela to, ze proste pricte
                            #cisla, jez by mely byt mezi zduplikovanymi bloky
                            #To by vyvolalo gelkou chybu, je to osetreno az pri vypisu
                            while (dict_pid_cc[pid] + dict_pid_cc_first[pid]) % 16 != cc:
                                dict_pid_cc_bad_count[pid] = dict_pid_cc_bad_count[pid] + 1
                                dict_pid_cc[pid] = dict_pid_cc[pid] + 1

                    #############################################################
                    ## Zjisteni typu PID                                       ##
                    #############################################################
                    #Pokud je pusi rovno 1, za MPEG-TS hlavickou nasleduje dalsi hlavicka, ktera muze byt PES
                    if (pusi == 1):
                        #Nachystame si potencialni PES hlavicku
                        pes_header = struct.unpack('!HBB', mpeg_ts_data)
                        #Pokud se prvni tri byty rovnaji jedne, jedna se o PES
                        if ((pes_header[0] == 0x00) and (pes_header[1] == 0x01)):
                            #Nyni muzeme zjistit, jestli je PID audio, nebo video, ostatni typy jsou ignorovany (proto se celkovy bandwidth se souctem PID bandwidthu nepatrne lis)
                            #Opet stejny princip jak u zjistovani typu, zdroje, atd.. pokud je v danem rozsahu, nastavi se na audio
                            if ((pes_header[2] >= 0xc0) and (pes_header[2] <= 0xdf)):
                                for PID_key, source_value in dict_type.items():
                                    if (pid == PID_key):
                                        is_type_value = True

                                if (is_type_value == False):
                                    dict_type[pid] = "audio"

                            #pokud je v tomhle rozsahu, nastavi se na video
                            elif ((pes_header[2] >= 0xe0) and (pes_header[2] <= 0xef)):
                                for PID_key, source_value in dict_type.items():
                                    if (pid == PID_key):
                                        is_type_value = True

                                if (is_type_value == False):
                                    dict_type[pid] = "video"


        #############################################################
        ## Zjisteni avg a peak jitteru                             ##
        #############################################################

        #staci mi jenom unikatni hodnota z kazdeho prepisu, abych vedel, jake PIDcka dosla v jakem UDPcku
        pid_in_udp = list(set(pid_in_udp))
        #timto ziskam jitter
        for value in pid_in_udp:
            for neco3, other2 in dict_delay1.items():
                if (neco3 == value):
                    dict_pid_jitter[neco3] = abs(dict_delay1[neco3] - timeReceived)*1000
                    for neco4, other3 in dict_pid_max_jitter.items():
                        if (neco4 == neco3):
                            dict_pid_jitter_sum[neco3] += dict_pid_jitter[neco3]
                            dict_pid_jitter_counter[neco3] += 1
                            if (dict_pid_jitter[neco3] > dict_pid_max_jitter[neco3]):
                                dict_pid_max_jitter[neco3] = dict_pid_jitter[neco3]
        #ziskame delay1
        for value in pid_in_udp:
            for neco2, other in dict_pid_time.items():
                if (neco2 == value):
                    dict_delay1[neco2] = abs(timeReceived - dict_pid_time[neco2])
        #Naplnuji si hodnotami a porad prepisuji
        for value in pid_in_udp:
            dict_pid_time[value] = timeReceived


    ############################################
    ## VYPIS Z MONITOROVANI                   ##
    ############################################
    #Vypisuje se vzdy po jedne sekunde
    if seconds >= 1:
        #Nastavime posunuti radku
        ip_mc_stats = 2
        #Vypis celkovych statistik
        #Inicializujeme obrazovku a nodelay popsat
        stdscr = curses.initscr()
        stdscr.nodelay(True)
        #Tiskne se prvni radek s nazvem a potom druhy (resp. treti) s nazvy velicin
        stdscr.addstr(0, 0, "Multicast group statistics: ")
        stdscr.addstr(2, 20, "Bandwidth")
        stdscr.addstr(2, 34, "UDP packets")
        stdscr.addstr(2, 50, "MPEG-TS packets")
        #Pro kazdou ip adresu chceme vytisknout celkove statistiky, proto for cyklus
        for ip in ipList:
            #Nejprve si zjistime bandwidth pomoci vzorce nize
            #Dale mu priradime podle poctu stazenych bitu potrebnou jednotku a upravime vysledek pro ni
            bandwidth = (dict_ip_mpeg[ip] * 188 * 8) / (seconds)
            if (bandwidth >= 1000000):
                bandwidth = str(round(bandwidth / 1000000.0, 2)) + " Mbps"
            elif (bandwidth >= 1000):
                bandwidth = str(round(bandwidth / 1000.0, 2)) + " Kbps"
            else:
                bandwidth = str(round(bandwidth, 2)) + " bps"
            #Posuneme se o radek niz a zjistime si index pro dalsi vypisy
            ip_mc_stats = ip_mc_stats + 1
            ip_index = ipList.index(ip)
            #Protoze pocitame celkove mnozstvi UDP paketu a MPEG-TS bloku, meli bychom si je nekam ulozit
            dict_ip_udp_total[ip] += dict_ip_udp[ip]
            dict_ip_mpeg_total[ip] += dict_ip_mpeg[ip]
            #Nyni vypiseme ziskane statistiky na prislusne pozice
            stdscr.addstr(ip_mc_stats, 0, str(ipList[ip_index]))
            stdscr.addstr(ip_mc_stats, 20, str(bandwidth) + "   ")
            stdscr.addstr(ip_mc_stats, 34, str(dict_ip_udp_total[ip]))
            stdscr.addstr(ip_mc_stats, 50, str(dict_ip_mpeg_total[ip]))
            #Vynulujeme udp a mpeg counter, protoze je pouzivame pro bandwidth, ktery pocitame jako pocet bitu za jednotku casu
            dict_ip_udp[ip] = 0
            dict_ip_mpeg[ip] = 0
        #Posunume se o radek a zacneme s vypisem pro jednotlive Elementary Streams (uvazujeme audio/video)
        ip_mc_stats = ip_mc_stats + 2
        stdscr.addstr(ip_mc_stats, 0, "Elementary streams statistics:")
        #Pro kazdou adresu vypisujeme Elementary Streams
        for ip in ipList:
            ip_index = ipList.index(ip)
            #Chceme pro kazdou zdrojovou adresu vypisovat
            for source_key, ip_value in dict_sources.items():
                for ip_value in dict_sources[source_key]:
                    #Hledame zdroj, jez patri k prislusne adrese, pote se muzeme posunout o radek a vypsat nazvy velicin
                    if (ip_value == ipList[ip_index]):
                        ip_mc_stats = ip_mc_stats + 1
                        stdscr.addstr(ip_mc_stats, 0, str(ip_value) + ", source " + str(source_key))
                        ip_mc_stats = ip_mc_stats + 1
                        stdscr.addstr(ip_mc_stats, 2, "PID")
                        stdscr.addstr(ip_mc_stats, 11, "type")
                        stdscr.addstr(ip_mc_stats, 20, "bandwidth")
                        stdscr.addstr(ip_mc_stats, 36, "out of sync (%)")
                        stdscr.addstr(ip_mc_stats, 56, "avg jitter")
                        stdscr.addstr(ip_mc_stats, 71, "peak jitter")
                        #Nyni muzeme vkladat jednotlive statistiky, podle PID
                        for pid_key, ipvalue in dict_PID.items():
                            if (ipvalue == ipList[ip_index]):
                                #Nejprve vlozime PID cislo, k nemuz je prirazena dana ip adresa pro rozpoznani, ke ktere dane PID patri
                                for pid_key2, type in dict_type.items():
                                    if (pid_key == pid_key2):
                                        ip_mc_stats += 1
                                        stdscr.addstr(ip_mc_stats, 2, str(pid_key))
                                        #K danemu PID nalezneme jeho typ podle klice, jez je u vetsiny ES statistik urceny jako PID kvuli sve jedinecnosti
                                        for pid_key1, pid_type in dict_type.items():
                                            if (pid_key1 == pid_key):
                                                stdscr.addstr(ip_mc_stats, 11, str(pid_type))
                                        #Opet nalezneme spravny bandwith a postupujeme jako u celkovych statistik
                                        for pid_key3, pid_bandwidth in dict_bandwidth_pid.items():
                                            if (pid_key3 == pid_key):
                                                bandwidth = (pid_bandwidth * 188 * 8) / seconds
                                                if (bandwidth >= 1000000):
                                                    bandwidth = str(round(bandwidth / 1000000.0, 2)) + " Mbps"
                                                elif (bandwidth >= 1000):
                                                    bandwidth = str(round(bandwidth / 1000.0, 2)) + " Kbps"
                                                else:
                                                    bandwidth = str(round(bandwidth, 2)) + " bps"
                                                #Kvuli spravnemu refreshi jsem pridal tri mezery navic, eliminuje to znaky z predesleho vypisu
                                                stdscr.addstr(ip_mc_stats, 20, str(bandwidth) + "   ")
                                        #Nalezneme spravny pocet spatnych bloku, ale zapocitame si:
                                        #Jelikoz program pocita tak, jak jsem u vedle vyse, byl by out-of-sync kolem 20%, coz je nesmyslne, proto se duplikat bude
                                        #povazovat za jedinou chybu, jiz eliminujeme celociselnym delenim patnacti, zbytek budou pravdepodobne chybejici bloky
                                        #nebo ty, ktere dosly ve spatnem poradi
                                        #Ze zkoumani CC erroru jsem zjistil, ze vetsinou se jedna prave o zduplikovane bloky, tudiz odchylku z vypoctu out-of-sync
                                        #pomoci meho vzorce oproto skutecnemu out of sync povazuji za zanedbadelnou (chybejici, ci bloky ve spatnem poradi)
                                        for pid_key8, pid_bad in dict_pid_cc_bad_count.items():
                                            if (pid_key8 == pid_key):
                                                out_of_sync = ((((pid_bad // 15) + (pid_bad % 15))*100) / ((pid_bad // 15) + (pid_bad % 15) + dict_bandwidth_pid[pid_key8]))
                                                stdscr.addstr(ip_mc_stats, 36, str(round(out_of_sync, 2)))
                                        #Vlozime prumerny jitter, ktery si vypocitame
                                        for pid_key4, pid in dict_pid_jitter_sum.items():
                                            if (pid_key4 == pid_key):
                                                peak_jitter = ((dict_pid_jitter_sum[pid_key4])/(dict_pid_jitter_counter[pid_key4]))
                                                stdscr.addstr(ip_mc_stats, 56, str(round(peak_jitter, 2)) + "   ")

                                        #Nyni vlozime maximalni jitter
                                        for pid_key4, pid in dict_pid_max_jitter.items():
                                            if (pid_key4 == pid_key):
                                                stdscr.addstr(ip_mc_stats, 71, str(round(dict_pid_max_jitter[pid_key4],2)) + "   ")

        #Po vypisu jednotlivych statistik inicializujeme ty hodnoty, ktere potrebujeme pro vypocet za jednotku casu
        dict_pid_cc = {}
        dict_pid_cc_bad_count = {}
        dict_pid_cc_first = {}
        dict_bandwidth_pid = {}
        seconds = 0
    #Ukoncuje se, pokud stdctr zaznamena stisknuti mezerniku ostatni ignoruje
    try:
        key = stdscr.getkey()
    except:  # in no delay mode getkey raise and exeption if no key is press
        key = None
    if key == " ":  # of we got a space then break
        # jeste to musime ukoncit
        for sock in read_sockets:
            #Nakonec se odpojime ipv4 od skupiny a zavreme socket
            if (sock == s4):
                index = read_sockets.index(sock)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP,
                                socket.inet_aton(ipList[index]) + socket.inet_aton('0.0.0.0'))
                sock.close()
        break
    else:
        continue

curses.endwin()


