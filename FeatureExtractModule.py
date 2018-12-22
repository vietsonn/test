import time
from builtins import print

import pyshark
import glob
import os
import platform
from threading import Thread

src_packets_dic= {}
dst_packets_dic= {}
src_bytes_dic= {}
dst_bytes_dic= {}
ssrc_diff_dst_dic= {}
sdst_diff_src_dic= {}
land_dic= {}

class Protocol:
    protocol = {
        "tcp" : "1",
        "icmp" : "1",
        "udp" : "1",
    }


class HandlePcap:

    # Return "" if value equal None
    def cvNonetoStr(self, var):
        if var == None:
            return ""
        else:
            return var

    # Check has attribute
    def check_hasattr(self, parent, child):
        if hasattr(parent, child):
            return True;
        return False;

    # 1- Get Source ip
    def get_src_ip(self, packet):
        src_ip = 0
        if self.check_hasattr(packet, "ip"):
            src_ip = packet.ip.src_host
        return str(src_ip)

    # 2- Get Destination ip
    def get_dst_ip(self, packet):
        dst_ip = 0
        if self.check_hasattr(packet, "ip"):
            dst_ip = packet.ip.dst_host
        return str(dst_ip)

    # 3 - Get Source port
    def get_src_port(self, packet, protocol):
        src_port = 0
        if self.check_hasattr(packet, protocol):
            if self.check_hasattr(packet[protocol], "srcport"):
                src_port = packet[protocol].srcport
        return str(src_port)

    # 4 - Get Destination port
    def get_dst_port(self, packet, protocol):
        dst_port = 0
        if self.check_hasattr(packet, protocol):
            if self.check_hasattr(packet[protocol], "dstport"):
                dst_port = packet[protocol].dstport
        return str(dst_port)

    # 5- Get protocol
    def get_protocol(self, packet):
        protocol = "other"
        protocolDic = Protocol.protocol
        if self.check_hasattr(packet, "frame_info"):
            split = str(packet.frame_info.protocols).split(":")
            i = 0
            while i < len(split):
                protocol = protocolDic.get(split[i])
                if protocol != None:
                    protocol = split[i]
                    break
                i += 1
        return protocol

    # 6 - Get number of packet has same source ip
    # 7 - Get number of packets to dst_ip per protocol
    # 8 - get number of bytes from src_ip
    # 9 - Get number of bytes to dst_ip per protocol
    # 10 - Count same src_ip, src_port  to difference dst_ip, dst_port
    # 11 - Count diff src_ip, src_port  to same dst_ip, dst_port
    # 12 - get Land
    def get_calculate_feature(self, protocol, src_ip, src_port, dst_ip, dst_port, pcap):
        src_packets = 0
        dst_packets = 0
        src_bytes = 0
        dst_bytes = 0
        ssrc_diff_dst = 0
        sdst_diff_src = 0
        land = 0
        check_src_packets = False
        check_dst_packets = False
        check_src_bytes = False
        check_dst_bytes = False
        check_ssrc_diff_dst = False
        check_sdst_diff_src = False
        check_land = False
        str_src_packets = protocol + "," + src_ip
        str_dst_packets = protocol + "," + dst_ip
        str_src_bytes = protocol + "," + src_ip
        str_dst_bytes = protocol + "," + dst_ip
        str_ssrc_diff_dst = src_ip + "," + src_port + "," + dst_ip + "," + dst_port
        str_sdst_diff_src = dst_ip + "," + dst_port + "," + src_ip + "," + src_port
        str_land = src_ip + "," + src_port

        # src_packets
        if str_src_packets in src_packets_dic:
            src_packets = src_packets_dic.get(str_src_packets)
            check_src_packets = True

        # dst_packets
        if str_dst_packets in dst_packets_dic:
            dst_packets = dst_packets_dic.get(str_dst_packets)
            check_dst_packets = True

        # src_bytes
        if str_src_bytes in src_bytes_dic:
            src_bytes = src_bytes_dic.get(str_src_bytes)
            check_src_bytes = True

        # dst_bytes
        if str_dst_bytes in dst_bytes_dic:
            dst_bytes = dst_bytes_dic.get(str_dst_bytes)
            check_dst_bytes = True

        # ssrc_diff_dst_dic
        if str_ssrc_diff_dst in ssrc_diff_dst_dic:
            ssrc_diff_dst = ssrc_diff_dst_dic.get(str_ssrc_diff_dst)
            check_ssrc_diff_dst = True

        # sdst_diff_src
        if str_sdst_diff_src in sdst_diff_src_dic:
            sdst_diff_src = sdst_diff_src_dic.get(str_sdst_diff_src)
            check_sdst_diff_src = True

        # land
        if str_land in land_dic:
            land = land_dic.get(str_land)
            check_land = True

        if check_src_packets == False or  check_dst_packets == False or check_src_bytes == False or check_dst_bytes == False or check_ssrc_diff_dst == False or check_sdst_diff_src == False or check_land == False:
            for packet in pcap:
                if check_src_packets == False:
                    if protocol == self.get_protocol(packet) and src_ip == self.get_src_ip(packet):
                        src_packets += 1
                if check_dst_packets == False:
                    if protocol == self.get_protocol(packet) and dst_ip == self.get_dst_ip(packet):
                        dst_packets += 1
                if check_src_bytes == False:
                    if protocol == self.get_protocol(packet) and src_ip == self.get_src_ip(packet):
                        src_bytes += int(packet.frame_info.len)
                if check_dst_bytes == False:
                    if protocol == self.get_protocol(packet) and dst_ip == self.get_dst_ip(packet):
                        dst_bytes += int(packet.frame_info.len)
                if check_ssrc_diff_dst == False:
                    if src_ip == self.get_src_ip(packet) and src_port == self.get_src_port(packet, protocol) \
                            and (
                            dst_ip != self.get_dst_ip(packet) or dst_port != self.get_dst_port(packet, protocol)):
                        ssrc_diff_dst += 1
                if check_sdst_diff_src == False:
                    if dst_ip == self.get_dst_ip(packet) and dst_port == self.get_dst_port(packet, protocol) \
                            and (
                            src_ip != self.get_src_ip(packet) or src_port != self.get_src_port(packet, protocol)):
                        sdst_diff_src += 1
                if check_land == False:
                    if src_ip == self.get_src_ip(packet) and src_ip == self.get_dst_ip(packet) \
                            and src_port == self.get_src_port(packet, protocol) and src_port == self.get_dst_port(packet, protocol):
                        land += 1
            if check_src_packets == False:
                src_packets_dic[str_src_packets] = src_packets
        return str(src_packets) + "," + str(dst_packets) + "," + str(src_bytes) + "," + str(dst_bytes) + "," + str(ssrc_diff_dst) + "," + str(sdst_diff_src) + "," + str(land)

    def get_extract_path(self, src_path):
        fileExtract = ""
        if platform.system() == "Windows":
            list = src_path.split("\\")
            fileExtract = os.getcwd() + "\\DatasetTest\\" + list[-1].replace("pcap", "csv")
        elif platform.system() == "Linux":
            list = src_path.split("/")
            fileExtract = os.getcwd() + "/DatasetTest/" + list[-1].replace("pcap", "csv")
        else:
            print("Sorry, we do not support your system")
        return fileExtract

    def getFeature(self, src_path):
        i = 0
        FILEPATH = src_path
        print("Start: " + FILEPATH)
        FILE_EXTRACT_PATH = self.get_extract_path(FILEPATH)
        pcap = pyshark.FileCapture(FILEPATH)
        featureTotal = ""
        featureSet = set()
        src_packets_dic.clear()
        dst_packets_dic.clear()
        src_bytes_dic.clear()
        dst_bytes_dic.clear()
        ssrc_diff_dst_dic.clear()
        sdst_diff_src_dic.clear()
        land_dic.clear()
        for packet in pcap:
            i += 1
            print(i)
            protocol = self.get_protocol(packet)
            if protocol != "other":
                featureStr = ""
                featureStrTuple = ""
                src_ip = self.get_src_ip(packet)
                dst_ip = self.get_dst_ip(packet)
                src_port = self.get_src_port(packet, protocol)
                dst_port = self.get_dst_port(packet, protocol)

                featureStrTuple += src_ip + ","
                featureStrTuple += dst_ip + ","
                featureStrTuple += src_port + ","
                featureStrTuple += dst_port + ","
                featureStrTuple += protocol + ","

                if featureStrTuple not in featureSet:
                    featureSet.add(featureStrTuple)
                else:
                    continue

                calcu_feature = self.get_calculate_feature(protocol, src_ip, src_port, dst_ip, dst_port, pcap)

                featureStr += src_ip + ","
                featureStr += dst_ip + ","
                featureStr += src_port + ","
                featureStr += dst_port + ","
                featureStr += protocol + ","
                featureStr += calcu_feature
                featureStr += "\n"
                # if featureStr not in featureSet:
                #     featureSet.add(featureStr)
                featureTotal += featureStr
        f = open(FILE_EXTRACT_PATH, "w+")
        f.write(featureTotal)
        f.close()
        #     pcap.close()
        print("Done: " + FILEPATH)


def featureExtract():

    handlePcap = HandlePcap()
    LASTFILE = ""
    curDirWorking = ""
    if platform.system() == "Windows":
        curDirWorking = os.getcwd() + "\\PcapCapture\\*"
    elif platform.system() == "Linux":
        curDirWorking = os.getcwd() + "/PcapCapture/*"
    else:
        print("Sorry, we do not support your system")
    while True:
        # * means all if need specific format then *.pcap
        list_of_files = glob.glob(curDirWorking)
        if len(list_of_files) != 0:
            latest_file = max(list_of_files, key=os.path.getctime)
            if LASTFILE != latest_file:
                LASTFILE = latest_file
                time.sleep(2)
                thread = Thread(target=handlePcap.getFeature(LASTFILE))
                thread.start()

        time.sleep(0.1)
