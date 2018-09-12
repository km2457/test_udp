# -*- coding: UTF-8 -*-
import struct
import binascii
import time
import datetime
import random
import string
import unicodedata
import threading
import select

t = time.time()


class udpclass:
    def charToUnic(self, ch):
        tmp_ch = hex(ord(ch))[2:]
        return "0" * (4 - len(tmp_ch)) + tmp_ch

    def charToUnic2(self, ch):
        r = ''
        if len(ch) == 1:
            tmp_ch = hex(ord(ch))[2:]
            res = "\u00" + tmp_ch

            return res
        else:
            while ch:

                if len(ch) == 1:
                    tmp_ch = hex(ord(ch[0]))[2:]
                    res = "\u00" + tmp_ch
                    r += res
                    ch = ch[1:]
                else:
                    tmp_ch = hex(ord(ch[0]))[2:]
                    res = "\u00" + tmp_ch
                    r += res
                    ch = ch[1:]
        return r

    def chineseToUnic(self, ch):
        return ch.encode('unicode_escape')[2:]

    def is_number(self, s):
        try:
            float(s)
            return True
        except ValueError:
            pass

        try:
            import unicodedata
            unicodedata.numeric(s)
            return True
        except (TypeError, ValueError):
            pass

        return False

    def get_low(self, num):  # 获得低八位
        return num & 0xff

    def generate_random_str(self, randomlength=16):
        """
        生成一个指定长度的随机字符串
        """
        random_str = ''
        base_str = 'ABCDEFGHIGKLMNOPQRSTUVWXYZabcdefghigklmnopqrstuvwxyz0123456789'
        length = len(base_str) - 1
        for i in range(randomlength):
            random_str += base_str[random.randint(0, length)]
        return random_str

    # print(generate_random_str(8))

    def get_hight(self, num):  # 获得高八位
        return (num & 0xff00) >> 8

    def create_values(self, *args):
        r = []
        while args:
            r.append(self.get_hight(int(args[0], 16)))
            r.append(self.get_low(int(args[0], 16)))

            if isinstance(args[1], str):
                if self.is_number(args[1]) == False:

                    if args[0] == '0x1f':
                        r.append(self.get_hight(len(self.charToUnic2(args[1]).encode('utf-8'))))
                        r.append(self.get_low(len(self.charToUnic2(args[1]).encode('utf-8'))))
                        r.append(self.charToUnic2(args[1]).encode('utf-8'))  # string-escape .encode('ASCII')
                    elif args[0] == '0x6':
                        r.append(self.get_hight(len(self.charToUnic2(args[1]).encode('utf-8'))))
                        r.append(self.get_low(len(self.charToUnic2(args[1]).encode('utf-8'))))
                        r.append(self.charToUnic2(args[1]).encode('utf-8'))  # string-escape .encode('ASCII')
                    elif args[0] == '0x13':
                        r.append(self.get_hight(len(self.charToUnic2(args[1]).encode('utf-8'))))
                        r.append(self.get_low(len(self.charToUnic2(args[1]).encode('utf-8'))))
                        r.append(self.charToUnic2(args[1]).encode('utf-8'))  # string-escape .encode('ASCII')
                    elif args[0] == '0x54':
                        r.append(self.get_hight(len(args[1].encode('unicode_escape'))))
                        r.append(self.get_low(len(args[1].encode('unicode_escape'))))
                        r.append(args[1].encode('unicode_escape'))
                    else:
                        r.append(self.get_hight(len(args[1].encode('unicode_escape'))))
                        r.append(self.get_low(len(args[1].encode('unicode_escape'))))
                        r.append(args[1].encode('unicode_escape'))

                elif self.is_number(args[1]) == True:
                    if args[0] == '0x10':
                        r.append(self.get_hight(len(args[1].encode('unicode_escape'))))
                        r.append(self.get_low(len(args[1].encode('unicode_escape'))))
                        r.append(args[1].encode('unicode_escape'))
                    elif args[0] == '0x11':
                        r.append(self.get_hight(len(args[1].encode('unicode_escape'))))
                        r.append(self.get_low(len(args[1].encode('unicode_escape'))))
                        r.append(args[1].encode('unicode_escape'))
                    elif args[0] == '0x13':
                        r.append(self.get_hight(len(self.charToUnic2(args[1]).encode('utf-8'))))
                        r.append(self.get_low(len(self.charToUnic2(args[1]).encode('utf-8'))))
                        r.append(self.charToUnic2(args[1]).encode('utf-8'))  # string-escape .encode('ASCII')
                    elif args[0] == '0x14':
                        r.append(self.get_hight(15))
                        r.append(self.get_low(15))
                        r.append(args[1].encode('unicode_escape'))
                    elif args[0] == '0x15':
                        r.append(self.get_hight(len(args[1].encode('unicode_escape'))))
                        r.append(self.get_low(len(args[1].encode('unicode_escape'))))
                        r.append(args[1].encode('unicode_escape'))
                    elif args[0] == '0x15':
                        r.append(self.get_hight(len(args[1].encode('unicode_escape'))))
                        r.append(self.get_low(len(args[1].encode('unicode_escape'))))
                        r.append(args[1].encode('unicode_escape'))
                    elif args[0] == '0x1f':
                        r.append(self.get_hight(len(self.charToUnic2(args[1]).encode('utf-8'))))
                        r.append(self.get_low(len(self.charToUnic2(args[1]).encode('utf-8'))))
                        r.append(self.charToUnic2(args[1]).encode('utf-8'))  # string-escape .encode('ASCII')
                    elif args[0] == '0x30':
                        r.append(self.get_hight(4))
                        r.append(self.get_low(4))
                        r.append(args[1])
                    elif args[0] == '0x31':
                        r.append(self.get_hight(4))
                        r.append(self.get_low(4))
                        r.append(args[1])
                    elif args[0] == '0x50':
                        r.append(self.get_hight(4))
                        r.append(self.get_low(4))
                        r.append(args[1])
                    elif args[0] == '0x51':
                        r.append(self.get_hight(4))
                        r.append(self.get_low(4))
                        r.append(args[1])
                    elif args[0] == '0x52':
                        r.append(self.get_hight(4))
                        r.append(self.get_low(4))
                        r.append(args[1])
                    elif args[0] == '0x53':
                        r.append(self.get_hight(4))
                        r.append(self.get_low(4))
                        r.append(args[1])
                    elif args[0] == '0x56':
                        r.append(self.get_hight(4))
                        r.append(self.get_low(4))
                        r.append(args[1])
                    else:
                        r.append(self.get_hight(len(self.charToUnic2(args[1]).encode('utf-8'))))
                        r.append(self.get_low(len(self.charToUnic2(args[1]).encode('utf-8'))))
                        r.append(self.charToUnic2(args[1]).encode('utf-8'))  # string-escape .encode('ASCII')
            elif isinstance(args[1], int):
                r.append(self.get_hight(4))
                r.append(self.get_low(4))
                r.append(args[1])
            elif isinstance(args[1], bytes):
                r.append(args[1])
            args = args[2:]
        return r

    def create_index(self, *args):
        r = ''
        while args:
            if isinstance(args[1], str):
                # print('a')
                # r += '4B'+str(len(args[1].encode('unicode_escape')))+'s'

                if self.is_number(args[1]) == False:

                    if args[0] == '0x1f':
                        r += '4B' + str(len(self.charToUnic2(args[1]).encode('utf-8'))) + 's'
                    elif args[0] == '0x6':
                        r += '4B' + str(len(self.charToUnic2(args[1]).encode('utf-8'))) + 's'
                    elif args[0] == '0x13':
                        r += '4B' + str(len(self.charToUnic2(args[1]).encode('utf-8'))) + 's'
                    elif args[0] == '0x54':
                        r += '4B' + str(len(args[1].encode('unicode_escape'))) + 's'
                    else:
                        r += '4B' + str(len(args[1].encode('unicode_escape'))) + 's'
                elif self.is_number(args[1]) == True:

                    if args[0] == '0x10':
                        r += '4B' + str(len(args[1].encode('unicode_escape'))) + 's'
                    elif args[0] == '0x11':
                        r += '4B' + str(len(args[1].encode('unicode_escape'))) + 's'
                    elif args[0] == '0x13':
                        r += '4B' + str(len(self.charToUnic2(args[1]).encode('utf-8'))) + 's'
                    elif args[0] == '0x14':
                        r += '4B' + str(15) + 's'
                    elif args[0] == '0x15':
                        r += '4B' + str(len(args[1].encode('unicode_escape'))) + 's'
                    elif args[0] == '0x1f':
                        r += '4B' + str(len(self.charToUnic2(args[1]).encode('utf-8'))) + 's'
                    elif args[0] == '0x30':
                        r += '4BL'
                    elif args[0] == '0x31':
                        r += '4BL'
                    elif args[0] == '0x50':
                        r += '4BL'
                    elif args[0] == '0x51':
                        r += '4BL'
                    elif args[0] == '0x52':
                        r += '4BL'
                    elif args[0] == '0x53':
                        r += '4BL'
                    elif args[0] == '0x56':
                        r += '4BL'
                    else:
                        r += '4B' + str(len(self.charToUnic2(args[1]).encode('utf-8'))) + 's'
                    # r += '4B' + str(len(charToUnic2(args[1]).encode('unicode_escape'))) + 's'

            elif isinstance(args[1], int):
                r += '4BL'
            elif isinstance(args[1], bytes):
                r += '4B' + str(args[1]) + 's'
            args = args[2:]
        return r

    def create_baochang(self, *args):
        r = 1
        while args:
            r += 2
            r += 2
            if isinstance(args[1], str):
                # r += len(args[1].encode('unicode_escape'))

                if self.is_number(args[1]) == False:

                    if args[0] == '0x1f':
                        r += len(self.charToUnic2(args[1]).encode('utf-8'))
                    elif args[0] == '0x16':
                        r += len(self.charToUnic2(args[1]).encode('utf-8'))
                    elif args[0] == '0x6':
                        r += len(self.charToUnic2(args[1]).encode('utf-8'))
                    elif args[0] == '0x13':
                        r += len(self.charToUnic2(args[1]).encode('utf-8'))
                    if args[0] == '0x54':
                        r += len(args[1].encode('unicode_escape'))
                    else:
                        r += len(args[1].encode('unicode_escape'))
                elif self.is_number(args[1]) == True:
                    # print(len(charToUnic2(args[1]).encode('unicode_escape')))
                    if args[0] == '0x10':
                        r += len(args[1].encode('unicode_escape'))
                    elif args[0] == '0x11':
                        r += len(args[1].encode('unicode_escape'))
                    elif args[0] == '0x13':
                        r += len(self.charToUnic2(args[1]).encode('utf-8'))
                    elif args[0] == '0x14':
                        r += 15
                    elif args[0] == '0x15':
                        r += len(args[1].encode('unicode_escape'))
                    elif args[0] == '0x1f':
                        r += len(self.charToUnic2(args[1]).encode('utf-8'))
                    elif args[0] == '0x30':
                        r += 4
                    elif args[0] == '0x31':
                        r += 4
                    elif args[0] == '0x50':
                        r += 4
                    elif args[0] == '0x51':
                        r += 4
                    elif args[0] == '0x52':
                        r += 4
                    elif args[0] == '0x53':
                        r += 4
                    elif args[0] == '0x56':
                        r += 4
                    else:
                        r += len(self.charToUnic2(args[1]).encode('utf-8'))



            elif isinstance(args[1], int):
                r += 4
            elif isinstance(args[1], bytes):
                r += len(args[1])
            args = args[2:]
        return r

    import socket

    # 获取本机计算机名称
    hostname = socket.gethostname()
    # 获取本机ip

    ip = socket.gethostbyname(hostname)

    ip_byte = socket.inet_aton(ip)

    def get_data_values(self, data, answer=1):
        result_value = 0
        if data == 'first_reg':
            result_value = ('0x1', '',  # 注册 必须在第一个子包 为必要发
                            '0x10', '98200940720187',  # 终端厂商编号 字符串
                            '0x11', '586356170700008',  # 终端序列号(SN) 字符串 固定15byte
                            '0x12', '1982934579',  # 终端版本号 unicode
                            '0x13', '01',  # 终端制式(LTE/2G等) #unicode
                            '0x14', '291868248829057',  # 终端IMEI号 字符串
                            '0x1f', '86141403,86141409',  # IMSI（支持多个IMSI号） unicode
                            )
        elif data == 'last_reg':
            result_value = ('0x1', '',  # 注册 必须在第一个子包 为必要发东西
                            '0x11', '586356170700002',  # 终端序列号(SN) 当字符串
                            )
        elif data == 'beat':
            result_value = (
                '0x2', '',  # 心跳 在第一个子包
                '0x11', '123456',  # 终端序列号(SN) 字符串
                '0x24', '123456',  # 业务流量统计 unicode
                '0x25', '123456',  # 网管流量统计 unicode
                '0x30', 80,  # 终端CPU占用率 整数
                '0x31', 80,  # 终端内存使用率 整数
                '0x35', '12',  # 通信模块温度 unicode
                '0x36', '123456',  # 信号强弱度 unicdoe
                '0x37', '123456',  # 信噪比（信号质量） unicdoe
            )
        elif data == 'select':
            result_value = (
                '0x04', self.generate_random_str(8),  # 心跳 在第一个子包
                '0x10', '',  # 终端厂商编号O  字符串 不得超过15字节 现在其实是定死了15字节来填
                '0x11', '',  # 终端序列号(SN)0 字符串 不得超过15字节 现在其实是定死了15字节来填
                '0x12', '',  # 终端版本号O  unicode
                '0x13', '',  # 终端制式(LTE/2G等)O unicode的enum
                '0x14', '',  # 终端IMEI号O 不得超过15字节 现在其实是定死了15字节来填
                '0x16', '',  # 终端能力级别 unicode
                '0x17', '',  # 终端型号 unicode
                '0x20', '',  # 终端版本号 unicode
                '0x24', '',  # 业务流量统计 unicode
                '0x25', '',  # 网管流量统计 unicode
                '0x30', '',  # 终端CPU占用率 整数
                '0x31', '',  # 终端内存使用率 整数
                '0x32', '',  # 流量异常信息 unicode
                '0x35', '',  # 终端温度 Unicode
                '0x36', '',  # 信号强度弱 unicode
                '0x37', '',  # 信噪比（信号质量） unicode
            )
        elif data == 'act_report':
            result_value = (
                '0x3', '0',  # 周期性上报数据id
                '0x11', '123456',  # 终端序列号(SN) 字符串
                '0x20', '0',  # 无线网络信息;当终端为多通道时,包含多个本CMD
                '0x6', '01',  # 告警信息(如果有)

            )
        elif data == 'config':
            result_value = (
                '0x5', '',  # 设置消息
                '0x41', '123456',  # APN名称 unicode
                '0x42', '123',  # APN用户名 unicode
                '0x43', '123456',  # APN密码 unicode
                '0x50', 10,  # 周期性信息上报周期 整数
                '0x51', 10,  # 心跳上报周期 整数
                '0x52', 10,  # 消息合并周期 整数
                '0x53', 1,  # 重启设备 正整数 1就是要重启
                '0x54', 'http://site.baidu.com/',  # 远程升级 字符串形式
                '0x55', '10',  # 网管服务IP IP地址 4byte
                '0x56', 10,  # 网管服务端口 正整数

            )
        elif data == 'report':
            result_value = (
                # '0x6', len('01H'), '01',  # 告警
                # '0x11', len('123456'), '123456',  # 终端序列号
            )
        elif data == 'return_select':
            result_value = answer

        return result_value

    # print(new_values)

    def ichecksum3(self, data):
        length = len(data)

        checksum = 0
        for i in range(0, length):
            num = (int(data[i], 16))
            checksum += (num & 0xFF) + (num >> 8)

        return ~checksum & 0xFF

    def ichecksum_change(self, data):
        res = []
        while data:
            res.append(data[0:2])
            data = data[2:]

        return res

    def build_msg(self, target, answer=1):
        now_data_values = self.get_data_values(target, answer)
        timestamp_mesc = int(round(t) * 1000)
        sequence = '0x1'
        header = '0XEF'
        pack_length = self.create_baochang(*now_data_values)
        pack_length_hight = self.get_hight(pack_length)
        pack_length_low = self.get_low(pack_length)
        timestamp_mesc_last4byte = long(hex(timestamp_mesc)[-9:-1], 16)
        new_values = [int(header, 16), 1, timestamp_mesc_last4byte, pack_length_hight,
                      pack_length_low] + self.create_values(
            *now_data_values)
        print(new_values)
        a = struct.Struct('>BBLBB' + self.create_index(*now_data_values))
        result_nochecksum = a.pack(*new_values)
        checksum = self.ichecksum3(self.ichecksum_change((binascii.hexlify(result_nochecksum[6:]))))
        new_values.append(checksum)
        b = struct.Struct('>BBLBB' + self.create_index(*now_data_values) + 'B')
        result = b.pack(*new_values)

        print('Original values:', new_values)
        print('Format string :', b.format)
        print('Uses :', b.size, 'bytes')
        print('Packed Value :', binascii.hexlify(result))
        print(struct.unpack('>BBLBB' + self.create_index(*now_data_values) + 'B', result))
        print('Unpacked Type :', type(result), ' Value:', result)

        return result

    def send_msg_manage(self, data):
        data_all = data[16:-2]
        data_cmdid_array = self.data_pick_cmdid(data_all)
        print(data_cmdid_array)
        print(u'获得服务器回应')
        if '0x1' in data_cmdid_array:
            print(u'注册信息')
            if '0x2' in data_cmdid_array:
                print(u'需要重新提交资料')
            else:
                print(u'全资料注册成功')
            # print(data_cmdid_array)
        elif '0x2' in data_cmdid_array:
            print(u'心跳信息')
        elif '0x3' in data_cmdid_array:
            print(u'主动上报信息')

        return 1

    def send_msg(self, data, ip, port, answer=1):
        send_data = u.build_msg(data, answer)
        import socket

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # print('sentojieguo')
        s.sendto(send_data, (ip, port))
        # print('fasongchenggong')
        s.setblocking(0)
        ready = select.select([s], [], [], timeout)
        if ready[0]:
            # 接收结果
            # data = s.recv(1024).strip('\x00')
            res = s.recv(1024)
            # print(binascii.b2a_hex(res))
            self.send_msg_manage(binascii.b2a_hex(res))
            print(binascii.b2a_hex(res))

        else:
            print("time out")
            relink = 3
            c = 1
            while c <= relink:
                s.sendto(send_data, (ip, port))
                s.setblocking(0)
                ready = select.select([s], [], [], timeout)
                if ready[0]:
                    # 接收结果
                    # data = s.recv(1024).strip('\x00')
                    res = s.recv(1024)
                    # print(binascii.b2a_hex(res))
                    self.send_msg_manage(binascii.b2a_hex(res))
                    break
                else:
                    print("time out")
                    print("relink:" + str(c))
                c += 1
            # print(1)



        # exit()

        # exit()

        return '1'

    def create_answer(self, header, data):

        if '0x11' in data:
            res = ['0x4', header]
        else:
            res = ['0x4', header, '0x11', '586356170700002']

        for i in data:
            res.append(i)
            # res.append("123456")
            if i == '0x10':  # 终端序列号(SN)0
                res.append("586356170700002")
            elif i == '0x11':  # 终端序列号(SN)0
                res.append("586356170700002")
            elif i == '0x12':  # 终端版本号O
                res.append("111")
            elif i == '0x13':  # 终端制式(LTE/2G等)O
                res.append("01")
            elif i == '0x14':  # 终端IMEI号O
                res.append("111111")
            elif i == '0x16':  # 终端能力级别
                res.append("1")
            elif i == '0x17':  # 终端型号
                res.append("11")
            elif i == '0x20':  # 终端无线网络信息
                res.append("11")
            elif i == '0x24':  # 业务流量统计
                res.append("11")
            elif i == '0x25':  # 网管流量统计
                res.append("11")
            elif i == '0x30':  # 终端CPU占用率
                res.append(20)
            elif i == '0x31':  # 终端内存使用率
                res.append(20)
            elif i == '0x32':  # 流量异常信息
                res.append("2")
            elif i == '0x35':  # 终端温度
                res.append("1")
            elif i == '0x36':  # 信号强度弱
                res.append("1")
            elif i == '0x37':  # 信噪比（信号质量）
                res.append("1")

        return tuple(res)

    def data_pick_cmdid(self, data):
        res = []
        # print(data)
        while data:
            # print(data)
            id = data[0:4]
            # print(id)
            pack_length = data[4:8]
            pack = data[8:8 + int(pack_length, 16)*2]
            res.append(hex(int(id, 16)))
            res.append(pack)
            data = data[8 + int(pack_length, 16) * 2:]

        return res

    def data_get(self):
        import socket, binascii

        HOST = ''  # use '' to expose to all networks
        port = 5577

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((HOST, port))

        try:

            while True:
                # print("11")
                data, addr = s.recvfrom(4096)
                if not data: break
                data_side = binascii.b2a_hex(data)[16:-2]
                select_msg_pack_legth = int(data_side[4:8], 16)
                other_data = data_side[8 + select_msg_pack_legth * 2:]
                select_header = data_side[8:select_msg_pack_legth * 2]


                data_all = binascii.b2a_hex(data)[16:-2]
                print('nizhuan')
                print(binascii.unhexlify(data_side))
                #print(data_all)

                data_cmdid_array = self.data_pick_cmdid(data_all)

                if '0x4' in data_cmdid_array:
                    self.send_msg('return_select', '119.23.138.79', 5577,
                                  answer=self.create_answer(select_header, self.data_pick_cmdid(other_data)))
                elif '0x5' in data_cmdid_array:
                    print('config')
                    print(binascii.hexlify(data))
                    #print(other_data)
                    #print(data_side)
                    y = self.create_answer(select_header, self.data_pick_cmdid(data_side))
                    print(y)
                    print()
                    #print(binascii.unhexlify(y))
                    t = 0
                    for r in y:
                        print(binascii.unhexlify(r))
                        print(t)
                        t += 1
                print(repr(data))
                print(addr[0])
                print(addr[1])
                print(data_cmdid_array)



        except KeyboardInterrupt:
            print()
    # , '127.0.0.1', 10000


u = udpclass()
# listen()
# u.send_msg(u.build_msg('beat'),'127.0.0.1',5577) #自己
# u.data_get()

# u.data_get()

# u.send_msg(u.build_msg('select'),'118.25.225.194',5577) #15日停的服务器

# u.send_msg(u.build_msg('beat'), '119.23.138.79', 5577)  #任务服务器

# u.send_msg(u.build_msg('select'), '144.34.158.18', 5577) # 搬瓦工
# thread.start_new_thread(u.send_msg,(u.build_msg('select'),'144.34.158.18',5577))

timeout = 3 * 1  #

# t1 = threading.Thread(target=u.send_msg,args=("config",'144.34.158.18',5577))
# t1.start()
t2 = threading.Thread(target=u.data_get(), args=())
# print('11')
t2.start()

# while True:
# print('11')
# t1.start()      # 并发
# t2.start()      # 并发
# time.sleep(1)
# u.data_get()
# u.send_msg(u.build_msg('select'), '120.25.231.139', 5577) # 公司自有


'''
while True:
    #print(t2.isAlive())
    if t1.isAlive() is False:
        t1 = threading.Thread(target=u.send_msg,args=(u.build_msg('first_reg'),'144.34.158.18',5577))
        t1.start()
        #print(t1.isAlive())
        # t1.join(''
'''


