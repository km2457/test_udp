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
import socket

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

    def get_ip(self):
        import urllib2
        import re

        url = urllib2.urlopen("http://txt.go.sohu.com/ip/soip")
        text = url.read()
        ip = re.findall(r'\d+.\d+.\d+.\d+', text)

        return ip[0]

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

            if args[0] in str_data:
                if args[0] in ('0x4', '0x10', '0x11', '0x14'):  # 15
                    r.append(self.get_hight(min(len(args[1].encode('unicode_escape')), 15)))
                    r.append(self.get_low(min(len(args[1].encode('unicode_escape')), 15)))
                    r.append(args[1].encode('unicode_escape'))
                elif args[0] in ('0x20'):  # 2
                    r.append(self.get_hight(min(len(args[1].encode('unicode_escape')), 2)))
                    r.append(self.get_low(min(len(args[1].encode('unicode_escape')), 2)))
                    r.append(args[1].encode('unicode_escape'))
                elif args[0] in ('0x12'):  # 20
                    r.append(self.get_hight(min(len(args[1].encode('unicode_escape')), 20)))
                    r.append(self.get_low(min(len(args[1].encode('unicode_escape')), 20)))
                    r.append(args[1].encode('unicode_escape'))
                elif args[0] in ('0x17'):  # 8
                    r.append(self.get_hight(min(len(args[1].encode('unicode_escape')), 8)))
                    r.append(self.get_low(min(len(args[1].encode('unicode_escape')), 8)))
                    r.append(args[1].encode('unicode_escape'))
                elif args[0] in ('0x1f'):  # 32
                    r.append(self.get_hight(min(len(args[1].encode('unicode_escape')), 32)))
                    r.append(self.get_low(min(len(args[1].encode('unicode_escape')), 32)))
                    r.append(args[1].encode('unicode_escape'))
                else:
                    r.append(self.get_hight(len(args[1].encode('unicode_escape'))))
                    r.append(self.get_low(len(args[1].encode('unicode_escape'))))
                    r.append(args[1].encode('unicode_escape'))

            elif args[0] in int_data:
                if args[0] in ('0x24', '0x25','0x36'):  # 4
                    r.append(self.get_hight(4))
                    r.append(self.get_low(4))
                    r.append(args[1])
                elif args[0] in ('0x72'):
                    r.append(self.get_hight(8))
                    r.append(self.get_low(8))
                    r.append(args[1])
                else:
                    r.append(self.get_hight(2))
                    r.append(self.get_low(2))
                    r.append(args[1])

            elif args[0] in float_data:
                r.append(self.get_hight(8))
                r.append(self.get_low(8))
                r.append(args[1])


            elif args[0] in unicode_data:
                r.append(self.get_hight(len(self.charToUnic2(args[1]).encode('utf-8'))))
                r.append(self.get_low(len(self.charToUnic2(args[1]).encode('utf-8'))))
                r.append(self.charToUnic2(args[1]).encode('utf-8'))  # string-escape .encode('ASCII')

            args = args[2:]

        return r

    def create_index(self, *args):
        r = ''

        while args:

            if args[0] in str_data:

                if args[0] in ('0x4', '0x10', '0x11', '0x14'):  # 15
                    r += '4B' + str(min(len(args[1].encode('unicode_escape')), 15)) + 's'
                elif args[0] in ('0x20'):  # 2
                    r += '4B' + str(min(len(args[1].encode('unicode_escape')), 2)) + 's'
                elif args[0] in ('0x12'):  # 20
                    r += '4B' + str(min(len(args[1].encode('unicode_escape')), 20)) + 's'
                elif args[0] in ('0x17'):  # 8
                    r += '4B' + str(min(len(args[1].encode('unicode_escape')), 8)) + 's'
                elif args[0] in ('0x1f'):  # 32
                    r += '4B' + str(min(len(args[1].encode('unicode_escape')), 32)) + 's'
                else:
                    r += '4B' + str(len(args[1].encode('unicode_escape'))) + 's'

            elif args[0] in int_data:

                if args[0] in ('0x24', '0x25','0x36'):  # 4
                    r += '4Bl'
                elif args[0] in ('0x72'):
                    r += '4Bq'
                else:
                    r += '4BH'

            elif args[0] in float_data:
                r += '4Bd'


            elif args[0] in unicode_data:
                r += '4B' + str(len(self.charToUnic2(args[1]).encode('utf-8'))) + 's'

            args = args[2:]

        return r

    def create_baochang(self, *args):
        r = 1

        while args:
            r += 2
            r += 2

            if args[0] in str_data:
                # r += len(args[1].encode('unicode_escape'))
                if args[0] in ('0x4', '0x10', '0x11', '0x14'):  # 15
                    r += min(len(args[1].encode('unicode_escape')), 15)
                elif args[0] in ('0x20'):  # 2
                    r += min(len(args[1].encode('unicode_escape')), 2)
                elif args[0] in ('0x12'):  # 20
                    r += min(len(args[1].encode('unicode_escape')), 20)
                elif args[0] in ('0x17'):  # 8
                    r += min(len(args[1].encode('unicode_escape')), 8)
                elif args[0] in ('0x1f'):  # 32
                    r += min(len(args[1].encode('unicode_escape')), 32)
                else:
                    r += len(args[1].encode('unicode_escape'))
            elif args[0] in int_data:
                if args[0] in ('0x24', '0x25','0x36'):  # 4
                    r += 4
                elif args[0] in ('0x72'):
                    r += 8
                else:
                    r += 2

            elif args[0] in float_data:
                r += 8

            elif args[0] in unicode_data:
                r += len(self.charToUnic2(args[1]).encode('utf-8'))

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
                            '0x12', '1982934579',  # 终端版本号 unicode  字符
                            '0x13', '01',  # 终端制式(LTE/2G等) #unicode  字符
                            '0x14', '291868248829057',  # 终端IMEI号 字符串
                            '0x1f', '86141403,86141409',  # IMSI（支持多个IMSI号） unicode  字符
                            # '0x70', 29,  # 经度 双精度
                            # '0x71', 86,  # 纬度 双精度
                            # '0x72', 86,  # 海拔 整数
                            )
        elif data == 'last_reg':
            result_value = ('0x11', '',  # 注册 必须在第一个子包 为必要发东西
                            '0x11', '586356170700002',  # 终端序列号(SN) 当字符串
                            )
        elif data == 'beat':
            result_value = (
                '0x2', '',  # 心跳 在第一个子包
                '0x11', '123456',  # 终端序列号(SN) 字符串
            )
        elif data == 'select':
            result_value = (
                '0x4', self.generate_random_str(8),  # 心跳 在第一个子包
                #'0x10', '1',  # 终端厂商编号O  字符串 不得超过15字节 现在其实是定死了15字节来填
                #'0x11', '2',  # 终端序列号(SN)0 字符串 不得超过15字节 现在其实是定死了15字节来填
                #'0x12', '3',  # 终端版本号O  unicode    字符
                #'0x13', '4',  # 终端制式(LTE/2G等)O unicode的enum       字符
                #'0x14', '5',  # 终端IMEI号O 不得超过15字节 现在其实是定死了15字节来填     字符
                #'0x16', '6',  # 终端能力级别 unicode
                #'0x17', '7',  # 终端型号 unicode   上面已搞定 字符串
                #'0x20', '8',  # 终端无线网络信息 unicode  字符串
                #'0x24', 9,  # 业务流量统计 unicode  整数
                #'0x25', 10,  # 网管流量统计 unicode  整数a
                #'0x30', 11,  # 终端CPU占用率 整数
                #'0x31', 12,  # 终端内存使用率 整数
                #'0x32', '13',  # 流量异常信息 unicode
                #'0x35', 14,  # 终端温度 Unicode  整数
                #'0x36', 15,  # 信号强度弱 unicode 整数
                #'0x37', 16,  # 信噪比（信号质量） unicode 整数
            )
        elif data == 'act_report':  #
            result_value = (
                '0x3', '',  # 周期性上报数据id
                '0x11', '123456',  # 终端序列号(SN) 字符串
                '0x20', '12',  # 无线网络信息;当终端为多通道时,包含多个本CMD
                '0x24', 1,  # 业务流量统计 整数
                '0x25', 2,  # 网管流量统计 整数
                '0x30', 3,  # 终端CPU占用率 整数
                '0x31', 4,  # 终端内存使用率 整数
                '0x35', 5,  # 通讯模块温度 整数
                '0x36', -123,  # 信号强弱度 整数  改字符串
                '0x37', 10,  # 信噪比 整数

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
                #    '0x55', socket.inet_aton(self.get_ip()),  # 网管服务IP IP地址 4byte 暂时不管
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
        if hex(timestamp_mesc)[-1] =='L':
            timestamp_mesc_last4byte = long(hex(timestamp_mesc)[-9:-1], 16)
        else:
            timestamp_mesc_last4byte = long(hex(timestamp_mesc)[-8:], 16)
        print('warring')
        print(timestamp_mesc)
        print(timestamp_mesc_last4byte)
        print('warring')
        new_values = [int(header, 16), 1, timestamp_mesc_last4byte, pack_length_hight,
                      pack_length_low] + self.create_values(
            *now_data_values)
        print(new_values)
        a = struct.Struct('>BBLBB' + self.create_index(*now_data_values))
        result_nochecksum = a.pack(*new_values)
        checksum = self.ichecksum3(self.ichecksum_change((binascii.hexlify(result_nochecksum[6:]))))
        print('warring')
        print(binascii.hexlify(result_nochecksum[6:]))
        new_values.append(checksum)
        b = struct.Struct('>BBLBB' + self.create_index(*now_data_values) + 'B')
        result = b.pack(*new_values)

        print('Original values:', new_values)
        print('Format string :', b.format)
        print('Uses :', b.size, 'bytes')
        print('Packed Value :', binascii.hexlify(result))
        print(struct.unpack('>BBLBB' + self.create_index(*now_data_values) + 'B', result))
        print('Unpacked Type :', type(result), ' Value:', result)

        # print('ip')
        # print(repr(socket.inet_aton(self.get_ip())))
        # print(self.is_number(socket.inet_aton(self.get_ip())))
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
        send_data = self.build_msg(data, answer)
        import socket

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # print('sentojieguo')
        #send_data
        print('zhuyi')
        print(ip)
        print(port)
        s.sendto('ef015bab416a002b00050000005400222f7265736f75726365732f6d707675655f313533373935303337323538392e7a697063', (ip, port))
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
                s.sendto('ef015bab416a002b00050000005400222f7265736f75726365732f6d707675655f313533373935303337323538392e7a697063', (ip, port))
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
                res.append('11')
            elif i == '0x24':  # 业务流量统计
                res.append(11)
            elif i == '0x25':  # 网管流量统计
                res.append(11)
            elif i == '0x30':  # 终端CPU占用率
                res.append(20)
            elif i == '0x31':  # 终端内存使用率
                res.append(20)
            elif i == '0x32':  # 流量异常信息
                res.append('2')
            elif i == '0x35':  # 终端温度
                res.append(1)
            elif i == '0x36':  # 信号强度弱
                res.append(-1231)
            elif i == '0x37':  # 信噪比（信号质量）
                res.append(1)

        return tuple(res)

    def data_pick_cmdid(self, data, type=1):
        res = []
        # print(data)
        while data:
            # print(data)
            id = data[0:4]
            # print(id)
            pack_length = data[4:8]
            pack = data[8:8 + int(pack_length, 16) * 2]

            res.append(hex(int(id, 16)))
            if type == 1:
                if hex(int(id, 16)) == '0x55':
                    res.append(socket.inet_ntoa(pack.decode('hex')))
                else:
                    res.append(pack)
            else:
                pass

            data = data[8 + int(pack_length, 16) * 2:]

        return res

    def send_msg2(data, ip, port):
        import socket

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto('ef015bab416a002b00050000005400222f7265736f75726365732f6d707675655f313533373935303337323538392e7a697063',(ip, port))
        while True:
            # 接收来自客户端的数据,使用recvfrom
            data, addr = s.recvfrom(1024)
            print('Received from %s:%s.' % addr)
            print('heiheihei')
            '''
            if (binascii.b2a_hex(data)[16:])[:4] == '0001':
                print(u'服务器返回0x01')
            else:
                print(binascii.b2a_hex(data))
            '''
            print(binascii.b2a_hex(data))
            # print((binascii.b2a_hex(data)[16:])[:4])
            exit()

        return '1'




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

                # print(repr(data))
                data_all = binascii.b2a_hex(data)[16:-2]

                # print(binascii.unhexlify(data_side))
                # print(data_all)

                data_cmdid_array = self.data_pick_cmdid(data_all)

                if '0x4' in data_cmdid_array:
                    print('for 0x4')
                    print(self.create_answer(select_header, self.data_pick_cmdid(other_data, type=2)))
                    self.send_msg('return_select', '119.23.138.79', 5577,
                                  answer=self.create_answer(select_header, self.data_pick_cmdid(other_data, type=2)))
                elif '0x5' in data_cmdid_array:
                    print('config')
                    # print(binascii.hexlify(data))
                    # print(other_data)
                    # print(data_side)
                    y = self.data_pick_cmdid(data_side)

                    print(y)
                    # print(y)
                    # print()
                    # print(binascii.unhexlify(y))
                    t = 0
                    pick_new = []
                    new = {}
                    res_dict = dict(zip(y[::2], y[1::2]))
                    # print('res')
                    print(res_dict)

                    for x, y in res_dict.items():
                        if x in ('0x50', '0x51', '0x52', '0x53', '0x56'):
                            res_dict[x] = int(y, 16)
                        elif x in ('0x41', '0x42', '0x43'):
                            # res_dict[x] = binascii.unhexlify(y).decode('unicode-escape')
                            res_dict[x] = binascii.unhexlify(y).decode('unicode-escape')
                            print(binascii.unhexlify(y).decode('unicode-escape'))
                        elif x in ('0x54'):
                            # res_dict[x] = binascii.unhexlify(y).decode('unicode-escape')
                            res_dict[x] = binascii.unhexlify(y).decode('utf-8')
                            print(binascii.unhexlify(y).decode('utf-8'))
                        elif x in ('0x55'):
                            res_dict[x] = y.decode('utf-8')

                    print(res_dict)

                    # print("value:" + str(y))

                # print(pick_new)
                # print(res_dict)
                # print(repr(data))
                # print(addr[0])
                # print(addr[1])
                # print(data_cmdid_array)



        except KeyboardInterrupt:
            print()


    # , '127.0.0.1', 10000

u = udpclass()

str_data = ('0x1', '0x2', '0x3', '0x4','0x5', '0x10', '0x11', '0x12', '0x13', '0x14', '0x1f', '0x17', '0x20')
int_data = ('0x24', '0x25', '0x30', '0x31', '0x35', '0x37', '0x72', '0x36')
unicode_data = ('0x16', '0x32')
float_data = ('0x70', '0x71')

# listen()
# u.send_msg(u.build_msg('beat'),'127.0.0.1',5577) #自己
# u.data_get()

# u.data_get()

# u.send_msg(u.build_msg('select'),'118.25.225.194',5577) #15日停的服务器

# u.send_msg(u.build_msg('beat'), '119.23.138.79', 5577)  #任务服务器

# u.send_msg(u.build_msg('select'), '144.34.158.18', 5577) # 搬瓦工
# thread.start_new_thread(u.send_msg,(u.build_msg('select'),'144.34.158.18',5577))

timeout = 3 * 1  #



'''
def fun_timer(time):
    print('Hello Timer!')
    global timer

    timer = threading.Timer(time, fun_timer)
    u.send_msg("first_reg", '119.23.138.79', 5577)
    timer.start()

timer = threading.Timer(3, fun_timer(1*60*10))) #第一次
timer.start()


def fun_timer2(time):
    print('Hello Timer!')

    global timer
    timer = threading.Timer(time, fun_timer2)
    u.send_msg("beat", '119.23.138.79', 5577)
    timer.start()

timer2 = threading.Timer(5, fun_timer2(1*60*10))
timer2.start()


'''




#fun_timer()

#timer = threading.Timer(1, u.fun_timer)
#timer.start()



#t1 = threading.Thread(target=u.send_msg,args=("act_report",'144.34.158.18',5577))
#t1.start()


#t1 = threading.Thread(target=u.send_msg,args=("act_report",'144.34.158.18',5577))
#t1.start()


'''
while True:
    u.send_msg("first_reg", '119.23.138.79', 5577)
    time.sleep(1)
'''

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
