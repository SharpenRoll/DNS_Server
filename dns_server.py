import socket
import struct


RELAY_FILE = "dnsrelay.txt"
SERVER_IP = "10.201.8.81"
SERVER_PORT = 53
DNS_MESSAGE_LENGTH = 512
FORWARD_DNS_SERVER = ("10.3.9.5", 53)


class DNSBuffer:
    def __init__(self, dns_message=b''):
        self.buffer = dns_message

    def get(self, length):
        data = self.buffer[0:length]
        self.buffer = self.buffer[length:]
        return data

    def get_header(self):
        dns_header = self.get(12)
        (ID, Flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT) = struct.unpack("!HHHHHH", dns_header)
        return DNSHeader(ID, Flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)

    def get_question(self):
        q_name = ''
        first_dot = True
        while self.buffer[0] != 0:
            label_length = self.buffer[0]
            self.get(1)
            if first_dot:
                first_dot = False
            else:
                q_name = q_name + '.'
            q_name = q_name + self.get(label_length).decode('ascii')
        self.get(1)
        q_type, q_class = struct.unpack("!HH", self.get(4))
        return DNSQuestion(q_name, q_type, q_class)

    def get_resource(self):
        return

    def put(self, data):
        self.buffer = self.buffer + data


class DNSHeader:
    def __init__(self, id=None, flags=None, qd_count=0, an_count=0, ns_count=0, ar_count=0):
        self.ID = id
        self.Flags = flags
        self.QDCOUNT = qd_count
        self.ANCOUNT = an_count
        self.NSCOUNT = ns_count
        self.ARCOUNT = ar_count

        self.QR = (flags & 0x8000) >> 15
        self.Opcode = (flags & 0x7800) >> 11
        self.AA = (flags & 0x0400) >> 10
        self.TC = (flags & 0x0200) >> 9
        self.RD = (flags & 0x0100) >> 8
        self.RA = (flags & 0x0080) >> 7
        self.Z = (flags & 0x0070) >> 4
        self.RCODE = (flags & 0x000F)

    def build(self):
        buffer = struct.pack("!HHHHHH", self.ID, self.Flags, self.QDCOUNT, self.ANCOUNT, self.NSCOUNT, self.ARCOUNT)
        return buffer


class DNSQuestion:
    def __init__(self, q_name, q_type=1, q_class=1):
        self.QNAME = q_name
        self.QTYPE = q_type
        self.QCLASS = q_class

    def build(self):
        buffer = b''
        labels = self.QNAME.split('.')
        for label in labels:
            buffer = buffer + struct.pack("!B", len(label))
            buffer = buffer + label.encode("ascii")
        buffer = buffer + b'\x00'
        buffer = buffer + struct.pack("!HH", self.QTYPE, self.QCLASS)
        return buffer


class DNSResource:
    def __init__(self, r_name, r_type, r_class, ttl, rd_length, r_data):
        self.NAME = r_name
        self.TYPE = r_type
        self.CLASS = r_class
        self.TTL = ttl
        self.RDLENGTH = rd_length
        self.RDATA = r_data

    @staticmethod
    def build(ip):
        buffer = b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3C\x00\x04'
        labels = ip.split('.')
        for label in labels:
            buffer += struct.pack("!B", int(label))
        return buffer


class DNSMessage:
    def __init__(self, header, question, answer, authority, additional):
        self.Header = header
        self.Question = question
        self.Answer = answer
        self.Authority = authority
        self.Additional = additional

    @classmethod
    def from_bytes(cls, bytes_message):
        buffer = DNSBuffer(bytes_message)
        # HEADER
        header = buffer.get_header()
        # QUESTION
        question = []
        for _ in range(header.QDCOUNT):
            question.append(buffer.get_question())
        # ANSWER
        answer = []
        # AUTHORITY
        authority = []
        # ADDITIONAL
        additional = []

        return cls(header, question, answer, authority, additional)

    def build(self):
        buffer = b''
        buffer += self.Header.build()
        for i in range(self.Header.QDCOUNT):
            buffer += self.Question[i].build()
        for i in range(self.Header.ANCOUNT):
            buffer += self.Answer[i].build()
        return buffer


# 读入文件，建立初始映射表
def read_relay(relay_file):
    # relay_file: 文件名
    relay = {}
    with open(relay_file) as file_obj:
        for line in file_obj:
            if line.isspace():
                continue
            sp = line.split()
            # print(sp)
            relay[str(sp[1])] = sp[0]
    print("Load Complete")
    return relay


# 转发关系映射表和循环ID计数
forward_list = {}
current_id = 0


# 循环生成0~65535的ID
def generate_id():
    global current_id
    new_id = current_id
    current_id = (current_id + 1) % 65536
    return new_id


# 记录并替换请求包的ID，然后向远端服务器转发查询请求
def forward_query(dm, addr):
    new_id = generate_id()
    forward_list[new_id] = (addr, dm.Header.ID)
    header = DNSHeader(new_id, dm.Header.Flags, dm.Header.QDCOUNT, dm.Header.ANCOUNT, dm.Header.NSCOUNT, dm.Header.ARCOUNT).build()
    question = dm.Question[0].build()
    answer = header + question
    sock.sendto(answer, FORWARD_DNS_SERVER)

# 将远端服务器的响应替换回原ID，并发回原请求者
def forward_response(dns_message, ID, addr):
    response = struct.pack("!H", ID) + dns_message[2:]
    sock.sendto(response, addr)


# 从映射表中获取响应信息并返回
def instant_response(dm, ip, addr, is_NULL=False):
    # Flags最后4位(rcode)为3
    flag = (34179 if is_NULL else 34176)
    header = DNSHeader(dm.Header.ID, flag, 1, 1, 0, 0).build()
    question = dm.Question[0].build()
    answer = DNSResource.build(ip)
    response = header + question + answer
    print(response)
    sock.sendto(response, addr)
    print("OK")


if __name__ == '__main__':

    # 建立初始映射表
    book = read_relay(RELAY_FILE)
    # 监听53端口
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SERVER_IP, SERVER_PORT))

    while True:
        # 接收并解析DNS Message
        dns_message, addr = sock.recvfrom(DNS_MESSAGE_LENGTH)
        dm = DNSMessage.from_bytes(dns_message)
        '''
        print(dm.Question[0].QNAME)
        print(dm.Question[0].QTYPE)
        print(dm.Question[0].QCLASS)
        '''
        qr = dm.Header.QR
        # query
        if qr == 0:

            op = dm.Header.Opcode
            # standard query (QUERY)
            if op == 0:
                # 原始映射表中存在查询的域名
                if dm.Question[0].QNAME in book:
                    ip = book[dm.Question[0].QNAME]
                    # 如果文件中域名对应IP为"0.0.0.0"，则Flags最后4位(rcode)为3
                    is_NULL = ip == "0.0.0.0"
                    instant_response(dm, book[dm.Question[0].QNAME], addr, is_NULL)
                # 不存在，向远端服务器转发
                else:
                    forward_query(dm, addr)
            # 除了基本查询之外的OPCODE暂未做处理
            # inverse query (IQUERY)
            elif op == 1:
                pass
            # server status request (STATUS)
            elif op == 2:
                pass
            # reserved
            else:
                pass

        # response
        else:
            if dm.Header.ID in forward_list:
                addr, ID = forward_list[dm.Header.ID]
                forward_list.pop(dm.Header.ID)
                forward_response(dns_message, ID, addr)

        #print("-----------")

