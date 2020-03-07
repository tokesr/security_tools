import threading
import socketserver
import time

import argparse
import subprocess

from datetime import datetime
import csv

DEBUG_IS_ON = True

whitelist = []
method = ""
destination = ""
ips_to_handle = []
condition = threading.Condition()
redirected_file = ''
server_ip_addr = "192.168.0.20"


# TODO: check on the live system
# TODO: configure the code to be able to run on live system and execute commands
# TODO: ability to provide IP ranges, CIRD ranges as whitelist, ranges for ports
# TODO: if port is hit, turn on packet capturing


def debug_print(debug_string_array):
    """To show debug information"""
    if DEBUG_IS_ON:
        print(' '.join(debug_string_array[0:]))


def write_csv(arrey_of_values, output_file):
    '''
    for reusability
    :param arrey_of_values: the attributes of one record in a csv
    :param output_file: path of the output file
    :return: none
    '''
    with open(output_file, 'a+', newline='') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')
        debug_print(["Writing to csv" + str(arrey_of_values)])
        writer.writerow(arrey_of_values)


def redirect_handler():
    global condition
    global ips_to_handle
    global redirected_file
    debug_print(["Function: redirect handler"])
    while True:

        while ips_to_handle:
            already_handled = False
            destination_ip = ""
            client_ip, client_port = ips_to_handle.pop()
            commands = []
            with open(redirected_file, newline='') as csvfile:
                fieldnames = ['time', 'attacker_ip', 'detected_sourceport', 'redirection_target', 'used_method']
                reader = csv.DictReader(csvfile, delimiter=',', fieldnames=fieldnames)
                for row in reader:
                    if row['attacker_ip'] == client_ip:
                        already_handled = True
                        break

            if already_handled:
                continue

            if method == "block":
                commands.append("/sbin/iptables -A INPUT -s " + client_ip + " -j REJECT")
                destination_ip = ""

            elif method == "fix_redirect":
                try:
                    with open(destination, 'r+') as dest_file:
                        destination_ip = dest_file.read().splitlines()[0]
                except Exception as e:
                    print("type error: " + str(e))
                    break
                commands.append("/sbin/iptables -t nat -A PREROUTING -s " + client_ip
                                + " -j DNAT --to-destination " + str(destination_ip))
                commands.append("/sbin/iptables -t -nat -A POSTROUTING -d " + str(destination_ip) +
                                " -j SNAT --to-source " + server_ip_addr)
            else:
                print("failsafe_inside")
                while (not destination_ip):
                    # destination_ip = ""
                    try:
                        with open(destination, 'r+') as dest_file:
                            all_destination = dest_file.read().splitlines()
                        if all_destination:
                            destination_ip = all_destination[0]
                            commands.append("/sbin/iptables -t nat -A PREROUTING -s " + client_ip
                                            + " -j DNAT --to-destination " + str(destination_ip))
                            commands.append(
                                "/sbin/iptables -t -nat -A POSTROUTING -d " + str(destination_ip) + " -j SNAT"
                                + "--to-source " + server_ip_addr)

                        with open(destination, 'w+') as dest_file:
                            dest_file.write('\n'.join(all_destination[1:]))
                        if destination_ip == "":
                            if method == "failsafe_wait":
                                if not destination_ip:
                                    # if target is empty than we are waiting to the server to generate a new ip
                                    time.sleep(10)
                            if method == "failsafe_block":
                                if not destination_ip:
                                    command = "/sbin/iptables -A INPUT -s " + client_ip + " -j REJECT"
                                    print(command)
                                    break
                    except Exception as e:
                        print("type error: " + str(e))
                        break
            try:
                for com in commands:
                    subprocess.call(com, shell=True)
            except Exception as e:
                print("Subprocess call error: " + str(e))
            write_csv([datetime.timestamp(datetime.now()), client_ip,
                       client_port, destination_ip, method], redirected_file)

        with condition:
            # if there is nothing to handle than it waits until it is notified by redirect
            condition.wait()


def redirect(client_ip, client_port):
    # started by multiple threads, multiple instances can exist
    global whitelist
    global ips_to_handle
    global condition

    debug_print(["Function: redirect", client_ip, client_port])

    if client_ip in whitelist:
        debug_print(["Whitelisted"])
        return
    # if redirected
    for ip_port in ips_to_handle:
        # there can be one element in the redirect_handler which is not stored in the list but in the client_ip variable
        # in redirect_handler function we are going to check whether an ip had been handled and if it was we are going
        # to throw it out, so no duplicate element is going to be handled
        if client_ip == ip_port[0]:
            debug_print(["Already handled ip"])
            return
    else:
        ips_to_handle.append([client_ip, client_port])
        debug_print(["Appended to the list"])
        with condition:
            condition.notify()


class ThreadedTestRequestHandler(socketserver.BaseRequestHandler):
    # there can be multiple instance of this class (multiple threads)
    def handle(self):
        # for testing
        # not going to be called if verify_request returns False
        data = self.request.recv(1024)
        cur_thread = threading.currentThread()
        response = str.encode(cur_thread.getName())
        self.request.send(response)
        return


class ThreadedTestServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    # there is only one instance of this class, 1 Server (1 thread)
    def verify_request(self, request, client_address):
        c_ip, c_port = client_address
        redirect(c_ip, c_port)
        debug_print(["Verify request:", c_ip, c_port])
        return False


def ThreadedStartServer(host, port):
    server = ThreadedTestServer((host, port), ThreadedTestRequestHandler)
    s_ip, s_port = server.server_address  # find out what port we were given
    debug_print(["ThreadedStartServer"])
    t = threading.Thread(target=server.serve_forever)
    t.setDaemon(False)  # don't hang on exit
    t.start()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    meg_Whitelist = parser.add_mutually_exclusive_group()
    meg_Redirected = parser.add_mutually_exclusive_group(required=True)
    meg_Port = parser.add_mutually_exclusive_group(required=True)
    meg_Destination = parser.add_mutually_exclusive_group(required=False)

    meg_Whitelist.add_argument("-w", "--whitelist", action='store', nargs=1, help="A list of whitelisted systems")

    meg_Redirected.add_argument("-r", "--redirected", action='store',
                                help="List of already handled IP addresses in csv format", nargs=1)

    meg_Port.add_argument("-p", "--port", action='store', help="Port to use as honeyport", nargs=1)

    meg_Destination.add_argument("-d", "--destination", action='store', help="List of destination IPs. "
                                                                             "Separated with new line. "
                                                                             "Without it the tool just blocks.",
                                 nargs=1)

    parser.add_argument("-m", "--method", action='store', nargs='?', default='block', const='block',
                        choices=('block', 'failsafe_block', 'failsafe_wait', 'fix_redirect'),
                        help="Method block will block the IP. Failsafe block redirects if there is a target and blocks "
                             "if no target in the file. failsafe_wait redirects if there is a target and waits in a loop"
                             "if there is no target in the file. fix_redirects uses the same destination for all"
                             "redirection")

    parser.add_argument("--ip", action='store', nargs=1, help="IP address of the server", required=True)

    args = parser.parse_args()

    whitelist = []
    port = []
    destination = []
    # destination_file = [args.D[0]]

    # 1: method
    method = args.method

    # 2: Whitelist
    if args.whitelist is None:
        # no whitelist
        whitelist = []
    else:
        # reading whitelist entries into a list
        with open(args.whitelist[0]) as f:
            whitelist = f.read().splitlines()

    # 3: Redirected
    redirected_file = args.redirected[0]

    # 4: Port
    with open(args.port[0]) as f:
        port = f.read().splitlines()

    # 5:  Destination
    # reading on the fly
    if method != "block":
        if args.destination is None:
            # if no file with dest ips in it has been provided than the mode is going to be "block"
            method = "block"
        else:
            destination = args.destination[0]

    debug_print([method, redirected_file, destination])
    debug_print(port)
    debug_print(whitelist)

    host = args.ip[0]
    debug_print(["Host:", host])
    for hport in port:
        ThreadedStartServer(host, int(hport))
        debug_print(["Ports are opening"])

    # handling redirection in a single specific thread
    redirect_handler_thread = threading.Thread(target=redirect_handler)
    redirect_handler_thread.setDaemon(False)  # don't hang on exit
    redirect_handler_thread.start()
