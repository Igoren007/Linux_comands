#!/usr/bin/python3
import subprocess
import sys
import argparse

def run_ssh(host, command):
    cmd = ["ssh", "-q", host, command]
    return subprocess.Popen(cmd, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE)


def print_result_of_check(result, res_file):
    with open(res_file, "a") as f:
        for res in result.stdout:
            f.write("{}\n".format(res.strip().decode('utf-8')))


def print_service(service, res_file):
    with open(res_file, "a") as f:
        f.write("====> Check {} <====\n".format(service))
    print("Checking {}...".format(service))


def printing_decorator(func):
    def wrapper(*args, **kwargs):
        res = func(*args, **kwargs)
        print_result_of_check(res, res_file=result_file)
    return wrapper


@printing_decorator
def check_service(host, check_cmd):
    return run_ssh(host, check_cmd)


def is_host_available(host):
    available = False
    try:
        subprocess.check_output(['ssh', host, 'echo Success'])
        available = True
    except:
        print("Host is unavailable:\n  {}".format(sys.exc_info()[1]))
    return available

def parse_arguments():
    parser = argparse.ArgumentParser(usage='%(prog)s --hostname controller_hostname')
    parser.add_argument('--hostname', type=str, required=True)
    args = parser.parse_args()
    return args.hostname


## Needs check logs
# registry
# zabbix-proxy
# scribe
# fluentbit
# vector
# deploy-manager
# admin_interface (tail -f /var/log/container/admin_interface/stdout.log | grep -v " 200 " > res)
# kafka-proxy (kafka-proxy-safe)
# logcollector

## Needs check problems in Zabbix (pyzabbix)
# all

if __name__ == "__main__":
    controller = parse_arguments()
    location = controller.split('-')[0]
    result_file = "check_{}".format(controller)

    services = {
        'ldap': f"sudo docker exec ldap-server-{controller} /bin/bash -c 'healthcheck && slapcat | wc -l'",
        'bind': f"dig @127.0.0.1 -p 5353 -t SOA {location} && sudo docker exec bind9-{controller} /bin/bash -c '/usr/local/bin/healtcheck.sh'",
        'rabbitmq': f"sudo docker exec rabbitmq-{controller} /bin/bash -c 'rabbitmqctl cluster_status'",
        'hiera': "curl -s 'localhost:9090?key=scribe::log_cleaner&::service=tvbs'",
        'hwp': "curl -s 'localhost:9191?key=to_array.docker::run_instance::default_envs'",
        'servicecfg': "curl -s -Lv http://127.0.0.1:9192/hosts | jq .",
        'zookeeper': "echo stat | nc localhost 2181 && zookeepercli -servers localhost:2181 -c ls """,
        'http_proxy': f"sudo docker exec http_proxy-{controller} /bin/bash -c 'nginx -t' 2>&1",
        'apt_cacher': "nc -zv 127.0.0.1 3142 2>&1"
        #'logcollector': "sudo docker exec logcollector-{controller} /bin/bash -c '/usr/local/bin/healtcheck.sh'"
    }

    if is_host_available(controller):
        for k,v in services.items():
            print_service(k, result_file)
            check_service(controller, v)
   