"""

Fabric script to deploy Docker to my Trinity cluster,
try some inter-container/cross-host connectivity,
and deploy Solr.

Tested with Docker 1.12.1, Ubuntu 16.04, etcd 3.0.7.

Note:
- no attempt is made to secure ports for etcd or solr
- there is no proxy for external access
- ZooKeeper is a single host
"""
from fabric.api import env, run, sudo, execute, settings, roles
from fabric.contrib.files import exists, append, put, upload_template
from fabric.network import disconnect_all
from fabric.decorators import parallel
from fabric.context_managers import shell_env
import time, os, re, string, random, StringIO

# define cluster IPs
env.cluster_address = {
    'trinity10': '192.168.77.10',
    'trinity20': '192.168.77.20',
    'trinity30': '192.168.77.30'
}

env.roledefs = {
    'all': sorted(env.cluster_address.keys()),
    'etcd': sorted(env.cluster_address.keys()),
    'docker_cli': ['trinity10'],
    'alpha_dockerhost': ['trinity10'],
    'beta_dockerhost': ['trinity20'],
    'zookeeperdockerhost': ['trinity10'],
    'solr1dockerhost': ['trinity10'],
    'solr2dockerhost': ['trinity20'],
    'solrclientdockerhost': ['trinity30'],
}
env.etcd_host = "trinity10"
env.etcd_cluster_token = "etcd-cluster-2123"
env.user = "mak"

SOLR_IMAGE = 'solr:latest'
ZOOKEEPER_IMAGE = 'jplock/zookeeper'
ZOOKEEPER_NAME = 'zookeeper1'

BUSYBOX_IMAGE = 'busybox:latest'
UBUNTU_IMAGE = 'ubuntu:16.04'
ETCD_URL = "https://github.com/coreos/etcd/releases/download/v3.0.7/etcd-v3.0.7-linux-amd64.tar.gz"
SOLR_COLLECTION = "sample"

NET_ALPHA_BETA = "netalphabeta"
NET_SOLR = "netsolr"

TEST_ALPHA = "alpha"
TEST_BETA = "beta"

env.etcd_client_port = 2379
env.etcd_peer_port = 7001

env.docker_port = 2375

TEMPLATES = 'templates'

def get_docker_host_for_role(role):
    """ get the docker host for a container role """
    return env.roledefs[role][0]


@roles('all')
def info():
    """ Show machine information """
    run('cat /etc/lsb-release')
    run('uname -a')


@roles('all')
def ping():
    """ Ping all the hosts in the cluster from this host """
    for name in sorted(env.cluster_address.keys()):
        run("ping -c 3 {}".format(env.cluster_address[name]))


@roles('all')
def copy_ssh_key(ssh_pub_key="~/.ssh/id_dsa.pub", user=env.user):
    """ Copy the local ssh key to the cluster machines """
    ssh_pub_key_path = os.path.expanduser(ssh_pub_key)
    remote = "tmpkey.pem"
    put(ssh_pub_key_path, remote)
    sudo("mkdir -p ~{}/.ssh".format(user))
    sudo("cat ~{}/{} >> ~{}/.ssh/authorized_keys".format(user, remote, user))
    sudo("chown {}:{} ~{}/.ssh".format(user, user, user))
    sudo("chown {}:{} ~{}/.ssh/authorized_keys".format(user, user, user))
    sudo("rm ~{}/{}".format(user, remote))

    #sudo("mkdir -p ~root/.ssh")
    #sudo("cat ~{}/.ssh/authorized_keys >> ~root/.ssh/authorized_keys".format(user, remote, user))
    #sudo("chown root:root ~root/.ssh/authorized_keys")


@roles('all')
def setup_sudoers():
    """ Add the user to sudoers, allowing password-less sudo """
    append("/etc/sudoers", "{0}  ALL=(ALL) NOPASSWD:ALL".format(env.user), use_sudo=True)


@roles('all')
def install_prerequisites():
    """ install OS pre-requisites """
    sudo("modprobe ip6_tables")
    append("/etc/modules", "ip6_tables", use_sudo=True)
    sudo("modprobe xt_set")
    append("/etc/modules", "xt_set", use_sudo=True)
    sudo("sysctl -w net.ipv6.conf.all.forwarding=1")
    sudo("echo net.ipv6.conf.all.forwarding=1 > /etc/sysctl.d/60-ipv6-forwarding.conf")
    sudo("apt-get install --yes --quiet unzip curl git")


@roles('all')
def install_docker():
    """ install docker """
    if exists('/usr/bin/docker'):
        return

    # per http://docs.docker.com/engine/installation/ubuntulinux/
    sudo("apt-get --yes --quiet install apt-transport-https ca-certificates")
    sudo("apt-key adv --keyserver hkp://pgp.mit.edu:80 --recv-keys 58118E89F3A912897C070ADBF76221572C52609D")

    distrib_codename = run("grep DISTRIB_CODENAME /etc/lsb-release |sed 's/.*=//'")
    put(StringIO.StringIO('deb https://apt.dockerproject.org/repo ubuntu-{} main\n'.format(distrib_codename)),
        '/etc/apt/sources.list.d/docker.list', use_sudo=True)
    sudo('apt-get --yes --quiet update')
    sudo('apt-cache policy docker-engine')
    sudo('apt-get --yes --quiet install docker-engine')
    sudo('adduser {} docker'.format(env.user))
    sudo('sudo service docker restart')
    time.sleep(5)
    disconnect_all() # so we reconnect and to group applies.
    run("docker version")


@roles('all')
def docker_version():
    """ display docker version and status """
    run('docker version')
    run('systemctl  status -l --no-pager docker')


def get_addressv4_address():
    """ utility method to return the ip address for the current host """
    ipv4_address = run("ip -4 addr list $(ip route list|grep default|sed 's/.*dev //') | "
                       "grep inet | awk '{print $2}' | sed -e 's,/.*,,'")
    if not re.match(r'^\d+\.\d+\.\d+\.\d+', ipv4_address):
        raise Exception("cannot get IP address")
    return ipv4_address


@roles('etcd')
@parallel
def install_etcd():
    """ install etcd """
    # See https://github.com/coreos/etcd/blob/master/Documentation/clustering.md#static
    my_name = "etcd-{}".format(env.host)
    initial_cluster_members = []
    for name in sorted(env.cluster_address.keys()):
        ipv4_address = env.cluster_address[name]
        initial_cluster_members.append("etcd-{}=http://{}:{}".format(name, ipv4_address, env.etcd_peer_port))
    initial_cluster = ",".join(initial_cluster_members)

    etc_tgz = ETCD_URL.rpartition('/')[2]
    etc_dir = etc_tgz.replace('.tar.gz', '')
    if not exists(etc_tgz):
        run("wget -nv {}".format(ETCD_URL))
    if not exists(etc_dir):
        run("tar xvzf {}".format(etc_tgz))
    etcd_home = run("cd {}; /bin/pwd".format(etc_dir))
    ipv4_address = get_addressv4_address()
    ctx = {
        "name": my_name,
        "etcd_home": etcd_home,
        "advertise_client_urls": 'http://{}:{}'.format(ipv4_address, env.etcd_client_port),
        "listen_client_urls": 'http://0.0.0.0:{}'.format(env.etcd_client_port),
        "advertise_peer_urls": 'http://{}:{}'.format(ipv4_address, env.etcd_peer_port),
        "etcd_peer_port": env.etcd_peer_port,
        "initial_cluster": initial_cluster
    }
    upload_template(filename='etcd.service', destination='/etc/systemd/system/etcd.service',
                    template_dir=TEMPLATES, context=ctx, use_sudo=True, use_jinja=True,
                    keep_trailing_newline=True)

@roles('etcd')
def start_etcd():
    """ start etcd """
    sudo("systemctl daemon-reload")
    sudo("systemctl enable etcd")
    sudo("systemctl start etcd")
    time.sleep(2)
    sudo("systemctl is-active etcd.service")

@roles('etcd')
def check_etcd():
    """ check etcd: on each etcd host, talk to the local etcd server """
    run("curl -L http://{}:{}/version".format("localhost", env.etcd_client_port))
    run("curl -L http://{}:{}/v2/machines".format("localhost", env.etcd_client_port))


@roles('etcd')
def install_docker_config():
    """ configure Docker to use our etcd cluster """
    initial_cluster_members = []
    for name in sorted(env.cluster_address.keys()):
        ipv4_address = env.cluster_address[name]
        initial_cluster_members.append("{}:{}".format(ipv4_address, env.etcd_client_port))
    initial_cluster = ",".join(initial_cluster_members)

    # configure docker daemon under systemd.
    # Note this also changes the -H to listen on tcp.
    # See https://docs.docker.com/engine/admin/systemd/#/custom-docker-daemon-options
    # The default service is in /lib/systemd/system/docker.service
    ctx = {
        "listen": "{}:{}".format(env.cluster_address[env.host], env.docker_port),
        "cluster_store": "etcd://{}".format(initial_cluster),
        "cluster_advertise": "{}:{}".format(env.cluster_address[env.host], env.docker_port)

    }
    sudo("mkdir -p /etc/systemd/system/docker.service.d")
    upload_template(filename='docker-etcd.conf', destination='/etc/systemd/system/docker.service.d/',
                    template_dir=TEMPLATES, context=ctx, use_sudo=True, use_jinja=True,
                    keep_trailing_newline=True)


    sudo("systemctl daemon-reload")
    sudo("systemctl restart docker")
    time.sleep(5)
    sudo("systemctl is-active docker.service")

@roles('all')
def docker_clean():
    """ remove containers that have exited """
    run("docker rm `docker ps --no-trunc --all --quiet --filter=status=exited`")


@roles('docker_cli')
def create_networks():
    """ create two example networks """
    etcd_address = env.cluster_address[env.roledefs['etcd'][0]]
    with shell_env(ETCD_AUTHORITY='{}:{}'.format(etcd_address, env.etcd_client_port)):
        run("docker network create --driver=overlay --subnet 192.168.91.0/24 " + NET_ALPHA_BETA)
        run("docker network create --driver=overlay --subnet 192.168.89.0/24 " + NET_SOLR)
        run("docker network ls")

@roles('docker_cli')
def create_test_container_alpha():
    """ create first test container """
    with settings(host_string=get_docker_host_for_role('alpha_dockerhost')):
        create_test_container(TEST_ALPHA)


@roles('docker_cli')
def create_test_container_beta():
    """ create second test container """
    with settings(host_string=get_docker_host_for_role('beta_dockerhost')):
        create_test_container(TEST_BETA)


# http://stackoverflow.com/questions/2257441/random-string-generation-with-upper-case-letters-and-digits-in-python
def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    """ return a random identifier """
    return ''.join(random.choice(chars) for _ in range(size))


def create_test_container(name='', image=BUSYBOX_IMAGE):
    """ create a test container """
    container_name = 'c-' + name
    run("docker pull {}".format(image), pty=False)
    container_id = run("docker run --net {} --name {} --hostname={}.{} -tid {}".format(
        NET_ALPHA_BETA, container_name, container_name, NET_ALPHA_BETA, image))
    inspect_container(container_id)


def inspect_container(container_name_or_id=''):
    """ e.g. fab --host trinity10 inspect_container:container_name_or_id=... """
    container_id = run("docker inspect --format '{{.Id}}' " + container_name_or_id)
    container_name = run("docker inspect --format '{{.Name}}' " + container_name_or_id)
    if container_name[0] == '/':
        container_name = container_name[1:]
    net = run("docker inspect --format '{{ .HostConfig.NetworkMode }}' " + container_id)
    ip_address = run("docker inspect --format '{{ .NetworkSettings.Networks." + net + ".IPAddress }}' " + container_id)
    print "container_id={}, container_name={}, ip_address={}".format(
        container_id, container_name, ip_address)
    run("docker exec -i {} hostname".format(container_id))

    with settings(warn_only=True):
        run("docker exec -i {} ls -l /sys/devices/virtual/net/".format(container_id))
        run("docker exec -i {} ip link list".format(container_id))
        run("docker exec -i {} ip addr list".format(container_id))
        run("docker exec -i {} ip route list".format(container_id))


@roles('docker_cli')
def ping_test_containers():
    """ see if containers A and B can ping eachother """
    alpha_name = 'c-' + TEST_ALPHA
    beta_name = 'c-' + TEST_BETA
    with settings(host_string=get_docker_host_for_role('alpha_dockerhost')):
        run("docker exec -i {} ping -c 1 {}.{}".format(alpha_name, beta_name, NET_ALPHA_BETA))
    with settings(host_string=get_docker_host_for_role('beta_dockerhost')):
        run("docker exec -i {} ping -c 1 {}.{}".format(beta_name, alpha_name, NET_ALPHA_BETA))


@roles('docker_cli')
def create_test_zookeeper():
    """ create zookeeper container """
    run("docker pull {}".format(ZOOKEEPER_IMAGE), pty=False)
    with settings(host_string=get_docker_host_for_role('zookeeperdockerhost')):
        container_id = run("docker run --net {} --name {} --hostname={}.{} -tid {}".format(
            NET_SOLR, ZOOKEEPER_NAME, ZOOKEEPER_NAME, NET_SOLR, ZOOKEEPER_IMAGE))
    time.sleep(3)
    inspect_container(ZOOKEEPER_NAME)


@roles('all')
@parallel
def pull_docker_images():
    """ pull images we'll use """
    for image in [SOLR_IMAGE, ZOOKEEPER_IMAGE, BUSYBOX_IMAGE, UBUNTU_IMAGE]:
        run("docker pull {}".format(image), pty=False)


@roles('docker_cli')
def create_test_solr1():
    """ create a first Solr container """
    create_test_solr("solr1", get_docker_host_for_role('solr1dockerhost'), '192.168.89.11')


@roles('docker_cli')
def create_test_solr2():
    """ create a second Solr container """
    create_test_solr("solr2", get_docker_host_for_role('solr2dockerhost'), '192.168.89.12')


def create_test_solr(name, docker_host, ip_address):
    """ create a container running solr """
    run("docker pull {}".format(SOLR_IMAGE), pty=False)
    zookeeper_address = run("docker inspect --format '{{ .NetworkSettings.Networks." + NET_SOLR + ".IPAddress }}' " + ZOOKEEPER_NAME)
    with settings(host_string=docker_host):
        container_id = run("docker run --net {} --name {} --ip={} --hostname={}.{} --label=solr -p 8983 -tid {} bash -c '/opt/solr/bin/solr start -f -z {}:2181'".format(
        NET_SOLR, name, ip_address, name, NET_SOLR, SOLR_IMAGE, zookeeper_address))

        time.sleep(5) # does this help "Error: No such image or container:"?
        inspect_container(name)

        time.sleep(15)

        run("docker logs {}".format(container_id))


@roles('docker_cli')
def create_test_solrclient():
    """ talk to both solr nodes from a container """
    # TODO: why does this now take 5s?
    name = 'solrclient-' + id_generator()
    run("docker run --net {} --name {} --hostname {}.{} -i {} curl -sSL http://solr1.{}:8983/".format(NET_SOLR, name, name, NET_SOLR, SOLR_IMAGE, NET_SOLR))
    name = 'solrclient-' + id_generator()
    run("docker run --net {} --name {} --hostname {}.{} -i {} curl -sSL http://solr2.{}:8983/".format(NET_SOLR, name, name, NET_SOLR, SOLR_IMAGE, NET_SOLR))


@roles('docker_cli')
def solr_collection():
    """ create collection in solr """
    run("docker exec -i -t solr1 /opt/solr/bin/solr create_collection -c {} -shards 2 -p 8983 | tr -d '\r' | grep -v '^$'".format(SOLR_COLLECTION))


@roles('docker_cli')
def solr_data():
    """ load test data into solr """
    run("docker exec -it --user=solr solr1 bin/post -c {} /opt/solr/example/exampledocs/manufacturers.xml | tr -d '\r' | grep -v '^$'".format(SOLR_COLLECTION))


@roles('docker_cli')
def solr_query():
    """ query solr """
    print "demonstrate you can query either server and get a response:"
    with settings(host_string=get_docker_host_for_role('solr1dockerhost')):
        response = run("docker exec -it --user=solr solr1 "
            "curl 'http://localhost:8983/solr/{}/select?q=maxtor&indent=true' | tr -d '\r' | grep -v '^$'".format(SOLR_COLLECTION))
        if 'numFound="1"' in response:
            print "got one found, as expected"
        else:
            print "none found!"
    with settings(host_string=get_docker_host_for_role('solr2dockerhost')):
        response = run("docker exec -it --user=solr solr2 "
            "curl 'http://localhost:8983/solr/{}/select?q=maxtor&indent=true' | tr -d '\r' | grep -v '^$'".format(SOLR_COLLECTION))
        if 'numFound="1"' in response:
            print "got one found, as expected"
        else:
            print "none found!"

    print "demonstrate the response only comes from a single shard:"
    query = 'maxtor'
    url1 = 'http://localhost:8983/solr/{}/select?q={}&indent=true&shards=localhost:8983/solr/{}_{}_replica1'.format(query, SOLR_COLLECTION, SOLR_COLLECTION, 'shard1')
    response1 = run("docker exec -it --user=solr solr1 curl '{}' | tr -d '\r' | grep -v '^$'".format(url1))
    url2 = 'http://localhost:8983/solr/{}/select?q={}&indent=true&shards=localhost:8983/solr/{}_{}_replica1'.format(query, SOLR_COLLECTION, SOLR_COLLECTION, 'shard2')
    response2 = run("docker exec -it --user=solr solr1 curl '{}' | tr -d '\r' | grep -v '^$' ".format(url2))
    if (('numFound="1"' in response1) or ('numFound="1"' in response2)) and not ('numFound="1"' in response1 and 'numFound="1"' in response2):
        print "found only in one shard, as expected"
    else:
        print "ehr?!"


@roles('all')
def docker_ps():
    """ run docker ps """
    run('docker ps')


def install():
    """ install the cluster """
    # I've not run this in a single go; but it illustrates the order
    execute(info)
    execute(copy_ssh_key)
    execute(setup_sudoers)
    execute(install_prerequisites)
    execute(install_docker)
    execute(docker_version)
    execute(install_etcd)
    execute(start_etcd)
    execute(check_etcd)
    execute(install_docker_config)

    execute(create_networks)

    execute(pull_docker_images)

    execute(create_test_container_alpha)
    execute(create_test_container_beta)
    execute(ping_test_containers)

    execute(create_test_zookeeper)
    execute(create_test_solr1)
    execute(create_test_solr2)
    execute(docker_ps)

    execute(create_test_solrclient)
    execute(solr_collection)
    execute(solr_data)
    execute(solr_query)
