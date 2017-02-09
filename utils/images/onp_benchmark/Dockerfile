FROM fedora/nginx
MAINTAINER intel.com
ENV http_proxy $http_proxy
RUN echo "proxy=$http_proxy" >> /etc/dnf/dnf.conf
RUN dnf -y install iperf3 \
                   etcd \
           python3-pip \
           nmap \
           net-tools \
           htop \
           procps-ng\
           tcpdump\
           strace\
           httpd-tools\
           python3-ipython-console\
           && dnf clean all
RUN pip3 --proxy $http_proxy install python-etcd
COPY ./invoke_test.py /home/invoke_test.py
COPY ./10_mb_file /usr/share/nginx/html/10_mb_file
COPY ./2_mb_file /usr/share/nginx/html/2_mb_file
COPY ./4_mb_file /usr/share/nginx/html/4_mb_file
COPY ./nginx.conf /etc/nginx/nginx.conf
