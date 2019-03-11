FROM ubuntu:latest

# author
MAINTAINER Garvit Chawla(001859169)

#extra metadata
LABEL version="1.0"
LABEL description="Image with Dockerfile for Arp Spoofing Detection."
    
#RUN pip install --upgrade pip
RUN apt-get update
RUN apt install python3-pip -y
RUN apt install python-pip -y
RUN pip install scapy
RUN pip install oyaml
RUN pip install pyyaml
RUN mkdir /data
RUN chmod -R 777 /data

WORKDIR /data
#COPY dump.pcap .
#COPY second.py .
ADD second.py .

#CMD ["/bin/bash"]
ENTRYPOINT ["python", "./second.py"]
#CMD ["python", "/second.py"]
