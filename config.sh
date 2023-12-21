#!/bin/bash

#-----------install python3-------------------------#
sudo add-apt-repository ppa:ubuntu-toolchain-r/ppa
sudo apt install python3.7
sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.6 1
sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.7 2
sudo update-alternatives --config python3
#--------------------------------------------------#
sudo apt-get update
sudo apt-get install git
sudo apt install python-minimal
sudo apt-get install openjdk-8-jdk
sudo apt-get install python-setuptools python-dev
sudo apt-get install graphviz libgraphviz-dev graphviz-dev
sudo apt-get install pkg-config
sudo apt-get install unzip
sudo apt-get install p7zip-full
sudo apt-get -y install python-pip
sudo apt-get -y install python3-pip
pip install python-igraph==0.8.3
pip3 install xlrd
pip3 install gensim==3.8.3 (3.4.0)
pip3 install imbalanced-learn==0.4.0
pip3 install scikit-learn==1.3.2
pip3 install tensorflow==2.8.0 (1.6.0)
pip3 install keras==2.8.0
