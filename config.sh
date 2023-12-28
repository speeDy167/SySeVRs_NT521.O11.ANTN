#!/bin/bash

# Skip this if you already user ubuntu18.04 
#-----------install python3 and set to use-------------------------#
sudo add-apt-repository ppa:ubuntu-toolchain-r/ppa
sudo apt install python3.7
sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.6 1
sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.7 2
sudo update-alternatives --config python3
#--------------------------------------------------#
# =========================== #
# ==== setup environment ==== #
# =========================== #
sudo apt-get -y update
sudo apt-get install open-vm-tools-desktop open-vm-tools
sudo apt-get install git

# Set up Joern,Neo4j,Ant
git clone https://github.com/speeDy167/SySeVRs_NT521.O11.ANTN.git
echo 'export PATH="$HOME/Tools/joern-0.3.1/bin:$PATH"' >> ~/.bashrc
echo 'export PATH="$HOME/Tools/apache-ant-1.9.14/bin:$PATH"' >> ~/.bashrc
echo 'export PATH="$HOME/Tools/neo4j/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# Set up required dependencies
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
# You can install gensim==3.4.0 or tensorflow==1.6.0 its depended on your python version
pip3 install gensim==3.8.3
pip3 install imbalanced-learn==0.4.0
pip3 install scikit-learn==1.3.2
pip3 install tensorflow==2.8.0
pip3 install keras==2.8.0
