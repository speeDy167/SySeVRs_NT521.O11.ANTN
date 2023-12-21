#!/bin/bash

# install dependencies
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

# =========================== #
# ==== setup environment ==== #
# =========================== #

# adding environment
# clone my resposity
echo 'export PATH="$HOME/PSySeVRs/Tools/joern-0.3.1/bin:$PATH"' >> ~/.bashrc
echo 'export PATH="$HOME/PSySeVRs/Tools/apache-ant-1.9.14/bin:$PATH"' >> ~/.bashrc
echo 'export PATH="$HOME/PSySeVRs/Tools/neo4j/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# set up neo4j
# go to $HOME/PSySeVRs/Tools/neo4j/conf
# change in neo4j-server.properties
# org.neo4j.server.database.location=$HOME/Tools/joern-0.3.1/.joernIndex
sudo neo4j start-no-wait
# go to localhost://7474 to check if neo4j start
sudo neo4j stop

# set up joern
cd $HOME/PSySeVRs/Tools/joern-0.3.1
ant
ant tools

# set up py2neo
cd $HOME/PSySeVRs/Tools/py2neo-py2neo-2.0
python setup.py install --user

# set up pyjoern
cd $HOME/PSySeVRs/Tools/python-joern-0.3.1
python setup.py install --user

# install other dependencies
pip3 install xlrd
pip3 install gensim==3.8.3 (3.4.0)
pip3 install imbalanced-learn==0.4.0
pip3 install scikit-learn==1.3.2
pip3 install tensorflow==2.8.0 (1.6.0)
pip3 install keras==2.8.0

# ========================== #
# ==== prepare raw data ==== #
# ========================== #
# (i'm using NVD, e.g., SARD)
java -jar /path/joern-0.3.1/bin/joern.jar /home/test/source2slice/NVD
# ===================================== #
# ==== process data: source2slice/ ==== #
# ===================================== #

# (on screen A: start neo4j service)
neo4j start-no-wait

# (on screen B: start processing)
python ./get_cfg_relation.py # this outputs to src/source2slice/cfg_db/
python ./complete_PDG.py # this outputs to src/source2slice/pdg_db/
python ./access_db_operate.py # this outputs to src/source2slice/dict_call2cfgNodeID_funcID/
python ./points_get.py # this outputs to sensifunc_slice_points.pkl, pointuse_slice_points.pkl, arrayuse_slice_points.pkl, integeroverflow_slice_points_new.pkl
python ./extract_df.py
python ./dealfile.py
python ./make_label_nvd.py # create label_data in C/
python ./data_preprocess.py # create in slice_label folder

# ======================================== #
# ==== process data: data_preprocess/ ==== #
# ======================================== #
python3 ./create_hash.py
python3 ./delete_list.py
python3 ./process_dataflow_func.py
python3 ./create_w2vmodel.py
python3 ./get_dl_input.py
python3 ./dealrawdata.py
# ================================ #
# ==== model training: model/ ==== #
# ================================ #


python3 ./bgru.py

