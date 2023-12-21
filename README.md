# ReSyVRs

## Overview
This project involves a series of steps to generate slices (SeVCs) from source code, preprocess data, and utilize a deep learning model for analysis. In this i've able to run SySeVRs. 
## Instructions for Running Scripts
Please read and install what you need in **config.sh** instead of running them.

## License
This project is for my school project. And i forked it from https://github.com/SySeVR/SySeVR.

## Acknowledgments
If you have any questions, please feel free to contact me at trongphucphan7@gmail.com

## Dataset processed
https://drive.google.com/drive/folders/1F0mhFlXlNdlpuaxYHNcoHGDAM2f9U24u?usp=drive_link


## How to run ?
# Install requires dependencies in config.sh then following the intruction below:
go to joern-0.3.1/bin folder then run: java -jar /path/joern-0.3.1/bin/joern.jar /home/test/source2slice/NVD
#(on screen A: start neo4j service)
neo4j start-no-wait
#(on screen B)
## Step 1: Generating Slices
Note: if you have problem while running get_cfg_relationg.py make sure you've install the right python-igraph version i've mentioned in the config.sh instead of igraph. This is wrong library.
python ./get_cfg_relation.py # this outputs to src/source2slice/cfg_db/
python ./complete_PDG.py # this outputs to src/source2slice/pdg_db/
python ./access_db_operate.py # this outputs to src/source2slice/dict_call2cfgNodeID_funcID/
python ./points_get.py # this outputs to sensifunc_slice_points.pkl, pointuse_slice_points.pkl, arrayuse_slice_points.pkl, integeroverflow_slice_points_new.pkl
python ./extract_df.py
python ./dealfile.py
python ./make_label_nvd.py # create label_data in C/
python ./data_preprocess.py # create in slice_label folder
## Step 2: Data Preprocessing
python3 ./create_hash.py
python3 ./delete_list.py
python3 ./process_dataflow_func.py
python3 ./create_w2vmodel.py
python3 ./get_dl_input.py
python3 ./dealrawdata.py
## Step 3: Deep Learning Model
python3 ./bgru.py
