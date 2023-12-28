# ReSyVRs
## Overview
PyReSyVRs is a project try to reimplemented SySeVR.

## Instructions for Running Scripts
Please review and install the necessary dependencies outlined in the config.sh file instead of directly executing the scripts.

## License
This project is for my school project. Full source project in https://github.com/SySeVR/SySeVR.

## Acknowledgments
If you have any inquiries or require assistance, please don't hesitate to contact me at trongphucphan7@gmail.com.

## Dataset processed
Access the full NVD processed dataset via the following link: https://drive.google.com/drive/folders/1F0mhFlXlNdlpuaxYHNcoHGDAM2f9U24u?usp=drive_link

## How to run ?
Install the required dependencies mentioned in the config.sh file.
Follow the instructions below:

go to joern-0.3.1/bin folder then run: java -jar /path_to_joernfolder/joern-0.3.1/bin/joern.jar /home/test/source2slice/NVD
(on screen A: start neo4j service)
neo4j start-no-wait


(on screen B)
## Step 1: Generating Slices
Note: If you encounter issues while running get_cfg_relationg.py, ensure that you've installed the correct version of python-igraph as specified in config.sh instead of igraph as it may cause errors.

python ./get_cfg_relation.py # this outputs to src/source2slice/cfg_db/

python ./complete_PDG.py # this outputs to src/source2slice/pdg_db/

python ./access_db_operate.py # this outputs to src/source2slice/dict_call2cfgNodeID_funcID/

python ./points_get.py # this outputs to sensifunc_slice_points.pkl, pointuse_slice_points.pkl, arrayuse_slice_points.pkl, integeroverflow_slice_points_new.py

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

python3 ./deal_raw_data.py

## Step 3: DL step
Note: In this step i always get the TP=0.000000e+0 rate or TN=0.000000e+0. After debug i found out that the problem can be in the step 2.
python3 ./bgru.py

Feel free to adjust and execute the provided commands as per your project requirements.
This revised README should make it clearer and easier for users to understand and follow the steps necessary to run the project.
