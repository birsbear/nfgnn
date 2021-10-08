# -*- coding: utf-8 -*-
"""
Created on Fri Oct  8 09:46:29 2021

@author: brian_chiu
"""


import os
import pandas as pd
import numpy as np



def NFGNN_binary_dataset(path = './paper data/'):
    
    
    
    benign_df = []
    malware_df = []
    
    for layer1 in os.listdir(path):
        if layer1 == 'Benign':
            for layer2 in os.listdir(path+layer1):
                file_list = os.listdir(f"{path}{layer1}/{layer2}")
                for file in file_list:
                    df = pd.read_csv(f"{path}{layer1}/{layer2}/{file}")
                    df['Label'] = np.zeros(df.shape[0])
                    benign_df.append(df)

        else:
            for layer2 in os.listdir(path+layer1):
                file_list = os.listdir(f"{path}{layer1}/{layer2}")
                if len(file_list) <=9:
                    continue
                for file in file_list:
                    df = pd.read_csv(f"{path}{layer1}/{layer2}/{file}")
                    df['Label'] = np.ones(df.shape[0])
                    malware_df.append(df)
                
    benign_df = pd.concat(benign_df)
    malware_df = pd.concat(malware_df)
    
    final_df = pd.concat([benign_df, malware_df])
    return final_df


def NFGNN_category_dataset(path = './paper data/'):
    
    benign_df = []
    label_map = {}
    malware_df = {}
    
    for layer1 in os.listdir(path):
        if layer1 == 'Benign':
            for layer2 in os.listdir(path+layer1):
                file_list = os.listdir(f"{path}{layer1}/{layer2}")
                for file in file_list:
                    df = pd.read_csv(f"{path}{layer1}/{layer2}/{file}")
                    df['Label'] = np.zeros(df.shape[0])
                    benign_df.append(df)

        else:
            malware_df[layer1] = []
            label_map[layer1] = len(label_map)+1
            for layer2 in os.listdir(path+layer1):
                file_list = os.listdir(f"{path}{layer1}/{layer2}")
                if len(file_list) <=9:
                    continue
                for file in file_list:
                    df = pd.read_csv(f"{path}{layer1}/{layer2}/{file}")
                    df['Label'] = np.ones(df.shape[0])*label_map[layer1]
                    malware_df[layer1].append(df)
            malware_df[layer1] = pd.concat(malware_df[layer1])
    malware_df = pd.concat(malware_df)
    benign_df = pd.concat(benign_df)
    final_df = pd.concat([benign_df, malware_df]).reset_index(drop = True)
    return final_df, label_map
    
    
    pass

def NFGNN_family_dataset(path = './paper data/'):
    
    benign_df = []
    label_map = {}
    malware_df = {}
    
    for layer1 in os.listdir(path):
        if layer1 == 'Benign':
            for layer2 in os.listdir(path+layer1):
                file_list = os.listdir(f"{path}{layer1}/{layer2}")
                for file in file_list:
                    df = pd.read_csv(f"{path}{layer1}/{layer2}/{file}")
                    df['Label'] = np.zeros(df.shape[0])
                    benign_df.append(df)

        else:
            for layer2 in os.listdir(path+layer1):
                file_list = os.listdir(f"{path}{layer1}/{layer2}")
                if len(file_list) <=9:
                    continue
                malware_df[layer2] = []
                label_map[layer2] = len(label_map)+1
                for file in file_list:
                    df = pd.read_csv(f"{path}{layer1}/{layer2}/{file}")
                    df['Label'] = np.ones(df.shape[0])*label_map[layer2]
                    malware_df[layer2].append(df)
                malware_df[layer2] = pd.concat(malware_df[layer2])
    benign_df = pd.concat(benign_df)
    malware_df = pd.concat(malware_df)
    
    final_df = pd.concat([benign_df, malware_df]).reset_index(drop = True)
    return final_df, label_map
    
    
    pass


def flow_feature():
    pass