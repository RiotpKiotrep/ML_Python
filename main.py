#Importing necessary libraries
import pandas as pd
import numpy as np
import math
import operator

pd.set_option('future.no_silent_downcasting', True)
pd.set_option('display.max_columns', None)

from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report


#import panos
from panos import firewall
from panos import network
from fw_func import *

#fw = firewall.Firewall("10.74.1.18", api_username="admin", api_password="Admin12345")
#print(fw.op("show system info"))

api_key = "LUFRPT10TFJITGcwU3RoRDlLZ1pTOXhFWVFxWHhEN289Um0vWSs3b0toUHRsZnl4YUh0cUwzZmJXdTNibHEzWjMzNjA2aVd3aWh5SlRJSHR5aWxZYkNzQ2VwRW1kb2dRRw=="
fw_ip = "10.74.1.18"

"""# Import data - UNSW-NB15 Dataset

"""

#Import data
train_url = "https://drive.google.com/uc?id=1Jm25hKfLh61phgdKA9Aj2QQVnUug_0uz&export=download"
test_url = "https://drive.google.com/uc?id=1tWypzJIfEj07qwAaT6y8raMCI0od3S8T&export=download"

print("Importing train data...")
training_df = pd.read_csv(train_url, sep=',', on_bad_lines='warn')
print("Importing test data...")
testing_df = pd.read_csv(test_url, sep=',', on_bad_lines='warn')

# remove columns that don't match
cols_to_remove = ['id', 'service', 'state', 'rate', 'sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss',
       'sinpkt', 'dinpkt', 'sjit', 'djit', 'swin', 'stcpb', 'dtcpb', 'dwin',
       'tcprtt', 'synack', 'ackdat', 'smean', 'dmean', 'trans_depth',
       'response_body_len', 'ct_srv_src', 'ct_state_ttl', 'ct_dst_ltm',
       'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm',
       'is_ftp_login', 'ct_ftp_cmd', 'ct_flw_http_mthd', 'ct_src_ltm',
       'ct_srv_dst', 'is_sm_ips_ports']

training_df = training_df.drop(cols_to_remove, axis=1)
testing_df = testing_df.drop(cols_to_remove, axis=1)

combined_df = pd.concat([training_df, testing_df], axis=0)

#combined_df.head()

cols = training_df.columns
training_df.rename(columns={cols[i]: i for i in range(cols.shape[0])}, inplace=True)
testing_df.rename(columns={cols[i]: i for i in range(cols.shape[0])}, inplace=True)
combined_df.rename(columns={cols[i]: i for i in range(cols.shape[0])}, inplace=True)
# replace protocols with numbers
proto_values = np.concatenate((training_df[1].unique(), testing_df[1].unique()))
proto_values = np.unique(proto_values)
#print(proto_values)
training_df[1] = training_df[1].replace(proto_values, [i for i in range(len(proto_values))])
testing_df[1] = testing_df[1].replace(proto_values, [i for i in range(len(proto_values))])
combined_df[1] = combined_df[1].replace(proto_values, [i for i in range(len(proto_values))])

# to float128
cols_to_cast = [i for i in range(cols.shape[0]-2)]
training_df[cols_to_cast] = training_df[cols_to_cast].astype(np.float64)
testing_df[cols_to_cast] = testing_df[cols_to_cast].astype(np.float64)
combined_df[cols_to_cast] = combined_df[cols_to_cast].astype(np.float64)

"""# KNN - set params"""

# scaling
scaler = RobustScaler()
scaler.fit(combined_df.iloc[:, :-2])
knn = KNeighborsClassifier(n_neighbors=8, weights='uniform', metric='manhattan')

X_train = training_df.iloc[:, :-2].values
y_train = training_df.iloc[:, -1].values
X_train = scaler.transform(X_train)
knn.fit(X_train, y_train)

try:
    while True:
        job_id = get_job_id(fw_ip, api_key)
        log_df = get_logs(job_id, fw_ip, api_key)
        
        cols = log_df.columns
        log_df.rename(columns={cols[i]: i for i in range(cols.shape[0])}, inplace=True)
        # replace protocols with numbers
        #log_df[1].replace(proto_values, [i for i in range(len(proto_values))], inplace=True)
        log_df[1] = log_df[1].replace(proto_values, [i for i in range(len(proto_values))])
        # to float128
        log_df[cols_to_cast] = log_df[cols_to_cast].astype(np.float64)
        X_test = log_df.iloc[:, :-1].values
        
        log_df['attack'] = knn.predict(X_test)
        print(log_df)
except:
    print("End")