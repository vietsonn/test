from time import time

import pandas as pd
import numpy as np
import sys
import sklearn
import sklearn.preprocessing
from sklearn.cluster import KMeans
from sklearn.feature_selection import SelectPercentile, f_classif

# check version for development later :)


print("version check")
print(pd.__version__)
print(np.__version__)
print(sys.version)
print(sklearn.__version__)

# assign column names

col_names = ["duration", "protocol_type", "service", "flag", "src_bytes",
             "dst_bytes", "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
             "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
             "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
             "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
             "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
             "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
             "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
             "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
             "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label"]

# due to unknown what the last column in kdd train, remove it

datafile = pd.read_csv("kddtrain.csv", header=None, names=col_names)
datafile_test = pd.read_csv("kddtest.csv", header=None, names=col_names)

# shape of the dataset

print("=====================")
print("shape")
print("Training set: ", datafile.shape)
print("Test set: ", datafile_test.shape)

# first 5 rows of train set

print("=====================")
print(datafile.head(5))


# statistical summary

print("=====================")
print(datafile.describe())

# label distribution

print("=====================")
print("label distribu    training set")
print(datafile["label"].value_counts())
print()
print("label distribu    test set")
print(datafile_test["label"].value_counts())

# data processing phrase
# transform data that is not number yet
# explore categorical features

print("=====================")
print("dataset: ")
for col_names in datafile.columns:
    if datafile[col_names].dtypes == "object":
        diff_cat = len(datafile[col_names].unique())
        print("Feature '{col_names}' has '{diff_cat}' categories".format(col_names=col_names, diff_cat=diff_cat))

print("=====================")
for col_names in datafile_test.columns:
    if datafile_test[col_names].dtypes == "object":
        diff_cat = len(datafile_test[col_names].unique())
        print("Feature '{col_names}' has '{diff_cat}' categories".format(col_names=col_names, diff_cat=diff_cat))


# get 6 missing categories from train set to test set

print("=====================")
trainservice = datafile["service"].tolist()
testservice = datafile_test["service"].tolist()
diff = list(set(trainservice)-set(testservice))
string = "service_"
diff = [string + x for x in diff]
print(diff)

# we need to make all categories in feature become number then transform it into binary
# labelencoder + hotencoder or get_dummies

print("=====================")
datafile = pd.get_dummies(
    datafile,
    columns=["protocol_type", "service", "flag"],
    prefix=["protocol_type", "service", "flag"])

print(datafile.shape)
print(datafile.head())

datafile_test = pd.get_dummies(
    datafile_test,
    columns=["protocol_type", "service", "flag"],
    prefix=["protocol_type", "service", "flag"])

print(datafile_test.shape)

# add 6 missing categories

print("=====================")
for col in diff:
    datafile_test[col] = 0

print(datafile_test.shape)
datafile_test = datafile_test.reindex(datafile.columns, axis=1)
print(datafile_test.head())

# normal=0, DoS=1, Probe=2, R2L=3, U2R=4

print("=====================")

labeldf = datafile['label']
labeldf_test = datafile_test['label']

newlabeldf = labeldf.replace({'normal': 0, 'neptune': 1, 'back': 1, 'land': 1, 'pod': 1, 'smurf': 1, 'teardrop': 1,
                              'mailbomb': 1, 'apache2': 1, 'processtable': 1, 'udpstorm': 1, 'worm': 1,
                              'ipsweep': 2, 'nmap': 2, 'portsweep': 2, 'satan': 2, 'mscan': 2, 'saint': 2,
                              'ftp_write': 3, 'guess_passwd': 3, 'imap': 3, 'multihop': 3, 'phf': 3, 'spy': 3,
                              'warezclient': 3, 'warezmaster': 3, 'sendmail': 3, 'named': 3, 'snmpgetattack': 3,
                              'snmpguess': 3, 'xlock': 3, 'xsnoop': 3, 'httptunnel': 3, 'buffer_overflow': 4,
                              'loadmodule': 4, 'perl': 4, 'rootkit': 4, 'ps': 4, 'sqlattack': 4, 'xterm': 4})

newlabeldf_test = \
    labeldf_test.replace({'normal': 0, 'neptune': 1, 'back': 1, 'land': 1, 'pod': 1, 'smurf': 1, 'teardrop': 1,
                          'mailbomb': 1, 'apache2': 1, 'processtable': 1, 'udpstorm': 1, 'worm': 1,
                          'ipsweep': 2, 'nmap': 2, 'portsweep': 2, 'satan': 2, 'mscan': 2, 'saint': 2,
                          'ftp_write': 3, 'guess_passwd': 3, 'imap': 3, 'multihop': 3, 'phf': 3, 'spy': 3,
                          'warezclient': 3, 'warezmaster': 3, 'sendmail': 3, 'named': 3, 'snmpgetattack': 3,
                          'snmpguess': 3, 'xlock': 3, 'xsnoop': 3, 'httptunnel': 3, 'buffer_overflow': 4,
                          'loadmodule': 4, 'perl': 4, 'rootkit': 4, 'ps': 4, 'sqlattack': 4, 'xterm': 4})

datafile['label'] = newlabeldf
datafile_test['label'] = newlabeldf_test
print(datafile["label"].head())

for col_names in datafile.columns:
    datafile[col_names] = datafile[col_names].astype(float)

for col_names in datafile_test.columns:
    datafile_test[col_names] = datafile_test[col_names].astype(float)

# split to 4

print("=====================")

to_drop_DoS = [0, 1]
to_drop_Probe = [0, 2]
to_drop_R2L = [0, 3]
to_drop_U2R = [0, 4]

# train
#DOS_df = datafile.loc[datafile.label.isin(to_drop_DoS)]

#print(type(DOS_df))
#print(DOS_df['label'][0])
DOS_df = datafile[datafile['label'].isin(to_drop_DoS)]
Probe_df = datafile[datafile['label'].isin(to_drop_Probe)]
R2L_df = datafile[datafile['label'].isin(to_drop_R2L)]
U2R_df = datafile[datafile['label'].isin(to_drop_U2R)]

# test

DOS_df_test = datafile_test[datafile_test['label'].isin(to_drop_DoS)]
Probe_df_test = datafile_test[datafile_test['label'].isin(to_drop_Probe)]
R2L_df_test = datafile_test[datafile_test['label'].isin(to_drop_R2L)]
U2R_df_test = datafile_test[datafile_test['label'].isin(to_drop_U2R)]


# feature scaling and drop label to train kmeans

print("=====================")

Y_DoS = DOS_df['label']
X_DoS = DOS_df.drop('label', 1)
print(X_DoS.shape)

#print(Y_DoS[113270])
X_Probe = Probe_df.drop('label', 1)
Y_Probe = Probe_df['label']
X_R2L = R2L_df.drop('label', 1)
Y_R2L = R2L_df['label']
X_U2R = U2R_df.drop('label', 1)
Y_U2R = U2R_df['label']

# test set

X_DoS_test = DOS_df_test.drop('label', 1)
Y_DoS_test = DOS_df_test['label']
X_Probe_test = Probe_df_test.drop('label', 1)
Y_Probe_test = Probe_df_test['label']
X_R2L_test = R2L_df_test.drop('label', 1)
Y_R2L_test = R2L_df_test['label']
X_U2R_test = U2R_df_test.drop('label', 1)
Y_U2R_test = U2R_df_test['label']

scaler1 = sklearn.preprocessing.StandardScaler().fit(X_DoS)
X_DoS = scaler1.transform(X_DoS)
print(X_DoS.std(axis=0))
scaler2 = sklearn.preprocessing.StandardScaler().fit(X_Probe)
X_Probe = scaler2.transform(X_Probe)
scaler3 = sklearn.preprocessing.StandardScaler().fit(X_R2L)
X_R2L = scaler3.transform(X_R2L)
scaler4 = sklearn.preprocessing.StandardScaler().fit(X_U2R)
X_U2R = scaler4.transform(X_U2R)
# test data
scaler5 = sklearn.preprocessing.StandardScaler().fit(X_DoS_test)
X_DoS_test = scaler5.transform(X_DoS_test)
scaler6 = sklearn.preprocessing.StandardScaler().fit(X_Probe_test)
X_Probe_test = scaler6.transform(X_Probe_test)
scaler7 = sklearn.preprocessing.StandardScaler().fit(X_R2L_test)
X_R2L_test = scaler7.transform(X_R2L_test)
scaler8 = sklearn.preprocessing.StandardScaler().fit(X_U2R_test)
X_U2R_test = scaler8.transform(X_U2R_test)



print(X_DoS.std(axis=0))

# now train with kmeans

print("=====================")
print("DOS")
k = 2
km = KMeans(n_clusters=k)

t0 = time()
km.fit(X_DoS_test)
tt = time() - t0
print("Clustered in {} seconds".format(round(tt, 3)))
print(pd.Series(km.labels_).shape)
print(pd.Series(km.labels_).value_counts())
# ################

print("=====================")

label_names = map(
              lambda x: pd.Series([Y_DoS_test.iloc[j] for j in range(len(km.labels_)) if km.labels_[j] == x]),
              range(k))

label_names = list(label_names)

for i in range(k):
    print("Cluster {} labels:".format(i))
    print(label_names[i].value_counts())
