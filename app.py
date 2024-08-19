# app.py

from flask import Flask, render_template, request
import numpy as np
import pandas as pd
from sklearn import preprocessing
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
from keras.models import load_model

app = Flask(__name__)

label_map = {
    0: 'Normal',
    1: 'DDoS',
    2: 'DoS',
    3: 'MITM ARP Spoofing',
    4: 'Mirai',
    5: 'MQTT_bruteforce',
    6: 'Sparta',
    7: 'Theft',
    8: 'Attack',
    9: 'C&C',
    10: 'FileDownload',
    11: 'HeartBeat',
    12: 'Okiru',
    13: 'Reconnaissance',
    14: 'Port Scan',
    15: 'Torii',
    16: 'Flood'
}


cat_map = {
    0: 'Normal',
    1: 'Mirai',
    2: 'DoS' ,
    3: 'Scan' ,
    4: 'MITM ARP Spoofing' ,
}
Label_map = {
   0: 'Normal',
   1: 'Anomaly'
}


def preprocess_data(X):
    features_to_be_dropped = [
    'Active_Max',
 'Active_Mean',
 'Active_Min',
 'Active_Std',
 'Bwd_PSH_Flags',
 'Fwd_Act_Data_Pkts',
 'Fwd_Pkts/b_Avg',
 'Fwd_Seg_Size_Min',
 'Idle_Max',
 'Idle_Mean',
 'Idle_Min',
 'Idle_Std',
 'Init_Fwd_Win_Byts',
 'Pkt_Len_Std'
]
    # Scale features
    X = X.drop(features_to_be_dropped, axis=1)
    scaler = MinMaxScaler(feature_range=(-1,1))
    scaler.fit(X)
    X_normalized = pd.DataFrame(scaler.transform(X), columns=X.columns)
    X.update(X_normalized)
    
    # Handle infinite values
    X[X == np.inf] = np.nan
    X.fillna(0, inplace=True)
    
    return X

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload_cnn1d', methods=['POST'])
def upload():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            iot_ds2 = pd.read_csv(file)
            iot_ds = iot_ds2.drop(['Flow_ID', 'Src_IP', 'Dst_IP', 'Timestamp', 'Src_Port'], axis=1)
            X = iot_ds.drop(['Cat'], axis=1)
            X = preprocess_data(X)
            
            # Load pre-trained CNN model
            model = load_model(r'C:\Users\missu\Desktop\s pro\cnn model in iot\models\CNN1D_iot_300mb_5epoch.h5')
            
            # Reshape data for CNN
            X = X.values.reshape(X.shape[0], X.shape[1], 1)
            
            # Make predictions
            predictions = model.predict(X)
            
            # Process predictions as needed
            
            # Example: extract predicted classes
            predicted_classes = np.argmax(predictions, axis=1)

            predictions_available = len(predicted_classes) > 0
            predicted_labels = [label_map[prediction] for prediction in predicted_classes]
            predictions_available_cnn1d = len(predicted_labels) > 0

            
            # Further processing or response to the user can be done here
            
    return render_template('index.html',  predictions_cnn1d=predicted_labels, predictions_available_cnn1d=predictions_available_cnn1d)

@app.route('/upload_intrusion', methods=['POST'])
def upload_intrusion():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            # Read the CSV file into a pandas DataFrame
            iot_ds2 = pd.read_csv(file)
            
            # Preprocess the data (drop unnecessary columns, etc.)
            iot_ds = iot_ds2.drop(['Flow_ID', 'Src_IP', 'Dst_IP', 'Timestamp', 'Src_Port'], axis=1)
            X = iot_ds.drop(['Cat'], axis=1)
            X = preprocess_data(X)
            
            # Load the pre-trained CNN2D model
            model = load_model(r'C:\Users\missu\Desktop\s pro\cnn model in iot\models\CNN1D_intrusion.h5')
            
            # Reshape data for CNN2D
            X = X.values.reshape(X.shape[0], X.shape[1], 1)
            
            # Make predictions
            predictions = model.predict(X)
            
            # Process predictions as needed
            
            # Example: extract predicted classes
            predicted_classes = np.argmax(predictions, axis=1)
            predicted_labels = [cat_map[prediction] for prediction in predicted_classes]
            predictions_available_intrusion = len(predicted_labels) > 0

            # Further processing or response to the user can be done here
            
    return render_template('index.html', predictions_intrusion=predicted_labels, predictions_available_intrusion=predictions_available_intrusion)

@app.route('/upload_Bi_iot', methods=['POST'])
def upload_bi_iot():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            iot_ds2 = pd.read_csv(file)
            iot_ds = iot_ds2.drop(['Flow_ID', 'Src_IP', 'Dst_IP', 'Timestamp', 'Src_Port'], axis=1)
            X = iot_ds.drop(['Cat'], axis=1)
            X = preprocess_data(X)
            
            # Load pre-trained CNN model
            model = load_model(r'C:\Users\missu\Desktop\s pro\cnn model in iot\models\Bi_CNN1D.h5')
            
            # Reshape data for CNN
            X = X.values.reshape(X.shape[0], X.shape[1], 1)
            
            # Make predictions
            predictions = model.predict(X)
            
            # Process predictions as needed
            
            # Example: extract predicted classes
            predicted_classes = np.argmax(predictions, axis=1)

            
            predicted_labels = [Label_map[prediction] for prediction in predicted_classes]
            predictions_available_bi_iot = len(predicted_labels) > 0

            
            # Further processing or response to the user can be done here
            
    return render_template('index.html',  predictions_bi_iot=predicted_labels, predictions_available_bi_iot=predictions_available_bi_iot)





if __name__ == '__main__':
    app.run(debug=True)
