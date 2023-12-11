from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.contrib import messages

from django.contrib.auth.models import User

from NetEYE.mpesa import request_stk_push, getTime
from NetEYE.models import mpesaRequest, MpesaPayments
from datetime import datetime
from django.http import Http404, HttpResponse
from django.views.decorators.http import require_POST
import json

import time
import pandas as pd
import os
# Create your views here.
# Home page





# Load in the trained model and the TRAIN_COLS variable
model = pd.read_pickle("./final/rf_clf.pkl")


# load encoder
label_encoder = pd.read_pickle('./final/encoder.pkl')
TRAIN_COLS_OUT = ['src_ip', 'dst_ip', 'src_port', 'src_mac', 'dst_mac', 'timestamp',"predicted_label", "predicted_score"]


TRAIN_COLS  =['Destination Port', 'Flow Duration', 'Total Fwd Packets',
       'Total Backward Packets', 'Total Length of Fwd Packets',
       'Total Length of Bwd Packets', 'Fwd Packet Length Max',
       'Fwd Packet Length Min', 'Fwd Packet Length Mean',
       'Fwd Packet Length Std', 'Bwd Packet Length Max',
       'Bwd Packet Length Min', 'Bwd Packet Length Mean',
       'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s',
       'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
       'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max',
       'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std',
       'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Fwd URG Flags',
       'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s',
       'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length',
       'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
       'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count',
       'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count',
       'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size',
       'Avg Bwd Segment Size', 'Fwd Header Length.1', 'Subflow Fwd Packets',
       'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
       'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd',
       'min_seg_size_forward', 'Active Mean', 'Active Std', 'Active Max',
       'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min']

rename_cols = {'flow_duration': 'Flow Duration',
 'flow_iat_mean': 'Flow IAT Mean',
 'flow_iat_std': 'Flow IAT Std',
 'flow_iat_max': 'Flow IAT Max',
 'flow_iat_min': 'Flow IAT Min',
 'fwd_iat_mean': 'Fwd IAT Mean',
 'fwd_iat_std': 'Fwd IAT Std',
 'fwd_iat_max': 'Fwd IAT Max',
 'fwd_iat_min': 'Fwd IAT Min',
 'bwd_iat_mean': 'Bwd IAT Mean',
 'bwd_iat_std': 'Bwd IAT Std',
 'bwd_iat_max': 'Bwd IAT Max',
 'bwd_iat_min': 'Bwd IAT Min',
 'fwd_psh_flags': 'Fwd PSH Flags',
 'bwd_psh_flags': 'Bwd PSH Flags',
 'fwd_urg_flags': 'Fwd URG Flags',
 'bwd_urg_flags': 'Bwd URG Flags',
 'cwe_flag_count': 'CWE Flag Count',
 'active_mean': 'Active Mean',
 'active_std': 'Active Std',
 'active_max': 'Active Max',
 'active_min': 'Active Min',
 'idle_mean': 'Idle Mean',
 'idle_std': 'Idle Std',
 'idle_max': 'Idle Max',
 'idle_min': 'Idle Min',
 'tot_fwd_pkts': 'Total Fwd Packets',
 'tot_bwd_pkts': 'Total Backward Packets',
 'totlen_fwd_pkts': 'Total Length of Fwd Packets',
 'totlen_bwd_pkts': 'Total Length of Bwd Packets',
 'fwd_pkt_len_max': 'Fwd Packet Length Max',
 'protocol': 'Fwd Header Length.1',
 'fwd_pkt_len_mean': 'Fwd Packet Length Mean',
 'fwd_pkt_len_std': 'Fwd Packet Length Std',
 'bwd_pkt_len_max': 'Bwd Packet Length Max',
 'bwd_pkt_len_min': 'Bwd Packet Length Min',
 'bwd_pkt_len_mean': 'Bwd Packet Length Mean',
 'bwd_pkt_len_std': 'Bwd Packet Length Std',
 'flow_byts_s': 'Flow Bytes/s',
 'flow_pkts_s': 'Flow Packets/s',
 'fwd_iat_tot': 'Fwd IAT Total',
 'bwd_iat_tot': 'Bwd IAT Total',
 'fwd_header_len': 'Fwd Header Length',
 'bwd_header_len': 'Bwd Header Length',
 'fwd_pkts_s': 'Fwd Packets/s',
 'bwd_pkts_s': 'Bwd Packets/s',
 'pkt_len_min': 'Min Packet Length',
 'pkt_len_max': 'Max Packet Length',
 'pkt_len_mean': 'Packet Length Mean',
 'pkt_len_std': 'Packet Length Std',
 'pkt_len_var': 'Packet Length Variance',
 'fin_flag_cnt': 'FIN Flag Count',
 'syn_flag_cnt': 'SYN Flag Count',
 'rst_flag_cnt': 'RST Flag Count',
 'psh_flag_cnt': 'PSH Flag Count',
 'ack_flag_cnt': 'ACK Flag Count',
 'urg_flag_cnt': 'URG Flag Count',
 'ece_flag_cnt': 'ECE Flag Count',
 'down_up_ratio': 'Down/Up Ratio',
 'pkt_size_avg': 'Average Packet Size',
 'subflow_fwd_pkts': 'Subflow Fwd Packets',
 'subflow_fwd_byts': 'Subflow Fwd Bytes',
 'subflow_bwd_pkts': 'Subflow Bwd Packets',
 'subflow_bwd_byts': 'Subflow Bwd Bytes',
 'init_fwd_win_byts': 'Init_Win_bytes_forward',
 'init_bwd_win_byts': 'Init_Win_bytes_backward',
 'fwd_seg_size_avg': 'Avg Fwd Segment Size',
 'bwd_seg_size_avg': 'Avg Bwd Segment Size',
 'fwd_seg_size_min': 'min_seg_size_forward',
 'fwd_byts_b_avg': 'Fwd Avg Bytes/Bulk',
 'fwd_pkts_b_avg': 'Fwd Avg Packets/Bulk',
 'fwd_blk_rate_avg': 'Fwd Avg Bulk Rate',
 'bwd_byts_b_avg': 'Bwd Avg Bytes/Bulk',
 'bwd_pkts_b_avg': 'Bwd Avg Packets/Bulk',
 'bwd_blk_rate_avg': 'Bwd Avg Bulk Rate',
 'fwd_act_data_pkts': 'act_data_pkt_fwd',
 'fwd_pkt_len_min': 'Fwd Packet Length Min',
 'dst_port': 'Destination Port'}

# Define a function to process the data before feeding it to the model
def process_data(data):
    # Preprocess the data as needed (e.g., one-hot encode categorical variables)
    try:
        processed_data = data.rename(columns=rename_cols)[TRAIN_COLS].values
        df = data.rename(columns=rename_cols)[TRAIN_COLS]
    except Exception as e:
        process_data = data[TRAIN_COLS].values
        df = data[TRAIN_COLS]
    return processed_data, df


def index(request):
    return render(request, 'index.html')

# signup page
@csrf_exempt
def signup(request):
    if request.user.is_authenticated:
        return redirect("index")
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        email = request.POST['email']

        user_obj = User.objects.filter(username=username)
        if user_obj.exists():
            msg = "User already exists"
            messages.warning(request, f"Hi {username}, details used already exists")
            return render(request, 'login.html', {"msg":msg})

        else:
            user_new = User(
                username=username, email=email
            )
            user_new.set_password(password)
            user_new.save()
            messages.success(request, f"Hi {username}, Account created well")
            return redirect('login')
    return render(request, 'signup.html')

# login page
@csrf_exempt
def login_user(request):
    if request.user.is_authenticated:
        return redirect("index")
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            messages.success(request, f"Hi {username}, Welcome back")
            return redirect('dashboard')
        else:
            msg = "Incorrect credentials"
            messages.error(request, f"Hi {username}, You have provided invalid logic credentials")
            return render(request, 'login.html', {'msg': msg})
    return render(request, 'login.html')

# logout page
def user_logout(request):
    logout(request)
    return redirect('index')



# Create your views here.
@login_required(login_url = "/login")
def dashboard(request):
    preds, label_names  = [], []
    chart_data = {
        'names': label_names,
        'data': preds,
    }
    selector_ = request.POST.get("optionSelector") 

    if request.method == "POST" and request.POST.get("optionSelector") == "1":
        #process the data for live data
        LIVE_DATA_PATH = "./final/DATA.csv"
        data = pd.read_csv(f"{LIVE_DATA_PATH}")
        processed_data, df = process_data(data)
        # Run the model on the processed data
        results = model.predict(processed_data)
        # Get the count of benign and malicious detections
        count = pd.Series(results).value_counts()

        label_names = label_encoder.inverse_transform(count.index)
        chart_data = {
                'names': list(label_names),
                'data': [str(x) for x in count.values],

            }

        #get some latest top 5
        latest_data = data.sample(5).reset_index(drop=True)[TRAIN_COLS_OUT]
        # print(latest_data)

        chart_data['table'] = latest_data.to_html(classes='table table-bordered table-striped')
        return render(request, 'dashboard.html', {'user': request.user, "selected": selector_, 'chart_data': json.dumps(chart_data), "table":chart_data['table']})


    if request.method == 'POST' and request.FILES.get('packets'):
        data_path = request.FILES.get('packets')

        try:
            if data_path:
                data = pd.read_csv(data_path)
                processed_data, df = process_data(data)
                # Run the model on the processed data
                results = model.predict(processed_data)
                # Get the count of benign and malicious detections
                count = pd.Series(results).value_counts()

                label_names = label_encoder.inverse_transform(count.index)
                chart_data = {
                        'names': list(label_names),
                        'data': [str(x) for x in count.values],

                    }

                #get some latest top 5
                try:
                    latest_data = data.sample(5).reset_index(drop=True)[TRAIN_COLS_OUT]
                except:
                    latest_data = data.sample(5)[['Destination Port',"Label"]].reset_index(drop=True)
                # print(latest_data)

                chart_data['table'] = latest_data.to_html(classes='table table-bordered table-striped')
                return render(request, 'dashboard.html', {'user': request.user, "selected": selector_, 'chart_data': json.dumps(chart_data), "table":chart_data['table']})

            else:
                messages.warning(request, "Hey please upload a csv file")

        except Exception as e:
            messages.warning(request, f"File uploaded is not working  {e}")

    # You can access the logged-in user using request.user
    user = request.user
    return render(request, 'dashboard.html', {'user': user, 'chart_data': json.dumps(chart_data) })




@login_required(login_url="/login")
def update_chart_data(request):
    preds, label_names = [], []
    #process the data for live data
    LIVE_DATA_PATH = "./final/DATA.csv"
    data = pd.read_csv(f"{LIVE_DATA_PATH}")
    processed_data, df = process_data(data)
    # Run the model on the processed data
    results = model.predict(processed_data)
    # Get the count of benign and malicious detections
    count = pd.Series(results).value_counts()

    label_names = label_encoder.inverse_transform(count.index)

    TRAIN_COLS_OUT = ['src_ip', 'dst_ip', 'src_port', 'src_mac', 'dst_mac', 'timestamp', 'predicted_label', 'predicted_score']

    latest_data = data.tail(5).reset_index(drop=True)

    table_data = []
    for index, row in latest_data.iterrows():
        table_row = {
            'src_ip': row['src_ip'],
            'dst_ip': row['dst_ip'],
            'src_port': row['src_port'],
            'src_mac': row['src_mac'],
            'dst_mac': row['dst_mac'],
            'timestamp': row['timestamp'],
            'predicted_label': row['predicted_label'],
            'predicted_score': row['predicted_score'],
        }
        table_data.append(table_row)

    chart_data = {
        'names': list(label_names),
        'data': [str(x) for x in count.values],
        "latest_data": table_data

    }
    return JsonResponse(chart_data)


def features(request):
    return render(request, 'features.html')

def services(request):
    return render(request, 'services.html')

def subscription(request):
    # Add logic for subscription details, if needed
    return render(request, 'subscription.html')

def settings(request):
    return render(request, 'settings.html')
# def payment(request):
#     return render(request, 'payment.html')









# payment


@csrf_exempt
def payment(request):
    if request.method == "POST":
        print(request.body.decode('utf-8'))
        print(f"Requested STK PUSH FROM WEB.......")
        amount = 1 #request.POST.get("amount")
        phone_number = request.POST.get("phone")
        print(f"Phone Number   {phone_number}")

        consumer_key = "yApSYjqZ5redC8F1SYxpjLzmoNDIFpqe"
        consumer_secret = "AMrKuqiGoArjSsPD"
        pass_key = "bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919"
        short_code = 174379


        transaction_description = f"payment for {request.user} premium Feature"
        print(f"Request is being send to stk push..... we have user {request.user} and phone {phone_number}")
        ret_val = request_stk_push(
            consumer_key,consumer_secret,
            pass_key,short_code,float(amount),
            phone_number, account_reference=str(request.user.id),
            transaction_description=transaction_description,user=request.user.id,
        )

        if "errorMessage" in ret_val:
            messages.error(request, f"Hi {request.user}, your payment did not go through. Error {ret_val['errorMessage']}")
        else:
            messages.warning(request, f"Hi {request.user}, your payment is initiated, please input mpesa pin from stk request in phone")
    
    return render(request, "subscription.html")


# mpesa MpesaPayments
@csrf_exempt
@require_POST
def stk_callback(request):
    print("Mpesa callback has been called")
    try:
        data = json.loads(request.body.decode('utf-8'))
    except json.JSONDecodeError:
        return JsonResponse({"message":"error"}, status=400)
    
    
    print(f"DATA is   {data}")
    data_res = {}
 
    data_res["merchant_id"] = data["Body"]["stkCallback"]["MerchantRequestID"]
    data_res["checkout_id"] = data["Body"]["stkCallback"]["CheckoutRequestID"]
    data_res["res_code"] = data["Body"]["stkCallback"]["ResultCode"]
    data_res["res_text"] = data["Body"]["stkCallback"]["ResultDesc"]

    if int(data_res["res_code"]) > 0:
        return JsonResponse(data, status=417)

    else:
        items = data["Body"]["stkCallback"]["CallbackMetadata"]["Item"]
        for item in items:
            data_res[item.get("Name")] = item.get("Value")


        data_res["trans_date"] = getTime(data_res["TransactionDate"])

        MerchantRequestID = data_res["merchant_id"]
        CheckoutRequestID = data_res["checkout_id"]


        # get order instance
        try:
            request_stk_push_res = mpesaRequest.objects.get(
                merchant_id=MerchantRequestID,
                checkout_id=CheckoutRequestID,
            )
        except mpesaRequest.DoesNotExist:
            raise Http404


        user_id = request_stk_push_res.ref

        try:
            user = User.objects.get(pk=user_id)
        except User.DoesNotExist:
            raise Http404

        # update order paid flag

        payment = MpesaPayments()

        print(f"Data is  {data}")

        payment.user = user
        payment.receipt = data_res.get("MpesaReceiptNumber")
        payment.merchant_id = data_res.get("merchant_id")
        payment.checkout_id = data_res.get("checkout_id")
        payment.res_code = data_res.get("res_code")
        payment.res_text = data_res.get("res_text")
        payment.amount = data_res.get("Amount")
        payment.phone = data_res.get("PhoneNumber")
        payment.trans_date = request_stk_push_res.trans_date

        # payment.trans_date = datetime.strptime(str(data_res.get("TransactionDate")), "%Y-%m-%d %H:%M:%S")

        payment.save()
        return JsonResponse({"desc": "success"}, status=200)
