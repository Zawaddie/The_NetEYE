from base64 import b64encode
from datetime import datetime

import requests
from django.conf import settings
from requests.auth import HTTPBasicAuth

from NetEYE.models import mpesaRequest



auth_URL = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials" 
onlinePayment_URL = "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest" 
callback_url ="https://a9e7-102-218-124-134.ngrok-free.app/mpesa-callback/"


def access_token_mpesa(consumer_key, consumer_secret):
    credentials = f"{consumer_key}:{consumer_secret}"
    encoded_credentials = b64encode(credentials.encode('utf-8')).decode('utf-8')
    headers = {'Authorization': f"Basic {encoded_credentials}",'Content-Type': 'application/json'}
    r = requests.get(auth_URL, headers=headers)
    json_response = r.json()
    access_token = json_response.get("access_token")
    return access_token


def current_time_stamp():
    unformatted_time = datetime.now()
    formatetted_time = unformatted_time.strftime("%Y%m%d%H%M%S")
    return formatetted_time


def getTime(unformatted_time):
    transation_time = str(unformatted_time)
    transation_date_time = datetime.strptime(transation_time, "%Y%m%d%H%M%S")
    return transation_date_time


def getPassword(business_short_code, passkey, timestamp):
    data = f"{business_short_code}{passkey}{timestamp}"
    encoded_string = b64encode(data.encode())
    return encoded_string.decode("utf-8")


def save_stkpush_request(response_data, phone_number, account_reference, transaction_description):
    if "errorCode" in response_data.keys():
        print(f"we have received an error here    {response_data}")
        return response_data
    else:
        data = {}
        data["merchant_id"] = response_data["MerchantRequestID"]
        data["checkout_id"] = response_data["CheckoutRequestID"]
        data["res_code"] = response_data["ResponseCode"]
        data["res_text"] = response_data["ResponseDescription"]
        data["msg"] = response_data["CustomerMessage"]
        data["phone"] = phone_number
        data["ref"] = account_reference
        data["trans_date"] = transaction_description

        push_request_res = mpesaRequest.objects.create(**data)
        push_request_res.save()
        return response_data


def request_stk_push(consumer_key,consumer_secret,passkey, business_short_code,amount,phone_number,account_reference="",transaction_description="",user=None,):
    timestamp = current_time_stamp()
    password = getPassword(business_short_code, passkey, timestamp)
    access_token = access_token_mpesa(consumer_key, consumer_secret)
    headers = {"Authorization": "Bearer %s" % access_token}
    request = {
        "BusinessShortCode": business_short_code,
        "Password": password,
        "Timestamp": timestamp,
        "TransactionType": "CustomerPayBillOnline", #"CustomerBuyGoodsOnline",
        "Amount": float(amount),
        "PartyA": str(phone_number),
        "PartyB": business_short_code,
        "PhoneNumber": str(phone_number),
        "CallBackURL": callback_url,
        "AccountReference": str(account_reference),
        "TransactionDesc": transaction_description,
    }
    response = requests.post(onlinePayment_URL, json=request, headers=headers)
    response_data = response.json()
    if "errorCode" in response_data.keys():
        print(f"Error At the MPESA CODE  {response_data}")
        return response_data
    else:
        save_stkpush_request(response_data, phone_number, account_reference, transaction_description )
        return response_data
