import pandas as pd

import matplotlib.pyplot as plt
import seaborn as sns
from wordcloud import WordCloud

from keras.models import Sequential, model_from_json
from keras import layers

import re
from urllib.parse import urlparse
from googlesearch import search
from urllib.parse import urlparse
import os.path
from sklearn.preprocessing import MinMaxScaler

def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0

def abnormal_url(url):
    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0

def google_index(url):
    site = search(url, 5)
    return 1 if site else 0

def count_dot(url):
    count_dot = url.count('.')
    return count_dot

def count_www(url):
    url.count('www')
    return url.count('www')

def count_atrate(url):

    return url.count('@')

def no_of_dir(url):
    urldir = urlparse(url).path
    return urldir.count('/')

def no_of_embed(url):
    urldir = urlparse(url).path
    return urldir.count('//')

def shortening_service(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      url)
    if match:
        return 1
    else:
        return 0

def count_https(url):
    return url.count('https')

def count_http(url):
    return url.count('http')

def count_per(url):
    return url.count('%')

def count_ques(url):
    return url.count('?')

def count_hyphen(url):
    return url.count('-')

def count_equal(url):
    return url.count('=')

def url_length(url):
    return len(str(url))

def hostname_length(url):
    return len(urlparse(url).netloc)

def suspicious_words(url):
    match = re.search('PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr',
                      url)
    if match:
        return 1
    else:
        return 0

def digit_count(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
    return digits

def letter_count(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters = letters + 1
    return letters

def fd_length(url):
    urlpath= urlparse(url).path
    try:
        return len(urlpath.split('/')[1])
    except:
        return 0

def GetFeatures(df, use_scaler = False):

  df_result = pd.DataFrame()
  df_result['use_of_ip'] = df['url'].apply(lambda i: having_ip_address(i))
  df_result['abnormal_url'] = df['url'].apply(lambda i: abnormal_url(i))
  df_result['google_index'] = df['url'].apply(lambda i: google_index(i))
  df_result['dot_count'] = df['url'].apply(lambda i: count_dot(i))
  df_result['count-www'] = df['url'].apply(lambda i: count_www(i))
  df_result['count@'] = df['url'].apply(lambda i: count_atrate(i))
  df_result['count_dir'] = df['url'].apply(lambda i: no_of_dir(i))
  df_result['count_embed_domian'] = df['url'].apply(lambda i: no_of_embed(i))
  df_result['short_url'] = df['url'].apply(lambda i: shortening_service(i))
  df_result['count-https'] = df['url'].apply(lambda i : count_https(i))
  df_result['count-http'] = df['url'].apply(lambda i : count_http(i))
  df_result['count%'] = df['url'].apply(lambda i : count_per(i))
  df_result['count?'] = df['url'].apply(lambda i: count_ques(i))
  df_result['count-'] = df['url'].apply(lambda i: count_hyphen(i))
  df_result['count='] = df['url'].apply(lambda i: count_equal(i))
  df_result['url_length'] = df['url'].apply(lambda i: url_length(i))
  df_result['hostname_length'] = df['url'].apply(lambda i: hostname_length(i))
  df_result['sus_url'] = df['url'].apply(lambda i: suspicious_words(i))
  df_result['count-digits']= df['url'].apply(lambda i: digit_count(i))
  df_result['count-letters']= df['url'].apply(lambda i: letter_count(i))
  df_result['fd_length'] = df['url'].apply(lambda i: fd_length(i))

  if use_scaler:
    print('use scaler')
    scaler = MinMaxScaler()
    scaled_features = scaler.fit_transform(df_result)

    df_result = pd.DataFrame(scaled_features, columns=['use_of_ip', 'abnormal_url', 'google_index', 'dot_count', 'count-www', 'count@', 'count_dir',
                                                            'count_embed_domian', 'short_url', 'count-https', 'count-http', 'count%', 'count?', 'count-',
                                                            'count=', 'url_length', 'hostname_length', 'sus_url', 'count-digits', 'count-letters', 'fd_length']
                                 )


  return df_result

def predict_url(url, model, use_scaler = False):

  X_sample = [url]
  df_sample = pd.DataFrame(X_sample, columns=['url'])
  df_feature = GetFeatures(df_sample, use_scaler)
  result = model.predict(df_feature)

  print("Prediction")

  print("benign: {:.3f}".format(float(result[0, 0])))
  print("defacement: {:.3f}".format(float(result[0, 1])))
  print("phishing: {:.3f}".format(float(result[0, 2])))
  print("malware: {:.3f}".format(float(result[0, 3])))

  return result

def LoadModel(model_name):
  model_file = model_name + '.json'

  json_file = open(model_name + '.json', 'r')
  loaded_model_json = json_file.read()
  json_file.close()

  model = model_from_json(loaded_model_json)
  model.load_weights(model_name + '.h5')

  print("model used: " + model_name)

  return model








