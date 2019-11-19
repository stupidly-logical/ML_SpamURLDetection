#!/usr/bin/env python
# coding: utf-8

# # Spam URL Detection 
# ## using Decision Tree algorithm.

# In[95]:


from __future__ import division
import os
import sys
import re
import matplotlib
import pandas as pd
import numpy as np
from os.path import splitext
import ipaddress as ip
import tldextract
import whois
import datetime
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
import pickle as pkl
from urllib.parse import urlparse

import warnings
warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

# get user input for testing

args = sys.argv
if len(args) > 1:
	print(args)

# In[96]:


df = pd.read_csv("./dataset.csv")
df = df.sample(frac=1).reset_index(drop=True)
print("Sample size: ", len(df))
df.head()


# In[97]:


#2016's top most suspicious TLD and words
Suspicious_TLD=['zip','cricket','link','work','party','gq','kim','country','science','tk']
Suspicious_Domain=['luckytime.co.kr','mattfoll.eu.interia.pl','trafficholder.com','dl.baixaki.com.br','bembed.redtube.comr','tags.expo9.exponential.com','deepspacer.com','funad.co.kr','trafficconverter.biz']
#trend micro's top malicious domains 


# ## Feature extraction from URLs

# In[98]:


# Method to count number of dots
def countdots(url):  
    return url.count('.')


# In[99]:


# Method to count number of delimeters
def countdelim(url):
    count = 0
    delim=[';','_','?','=','&']
    for each in url:
        if each in delim:
            count = count + 1
    
    return count


# In[100]:


# Is IP addr present as th hostname, let's validate

import ipaddress as ip #works only in python 3

def isip(uri):
    try:
        if ip.ip_address(uri):
            return 1
    except:
        return 0


# In[101]:


#method to check the presence of hyphens

def isPresentHyphen(url):
    return url.count('-')
        


# In[102]:


#method to check the presence of @

def isPresentAt(url):
    return url.count('@')


# In[103]:


def isPresentDSlash(url):
    return url.count('//')


# In[104]:


def countSubDir(url):
    return url.count('/')


# In[105]:


def get_ext(url):
    """Return the filename extension from url, or ''."""
    
    root, ext = splitext(url)
    return ext


# In[106]:


def countSubDomain(subdomain):
    if not subdomain:
        return 0
    else:
        return len(subdomain.split('.'))


# In[107]:


def countQueries(query):
    if not query:
        return 0
    else:
        return len(query.split('&'))


# In[108]:


featureSet = pd.DataFrame(columns=('url','no of dots','presence of hyphen','len of url','presence of at','presence of double slash','no of subdir','no of subdomain','len of domain','no of queries','is IP','presence of Suspicious_TLD','presence of suspicious domain','label'))


# In[109]:


from urllib.parse import urlparse
import tldextract
def getFeatures(url, label): 
    result = []
    url = str(url)
    
    #add the url to feature set
    result.append(url)
    
    #parse the URL and extract the domain information
    path = urlparse(url)
    ext = tldextract.extract(url)
    
    #counting number of dots in subdomain    
    result.append(countdots(ext.subdomain))
    
    #checking hyphen in domain   
    result.append(isPresentHyphen(path.netloc))
    
    #length of URL    
    result.append(len(url))
    
    #checking @ in the url    
    result.append(isPresentAt(path.netloc))
    
    #checking presence of double slash    
    result.append(isPresentDSlash(path.path))
    
    #Count number of subdir    
    result.append(countSubDir(path.path))
    
    #number of sub domain    
    result.append(countSubDomain(ext.subdomain))
    
    #length of domain name    
    result.append(len(path.netloc))
    
    #count number of queries    
    result.append(len(path.query))
    
    #Adding domain information
    
    #if IP address is being used as a URL     
    result.append(isip(ext.domain))
    
    #presence of Suspicious_TLD
    result.append(1 if ext.suffix in Suspicious_TLD else 0)
    
    #presence of suspicious domain
    result.append(1 if '.'.join(ext[1:]) in Suspicious_Domain else 0 )
    
    #result.append(get_ext(path.path))
    result.append(str(label))
    return result
                  
    #Yay! finally done!  



# In[110]:


for i in range(len(df)):
    features = getFeatures(df["URL"].loc[i], df["Lable"].loc[i])    
    featureSet.loc[i] = features      


# In[111]:


featureSet.head()

import sklearn.ensemble as ek
from sklearn import model_selection, tree, linear_model
from sklearn.feature_selection import SelectFromModel
from sklearn.externals import joblib
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import confusion_matrix
from sklearn.pipeline import make_pipeline
from sklearn import preprocessing
from sklearn import svm
from sklearn.linear_model import LogisticRegression


# In[116]:


featureSet.groupby(featureSet['label']).size()


# In[117]:


X = featureSet.drop(['url','label'],axis=1).values
y = featureSet['label'].values


# ## Learning

# In[118]:


model = {"DecisionTree":tree.DecisionTreeClassifier(max_depth=10),
          "LogisticRegression":LogisticRegression()}


# In[119]:


X_train, X_test, y_train, y_test = model_selection.train_test_split(X, y ,test_size=0.2)


# In[120]:


results = {}
for algo in model:
    clf = model[algo]
    clf.fit(X_train,y_train)
    score = clf.score(X_test,y_test)
    print ("%s : %s " %(algo, score))
    results[algo] = score


# In[121]:


decisionTree = model["DecisionTree"]
logisticRegression = model["LogisticRegression"]


# In[122]:


resDT = decisionTree.predict(X)
mt = confusion_matrix(y, resDT)
print("False positive rate : %f %%" % ((mt[0][1] / float(sum(mt[0])))*100))
print('False negative rate : %f %%' % ( (mt[1][0] / float(sum(mt[1]))*100)))


# In[123]:


resLR = logisticRegression.predict(X)
mt = confusion_matrix(y, resLR)
print("False positive rate : %f %%" % ((mt[0][1] / float(sum(mt[0])))*100))
print('False negative rate : %f %%' % ( (mt[1][0] / float(sum(mt[1]))*100)))


# ### Testing
# 
# Urls:
# - trafficconverter.biz:80/4vir/antispyware/loadadv.exe | 1
# - am10.ru:80/code.php | 1
# - zbavit.live/data/login.php | 1
# - iiti.ac.in | 0
# - services.runescape.com-aje.top | 1
# 
# Let's test' some of the malicious URL's listed in Trend Micro's website. http://apac.trendmicro.com/apac/security-intelligence/current-threat-activity/malicious-top-ten/

# ### Using Decision Tree

# In[137]:

# redefined testing

print("\nTesting using predefined URLs","Decision Tree")

urls = [["trafficconverter.biz:80/4vir/antispyware/loadadv.exe","1"],
       ["am10.ru:80/code.php", "1"],
       ["zbavit.live/data/login.php","1"],
       ["iiti.ac.in","0"],
       ["services.runescape.com-aje.top","1"]]

for i in range(len(urls)):
    result = pd.DataFrame(columns=('url','no of dots','presence of hyphen','len of url','presence of at','presence of double slash','no of subdir','no of subdomain','len of domain','no of queries','is IP','presence of Suspicious_TLD','presence of suspicious domain','label'))
    print(urls[i], urls[i][0], urls[i][1])
    results = getFeatures(urls[i][0], urls[i][1])
    result.loc[0] = results
    result = result.drop(['url','label'],axis=1).values
    print(decisionTree.predict(result))


# ### Using Logistic Regression

# In[138]:

print("\nTesting using predefined URLs","Logistic Regression")

urls = [["trafficconverter.biz:80/4vir/antispyware/loadadv.exe","1"],
       ["am10.ru:80/code.php", "1"],
       ["zbavit.live/data/login.php","1"],
       ["iiti.ac.in","0"],
       ["services.runescape.com-aje.top","1"]]

for i in range(len(urls)):
    result = pd.DataFrame(columns=('url','no of dots','presence of hyphen','len of url','presence of at','presence of double slash','no of subdir','no of subdomain','len of domain','no of queries','is IP','presence of Suspicious_TLD','presence of suspicious domain','label'))
    print(urls[i], urls[i][0], urls[i][1])
    results = getFeatures(urls[i][0], urls[i][1])
    result.loc[0] = results
    result = result.drop(['url','label'],axis=1).values
    print(logisticRegression.predict(result))


if len(args) > 1:
    print("Testing input URL:")
    print("URL:", args[1])
    print("Label:", args[2])
    result = pd.DataFrame(columns=('url','no of dots','presence of hyphen','len of url','presence of at', 'presence of double slash','no of subdir','no of subdomain','len of domain','no of queries','is IP','presence of Suspicious_TLD','presence of suspicious domain','label'))
    results = getFeatures(args[1], args[2])
    result.loc[0] = results
    result = result.drop(['url','label'],axis=1).values
    print("Decision Tree: ",decisionTree.predict(result))
    print("Logistic Regression: ", logisticRegression.predict(result))

