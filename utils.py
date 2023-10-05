import requests
import google
import xmltodict
from advertools import robotstxt_to_df
from bs4 import BeautifulSoup
from advertools import sitemap_to_df
from termcolor import colored
from collections import Counter
from googlesearch import search
import math

def redirectTest(domTest):
    try:
        r = requests.head(domTest, allow_redirects=False)
        if (r.status_code == 301):
            print ("Tested:"+domTest+"\n\t"+r.url+"\n\t"+str(r.status_code)+"\n\t"+r.headers['Location'])
            return str("Tested:"+domTest+"\n\t"+r.url+"\n\t"+str(r.status_code)+"\n\t"+r.headers['Location'])
        elif (r.status_code == 302):
            print ("Tested:"+domTest+"\n\t"+r.url+"\n\t"+str(r.status_code)+"\n\t"+r.headers['Location'])
            return str("Tested:"+domTest+"\n\t"+r.url+"\n\t"+str(r.status_code)+"\n\t"+r.headers['Location'])
        else:
            print ("Tested:"+domTest+"\n\t"+r.url+"\n\t"+str(r.status_code))
            return str("Tested:"+domTest+"\n\t"+r.url+"\n\t"+str(r.status_code))
    except requests.exceptions.RequestException as e:  
        print ("Tested:"+domTest+"\n\t"+e)
        return str("Tested:"+domTest+"\n\t"+e)
        return str(1)
    pass

def concatenateDom(dom):
    mylist = ['http://www.', 'http://', 'https://www.', 'https://']
    for a in mylist:
        domTest =   a + dom
        ret_str = redirectTest(domTest)
        return ret_str

def robots_df(url):
    output=robotstxt_to_df(url+'/robots.txt')
    return output


def gtag(url):
    html_text = requests.get(url).text
    soup = BeautifulSoup(html_text,'lxml')
    info = soup.find('g')
    print(info)
    return info

def sitemap(url):
    sigortam = sitemap_to_df(url+'/wp-sitemap.xml')
    return sigortam


def title(url):
    reqs = requests.get(url)
    soup = BeautifulSoup(reqs.text, 'html.parser')
    print(colored("TITLE OF THE WEBSITE : ","red", attrs=['bold']))
    for title in soup.find_all('title'):
        text=title.get_text()
        ret_title = text
        ret_title_len = str("Number of Character in the Title: "+str(len(text)))
        return ret_title, ret_title_len


########## RANK based on website and keyword



# Google rank for given website and key word
def url_keyword_rank(website, keyword):
    found = False
    print('1----')
    urls = search(keyword, tld="com", num=150, stop=150, pause=5)
    for index, url in enumerate(urls):
        print(index, url)
        if website in url:
            ret_str = str(index+1)+","
            ret_str += str(math.ceil((index+1)/10))
            found = True
            return ret_str
            break
    if not found:
        return "not found, not found"