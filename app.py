from flask import Flask, render_template, url_for, redirect, request,session
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Api, Resource
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from datetime import datetime
import pandas as pd
from utils import*
from bs4 import BeautifulSoup
import requests
# from seo import *
import time
import ssl
import socket
from xml.parsers.expat import ExpatError
import builtwith
import urllib.request

app = Flask(__name__)
api = Api(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'secretkey'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    email = db.Column(db.String(80), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    auth_date = db.Column(db.DateTime, default=datetime.now())


class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=30)], render_kw={"placeholder": "Username"})

    email = StringField(validators=[
                        InputRequired(), Length(min=5, max=100)], render_kw={"placeholder": "email"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError("That username already exists. Please choose a different one.")

class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=30)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))

    return render_template('login.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'GET':
         return render_template('rank_page_index.html', user=current_user)

    website = request.form.get('website')
    keywords = request.form.getlist('customFieldName[]')
    keyword_list = request.form.getlist('customFieldValue[]')
    keywords.extend(keyword_list)
    reqs = requests.get(website)
    soup = BeautifulSoup(reqs.text, 'html.parser')

    output_dict = {}
    output_df = pd.DataFrame()
    if len(keywords) >= 1:
       for i in keywords:
          ret = url_keyword_rank(website, i)
          output_dict[i] = ret
          print('sleep')
          time.sleep(2)
          print('sleep over')
          print(output_dict)

    else:  
        ret = url_keyword_rank(website, keywords[0])
        output_dict[i] = ret

    for i, j in output_dict.items():
        d = {}
        d['Keyword'] = i
        g_val = j.split(',')
        d['Position'] = g_val[0]
        d['Page'] = g_val[1]
        output_df = pd.concat([output_df, pd.DataFrame(d, index=[0])], ignore_index=True)

# LENGTH OF THE TITLE
    title_text, title_length=get_title_info(website)
#meta tag
    cont, desc_len=get_meta_description(website)
            
 # H1 tag words (CALLING THE FUNCTION)
    h1_content = find_h1_tag(website)

# Header tags count (CALLING THE FUNCTION)
    heading_counts = count_heading_tags(website)

# amount of content
    content_amt=calculate_content_amount(website)

# img alt tags count
    alt_count, non_alt_count = count_alt_tags(website)

#check ssl is enabled or not
    ssl=check_website_ssl(website)

#Call the seo_audit_tool function with the URL argument
    ssl_info = check_ssl_certificate(website)
# Check SSL certificate
    expiration_date = ssl_info["expiration_date"]
    days_left = ssl_info["Days_Left"]
    is_valid = ssl_info["valid"]

# Robots.txt
    robots_txt = find_robots_txt(website)
    

#sitemap.xml
    count = check_sitemap(website)

#google analytics
    is_registered = is_google_analytics_registered(website)

#page speed
    page_loading_speed = calculate_loading_speed(website)                                                                               
#Page size
    page_size = get_page_size(website)

# Get the technologies used
    try:
        technologies = builtwith.builtwith(website)
    except Exception as e:
        print(f"Error retrieving technologies: {e}")
        technologies = {}


#social media report
    report = get_social_media_report(website)

#on pagelinks
    total_links,total_internal_urls,total_external_urls,remaining_links=onpagelinks(website)

    return render_template('rank_page_op.html',website_name=website,h1_tag=h1_content,header_count=heading_counts,
                           title=title_text,len_title=title_length,
                           cont=cont,desc_len=desc_len,
                           content=content_amt,alt_count=alt_count, non_alt_count=non_alt_count,
                           expiration_date=expiration_date, days_left=days_left,is_valid=is_valid,ssl_status=ssl,
                           robots=robots_txt,sitemap_count=count,
                           analytics=is_registered,meta_len=desc_len,meta=cont,
                           output_dict=output_dict, output_df=output_df, user=current_user,report=report,
                           page_size=page_size,technologies=technologies,
                           total_links=total_links,total_external_urls=total_external_urls,total_internal_urls=total_internal_urls,
                           remaining_links=remaining_links,page_loading_speed=page_loading_speed)

# length of the title
def get_title_info(url):
    try:
        response=requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        title_text = soup.title.string
        title_length = len(title_text)
        return title_text, title_length
    except Exception as e:
        print("Error occurred:", str(e))
        return None, None, None

#meta tag
def get_meta_description(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        meta = soup.find_all('meta')
        for tag in meta:
            if 'name' in tag.attrs.keys() and tag.attrs['name'].strip().lower() in ['description', 'keywords']:
                if 'content' in tag.attrs:    
                    cont = tag.attrs['content']
                    desc_len = len(cont)
                    return cont, desc_len
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return "no access",0

# H1 tag content FUNCTION
def find_h1_tag(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        h1_tag = soup.find('h1')
        if h1_tag:
           return h1_tag.text
        else:
         return "H1 TAG NOT FOUND!!!"
        
    except Exception as e:
        print("Error occurred:",str(e))

# Header tags count [H1-H6] FUNCTION
def count_heading_tags(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')

    heading_counts = {}
    tags = ['h1', 'h2', 'h3', 'h4', 'h5', 'h6']
    for tag in tags:
        count = len(soup.find_all(tag))
        if count == 0:
            heading_counts[tag] = "{} TAG NOT FOUND".format(tag.upper())
        else:
            heading_counts[tag] = "{} tag - {}".format(tag.upper(), count)
    return heading_counts

#  amount of content
def calculate_content_amount(url):
    try:
        response = requests.get(url)
        content = response.text
        words = content.split()
        word_count = len(words)
        return word_count
    except Exception as e:
        print(f"Error retrieving content: {e}")
        return None

# image alt tag  
def count_alt_tags(url):
    alt_count = 0  
    non_alt_count = 0  
    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.content, 'html.parser')
        images = soup.find_all('img')
        for image in images:
            if 'alt' in image.attrs:
                if image['alt']:
                    alt_count += 1
                else:
                    non_alt_count += 1
            else:
                non_alt_count += 1
    else:
        print("Failed to retrieve the website content.")

    return alt_count, non_alt_count

#check ssl
def check_website_ssl(url):
    response = requests.get(url, verify=True)
    if response.status_code == 200:
        ssl=response.url.startswith('https://')    
    else:
        ssl = "Failed to retrieve website information."
    return ssl

#ssl certificate 
def check_ssl_certificate(url):
    hostname = url.split('//')[-1].split('/')[0]
    context = ssl.create_default_context()
    
    try:
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expiration_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                current_date = datetime.now()
                daysToExpiration = (expiration_date - datetime.now()).days
                return {
                    "expiration_date": expiration_date,
                    "Days_Left": daysToExpiration,
                    "valid": expiration_date > current_date
                }
    except Exception as e:
        print("Error on connection to Server", hostname)
        print(e)
        return {
            "expiration_date": None,
            "Days_Left": None,
            "valid": False
        }

# Robots.txt FUNCTION
def find_robots_txt(url):
    try:
        if not url.endswith('/'):
            url += '/'
        robots_url = url + 'robots.txt'
        response = requests.get(robots_url)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException:
            return None

#sitemap.xml
def check_sitemap(url):
    sitemap_url = url + "/sitemap.xml"
    response = requests.get(sitemap_url)
    try:
        raw = xmltodict.parse(response.text)
    except (ExpatError,KeyError):
        return False,0,"Your website doesn't allow to access sitemap.xml file"
    if "urlset" in raw:
        data = []
        for r in raw["urlset"]["url"]:
            loc=r.get("loc","")
            lastmod=r.get("lastmod","")
            data.append([loc,lastmod])
    elif "sitemapindex" in raw:
        data = [] 
        for r in raw["sitemapindex"]["sitemap"]:
            loc = r.get("loc","")
            lastmod=r.get("lastmod","")
            data.append([loc,lastmod])
    else:
        return False, 0
    count=len(data)
    if count == 0:
        return False,0
    else:
        return True, count



#Google analytics
def is_google_analytics_registered(url):
    response = requests.get(url)
    if response.status_code == 200:
        html_content = response.text
        if 'google-analytics.com/analytics.js' in html_content or 'googletagmanager.com/gtag/js' in html_content:
            return True
    return False

#page speed
def calculate_loading_speed(url):
    start_time = time.time()
    response = requests.get(url)
    end_time = time.time()
    loading_time = end_time - start_time
    return loading_time

#page size
def get_page_size(url):
    try:
        with urllib.request.urlopen(url) as response:
            total_bytes = 0
            while True:
                chunk = response.read(4096)  # Read 4KB at a time
                if not chunk:
                    break
                total_bytes += len(chunk)
                
        page_size_mb = total_bytes / 1048576
        return page_size_mb

    except urllib.error.URLError as e:
        print(f"An error occurred: {e}")
        return None



# Social media report
def get_social_media_report(url):
    response = requests.get(url)
    html_content = response.text

    social_media_accounts = {
        'Facebook': 'facebook.com',
        'Instagram': 'instagram.com',
        'LinkedIn': 'linkedin.com',
        'Twitter': 'twitter.com',
        'YouTube': 'youtube.com'
    }

    results = {}

    for platform, account_url in social_media_accounts.items():
        if account_url in html_content:
            results[platform] = 'Account Found'
        else:
            results[platform] = 'No Result Found'

    return results
#on page links
def onpagelinks(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, "html.parser")
    all_urls = soup.findAll("a")
    internal_urls = set()
    external_urls = set()
    
    for link in all_urls:
        href = link.get('href')
        if href:
            if url in href:
                internal_urls.add(href)
            elif href[0] == "#":
                internal_urls.add(f"{url}{href}")
            elif href[0:3] == "tel":
                internal_urls.add(f"{url}{href}")
            elif href[0] == "/":
                internal_urls.add(f"{url}{href}")
            else:
                external_urls.add(href)
    
    total_links = len(all_urls)
    total_internal_urls = len(internal_urls)
    total_external_urls = len(external_urls)
   
    remaining_links = total_links - total_internal_urls - total_external_urls

    return  total_links,total_internal_urls,total_external_urls,remaining_links
        

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
         hashed_password = bcrypt.generate_password_hash(form.password.data)
         new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
         db.session.add(new_user)
         db.session.commit()
         return redirect(url_for('login'))

    return render_template('register.html', form=form)


if __name__ == "__main__":
    app.run(debug=True)