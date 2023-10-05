#Load Libraries
from oauth2client.service_account import ServiceAccountCredentials
from googleapiclient.discovery import build
import httplib2
 
#Create service credentials
#Rename your JSON key to client_secrets.json and save it to your working folder
scope = ['https://www.googleapis.com/auth/analytics.readonly']
credentials = ServiceAccountCredentials.from_json_keyfile_name('client_secrets.json,scope')
#client = gspread.authorize(credentials) 
                                                  
                                                               
  
#Create a service object
http = credentials.authorize(httplib2.Http())
service = build('analytics', 'v4', http=http, discoveryServiceUrl=('https://analyticsreporting.googleapis.com/$discovery/rest'))