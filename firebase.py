import firebase_admin
from firebase_admin import credentials
from firebase_admin import db
import dotenv
import os

dotenv.load_dotenv()
CRED=os.environ.get("CRED")
URL=os.environ.get("URL")

cred = credentials.Certificate(CRED)

firebase_admin.initialize_app(cred, {
    'databaseURL': URL
})

ref = db.reference('/')