from dotenv import load_dotenv
import os

load_dotenv()
print("VT_API_KEY:", os.getenv("VT_API_KEY"))