from pymongo import MongoClient

uri = "mongodb+srv://crmuser1:crmuser%402025@cluster0.lnoynnv.mongodb.net/crm?retryWrites=true&w=majority&appName=Cluster0"

try:
    client = MongoClient(uri, serverSelectionTimeoutMS=5000)
    client.server_info()  # Forces a call to test the connection
    print("✅ MongoDB connection successful!")
except Exception as e:
    print("❌ Connection failed:")
    print(e)