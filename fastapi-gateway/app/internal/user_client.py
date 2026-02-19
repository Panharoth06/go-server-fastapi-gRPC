import grpc

# We import the generated files from the gen folder
from gen import user_pb2, user_pb2_grpc

class UserClient:
    def __init__(self):
        # Establish the connection to the Go server
        self.channel = grpc.insecure_channel('localhost:50051')
        
        # Create the 'stub' (our portal to the Go methods)
        self.stub = user_pb2_grpc.UserServiceStub(self.channel)
        
    def get_user(self, user_id: str):
        # Construct the request message defined in our .proto
        request = user_pb2.UserRequest(user_id=user_id)

        # Call the Go server!
        return self.stub.GetUser(request)


# Create a singleton instance to be used by FastAPI
user_client = UserClient()


def get_user(user_id: str):
    return user_client.get_user(user_id)
