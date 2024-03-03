import torch
import torchvision.models as models

# Example of saving a model
model = models.resnet18(pretrained=True)
torch.save(model.state_dict(), 'model_weights.pth')

# Example of loading the model weights in an insecure way
loaded_model = models.resnet18()
loaded_model.load_state_dict(torch.load('model_weights.pth'))

# Another example using torch.load with more parameters
another_model = models.resnet18()
another_model.load_state_dict(torch.load('model_weights.pth', map_location='cpu'))

print("Model loaded successfully!")
