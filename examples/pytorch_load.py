import torch
import torchvision.models as models

# Example of saving a model
model = models.resnet18(pretrained=True)
torch.save(model.state_dict(), 'model_weights.pth')

# Example of loading the model weights in an insecure way (should trigger B614)
loaded_model = models.resnet18()
loaded_model.load_state_dict(torch.load('model_weights.pth'))

# Example of loading with weights_only=True (should NOT trigger B614)
safe_model = models.resnet18()
safe_model.load_state_dict(torch.load('model_weights.pth', weights_only=True))

# Example of loading with weights_only=False (should trigger B614)
unsafe_model = models.resnet18()
unsafe_model.load_state_dict(torch.load('model_weights.pth', weights_only=False))

# Example of loading with map_location but no weights_only (should trigger B614)
cpu_model = models.resnet18()
cpu_model.load_state_dict(torch.load('model_weights.pth', map_location='cpu'))

# Example of loading with both map_location and weights_only=True (should NOT trigger B614)
safe_cpu_model = models.resnet18()
safe_cpu_model.load_state_dict(torch.load('model_weights.pth', map_location='cpu', weights_only=True))
