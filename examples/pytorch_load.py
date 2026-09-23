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

# Example of a torch.*.load call that should NOT trigger B614
# Only pickle deserializers should trigger B614
torch.utils.cpp_extension.load(name="example_ext", sources=[])

# torch.jit.load uses TorchScript serialization, not pickle.
# It has no weights_only parameter and should NOT trigger B614.
jit_model = torch.jit.load('script_model.pt')

# torch.jit.load with map_location is still TorchScript; should NOT
# trigger B614.
jit_model_cpu = torch.jit.load('script_model.pt', map_location='cpu')

# weights_only reaching torch.load as a name rather than a literal. The
# dangerous value is right there, but B614 does no dataflow, so it cannot
# resolve either of these statically. Both still trigger B614, at MEDIUM
# confidence instead of HIGH.
unsafe_flag = False


def load_checkpoint(path, weights_only=False):
    return torch.load(path, weights_only=weights_only)


unresolved_model = models.resnet18()
unresolved_model.load_state_dict(
    torch.load('model_weights.pth', weights_only=unsafe_flag))
