from datasets import load_dataset
from huggingface_hub import hf_hub_download, snapshot_download
from transformers import AutoModel, AutoTokenizer

# UNSAFE: These should trigger B615 warnings

# Unsafe model loading without revision
model = AutoModel.from_pretrained("bert-base-uncased")

# Unsafe tokenizer loading without revision  
tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased")

# Unsafe dataset loading without revision
dataset = load_dataset("imdb")

# Unsafe file download without revision
file_path = hf_hub_download(
    repo_id="deepseek-ai/DeepSeek-R1",
    filename="config.json"
)

# Unsafe snapshot download without revision
snapshot_download(repo_id="meta-llama/Llama-3.1-8B-Instruct")

# SAFE: These should NOT trigger warnings

# Safe model loading with revision pinned
safe_model = AutoModel.from_pretrained(
    "deepseek-ai/DeepSeek-V3", 
    revision="main"
)

# Safe model loading with commit hash
safe_model_hash = AutoModel.from_pretrained(
    "google-bert/bert-base-uncased",
    revision="5d0f2e8a7f1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d"
)

# Safe tokenizer with revision
safe_tokenizer = AutoTokenizer.from_pretrained(
    "bert-base-uncased",
    revision="v1.0"
)

# Safe dataset loading with revision
safe_dataset = load_dataset("imdb", revision="main")

# Safe file download with revision
safe_file = hf_hub_download(
    repo_id="microsoft/DialoGPT-medium",
    filename="config.json",
    revision="main"
)

# Safe snapshot download with revision
snapshot_download(
    repo_id="microsoft/DialoGPT-medium",
    revision="v1.0"
)

# Safe: using authentication token (implies controlled access)
auth_model = AutoModel.from_pretrained(
    "private/model",
    use_auth_token=True
)

# Safe: local path (not downloading from hub)
local_model = AutoModel.from_pretrained("./local_model")
local_model2 = AutoModel.from_pretrained("/path/to/model")
