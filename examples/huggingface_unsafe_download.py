from datasets import load_dataset
from huggingface_hub import hf_hub_download, snapshot_download
from transformers import AutoModel, AutoTokenizer

# UNSAFE USAGE

# AutoModel (Model Loading)

# Example #1: No revision (defaults to floating 'main')
unsafe_model_no_revision = AutoModel.from_pretrained("org/model_name")

# Example #2: Floating revision: 'main'
unsafe_model_main = AutoModel.from_pretrained(
    "org/model_name",
    revision="main"
)

# Example #3: Floating tag revision: 'v1.0.0'
unsafe_model_tag = AutoModel.from_pretrained(
    "org/model_name",
    revision="v1.0.0"
)


# AutoTokenizer (Tokenizer Loading)

# Example #4: No revision
unsafe_tokenizer_no_revision = AutoTokenizer.from_pretrained("org/model_name")

# Example #5: Floating revision: 'main'
unsafe_tokenizer_main = AutoTokenizer.from_pretrained(
    "org/model_name",
    revision="main"
)

# Example #6: Floating tag revision: 'v1.0.0'
unsafe_tokenizer_tag = AutoTokenizer.from_pretrained(
    "org/model_name",
    revision="v1.0.0"
)


# Example #7: load_dataset (Dataset Loading)

# Example #8: No revision
unsafe_dataset_no_revision = load_dataset("org_dataset")

# Example #9: Floating revision: 'main'
unsafe_dataset_main = load_dataset("org_dataset", revision="main")

# Example #10: Floating tag revision: 'v1.0.0'
unsafe_dataset_tag = load_dataset("org_dataset", revision="v1.0.0")


# f_hub_download (File Download)

# Example #11: No revision
unsafe_file_no_revision = hf_hub_download(
    repo_id="org/model_name",
    filename="config.json"
)

# Example #12: Floating revision: 'main'
unsafe_file_main = hf_hub_download(
    repo_id="org/model_name",
    filename="config.json",
    revision="main"
)

# Example #13: Floating tag revision: 'v1.0.0'
unsafe_file_tag = hf_hub_download(
    repo_id="org/model_name",
    filename="config.json",
    revision="v1.0.0"
)


# snapshot_download (Repo Snapshot)

# Example #14: No revision
unsafe_snapshot_no_revision = snapshot_download(repo_id="org/model_name")

# Example #15: Floating revision: 'main'
unsafe_snapshot_main = snapshot_download(
    repo_id="org/model_name",
    revision="main"
)

# Example #16: Floating tag revision: 'v1.0.0'
unsafe_snapshot_tag = snapshot_download(
    repo_id="org/model_name",
    revision="v1.0.0"
)


# -------------------------------
# SAFE USAGE
# -------------------------------

# AutoModel

# Example #17: Pinned commit hash
safe_model_commit = AutoModel.from_pretrained(
    "org/model_name",
    revision="5d0f2e8a7f1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d"
)

# Example #18: Local path
safe_model_local = AutoModel.from_pretrained("./local_model")
safe_model_local_abs = AutoModel.from_pretrained("/path/to/model")

# AutoTokenizer

# Example #19: Pinned commit hash
safe_tokenizer_commit = AutoTokenizer.from_pretrained(
    "org/model_name",
    revision="5d0f2e8a7f1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d"
)

# Example #20: Local path
safe_tokenizer_local = AutoTokenizer.from_pretrained("./local_tokenizer")


# load_dataset

# Example #21: Pinned commit hash
safe_dataset_commit = load_dataset(
    "org_dataset",
    revision="5d0f2e8a7f1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d"
)


# hf_hub_download

# Example #22: Pinned commit hash
safe_file_commit = hf_hub_download(
    repo_id="org/model_name",
    filename="config.json",
    revision="5d0f2e8a7f1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d"
)


# snapshot_download

# Example #23: Pinned commit hash
safe_snapshot_commit = snapshot_download(
    repo_id="org/model_name",
    revision="5d0f2e8a7f1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d"
)
