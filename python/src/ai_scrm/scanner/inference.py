"""
Model inference database for smart defaults.

Maps common model name patterns to their suppliers and metadata.
This allows AI-SCRM to automatically fill in supplier information
for well-known models without requiring manual input.

AI-SCRM Supply Chain Tooling for AI Architecture
Version: 1.0.1
By: Shawn Kahalewai Reilly
Repo: HTTPS://github.com/kahalewai/ai-scrm
License: Apache License 2.0
"""

from typing import Dict, List, Optional, Any
import re
from dataclasses import dataclass


@dataclass
class ModelInfo:
    """Inferred model information."""
    supplier: str
    model_type: str = "base"
    architecture: Optional[str] = None
    family: Optional[str] = None
    parameters: Optional[str] = None
    license: Optional[str] = None


# Pattern-based model database
# Patterns are matched against lowercase filenames
MODEL_PATTERNS: List[tuple] = [
    # Meta / Llama models
    (r"llama[-_]?3[-_.]?3", ModelInfo(
        supplier="Meta",
        architecture="llama",
        family="Llama 3.3"
    )),
    (r"llama[-_]?3[-_.]?2", ModelInfo(
        supplier="Meta",
        architecture="llama",
        family="Llama 3.2"
    )),
    (r"llama[-_]?3[-_.]?1", ModelInfo(
        supplier="Meta",
        architecture="llama",
        family="Llama 3.1"
    )),
    (r"llama[-_]?3", ModelInfo(
        supplier="Meta",
        architecture="llama",
        family="Llama 3"
    )),
    (r"llama[-_]?2", ModelInfo(
        supplier="Meta",
        architecture="llama",
        family="Llama 2"
    )),
    (r"codellama|code[-_]?llama", ModelInfo(
        supplier="Meta",
        architecture="llama",
        family="Code Llama"
    )),
    
    # Mistral AI
    (r"mistral[-_]?large", ModelInfo(
        supplier="Mistral AI",
        architecture="mistral",
        family="Mistral Large"
    )),
    (r"mistral[-_]?medium", ModelInfo(
        supplier="Mistral AI",
        architecture="mistral",
        family="Mistral Medium"
    )),
    (r"mistral[-_]?small", ModelInfo(
        supplier="Mistral AI",
        architecture="mistral",
        family="Mistral Small"
    )),
    (r"mistral[-_]?nemo", ModelInfo(
        supplier="Mistral AI",
        architecture="mistral",
        family="Mistral Nemo"
    )),
    (r"mixtral", ModelInfo(
        supplier="Mistral AI",
        architecture="mixtral",
        family="Mixtral"
    )),
    (r"mistral", ModelInfo(
        supplier="Mistral AI",
        architecture="mistral",
        family="Mistral"
    )),
    (r"codestral", ModelInfo(
        supplier="Mistral AI",
        architecture="mistral",
        family="Codestral"
    )),
    
    # OpenAI
    (r"gpt[-_]?4[-_]?o", ModelInfo(
        supplier="OpenAI",
        architecture="gpt",
        family="GPT-4o"
    )),
    (r"gpt[-_]?4[-_]?turbo", ModelInfo(
        supplier="OpenAI",
        architecture="gpt",
        family="GPT-4 Turbo"
    )),
    (r"gpt[-_]?4", ModelInfo(
        supplier="OpenAI",
        architecture="gpt",
        family="GPT-4"
    )),
    (r"gpt[-_]?3\.?5", ModelInfo(
        supplier="OpenAI",
        architecture="gpt",
        family="GPT-3.5"
    )),
    (r"text[-_]?embedding[-_]?ada", ModelInfo(
        supplier="OpenAI",
        architecture="embedding",
        family="Ada Embedding",
        model_type="embedding"
    )),
    (r"text[-_]?embedding[-_]?3", ModelInfo(
        supplier="OpenAI",
        architecture="embedding",
        family="Embedding v3",
        model_type="embedding"
    )),
    (r"whisper", ModelInfo(
        supplier="OpenAI",
        architecture="whisper",
        family="Whisper"
    )),
    
    # Anthropic
    (r"claude[-_]?3[-_.]?5[-_]?sonnet", ModelInfo(
        supplier="Anthropic",
        architecture="claude",
        family="Claude 3.5 Sonnet"
    )),
    (r"claude[-_]?3[-_.]?5[-_]?haiku", ModelInfo(
        supplier="Anthropic",
        architecture="claude",
        family="Claude 3.5 Haiku"
    )),
    (r"claude[-_]?3[-_]?opus", ModelInfo(
        supplier="Anthropic",
        architecture="claude",
        family="Claude 3 Opus"
    )),
    (r"claude[-_]?3[-_]?sonnet", ModelInfo(
        supplier="Anthropic",
        architecture="claude",
        family="Claude 3 Sonnet"
    )),
    (r"claude[-_]?3[-_]?haiku", ModelInfo(
        supplier="Anthropic",
        architecture="claude",
        family="Claude 3 Haiku"
    )),
    (r"claude", ModelInfo(
        supplier="Anthropic",
        architecture="claude",
        family="Claude"
    )),
    
    # Google
    (r"gemma[-_]?2", ModelInfo(
        supplier="Google",
        architecture="gemma",
        family="Gemma 2"
    )),
    (r"gemma", ModelInfo(
        supplier="Google",
        architecture="gemma",
        family="Gemma"
    )),
    (r"gemini[-_]?pro", ModelInfo(
        supplier="Google",
        architecture="gemini",
        family="Gemini Pro"
    )),
    (r"gemini[-_]?ultra", ModelInfo(
        supplier="Google",
        architecture="gemini",
        family="Gemini Ultra"
    )),
    (r"gemini[-_]?flash", ModelInfo(
        supplier="Google",
        architecture="gemini",
        family="Gemini Flash"
    )),
    (r"gemini", ModelInfo(
        supplier="Google",
        architecture="gemini",
        family="Gemini"
    )),
    (r"palm", ModelInfo(
        supplier="Google",
        architecture="palm",
        family="PaLM"
    )),
    (r"bert", ModelInfo(
        supplier="Google",
        architecture="bert",
        family="BERT"
    )),
    (r"t5", ModelInfo(
        supplier="Google",
        architecture="t5",
        family="T5"
    )),
    
    # Microsoft
    (r"phi[-_]?3", ModelInfo(
        supplier="Microsoft",
        architecture="phi",
        family="Phi-3"
    )),
    (r"phi[-_]?2", ModelInfo(
        supplier="Microsoft",
        architecture="phi",
        family="Phi-2"
    )),
    (r"phi", ModelInfo(
        supplier="Microsoft",
        architecture="phi",
        family="Phi"
    )),
    (r"orca", ModelInfo(
        supplier="Microsoft",
        architecture="orca",
        family="Orca"
    )),
    
    # Cohere
    (r"command[-_]?r[-_]?plus", ModelInfo(
        supplier="Cohere",
        architecture="command",
        family="Command R+"
    )),
    (r"command[-_]?r", ModelInfo(
        supplier="Cohere",
        architecture="command",
        family="Command R"
    )),
    (r"command", ModelInfo(
        supplier="Cohere",
        architecture="command",
        family="Command"
    )),
    (r"embed[-_]?v3", ModelInfo(
        supplier="Cohere",
        architecture="embedding",
        family="Embed v3",
        model_type="embedding"
    )),
    
    # Alibaba
    (r"qwen[-_]?2\.?5", ModelInfo(
        supplier="Alibaba",
        architecture="qwen",
        family="Qwen 2.5"
    )),
    (r"qwen[-_]?2", ModelInfo(
        supplier="Alibaba",
        architecture="qwen",
        family="Qwen 2"
    )),
    (r"qwen", ModelInfo(
        supplier="Alibaba",
        architecture="qwen",
        family="Qwen"
    )),
    
    # DeepSeek
    (r"deepseek[-_]?coder[-_]?v2", ModelInfo(
        supplier="DeepSeek",
        architecture="deepseek",
        family="DeepSeek Coder V2"
    )),
    (r"deepseek[-_]?coder", ModelInfo(
        supplier="DeepSeek",
        architecture="deepseek",
        family="DeepSeek Coder"
    )),
    (r"deepseek[-_]?v2", ModelInfo(
        supplier="DeepSeek",
        architecture="deepseek",
        family="DeepSeek V2"
    )),
    (r"deepseek", ModelInfo(
        supplier="DeepSeek",
        architecture="deepseek",
        family="DeepSeek"
    )),
    
    # Stability AI
    (r"stable[-_]?diffusion[-_]?xl|sdxl", ModelInfo(
        supplier="Stability AI",
        architecture="diffusion",
        family="Stable Diffusion XL"
    )),
    (r"stable[-_]?diffusion[-_]?3", ModelInfo(
        supplier="Stability AI",
        architecture="diffusion",
        family="Stable Diffusion 3"
    )),
    (r"stable[-_]?diffusion", ModelInfo(
        supplier="Stability AI",
        architecture="diffusion",
        family="Stable Diffusion"
    )),
    (r"stablelm", ModelInfo(
        supplier="Stability AI",
        architecture="stablelm",
        family="StableLM"
    )),
    
    # Hugging Face
    (r"starcoder[-_]?2", ModelInfo(
        supplier="Hugging Face",
        architecture="starcoder",
        family="StarCoder 2"
    )),
    (r"starcoder", ModelInfo(
        supplier="Hugging Face",
        architecture="starcoder",
        family="StarCoder"
    )),
    (r"falcon", ModelInfo(
        supplier="Technology Innovation Institute",
        architecture="falcon",
        family="Falcon"
    )),
    (r"bloom", ModelInfo(
        supplier="BigScience",
        architecture="bloom",
        family="BLOOM"
    )),
    
    # Sentence Transformers / Embeddings
    (r"all[-_]?minilm", ModelInfo(
        supplier="Sentence Transformers",
        architecture="minilm",
        family="MiniLM",
        model_type="embedding"
    )),
    (r"all[-_]?mpnet", ModelInfo(
        supplier="Sentence Transformers",
        architecture="mpnet",
        family="MPNet",
        model_type="embedding"
    )),
    (r"bge[-_]?large|bge[-_]?base|bge[-_]?small", ModelInfo(
        supplier="BAAI",
        architecture="bge",
        family="BGE",
        model_type="embedding"
    )),
    (r"e5[-_]?large|e5[-_]?base|e5[-_]?small", ModelInfo(
        supplier="Microsoft",
        architecture="e5",
        family="E5",
        model_type="embedding"
    )),
    (r"instructor", ModelInfo(
        supplier="Instructor Team",
        architecture="instructor",
        family="Instructor",
        model_type="embedding"
    )),
    (r"nomic[-_]?embed", ModelInfo(
        supplier="Nomic AI",
        architecture="nomic",
        family="Nomic Embed",
        model_type="embedding"
    )),
    (r"jina[-_]?embed", ModelInfo(
        supplier="Jina AI",
        architecture="jina",
        family="Jina Embeddings",
        model_type="embedding"
    )),
    
    # Other notable models
    (r"yi[-_]?34b|yi[-_]?6b|yi[-_]?9b", ModelInfo(
        supplier="01.AI",
        architecture="yi",
        family="Yi"
    )),
    (r"vicuna", ModelInfo(
        supplier="LMSYS",
        architecture="vicuna",
        family="Vicuna"
    )),
    (r"wizardlm|wizard[-_]?lm", ModelInfo(
        supplier="WizardLM Team",
        architecture="wizardlm",
        family="WizardLM"
    )),
    (r"zephyr", ModelInfo(
        supplier="Hugging Face",
        architecture="zephyr",
        family="Zephyr"
    )),
    (r"neural[-_]?chat", ModelInfo(
        supplier="Intel",
        architecture="neuralchat",
        family="Neural Chat"
    )),
    (r"openchat", ModelInfo(
        supplier="OpenChat Team",
        architecture="openchat",
        family="OpenChat"
    )),
    (r"solar", ModelInfo(
        supplier="Upstage",
        architecture="solar",
        family="Solar"
    )),
]

# Parameter size patterns
PARAM_PATTERNS: List[tuple] = [
    (r"(\d+\.?\d*)[-_]?b\b", lambda m: f"{m.group(1)}B"),  # 7b, 70b, 1.5b
    (r"(\d+)[-_]?m\b", lambda m: f"{m.group(1)}M"),  # 125m, 350m
    (r"(\d+)[-_]?k\b", lambda m: f"{m.group(1)}K"),  # rare but exists
]

# Fine-tuned model indicators
FINETUNE_INDICATORS = [
    "instruct", "chat", "tuned", "sft", "rlhf", "dpo",
    "ft", "finetuned", "fine-tuned", "aligned"
]

# Adapter/LoRA indicators
ADAPTER_INDICATORS = [
    "lora", "qlora", "peft", "adapter", "delta"
]

# Quantization indicators (for format detection)
QUANT_INDICATORS = {
    "q4_0": "GGUF-Q4_0",
    "q4_1": "GGUF-Q4_1",
    "q4_k_m": "GGUF-Q4_K_M",
    "q4_k_s": "GGUF-Q4_K_S",
    "q5_0": "GGUF-Q5_0",
    "q5_1": "GGUF-Q5_1",
    "q5_k_m": "GGUF-Q5_K_M",
    "q5_k_s": "GGUF-Q5_K_S",
    "q6_k": "GGUF-Q6_K",
    "q8_0": "GGUF-Q8_0",
    "f16": "FP16",
    "f32": "FP32",
    "bf16": "BF16",
    "int8": "INT8",
    "int4": "INT4",
    "awq": "AWQ",
    "gptq": "GPTQ",
    "exl2": "EXL2",
}


def infer_model_info(filename: str) -> Optional[ModelInfo]:
    """
    Infer model information from filename.
    
    Args:
        filename: Model filename (e.g., "llama-3-8b-instruct.safetensors")
    
    Returns:
        ModelInfo if pattern matched, None otherwise
    """
    name_lower = filename.lower()
    
    # Find matching model pattern
    for pattern, info in MODEL_PATTERNS:
        if re.search(pattern, name_lower):
            # Create copy to modify
            result = ModelInfo(
                supplier=info.supplier,
                model_type=info.model_type,
                architecture=info.architecture,
                family=info.family,
                parameters=info.parameters,
                license=info.license
            )
            
            # Try to extract parameter count
            for param_pattern, extractor in PARAM_PATTERNS:
                match = re.search(param_pattern, name_lower)
                if match:
                    result.parameters = extractor(match)
                    break
            
            # Check for fine-tuned indicators
            for indicator in FINETUNE_INDICATORS:
                if indicator in name_lower:
                    result.model_type = "fine-tuned"
                    break
            
            # Check for adapter indicators
            for indicator in ADAPTER_INDICATORS:
                if indicator in name_lower:
                    result.model_type = "adapter"
                    break
            
            return result
    
    return None


def infer_format_from_extension(filepath: str) -> Optional[str]:
    """
    Infer model format from file extension.
    
    Args:
        filepath: Full path or filename
    
    Returns:
        Format string if recognized, None otherwise
    """
    ext_lower = filepath.lower()
    
    if ext_lower.endswith(".safetensors"):
        return "safetensors"
    elif ext_lower.endswith(".gguf"):
        return "gguf"
    elif ext_lower.endswith(".ggml"):
        return "ggml"
    elif ext_lower.endswith(".pt") or ext_lower.endswith(".pth"):
        return "pytorch"
    elif ext_lower.endswith(".bin"):
        return "pytorch-bin"
    elif ext_lower.endswith(".onnx"):
        return "onnx"
    elif ext_lower.endswith(".tflite"):
        return "tflite"
    elif ext_lower.endswith(".mlmodel"):
        return "coreml"
    elif ext_lower.endswith(".h5") or ext_lower.endswith(".keras"):
        return "keras"
    elif ext_lower.endswith(".pb"):
        return "tensorflow"
    elif ext_lower.endswith(".engine") or ext_lower.endswith(".trt"):
        return "tensorrt"
    
    return None


def infer_quantization(filename: str) -> Optional[str]:
    """
    Infer quantization type from filename.
    
    Args:
        filename: Model filename
    
    Returns:
        Quantization string if detected, None otherwise
    """
    name_lower = filename.lower()
    
    for indicator, quant_type in QUANT_INDICATORS.items():
        if indicator in name_lower:
            return quant_type
    
    return None


def get_huggingface_info(cache_path: str) -> Optional[Dict[str, str]]:
    """
    Extract model info from HuggingFace cache directory structure.
    
    Args:
        cache_path: Path like ~/.cache/huggingface/hub/models--meta-llama--Llama-3-8B/
    
    Returns:
        Dict with org and model name if parseable
    """
    import os
    dirname = os.path.basename(cache_path.rstrip("/"))
    
    if dirname.startswith("models--"):
        parts = dirname[8:].split("--")  # Remove "models--" prefix
        if len(parts) >= 2:
            return {
                "organization": parts[0],
                "model_name": "--".join(parts[1:]),
                "source": "huggingface"
            }
    
    return None
