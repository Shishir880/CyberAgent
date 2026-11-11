"""
CyberAgent Qwen 2.5 3B Fast Fine-Tuning Script (Unsloth + QLoRA)
===============================================================
Trains Qwen 2.5 3B on CyberAgent's 41 tools for lightning-fast tool calling.
Runs in 15-20 minutes on Free Google Colab T4 or local RTX GPU.

Requirements:
    pip install "unsloth[colab-new] @ git+https://github.com/unslothai/unsloth.git"
    pip install --no-deps trl peft accelerate bitsandbytes
"""

import os
import torch
from datasets import load_dataset
from unsloth import FastLanguageModel
from trl import SFTTrainer
from transformers import TrainingArguments

# 1. Configuration
MAX_SEQ_LENGTH = 2048
DTYPE = None  # None for auto detection (Float16 for Tesla T4, Bfloat16 for Ampere+)
LOAD_IN_4BIT = True  # Uses 4bit quantization to save 80% VRAM

MODEL_NAME = "unsloth/Qwen2.5-3B-Instruct"  # Fast 3B model

print("[*] Loading base model and tokenizer...")
model, tokenizer = FastLanguageModel.from_pretrained(
    model_name=MODEL_NAME,
    max_seq_length=MAX_SEQ_LENGTH,
    dtype=DTYPE,
    load_in_4bit=LOAD_IN_4BIT,
)

# 2. Add LoRA Adapters
model = FastLanguageModel.get_peft_model(
    model,
    r=16,  # Suggested 8, 16, 32, 64
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                    "gate_proj", "up_proj", "down_proj"],
    lora_alpha=16,
    lora_dropout=0,  # 0 is optimized by Unsloth
    bias="none",
    use_gradient_checkpointing="unsloth",
    random_state=3407,
)

# 3. Load & Format Dataset
this_dir = os.path.dirname(os.path.abspath(__file__))
master_dataset_path = os.path.join(this_dir, "cyberagent_master_multiturn_dataset.jsonl")
legacy_dataset_path = os.path.join(this_dir, "cyber_agent_finetune_dataset.jsonl")

dataset_path = master_dataset_path if os.path.exists(master_dataset_path) else legacy_dataset_path
print(f"[*] Loading training dataset from: {dataset_path}")

dataset = load_dataset("json", data_files=dataset_path, split="train")

def format_conversations(batch):
    formatted_texts = []
    for conv in batch["messages"]:
        # Render into Qwen ChatML format
        text = tokenizer.apply_chat_template(conv, tokenize=False, add_generation_prompt=False)
        formatted_texts.append(text)
    return {"text": formatted_texts}

dataset = dataset.map(format_conversations, batched=True)

# 4. Initialize Trainer
trainer = SFTTrainer(
    model=model,
    tokenizer=tokenizer,
    train_dataset=dataset,
    dataset_text_field="text",
    max_seq_length=MAX_SEQ_LENGTH,
    dataset_num_proc=2,
    packing=False,
    args=TrainingArguments(
        per_device_train_batch_size=2,
        gradient_accumulation_steps=4,
        warmup_steps=5,
        max_steps=60,
        learning_rate=2e-4,
        fp16=not torch.cuda.is_bf16_supported(),
        bf16=torch.cuda.is_bf16_supported(),
        logging_steps=1,
        optim="adamw_8bit",
        weight_decay=0.01,
        lr_scheduler_type="linear",
        seed=3407,
        output_dir="outputs",
    ),
)

print("[*] Starting fast fine-tuning training...")
trainer_stats = trainer.train()

# 5. Export to GGUF for Ollama
output_gguf_dir = os.path.join(this_dir, "cyberagent_qwen3b_gguf")
print(f"[*] Exporting trained model to GGUF for Ollama at {output_gguf_dir}...")
model.save_pretrained_gguf(output_gguf_dir, tokenizer, quantization_method="q4_k_m")

print("\n[+] Done! You can now import it into Ollama with:")
print(f"    ollama create cyberagent-3b -f Modelfile")
