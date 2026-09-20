# Model-Based Detection

A detector can use a machine learning model to detect threats.
The model mode runs the model against the value text.
The mixed mode runs regex rules and the model together.


## ModelConfig

`ModelConfig` carries all settings for a model.

```python
from qarai_agent_guard.core.models import ModelConfig

config = ModelConfig(
    provider="huggingface",
    model="my-org/my-custom-model",
    task="text-classification",
    threshold=0.6,
)
```

### Parameters

| Parameter | Type | Default | Role |
| --- | --- | --- | --- |
| `provider` | `ModelProviderName` or `str` | Required | The model hosting provider. |
| `model` | `str` | Required | The model identifier. |
| `task` | `ModelTask` or `str` | `"text-classification"` | The task type that selects the model class. |
| `threshold` | `float` | `0.5` | Confidence threshold in `[0, 1]`. |
| `hf_access_token` | `str` | `None` | HuggingFace access token for private models. |
| `api_key` | `str` | `None` | API key for providers. Reserved for future use. |
| `output_formatter` | `Callable` | `None` | Converts raw model output to a result. |
| `model_options` | `dict` | `None` | Arguments for `AutoModel*.from_pretrained()`. |
| `tokenizer_options` | `dict` | `None` | Arguments for `AutoTokenizer.from_pretrained()`. |
| `inference_options` | `dict` | `None` | Arguments for the model call at inference time. |

Raises `ConfigurationError` when:

- `provider` is not `"huggingface"`.
- `model` is empty.
- `task` is not a supported task.
- `threshold` is not a number in `[0, 1]`.
- `output_formatter` is not callable.
- `model_options`, `tokenizer_options`, or `inference_options` is not a dictionary.

### Providers

The library supports one provider:

| Value | Provider |
| --- | --- |
| `"huggingface"` | HuggingFace Hub models and local paths |

### Tasks

The library supports four task types:

| Value | Model class | Use |
| --- | --- | --- |
| `"text-classification"` | `AutoModelForSequenceClassification` | Whole-text classification, for example prompt-injection detection. |
| `"token-classification"` | `AutoModelForTokenClassification` | Token-level labeling, for example PII or NER. |
| `"text-generation"` | `AutoModelForCausalLM` | Causal language modeling. |
| `"text2text-generation"` | `AutoModelForSeq2SeqLM` | Encoder-decoder generation. |

## Default models

The library provides default models for two rule sets.
`resolve_default_model` returns the `ModelConfig` for a rule set.

```python
from qarai_agent_guard.core.models import resolve_default_model

config = resolve_default_model("prompt_injection")
```

### Default model table

| Rule set | Model | Task | Threshold |
| --- | --- | --- | --- |
| `prompt_injection` | `deepset/deberta-v3-base-injection` | `text-classification` | `0.5` |
| `pii` | `SoelMgd/bert-pii-detection` | `token-classification` | `0.4` |

The PII default config also sets the inference option `aggregation_strategy` to `"simple"`.

`resolve_default_model` returns `None` for rule sets without a default model:

```python
print(resolve_default_model("secrets"))  # None
```

It also returns `None` for an invalid rule set.
It does not raise an exception.
The detector layer performs configuration validation.

A detector resolves the default model automatically when you set `default_rules`:

```python
from qarai_agent_guard import Detector

detector = Detector(
    name="model_prompt_injection",
    detector_type="model",
    default_rules="prompt_injection",
)
```

The default prompt-injection model is `deepset/deberta-v3-base-injection`.
The default PII model is `SoelMgd/bert-pii-detection`.

An explicit `model` takes precedence over a default model:

```python
config = ModelConfig(
    provider="huggingface",
    model="my-org/my-custom-model",
    task="text-classification",
    threshold=0.6,
)

detector = Detector(
    name="custom_model",
    detector_type="model",
    model=config,
)
```

## Output formatting

The model provider returns raw model output.
The inference engine converts the raw output into a `ModelDetectionResult`.

### DefaultOutputFormatter

`DefaultOutputFormatter` recognizes these output shapes:

| Shape | Detection rule |
| --- | --- |
| `bool` | `True` is a detection. |
| Integer `0` or `1` | `1` is a detection. |
| Float in `[0, 1]` | A detection when the score meets `threshold`. |
| `{"label": str, "score": float}` | A detection when the score meets `threshold`. |
| `list` of token entities | A detection when any entity score meets `threshold`. |
| `[{"generated_text": str}]` | A detection when the text matches a positive verdict word. |

Positive verdict words: `true`, `yes`, `unsafe`, `block`, `malicious`, `injection`.
Negative verdict words: `false`, `no`, `safe`, `allow`, `benign`, `clean`.

`DefaultOutputFormatter` raises `ModelOutputError` for unsupported output.

Models with custom heads, JSON text output, or custom label semantics need an explicit `output_formatter`.

### ModelDetectionResult

A formatter returns a `ModelDetectionResult`:

| Field | Type | Role |
| --- | --- | --- |
| `detected` | `bool` | Whether the model found a threat. |
| `score` | `float` or `None` | The detection score. |
| `severity` | `Severity` or `None` | The detection severity. |
| `metadata` | `dict` | Extra context. |
| `entities` | `list[dict]` | Detected entities for redaction. |

When `detected` is `True` and no severity is given, the severity becomes `CRITICAL`.
When `detected` is `False` and no severity is given, the severity becomes `LOW`.

## Use an external model with an explicit formatter

The provider may return output that the default formatter cannot read.
In this case, write an explicit `output_formatter`.

The formatter signature is:

```python
def formatter(raw_output, config) -> ModelDetectionResult:
    ...
```

It receives the raw provider output and the `ModelConfig`.
It must return a `ModelDetectionResult`.
The `InferenceEngine` raises `ModelFormatterError` when the formatter returns another type.

Example for a text-classification model:

```python
from qarai_agent_guard.core.models import ModelConfig
from qarai_agent_guard.core.schemas import Severity
from qarai_agent_guard.core.schemas.models import ModelDetectionResult


def classify_formatter(raw, config):
    item = raw[0] if isinstance(raw, list) else raw
    label = str(item["label"]).upper()
    score = float(item["score"])
    detected = label in {"INJECTION", "LABEL_1", "PROMPT_INJECTION"} and score >= config.threshold
    return ModelDetectionResult(
        detected=detected,
        score=score if detected else 1 - score,
        severity=Severity.CRITICAL if detected else Severity.LOW,
        metadata={"raw_label": item["label"], "raw_score": score},
    )


config = ModelConfig(
    provider="huggingface",
    model="deepset/deberta-v3-base-injection",
    task="text-classification",
    threshold=0.5,
    output_formatter=classify_formatter,
)

detector = Detector(
    name="external_model",
    detector_type="model",
    model=config,
)
```

Example for a token-classification model:

```python
def token_formatter(raw, config):
    entities = [
        item
        for item in raw
        if item.get("entity_group", item.get("entity", "O")) not in ("O", "")
        and float(item.get("score", 0)) >= config.threshold
    ]
    score = max((float(item["score"]) for item in entities), default=0.0)
    return ModelDetectionResult(
        detected=bool(entities),
        score=score,
        severity=Severity.CRITICAL if entities else Severity.LOW,
        entities=entities,
        metadata={"detected_token_count": len(entities)},
    )
```

## InferenceEngine

`InferenceEngine` executes model inference and normalizes the output.

The detector creates an engine automatically.
You can share one engine across detectors:

```python
from qarai_agent_guard.core.models import InferenceEngine, ModelLoader
from qarai_agent_guard import Detector

loader = ModelLoader()
engine = InferenceEngine(loader)

first = Detector(
    name="injection_a",
    detector_type="model",
    default_rules="prompt_injection",
    inference_engine=engine,
)

second = Detector(
    name="injection_b",
    detector_type="model",
    default_rules="prompt_injection",
    inference_engine=engine,
)
```

`InferenceEngine.predict` runs this process:

1. Load the provider through the `ModelLoader`.
2. Call the provider with the value text.
3. Format the raw output with the configured formatter.
4. Return the `ModelDetectionResult`.

## ModelLoader

`ModelLoader` loads, caches, and unloads model providers.

The loader caches providers by model configuration.
Multiple detectors that use the same model share one loaded pipeline.

The cache key covers the provider, the model identifier, the task, and the model and tokenizer options.
It does not cover the threshold or the output formatter.

```python
loader = ModelLoader()
provider = loader.get(config)   # Loads and caches the model
loader.release(config)          # Unloads one provider
loader.clear()                  # Unloads all providers
```

Methods:

| Method | Role |
| --- | --- |
| `get(config)` | Returns a loaded provider for the configuration. Loads the model on first access. |
| `release(config)` | Removes and unloads the provider. |
| `clear()` | Removes and unloads all cached providers. |

`get` raises `ModelLoadError` when the model cannot load.
`release` raises `ModelLoadError` when the unload fails.
`clear` raises `ModelLoadError` when at least one unload fails.

## Providers

Providers load a model and run inference.

| Class | Role |
| --- | --- |
| `ModelProvider` | Abstract base class for all providers. |
| `HuggingFaceProvider` | Loads a HuggingFace pipeline and returns raw output. |
| `ModelProviderFactory` | Creates a provider for a `ModelConfig`. |

`HuggingFaceProvider` returns raw, unmodified output.
The `InferenceEngine` handles output shaping.

The provider maps each task to a HuggingFace pipeline name:

| Task | Pipeline |
| --- | --- |
| `text-classification` | `text-classification` |
| `token-classification` | `token-classification` |
| `text-generation` | `text-generation` |
| `text2text-generation` | `text2text-generation` |
