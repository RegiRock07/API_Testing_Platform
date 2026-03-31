# API Sentinel — Version 4

## Overview of Changes: Groq Integration

Version 4 transitions the API Sentinel platform from using Ollama as its hardcoded LLM to a **centralized, pluggable LLM architecture** where **Groq is the primary provider** and Ollama serves as a development/offline fallback.

### What Changed?

1. **Centralized LLM Gateway (`llm_service.py`)**
   - Moved all LLM calling logic (previously duplicated across 5+ files) into `backend/app/services/llm_service.py`.
   - The service exposes a single `call_llm(messages)` function, abstracting away the provider implementation.
   - Replaced redundant `.json()` parsing code with a robust, shared `parse_llm_json()` utility that properly handles markdown fenced JSON blocks and exceptions.
   - Replaced silent `None` failures with explicit `LLMError` exceptions, handled uniformly by individual agents.

2. **Provider Controls**
   - The active LLM provider is now controlled globally via the `LLM_PROVIDER` environment variable.
   - Supported values:
     - `groq` (Default, relies on `GROQ_API_KEY`)
     - `ollama` (Fallback)

3. **Unified Modeling**
   - Removed the per-agent model variables (e.g., `PLANNER_MODEL`, `SECURITY_MODEL`).
   - A single `GROQ_MODEL` or `OLLAMA_DEFAULT_MODEL` is used uniformly across the pipeline. This significantly reduces configuration complexity.

4. **Agent Refactoring**
   - **`planner_agent.py`**
   - **`security_agent.py`**
   - **`deep_scan_agent.py`**
   - **`test_generation_agent.py`**
   - **`api_testing_agent.py`**
   - **`orchestrator.py`** (Synthesis step)
   - All modules now import and use `call_llm()` and `parse_llm_json()` directly, cleaning up hundreds of lines of duplicated boilerplate. `deployment_agent.py` remains unchanged as it purely relies on HTTP rules.

5. **Infrastructure Updates**
   - Added `groq` to `requirements.txt`.
   - Updated `.env.example` and `docker-compose.yml` with the new Groq settings and an overhauled `LLM Configuration` section.

### Benefits
- **Performance**: Tests and test-generation powered by Groq (via models like `llama3-70b-8192`) run remarkably faster than local Ollama, drastically decreasing pipeline execution time.
- **Maintainability**: Modifying prompts, temperatures, or parsing logic takes place in a single spot (`llm_service.py`). Adding a new LLM provider (like OpenAI or Anthropic) only requires adding ~15 lines to one file.
- **Reliability**: Unified exception handling avoids obscure `NoneType` errors inside LangGraph nodes.
